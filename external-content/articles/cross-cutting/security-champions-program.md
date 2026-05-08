---
title: "Security Champions Programme: Embedding Security Knowledge in Engineering Teams"
description: "A central security team cannot review every PR and attend every design review. Security champions — engineers with security interest and training embedded in product teams — scale security knowledge across the organisation. This guide covers champion selection, curriculum design, tooling support, and measuring programme effectiveness."
slug: security-champions-program
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - security-champions
  - devSecOps
  - security-culture
  - training
  - shift-left
personas:
  - security-engineer
  - security-analyst
article_number: 601
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cross-cutting/security-champions-program/
---

# Security Champions Programme: Embedding Security Knowledge in Engineering Teams

## Problem

A central security team of four engineers cannot review the pull requests, design documents, and deployment decisions made by 200 developers every week. The maths never work. Either security becomes a bottleneck — slow, resented, circumvented — or security becomes advisory — warnings without teeth, findings without owners, recommendations without follow-through.

The standard response is to hire more security engineers. That helps, but it does not solve the structural problem. Security knowledge concentrated in a single team will always lag the pace of engineering. Developers make security-relevant decisions dozens of times per day: which library to use, how to structure an authentication flow, whether a piece of input needs sanitising, how broadly to scope a service account. A security engineer reviewing a PR three days later cannot change the decisions already embedded in design choices made at the start of the sprint.

The alternative is to distribute security knowledge into engineering teams — not by outsourcing security, but by developing engineers who can apply security thinking in context, with their peers, at the pace of development. This is the security champions programme: a network of engineers with security interest, formal training, and an explicit relationship with the central security team.

Common failure modes that make this problem urgent:

- **The bottleneck.** Every significant technical decision waits for a security team review. Reviews are slow because the team is small. Developers learn to frame decisions as low-risk to avoid the queue. Security coverage becomes sporadic and formulaic.
- **Rules without context.** Security guidance arrives as policy documents: "don't use MD5", "sanitise all user input". Without understanding why, developers apply rules mechanically and miss the spirit of them — disabling a broken hash but using another weak one, sanitising display output but not a SQL parameter.
- **Security debt accumulation.** Because no engineer on the product team owns security posture, security debt accumulates silently. It surfaces at penetration tests or, worse, at incidents.
- **No escalation path.** A developer notices something that feels wrong — an API endpoint with no authentication check, a dependency with a recent advisory — but does not know who to tell or whether it matters. The observation is lost.

**Target organisations:** Engineering organisations of 30+ developers where a central security team exists but cannot scale coverage across all product teams unassisted. The programme is most impactful in organisations with 5 or more distinct product or service teams.

## Programme Design

### Step 1: Champion Selection Criteria

The most important decision in programme design is who becomes a champion. Getting this wrong produces champions who are ignored, champions who burn out, and a programme that loses management confidence.

**Interest, not mandate.** Champions must volunteer. An engineer assigned to the role by a manager who wants to check a box will not engage with the curriculum, will not raise security issues with their team, and will not attend monthly meetings. The programme depends on intrinsic motivation. Recruitment should happen by direct invitation from the security team to engineers who have already demonstrated interest: asked security questions in all-hands, raised dependency vulnerabilities in PRs, attended optional security talks.

**Credibility with peers.** A champion who is not respected as an engineer will not be listened to on security. The security team should look for engineers who are already seen as technically strong within their team — people whose code reviews carry weight, whose architectural opinions are sought. Security training multiplies existing credibility; it does not create credibility from nothing.

**Communication skills.** Security knowledge that cannot be explained is not useful at the team level. A champion needs to translate security concepts into language their team understands: not "this violates the principle of least privilege" but "this service account can write to every S3 bucket in the account — if this service is compromised that's an immediate data loss event". Look for engineers who already communicate technical concepts clearly in documents and reviews.

**One champion per team.** Start with one champion per product or service team. Two champions per team sounds redundant until one leaves, but beginning with two dilutes the identity of the role and makes it harder to sustain the programme. Expand to two per team only once the programme is stable and attrition has been observed.

**Recommended champion-to-developer ratio:** 1 champion for every 8–15 engineers. Below this, champions are spread too thin. Above it, a single champion cannot maintain meaningful security coverage.

### Step 2: Champion Responsibilities

Responsibilities must be concrete, bounded, and agreed with the champion's manager before the programme starts. Vague responsibilities ("help with security") produce champions who are excluded from decisions because nobody knows when to involve them.

**Threat model participation.** Champions are the primary engineering contact for threat modelling sessions run by the central security team. They prepare their team's context — architecture diagrams, data flows, external integrations — and ensure that threat model outputs are translated into engineering tasks in the team's backlog. They are not expected to run threat modelling sessions independently until they have attended at least three facilitated by the security team.

**Security PR review.** Champions perform a security-focused pass on PRs that touch authentication, authorisation, input handling, cryptography, secrets, or external integrations. This is not a replacement for the standard review process — it is an additional review lens. The central security team should provide a PR review checklist tuned to the team's tech stack so that champions have a consistent framework rather than reviewing from memory.

**Security tooling liaison.** Champions are the first point of contact for security tooling outputs reaching their team: SAST findings, SCA alerts, secret scanning notifications, container image CVEs. They triage findings to distinguish genuine issues from false positives, assign remediation owners, and track resolution. They escalate to the central security team when a finding is ambiguous or the severity warrants it.

**Escalation path.** Champions provide the escalation path that developers currently lack. They are the named contact for "I saw something that seems wrong". They have a defined channel to the central security team — a Slack channel, a shared inbox, a weekly office hour — and are empowered to escalate without first having to determine whether something is a real issue. The act of escalation is itself the valuable contribution; assessment happens at the security team level.

### Step 3: Curriculum Design

Champions need training that is specific to their context, not generic security awareness content designed for all employees. A backend Python engineer and a platform engineer writing Terraform face different threat landscapes and need different applied knowledge.

**Foundation module — OWASP Top 10 for their stack.** Cover the OWASP Top 10 through the lens of the team's actual technology. For a Node.js team: how injection manifests in SQL queries constructed with string concatenation, how prototype pollution enables unexpected property overwrite, how broken access control surfaces in Express middleware ordering. Use real examples from the team's codebase where possible — a sanitised version of a finding from a recent code review or penetration test is more memorable than a contrived example.

**Secure coding patterns.** Cover the secure-by-default patterns for the team's primary language: parameterised queries, output encoding, constant-time comparison for secrets, CSRF token validation, secure cookie attributes, the correct way to call the crypto library. Provide a language-specific cheat sheet that champions can keep open during code reviews. The OWASP Cheat Sheet Series is a usable starting point; the security team should annotate it with organisation-specific decisions (which hashing algorithm the organisation standardises on, which JWT library is approved).

**Threat modelling basics.** Teach STRIDE as a thinking tool, not as a formal process. Champions do not need to run threat modelling sessions — they need to be able to ask the right questions when they encounter a new integration or feature. What data flows across this boundary? What happens if the caller is malicious? Who can trigger this operation, and should they all be able to? Practise through walkthroughs of the team's existing architecture rather than through abstract examples.

**Tool operation.** Champions should be able to interpret and triage output from the tools their organisation deploys: reading a Semgrep SAST report and distinguishing a true positive from a false positive; understanding a Grype container scan output and assessing exploitability; investigating a Gitleaks secret detection alert and determining whether credentials need rotating. Provide a one-page triage guide for each tool that covers the top five false positive patterns.

**Delivery format.** Four two-hour sessions works better than a two-day intensive. Space sessions two weeks apart so that champions can apply learning between sessions and bring real examples to the next one. Record sessions for asynchronous consumption by champions who join the programme later.

### Step 4: Time Commitment and Management Buy-In

A security champions programme without explicit management support will fail within six months. Champions will be pulled onto sprint work when timelines are tight. The first thing deprioritised will be the security review that was not in the sprint plan. Gradually, champions stop engaging.

**Time budget.** The realistic time commitment is 10–20% of a champion's working week, depending on the team's security surface area. For most product teams, 10% (roughly four hours per week) is sufficient: one to two PR reviews, tooling triage, and preparation for the monthly meeting. Teams handling financial data, authentication infrastructure, or regulated data may require 20%.

**Securing manager commitment.** Before announcing the programme publicly, meet with the managers of prospective champions. Frame the commitment explicitly: "four hours per week, ongoing, with the expectation that security reviews are not deprioritised during sprint pressure". Get written agreement — an email is sufficient. If a manager will not commit to the time allocation, do not enrol their team's engineer. A champion without protected time is a champion who will fail visibly, which is worse for the programme than having no champion on that team.

**Engineering leadership sponsorship.** The programme needs a sponsor at the VP of Engineering or CTO level who can reinforce the time allocation when middle management pushes back. Without this, security work will be treated as optional when it competes with feature delivery.

### Step 5: Monthly Champion Meetings

The monthly meeting is the operational heartbeat of the programme. It serves three functions: shared learning, programme coordination, and community maintenance.

**Vulnerability walkthroughs.** Each month, present one or two real vulnerabilities — either from the organisation's own findings or from recent public incidents — and walk through how they could have been detected earlier and what the champion network could do to find similar issues in the organisation's codebase. This keeps champion knowledge current and provides concrete examples they can bring back to their teams.

**Lessons from incidents.** After any security incident or near-miss, include a blameless retrospective in the monthly meeting. What did the champion network know or not know? Where was the escalation path unclear? What would a champion have noticed earlier? This loop ensures the programme improves from experience rather than remaining static.

**Shared tooling updates.** When the security team deploys new tools, updates SAST rules, or changes the triage process for a scanner, the monthly meeting is where champions are briefed first. Champions should hear about tooling changes before the general engineering population — this reinforces their position as informed liaisons rather than passive recipients.

**Format.** Sixty minutes, facilitated by the security team, with a rotating champion presenting a security topic relevant to their domain. Keep attendance records. Consistent non-attendance is a leading indicator of champion disengagement.

### Step 6: Recognition and Career Development

Security champions should gain concrete career benefit from participation. Relying on intrinsic motivation alone produces burnout; engineers need to see that the time investment translates to visible career outcomes.

**Security champion as a differentiator.** Work with engineering leadership to include security champion status in performance review frameworks — either as a standalone competency or as evidence of technical leadership. Champions should be able to reference the role, the curriculum completed, and specific contributions (threat models facilitated, vulnerabilities found in review) in performance conversations.

**Conference and writing opportunities.** The security team should actively route speaking and writing opportunities to champions. A champion who has been working on container image hardening for six months has a credible perspective for a conference talk or a technical blog post. This visibility benefits the organisation's security brand and rewards the champion with a professional asset that persists beyond their time at the company.

**Security certification support.** Offer to fund relevant certifications for active champions after 12 months of participation. GWEB, GWPT, or the ISC2 CSSLP are appropriate for most engineering champions. The cost is modest compared to attrition of a trained champion.

## Measuring Programme Effectiveness

A security champions programme that cannot demonstrate measurable outcomes will not survive budget cycles. Measure at three levels:

**Champion engagement.**
- Monthly meeting attendance rate (target: >80% of active champions per meeting)
- Curriculum completion rate for new champions (target: all four modules within 90 days of joining)
- Number of escalations to the central security team per month per champion (a low number may indicate champions are not raising issues, not that there are none)

**Security findings per team.**
- Count of SAST, SCA, and secret scanning findings by team, tracked monthly. The target is not zero findings — it is a declining trend in mean age of open findings and an increasing rate of findings caught before production.
- Track whether findings are caught in development (by the champion's review), in CI (by automated scanning), or in production (by monitoring or incident). Shift left over time is the measurable goal.

**Mean time to fix.**
- Measure mean time from finding creation to verified remediation, by severity tier, per team. Champions should accelerate this metric by providing triage context and owner assignment. Baseline before the programme starts and track quarterly.

**Security debt introduction rate.**
- Track the rate at which new security debt enters the backlog compared to the rate at which it is remediated. A healthy programme shows the remediation rate exceeding the introduction rate within 12–18 months.

## Common Failure Modes

**Champions ignored in design reviews.** Champions are enrolled in the programme but not included in design review invitations. The technical design happens without them; they see the output after decisions are made. Fix this by making champion involvement a stated requirement for design reviews above a certain size or risk threshold. Engineering leadership must enforce this.

**No escalation path.** A champion notices a suspicious pattern — an API that returns different data based on a parameter that looks like it should be internal-only — but does not know whether to raise it, to whom, or how urgently. The escalation path must be documented, practiced, and reinforced monthly. Champions should escalate without needing certainty that an issue is real.

**Too many champions diluting expertise.** In an attempt to achieve full coverage, the programme enrols one champion per team of three engineers. There are now thirty champions. Monthly meetings become large and impersonal. The security team cannot provide meaningful support to all of them. Individual champions feel less significant. Expertise is spread across too many people to develop depth. Keep champion density at the recommended ratio and resist pressure to expand coverage by reducing the quality of the champion role.

**Champion turnover without succession.** A champion leaves the organisation or moves to a different team. There is no identified successor. The team has no champion for six months while the programme cycles through another recruiting and training cohort. Maintain a lightweight successor identification process — champions should identify and informally mentor a potential successor within their team so that transitions are smooth.

**Programme treated as a one-time training exercise.** The curriculum is delivered once. Champions complete the four modules. The monthly meetings become irregular. The programme slowly becomes a historical artefact rather than a living network. A security champions programme is operational infrastructure, not a training initiative. It requires ongoing investment from the security team in the same way that security tooling requires ongoing maintenance.

## Hardening Checklist

- [ ] Champion selection criteria documented and shared with engineering leadership
- [ ] Prospective champions identified through voluntary expression of interest, not assignment
- [ ] Manager commitment to 10–20% time allocation confirmed in writing before enrolment
- [ ] Engineering leadership sponsor identified at VP or CTO level
- [ ] Curriculum delivered across four spaced sessions, recorded for asynchronous access
- [ ] Stack-specific OWASP Top 10 and secure coding cheat sheets prepared
- [ ] Tool-specific triage guides prepared for each scanner in use
- [ ] Monthly meeting cadence established with defined agenda structure
- [ ] Escalation path documented and communicated to all engineering teams
- [ ] Champion status included in performance review frameworks
- [ ] Baseline metrics collected before programme launch: MTTR, finding age, escalation volume
- [ ] Successor identification process built into champion onboarding
- [ ] Programme effectiveness reviewed with engineering leadership quarterly
- [ ] Certification funding committed for champions with 12+ months of active participation

## References

- OWASP Security Champions Playbook: https://github.com/c0rdis/security-champions-playbook
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- SAFECode Security Champions Framework: https://safecode.org/
- BSIMM Security Champions guidance: https://www.bsimm.com/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
