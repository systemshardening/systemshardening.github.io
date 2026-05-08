---
title: "Security Training for Developers: Building Skills That Prevent Vulnerabilities at Source"
description: "Generic security awareness training doesn't teach developers to write secure code. Effective developer security education is contextual, hands-on, and integrated into the development workflow. This guide covers threat modelling workshops, language-specific secure coding training, capture-the-flag programmes, and measuring training effectiveness."
slug: security-developer-training
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - security-training
  - developer-education
  - secure-coding
  - appsec
  - security-culture
personas:
  - security-engineer
  - security-analyst
article_number: 608
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cross-cutting/security-developer-training/
---

# Security Training for Developers: Building Skills That Prevent Vulnerabilities at Source

## Problem

Most organisations run annual security awareness training. Developers complete a 30-minute module covering phishing, password hygiene, and data classification. They pass the quiz. The module closes. The security team marks the compliance checkbox.

Then the next sprint produces an IDOR vulnerability in the payments endpoint. The sprint after that ships a SQL injection in the admin search. Both vulnerabilities could have been caught before the first commit. Neither developer who wrote them lacked intelligence or care — they lacked the specific knowledge required to recognise the pattern in the moment of writing code.

Generic security awareness training fails developers for a concrete reason: it does not address what developers actually do. A compliance module teaches a developer not to click phishing links. It does not teach them how parameterised queries prevent SQL injection in their ORM, how JWT validation errors produce auth bypasses in their framework, or how object serialisation in Java creates remote code execution surface. The gap between general awareness and actionable secure coding knowledge is where vulnerabilities are born.

Effective developer security education is:

- **Contextual** — anchored in the language, framework, and codebase the developer works in every day.
- **Hands-on** — built around writing, exploiting, and fixing real vulnerable code rather than reading about vulnerability classes.
- **Integrated** — embedded into code review, pull request templates, and sprint workflow rather than siloed in a separate training system.
- **Measured** — connected to observable outcomes (vulnerability escape rate, time to fix findings) rather than completion rate alone.

**Target systems:** Software engineering and platform engineering teams of any size. The patterns here apply equally to a 5-person startup and a 500-person engineering organisation.

## Threat Model for the Training Programme

- **Adversary 1 — Compliance-driven checkbox completion.** Developers complete training without engaging with the material, driven by deadline rather than interest. Completion rates are high; knowledge retention is negligible. The defence is making training difficult to passively consume: hands-on exercises that require working code, not multiple choice.
- **Adversary 2 — Knowledge without application.** A developer understands SSRF conceptually but does not recognise the pattern when they write `requests.get(user_supplied_url)` in a Django view. The defence is contextualisation: training exercises must use the team's actual language, framework, and code patterns.
- **Adversary 3 — Training without workflow integration.** Security knowledge that exists only in a training system decays rapidly. Without reinforcement in code review, PR templates, and daily tooling, developers revert to familiar patterns. The defence is embedding security cues into existing workflow touchpoints.
- **Adversary 4 — Security team as sole knowledge owner.** When all security expertise sits with one team, that team becomes a bottleneck and single point of failure. The goal of effective training is distributing security knowledge across engineering — creating a population of developers who can identify and fix common issues without escalation.

## Step 1: Diagnose Why Generic Training Fails Your Team

Before building a training programme, collect evidence about where vulnerabilities are actually originating.

```yaml
# diagnostic-questions.yaml — questions to answer before designing training

vulnerability_source_analysis:
  questions:
    - "Which vulnerability classes appear most frequently in SAST findings?"
    - "Which vulnerability classes are most commonly promoted to production (escaping static analysis)?"
    - "Which teams or codebases produce the most findings per 1000 lines of code?"
    - "How many days on average does it take to fix a critical finding after it is reported?"
    - "What percentage of developers can describe OWASP Top 10 without prompting?"
    - "What percentage of developers can name two injection vulnerabilities specific to their primary language?"

data_sources:
  - SAST scan history (Semgrep, Snyk Code, CodeQL reports)
  - Penetration test findings from the last 12 months
  - Bug bounty reports if a program exists
  - Security-flagged code review comments (search PR comments for "security" keyword)
  - Post-mortem reports for security incidents

output: >
  A list of the five most common vulnerability classes in your codebase,
  mapped to the teams and codebases that produce them.
  This list is the curriculum for the first training cycle.
```

Running this diagnostic before building curriculum ensures training addresses real gaps rather than a generic vulnerability list. A Python shop with Django APIs may find that IDOR and mass assignment are the dominant findings. A Go shop building gRPC services may find that authentication bypass and missing authorisation checks dominate. The OWASP Top 10 provides a vocabulary, but the team's actual data determines priorities.

## Step 2: Hands-On Learning Formats

### Deliberately Vulnerable Applications

The most effective training format is exploiting a real vulnerability, then fixing it. Deliberately vulnerable applications provide this in a controlled environment.

**OWASP WebGoat** is a Java Spring application designed to be exploited. Exercises cover injection, broken access control, insecure deserialisation, and cryptographic failures. Developers run it locally in Docker and work through guided challenges:

```bash
# Run WebGoat locally — no external network access required.
docker run --rm -p 8080:8080 -p 9090:9090 webgoat/webgoat

# Access at http://localhost:8080/WebGoat
# Register a local account — all data stays on the container.
```

**PortSwigger Web Security Academy** provides 250+ labs covering every OWASP category with a built-in browser-based lab environment. Labs include apprentice, practitioner, and expert difficulty. The SQL injection series, for example, begins with basic UNION-based extraction and advances to blind time-based injection and filter bypass. No installation required — accessible from any browser during working hours.

**OWASP Juice Shop** is a Node.js/Express application with 100+ vulnerabilities across 10 difficulty tiers, making it suitable for both introductory and advanced exercises. The hacking progress is tracked in a score board, which makes it suitable for internal CTF competitions.

```bash
# Run Juice Shop locally.
docker run --rm -p 3000:3000 bkimminich/juice-shop

# Score board is accessible at http://localhost:3000/#/score-board
```

**DVWA (Damn Vulnerable Web Application)** remains useful for teaching PHP-specific vulnerabilities, particularly for teams maintaining legacy PHP codebases.

### Capture-the-Flag Programmes

Internal CTF events convert security learning into a competitive, social activity. A half-day CTF creates more durable learning than four hours of video content because it requires active problem-solving.

```yaml
# internal-ctf-format.yaml

format:
  duration: "4 hours (half day, during work hours)"
  team_size: "2-3 developers per team (mixed seniority)"
  challenge_categories:
    - name: "Web vulnerabilities"
      examples:
        - "Find the IDOR in the product listing endpoint"
        - "Exploit the reflected XSS in the search input"
        - "Bypass the JWT validation in the admin API"
      point_value: 100-300

    - name: "Code review"
      examples:
        - "Identify the SQL injection in this 50-line function"
        - "Find the race condition in the session handling"
        - "Spot the path traversal in the file download handler"
      point_value: 150-400

    - name: "Infrastructure"
      examples:
        - "Exploit the SSRF in the webhook handler to reach the metadata endpoint"
        - "Find the secret in the environment variable list"
      point_value: 200-500

  scoring:
    - "Points awarded for successful exploit"
    - "Bonus points for writing the fix after exploiting"
    - "Bonus points for identifying additional attack vectors beyond the intended solution"

  tooling:
    - "CTFd (open source CTF platform) for challenge hosting and scoring"
    - "Or use Juice Shop as the target: it has a built-in score board"

post_ctf:
  - "30-minute retrospective: what patterns appear across all findings?"
  - "Security team presents fixes for each challenge with explanation of root cause"
  - "Add the vulnerability patterns from CTF challenges to the SAST ruleset"
```

### Code Review Exercises

Asynchronous code review exercises work well for teams where scheduling a synchronous event is difficult. Provide a pull request with 3-5 intentional vulnerabilities and ask developers to identify them in comments.

```python
# exercise-example.py — deliberately vulnerable Python function.
# Developers review this in a PR and comment on security issues.

def get_user_document(user_id: str, document_name: str) -> dict:
    """Return a document belonging to a user."""
    # Issue 1: No authentication check — who is the caller?
    # Issue 2: No authorisation check — does the caller own user_id?
    # Issue 3: Path traversal in document_name not sanitised.
    path = f"/documents/{user_id}/{document_name}"
    with open(path, "r") as f:
        content = json.loads(f.read())

    # Issue 4: SQL query constructed with string formatting.
    query = f"SELECT * FROM access_log WHERE user_id = '{user_id}'"
    db.execute(query)

    return content
```

After the review period, hold a 20-minute session where the security team walks through each issue, explains the exploit scenario, and demonstrates the fix. This format works particularly well for senior developers who learn from analysis rather than guided exercises.

## Step 3: Language and Framework-Specific Training

OWASP Top 10 describes vulnerability classes. It does not describe how those classes manifest in a Python Django application versus a Java Spring Boot service versus a Go HTTP handler. Training must bridge this gap.

### OWASP Top 10 — Language-Specific Examples

```yaml
# owasp-language-mapping.yaml — map vulnerability classes to framework-specific patterns

A01_broken_access_control:
  python_django:
    vulnerable_pattern: |
      def user_profile(request, user_id):
          user = User.objects.get(id=user_id)  # No check: is request.user allowed to view this?
          return JsonResponse(user.to_dict())
    fix: |
      def user_profile(request, user_id):
          if request.user.id != user_id and not request.user.is_staff:
              raise PermissionDenied
          user = get_object_or_404(User, id=user_id)
          return JsonResponse(user.to_dict())

  go_net_http:
    vulnerable_pattern: |
      func userProfile(w http.ResponseWriter, r *http.Request) {
          userID := r.URL.Query().Get("user_id")  // Attacker supplies any user_id.
          user := db.GetUser(userID)
          json.NewEncoder(w).Encode(user)
      }
    fix: |
      func userProfile(w http.ResponseWriter, r *http.Request) {
          callerID := r.Context().Value(contextKeyUserID).(string)
          userID := r.URL.Query().Get("user_id")
          if callerID != userID && !isAdmin(callerID) {
              http.Error(w, "Forbidden", http.StatusForbidden)
              return
          }
          user := db.GetUser(userID)
          json.NewEncoder(w).Encode(user)
      }

A03_injection:
  python_sqlalchemy:
    vulnerable_pattern: |
      results = db.execute(f"SELECT * FROM users WHERE name = '{name}'")
    fix: |
      results = db.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})

  java_spring_jpa:
    vulnerable_pattern: |
      @Query("SELECT u FROM User u WHERE u.name = '" + name + "'")  // String concatenation.
    fix: |
      @Query("SELECT u FROM User u WHERE u.name = :name")
      List<User> findByName(@Param("name") String name);

  javascript_mongoose:
    vulnerable_pattern: |
      User.find({ username: req.body.username })  // NoSQL injection: attacker sends {"$gt": ""}
    fix: |
      const username = String(req.body.username);  // Coerce to string, reject objects.
      User.find({ username })

A02_cryptographic_failures:
  python:
    vulnerable_pattern: |
      import hashlib
      password_hash = hashlib.md5(password.encode()).hexdigest()
    fix: |
      import bcrypt
      password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

Build a reference document in your internal wiki with these patterns for every vulnerability class in the OWASP Top 10, using your team's actual languages and frameworks. Link this document from the code review guidelines and the PR template.

## Step 4: Threat Modelling Workshops

A threat modelling workshop run against a real feature in the team's codebase is one of the highest-ROI training activities available to a security team. It teaches developers to think like an attacker while making decisions about their own code.

### Workshop Format

```yaml
# threat-modelling-workshop.yaml

prerequisites:
  - "Select a feature currently in design or early development (not already shipped)."
  - "Attendees: feature lead, 2-3 developers, product manager, security engineer."
  - "Time: 2 hours."
  - "Materials: whiteboard or Miro/draw.io; STRIDE reference card."

agenda:
  "0:00-0:20":
    activity: "Define the scope"
    steps:
      - "What are we modelling? One feature, not the entire system."
      - "What is in scope? What is explicitly out of scope?"
      - "Who are the legitimate users? What are they trying to do?"

  "0:20-0:50":
    activity: "Draw the data flow diagram"
    steps:
      - "Map every actor that interacts with the feature (users, other services, admins)."
      - "Map every data store (databases, caches, queues, file systems)."
      - "Draw arrows for every data flow, labelled with the data type and protocol."
      - "Mark trust boundaries: where does data cross from untrusted to trusted context?"
    output: "A data flow diagram (DFD) with trust boundaries marked."

  "0:50-1:30":
    activity: "STRIDE analysis"
    method: "Walk each component and each data flow. For each, ask all six STRIDE questions."
    stride_categories:
      S_spoofing: "Can an attacker impersonate a legitimate actor?"
      T_tampering: "Can data be modified in transit or at rest without detection?"
      R_repudiation: "Can an actor deny performing an action? Is there sufficient audit logging?"
      I_information_disclosure: "Can sensitive data be read by an unauthorised actor?"
      D_denial_of_service: "Can the component be made unavailable by an attacker?"
      E_elevation_of_privilege: "Can an attacker gain permissions beyond those granted?"
    output: "A list of threats, each with an assigned STRIDE category."

  "1:30-2:00":
    activity: "Prioritise and assign mitigations"
    steps:
      - "Rate each threat: High / Medium / Low based on likelihood × impact."
      - "For each High threat, assign a mitigation and an owner."
      - "Create tickets for mitigations that are not already in scope for the feature."
      - "Decide which threats are accepted risks (low severity, high mitigation cost)."
    output: "A threat model document added to the feature's design doc or ADR."
```

Run this workshop for every significant new feature. After the first two sessions with security team facilitation, capable developers can facilitate their own threat models. The goal is institutionalising the practice, not creating a dependency on the security team's calendar.

## Step 5: Integrating Security Into Developer Workflow

Training knowledge decays without reinforcement. Embedding security cues into existing workflow touchpoints provides that reinforcement at the moment it matters.

### Secure Coding Checklist in PR Templates

```markdown
<!-- .github/pull_request_template.md -->

## Security checklist

_Check each item or explain why it does not apply to this change._

- [ ] **Input validation:** All user-supplied inputs are validated and sanitised before use.
- [ ] **Parameterised queries:** No string concatenation used to build SQL or NoSQL queries.
      See: [Injection prevention guide](https://wiki.internal/secure-coding/injection)
- [ ] **Authorisation:** Every endpoint that returns or modifies data checks that the caller
      is authorised to perform that action for the specific resource (not just authenticated).
- [ ] **Secrets:** No credentials, API keys, or tokens committed to the repository.
      Use environment variables or the secrets manager.
- [ ] **Error handling:** Error responses do not expose stack traces, internal paths, or
      database schema to the caller.
- [ ] **Logging:** Sensitive fields (passwords, tokens, PII) are not written to logs.
- [ ] **Dependency changes:** New dependencies reviewed for known CVEs
      (`npm audit` / `pip-audit` / `govulncheck`).
```

### Semgrep Rules That Explain Why

Static analysis findings are ignored when they lack context. Write Semgrep rules that explain the vulnerability class and provide a fix, not just a line number.

```yaml
# semgrep-rules/django-idor.yaml
rules:
  - id: django-missing-object-ownership-check
    patterns:
      - pattern: |
          def $FUNC($REQUEST, $ID, ...):
              ...
              $MODEL.objects.get(id=$ID)
              ...
      - pattern-not: |
          def $FUNC($REQUEST, $ID, ...):
              ...
              $MODEL.objects.get(id=$ID, user=$REQUEST.user)
              ...
      - pattern-not: |
          def $FUNC($REQUEST, $ID, ...):
              ...
              if not $REQUEST.user ...
              ...
    message: |
      Potential Insecure Direct Object Reference (IDOR): this view retrieves an object
      by ID from the request without checking that the requesting user owns or is
      authorised to access that object. An attacker can enumerate other users' data
      by incrementing the ID parameter.

      Fix: add an ownership filter to the query:
        obj = Model.objects.get(id=object_id, user=request.user)
      Or add an explicit authorisation check before returning the object.

      Reference: https://wiki.internal/secure-coding/idor
    languages: [python]
    severity: ERROR
```

A finding with a message like this teaches the developer something. A finding that says `CWE-284: Improper Access Control at line 42` does not.

### Security in Sprint Retrospectives

Reserve five minutes in the sprint retrospective for a security retrospective question. Rotate through a small set of prompts:

```
- "Did we introduce any new external inputs this sprint? How are we validating them?"
- "Did any of our SAST findings reveal a pattern we are repeating across services?"
- "Did any security findings from previous sprints appear again? What would prevent recurrence?"
- "Is there a security decision we made this sprint that should be documented as an ADR?"
```

This keeps security visible as a recurring quality concern rather than a compliance event.

## Step 6: Learning Paths by Role

Different roles encounter different vulnerability classes. Training should reflect this.

```yaml
# learning-paths.yaml

frontend_developer:
  priority_topics:
    - "XSS (stored, reflected, DOM-based) in the team's templating system"
    - "Content Security Policy headers: what they block and how to configure them"
    - "CORS configuration: what wildcard origins enable and why they are dangerous"
    - "postMessage security: validating origin before processing messages"
    - "Subresource Integrity for third-party scripts"
  recommended_platforms:
    - "PortSwigger Web Security Academy — XSS and CORS labs"
    - "Juice Shop — XSS and client-side security challenges"
  estimated_time: "8 hours initial + 2 hours/quarter"

backend_developer:
  priority_topics:
    - "Injection (SQL, command, LDAP) in the team's ORM and query patterns"
    - "IDOR and broken object-level authorisation (BOLA) in REST APIs"
    - "Authentication implementation: JWT pitfalls, session fixation, timing attacks"
    - "SSRF in HTTP client usage and webhook handlers"
    - "Deserialisation vulnerabilities in the team's serialisation libraries"
    - "Mass assignment / parameter binding in the team's framework"
  recommended_platforms:
    - "PortSwigger Web Security Academy — full web security fundamentals path"
    - "WebGoat — injection and access control modules"
  estimated_time: "16 hours initial + 4 hours/quarter"

infrastructure_engineer:
  priority_topics:
    - "Kubernetes RBAC and least-privilege service account configuration"
    - "Container escape vectors: privileged containers, host path mounts, capabilities"
    - "Secrets management: avoiding environment variables for long-lived credentials"
    - "Supply chain security: verifying container image provenance and SBOMs"
    - "Network policy and egress filtering in Kubernetes"
    - "Cloud IAM: cross-account access, role assumption, instance metadata SSRF"
  recommended_platforms:
    - "Hack The Box — Linux privilege escalation and infrastructure challenges"
    - "KubeCon security track sessions"
  estimated_time: "12 hours initial + 4 hours/quarter"
```

## Step 7: Measuring Effectiveness

Completion rate measures compliance, not learning. These metrics measure outcomes.

```yaml
# training-effectiveness-metrics.yaml

knowledge_metrics:
  pre_post_assessment:
    method: >
      Administer a 15-question practical assessment before and after each training
      module. Questions require writing a fix or identifying a vulnerability in code,
      not selecting from multiple choice options.
    target: "20+ percentage point improvement in post-assessment vs pre-assessment score"

  knowledge_retention:
    method: >
      Re-administer the same assessment 60 days after training without notice.
    target: "Post-assessment score decays by less than 15 percentage points at 60 days"

vulnerability_outcome_metrics:
  escape_rate:
    definition: >
      Vulnerabilities found in production or by penetration testers, divided by
      total vulnerabilities found (including those caught by SAST, code review,
      and developer self-identification).
    collection: "Track source of each finding in the vulnerability management system"
    target: "Escape rate decreases by 20% in the 6 months following initial training rollout"

  introduction_rate:
    definition: >
      New vulnerabilities introduced per 1000 lines of code merged to main,
      measured by SAST scan differential.
    collection: "SAST scan on every PR; track findings per team per sprint"
    target: "Introduction rate decreases quarter-over-quarter"

  time_to_fix:
    definition: >
      Median days from security finding reported to verified fix merged.
    collection: "Ticket created date to PR merge date for security-labelled issues"
    target: "Median time to fix critical findings < 5 business days"

  self_identification_rate:
    definition: >
      Percentage of security findings first identified by the developer who wrote
      the code, versus identified by tooling, code reviewers, or external parties.
    collection: "Track who first identifies each finding in the review workflow"
    target: "Self-identification rate increases as training matures"
```

Review these metrics quarterly. Present them to engineering leadership alongside team velocity and defect rate data — security metrics belong in the same conversation as other engineering quality metrics.

## Platform Reference

```yaml
# training-platforms.yaml

free:
  - name: "PortSwigger Web Security Academy"
    url: "https://portswigger.net/web-security"
    cost: "Free"
    format: "Self-paced labs with browser-based environment"
    coverage: "Full OWASP Top 10, API security, advanced topics"
    best_for: "Backend developers; the most comprehensive free web security curriculum available"

  - name: "OWASP WebGoat"
    url: "https://github.com/WebGoat/WebGoat"
    cost: "Free, self-hosted"
    format: "Guided exercises in a vulnerable Java application"
    coverage: "Injection, access control, cryptography, API security"
    best_for: "Java teams; workshop exercises with facilitated learning"

  - name: "OWASP Juice Shop"
    url: "https://github.com/juice-shop/juice-shop"
    cost: "Free, self-hosted"
    format: "CTF-style challenges in a vulnerable Node.js application"
    coverage: "OWASP Top 10 across 10 difficulty levels"
    best_for: "Internal CTF events; gamified team learning"

  - name: "Hack The Box"
    url: "https://www.hackthebox.com"
    cost: "Free tier available; VIP from $14/month"
    format: "CTF challenges and machine exploitation"
    coverage: "Web, infrastructure, Active Directory, reverse engineering"
    best_for: "Infrastructure engineers; developers building advanced attacker intuition"

paid:
  - name: "Secure Code Warrior"
    url: "https://www.securecodewarrior.com"
    cost: "Per-seat licensing"
    format: "Language-specific secure coding challenges integrated with IDE and CI"
    coverage: "OWASP Top 10 in 50+ languages and frameworks"
    best_for: "Large organisations needing LMS integration and compliance reporting"

  - name: "Snyk Learn"
    url: "https://learn.snyk.io"
    cost: "Free tier; paid with Snyk platform"
    format: "Contextual lessons triggered by Snyk findings in the developer's code"
    coverage: "Lessons matched to vulnerability types found by Snyk scanner"
    best_for: "Teams already using Snyk; training delivered at the point of finding"

  - name: "SANS Developer Security"
    url: "https://www.sans.org/cyber-security-courses/?focus=developer"
    cost: "~$3,500–$5,500 per course"
    format: "Instructor-led and on-demand; includes GSSP-{Java,.NET} certifications"
    coverage: "Deep technical coverage of secure development lifecycle"
    best_for: "Security champions and senior developers building deep expertise"
```

## Building an Incident Post-Mortem as a Learning Opportunity

Security incidents produce the most durable learning available to an engineering organisation. A post-mortem that extracts curriculum from an incident converts a costly event into a lasting training asset.

After any security incident, extend the standard post-mortem template with a training section:

```markdown
## Post-Mortem Training Addendum

**Vulnerability class:** [e.g., IDOR — missing object-level authorisation]

**Root cause in developer terms:**
[Explain the vulnerability in terms a developer unfamiliar with security jargon can understand.
What was the code pattern that enabled the attack? What assumption was wrong?]

**How it could have been caught earlier:**
- At design time: [What threat modelling question would have identified this?]
- At code review: [What pattern in the diff should have triggered a security comment?]
- By tooling: [Would a SAST rule have caught this? Does one exist? Should one be written?]

**Actions:**
- [ ] Add this vulnerability class to the next security training cycle.
- [ ] Write a Semgrep rule for the vulnerable pattern and add to the CI pipeline.
- [ ] Add the pattern to the secure coding checklist in the PR template.
- [ ] If a platform-level fix is possible (e.g., a middleware that enforces ownership checks),
      assign it to the platform team.
```

The training addendum turns an incident from a reactive event into a proactive curriculum update. Over 12 months, the post-mortem archive becomes a bank of real-world examples drawn from the organisation's own codebase — more compelling to developers than any generic case study.

## Rollout Sequence

```yaml
# rollout-sequence.yaml — recommended 12-month rollout

month_1_2:
  - "Diagnostic: analyse SAST findings and pen test reports to identify top 5 vulnerability classes."
  - "Baseline assessment: 15-question pre-training assessment across all engineering teams."
  - "Add security checklist to PR template (immediate, low effort, high reinforcement value)."

month_3_4:
  - "Language-specific training modules for top 3 vulnerability classes."
  - "First internal CTF event (half day, voluntary, use Juice Shop)."
  - "Threat modelling workshop for one upcoming feature per team."

month_5_6:
  - "PortSwigger Web Security Academy path assigned to backend developers."
  - "Infrastructure security path assigned to platform engineers."
  - "Post-assessment to measure knowledge gain from initial modules."

month_7_9:
  - "Security champions programme: identify one security-interested developer per team."
  - "Champions receive 8 hours of advanced training (Hack The Box, SANS on-demand)."
  - "Champions take over threat modelling facilitation for their team."

month_10_12:
  - "Second internal CTF — more advanced challenges; champions help design them."
  - "60-day retention assessment for all developers."
  - "Review escape rate, introduction rate, and time-to-fix metrics against baseline."
  - "Publish quarterly security quality report alongside engineering metrics."
```

## Verification

After each training cycle, verify that the programme is producing measurable outcomes rather than high completion rates:

```bash
# Pull SAST finding counts by team and month (adjust for your tooling).
# Example using Semgrep output parsed to JSON.

# Count findings introduced per team per quarter.
jq '[.results[] | {team: .extra.metadata.team, severity: .extra.severity}] |
    group_by(.team) | map({team: .[0].team, count: length})' semgrep-output.json

# Track escape rate: findings in production vs caught pre-production.
# Source: vulnerability management system (Jira, Linear, etc.)
# Tag findings by where they were discovered: pre-prod vs post-prod.
```

A training programme that is working produces a downward trend in vulnerability introduction rate and escape rate within two quarters of rollout. If the trend is flat after two quarters, revisit the curriculum against the diagnostic data — either the wrong vulnerability classes are being trained, or the format is not producing knowledge transfer.

## Summary

Generic security awareness training produces compliance data. Effective developer security education produces developers who write fewer vulnerabilities, catch more issues in code review, and fix findings faster.

The essential components are: a diagnostic that identifies which vulnerability classes to prioritise for your specific codebase; hands-on exercises using deliberately vulnerable applications and CTF challenges; language and framework-specific training anchored in code your developers actually write; threat modelling workshops run against real features; and security cues embedded into PR templates, SAST rules, and retrospectives. Completion rate is a lagging indicator of compliance. Vulnerability escape rate and introduction rate are leading indicators of programme effectiveness. Measure what matters.
