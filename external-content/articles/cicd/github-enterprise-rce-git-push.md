---
title: "GitHub Enterprise Server RCE via Git Push: CVE-2026-3854"
description: "CVE-2026-3854 allows any user with push access to achieve RCE on GitHub Enterprise Server by injecting HTTP/2 header delimiters into git push options. Patch to GHES 3.19.3+ and harden push option handling across self-hosted git infrastructure."
slug: github-enterprise-rce-git-push
date: 2026-05-04
lastmod: 2026-05-04
category: cicd
tags:
  - github-enterprise
  - rce
  - git
  - cve
  - push-security
personas:
  - platform-engineer
  - security-engineer
article_number: 442
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cicd/github-enterprise-rce-git-push/
---

# GitHub Enterprise Server RCE via Git Push: CVE-2026-3854

## The Problem

CVE-2026-3854 is a CVSS 8.7 remote code execution vulnerability in GitHub Enterprise Server that requires only push access to any repository on the instance — no admin privileges, no special permissions, no social engineering. It was reported on March 4 2026, patched in GHES 3.19.3 released shortly afterward, and publicly disclosed on April 28 2026 following coordinated disclosure. Any GHES instance below 3.19.3 that accepts pushes from untrusted users is a critical exposure.

The vulnerability is in the git push option processing pipeline. Git 2.10 introduced push options: a mechanism that lets clients send arbitrary string metadata alongside a push using `git push --push-option=<value>`. Multiple options can be sent in a single push. The server receives them and can forward them to hooks or internal services for processing. On GHES, push option values were forwarded to internal Rails-based services via HTTP/2 headers without sanitisation.

HTTP/2 uses CRLF (`\r\n`) as a field delimiter in its wire format. When a user-supplied push option value containing `\r\n` was embedded directly into an HTTP/2 header field being sent to an internal service, the embedded CRLF terminated the current header field and allowed the attacker to inject a new, attacker-controlled header field in its place. This is a git push variant of CRLF injection — a vulnerability class that has appeared across HTTP/1.1 response splitting, log injection, and URL manipulation for decades. CVE-2026-3854 applies the same pattern to a new protocol layer and a new delivery mechanism: the git push wire protocol rather than a browser or API request.

The specific header injected in the proof-of-concept was `rails_env: development`. GitHub Enterprise Server runs its Rails application in production mode, which enforces request sanitisation, disables verbose error output, and restricts certain execution paths. Switching the internal request's execution context to development mode via the injected header removed these guards. In development mode, the Rails application can be manipulated to execute arbitrary system commands through mechanisms that are blocked in production. The attacker does not need to persist any payload — the malicious git push itself carries the injection, executes code on the server during push processing, and completes.

The delivery surface is broad. Any user account that can push to any repository on the GHES instance is sufficient. This includes:

- Developer accounts with write access to their team's repositories.
- Service accounts used by CI/CD pipelines — GitHub Actions runners, deployment bots, automated package publishing accounts.
- External contributors who have been granted push access to a specific branch or repository.
- Any account that can create a fork and submit a pull request where the base repository is configured to grant fork PRs push access (a common but often unexamined configuration).

The vulnerability is not in GitHub Actions, the web UI, the GitHub API, or any other surface. It is in the git push wire protocol handler on the GHES server. It is exploitable from a plain `git push` command with no additional tooling.

Push option injection as a vulnerability class is worth understanding beyond this specific CVE. Any system that accepts git push options and forwards them — unvalidated — to a downstream process (a shell hook, an internal HTTP service, a logging pipeline) is potentially vulnerable. Gitolite installations with custom hooks that log or process push option values, Gitea instances with pre-receive hooks that embed push options in shell commands, and GitLab with custom server-side hooks that pass push options to external services are all candidates for the same class of issue. The sanitisation requirement is the same in all cases: validate that push option values conform to an expected format before using them in any downstream context.

## Threat Model

- **Any user with push access to any repository** on the GHES instance can exploit this vulnerability. The minimum required permission is the ability to run `git push` to any branch of any repository. This is the default state for every developer on the instance, every CI service account, and every automated bot that commits code.

- **Impact after RCE:** Code executes as the application user on the GHES host. From that position, an attacker has read access to every repository stored on the instance, all secrets stored in GHES's internal credential store, user data and SSH keys, the GHES admin console, and internal network services reachable from the GHES host. GHES hosts typically have access to internal infrastructure — artifact stores, deployment targets, secrets managers — that is not accessible from the public internet.

- **Cross-tenant blast radius:** GHES is frequently deployed as a shared platform hosting multiple organisations within the same company or serving multiple customer tenants. A single compromised developer account in one organisation can access all repositories across all organisations on the instance. The isolation boundary between organisations on GHES is access control within the application layer — RCE bypasses that layer entirely.

- **CI/CD pipeline compromise:** Service accounts used by GitHub Actions runners and deployment automation are often scoped to push access on specific repositories. These accounts are sufficient for exploitation. After exploiting one CI service account, an attacker has RCE on the GHES server and can access all other service account tokens, pipeline secrets, and deployment credentials stored on the instance.

- **External contributor exposure:** A GHES instance accessible from the public internet that accepts push access from contractors, open-source contributors, or partner organisations expands the attacker pool beyond internal employees to anyone granted push permissions.

- **PoC published post-disclosure:** No exploitation in the wild was confirmed before patching, but a proof-of-concept was published on April 28 2026 alongside public disclosure. Unpatched instances are now trivially exploitable by any attacker who can obtain push access — including through phishing a developer account or compromising a public-facing CI service.

## Hardening Configuration

### 1. Patch to GHES 3.19.3+

Check the current GHES version from the management console or from the instance CLI:

```bash
ghe-version
```

The output identifies the installed version:

```bash
GitHub Enterprise Server 3.18.11
```

Any version below 3.19.3 is vulnerable. Apply the GHES update via the standard update mechanism. Download the hotpatch or upgrade package from the GHES releases page, upload it to the management console, and apply it:

```bash
ghe-upgrade /tmp/github-enterprise-3.19.3.pkg
```

For high-availability configurations, verify that all replica nodes are also updated — the replica accepts git pushes during failover and must run the patched version:

```bash
ghe-repl-status
```

Confirm the version on each node after the update:

```bash
ghe-version
```

The patch validates push option values during parsing, before any value is forwarded to internal services. A push option value containing `\r\n` or other HTTP/2 header delimiters is rejected at the git protocol layer and the push is refused with an error. No CRLF sequence reaches any internal service header.

### 2. Restrict Push Access to the Minimum Required

Audit which users and service accounts hold push access across repositories. The GHES API exposes collaborator permissions per repository:

```bash
gh api \
  --paginate \
  "https://GHES_HOSTNAME/api/v3/repos/ORG/REPO/collaborators?permission=push" \
  --jq '.[] | {login: .login, role: .permissions}'
```

For a full org-wide audit across all repositories:

```bash
gh api --paginate \
  "https://GHES_HOSTNAME/api/v3/orgs/ORG/repos" \
  --jq '.[].name' | while read repo; do
    gh api --paginate \
      "https://GHES_HOSTNAME/api/v3/repos/ORG/${repo}/collaborators?permission=push" \
      --jq ".[] | {repo: \"${repo}\", login: .login}"
done
```

Review the output for:

- **Service accounts** that have org-wide push access when they only need access to specific repositories. Reduce the scope to the minimum set of repositories each service account touches.
- **Stale accounts**: contractors, former employees, or integration accounts that are no longer active. Revoke push access immediately.
- **Bot accounts** used by automation tools (Renovate, Dependabot, release bots) that have write access to all repositories when they only operate on a subset.

CI service accounts should hold push access only on the repositories they actually deploy from. A GitHub Actions runner that builds and deploys a single microservice does not need push access to every repository in the organisation.

### 3. Monitor for Exploitation Attempts

GHES records push events in its audit log, including push option values. Scan for push options containing CRLF sequences or URL-encoded equivalents:

```bash
ghe-audit-log -q 'action:git.push' \
  | grep -E '(push_options.*\\r\\n|push_options.*%0[dD]%0[aA])'
```

For organisations forwarding GHES audit logs to a SIEM, the equivalent search in Elasticsearch or Splunk targets the `push_options` field:

```bash
GET /ghes-audit-*/_search
{
  "query": {
    "bool": {
      "filter": [
        {"term": {"action": "git.push"}},
        {"regexp": {"push_options": ".*(\r\n|%0[Dd]%0[Aa]).*"}}
      ]
    }
  }
}
```

In Splunk:

```bash
index=ghes_audit action=git.push push_options=*%0d%0a* OR push_options=*\r\n*
| table _time, actor, repo, push_options
```

Alert on any result. Push options containing CRLF sequences are not valid in normal workflows — no legitimate git client sends them. A single match warrants immediate investigation of the actor's recent activity on the instance.

For real-time detection before a SIEM integration is in place, a pre-receive hook can log and reject suspicious push options:

```bash
#!/bin/bash
while read oldrev newrev refname; do
  if git for-each-ref --format='%(push)' | grep -qE $'\r\n|%0[Dd]%0[Aa]'; then
    echo "Push rejected: invalid characters in push options"
    exit 1
  fi
done
```

Access push option values in a pre-receive hook via the `GIT_PUSH_OPTION_COUNT` and `GIT_PUSH_OPTION_<N>` environment variables:

```bash
#!/bin/bash
count="${GIT_PUSH_OPTION_COUNT:-0}"
for i in $(seq 0 $((count - 1))); do
  opt_var="GIT_PUSH_OPTION_${i}"
  opt_value="${!opt_var}"
  if printf '%s' "$opt_value" | grep -qP '\r|\n|%0[Dd]|%0[Aa]'; then
    echo "Push rejected: push option ${i} contains invalid characters"
    exit 1
  fi
done
```

### 4. Network Segmentation for GHES

GHES should be accessible only from the corporate network or VPN. An internet-facing GHES instance running a vulnerable version is reachable by any attacker who can obtain or social-engineer push credentials — including through phishing a developer or compromising a CI service account token.

Restrict access at the network perimeter. For a firewall or security group controlling GHES ingress:

```bash
iptables -A INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j DROP
iptables -A INPUT -p tcp --dport 22 -j DROP
```

In cloud environments, the equivalent is a security group or network ACL that allows HTTPS and SSH only from the corporate network's CIDR range or from a VPN gateway's egress IP.

For external contributors who legitimately need push access, route them through a VPN rather than exposing GHES to the public internet. Alternatively, use github.com with branch protection rules for external contributions and sync to GHES via a controlled mirror pipeline.

### 5. Sanitise Push Options in All Git Hooks

For organisations running Gitolite, Gitea, GitLab, or any other self-hosted git infrastructure with custom hooks that process push options, the same vulnerability class applies. Never embed user-supplied push option values in system calls, shell commands, or HTTP headers without validation.

A safe pre-receive hook pattern that validates push option format before any processing:

```bash
#!/bin/bash
validate_push_option() {
  local value="$1"
  if [[ "$value" =~ $'\r' ]] || [[ "$value" =~ $'\n' ]]; then
    echo "Push rejected: push option contains CRLF characters"
    return 1
  fi
  if printf '%s' "$value" | grep -qiE '%0[dD]|%0[aA]'; then
    echo "Push rejected: push option contains URL-encoded CRLF"
    return 1
  fi
  if [[ ! "$value" =~ ^[a-zA-Z0-9_=:@/.,[:space:]-]+$ ]]; then
    echo "Push rejected: push option contains unexpected characters"
    return 1
  fi
  return 0
}

count="${GIT_PUSH_OPTION_COUNT:-0}"
for i in $(seq 0 $((count - 1))); do
  opt_var="GIT_PUSH_OPTION_${i}"
  opt_value="${!opt_var}"
  if ! validate_push_option "$opt_value"; then
    exit 1
  fi
done

exit 0
```

The validation applies three checks: literal CRLF bytes, URL-encoded CRLF sequences (`%0d%0a` in any case combination), and an allowlist of expected characters that rejects anything outside the normal push option value character set. If your push options carry structured data, add allowlist entries for the specific characters used — do not broaden the allowlist unnecessarily.

## Expected Behaviour After Hardening

After patching to GHES 3.19.3+: a push attempt using `git push --push-option=$'\r\nrails_env: development'` is rejected during the push option parsing phase — before any value reaches an internal service. The server returns an error to the git client and the push is not accepted. The rejection happens at the protocol layer, not at the application layer.

After audit monitoring is configured: a push attempt that includes `%0d%0a` in any push option value generates an audit log entry that matches the SIEM detection rule. An alert fires within minutes. The actor, repository, push option value, and timestamp are captured for investigation. Even if the GHES instance is already patched and the push is rejected, the attempt is recorded.

## Trade-offs and Operational Considerations

GHES updates require a maintenance window and instance restart. For teams with active CI/CD pipelines running continuously, this requires coordination: announce the window in advance, drain in-flight jobs, apply the update, verify service recovery, and restore normal operations. The restart typically takes 10–20 minutes. For HA configurations, a rolling upgrade reduces downtime but still requires planned coordination.

Network restriction to the corporate network blocks external contributors who currently push directly from outside the VPN. Assess which external push workflows exist before applying network restrictions — an unplanned block will disrupt legitimate contributors immediately. The correct remediation for external contributors is a VPN enrollment process or a migration to github.com-hosted collaboration with branch protection, not leaving GHES internet-accessible.

The pre-receive hook for push option validation can be deployed as a temporary mitigation before the patch is applied, specifically for sites where the maintenance window is days away. The hook rejects malicious push options at the repository level. It is a compensating control, not a substitute for the patch: a sufficiently creative attacker may find bypass paths, and the hook does not address the root cause in the push processing pipeline.

Service account tokens used by CI pipelines should be rotated after patching, particularly on any instance that was internet-accessible while vulnerable. If a token was used in a push between the public PoC release (April 28 2026) and the patch application, treat it as potentially compromised.

## Failure Modes

- **GHES patched on the primary but a replica or backup runs an older version.** GHES replication nodes can serve traffic during failover. If a replica runs GHES 3.18.x or earlier and becomes active after a failover event, it is vulnerable. Verify the version on every node in the HA cluster and every warm-standby backup before considering the instance fully remediated.

- **Audit monitoring searches for literal `\r\n` strings but misses URL-encoded variants.** The injection payload can be delivered as raw CRLF bytes, as URL-encoded `%0d%0a`, or as mixed case (`%0D%0A`, `%0d%0A`). An audit query that only searches for literal backslash-r-backslash-n in the log will miss URL-encoded delivery. Use a regular expression that covers all case combinations: `%0[Dd]%0[Aa]`.

- **Service account tokens not rotated after the vulnerability window.** If a service account token was accessible from an internet-facing GHES instance while the public PoC existed, and that account had push access, an attacker may have already used it for RCE. Patching the server does not invalidate the token. After patching, audit the list of push-capable service accounts, identify any that were exposed, and rotate those tokens — then audit their GHES activity during the exposure window for signs of misuse.

- **Pre-receive hook for push option validation deployed but not tested with URL-encoded payloads.** A hook that only checks for literal CRLF characters passes a URL-encoded payload through to the server. Test the hook explicitly with `%0d%0a` variants, not just with raw CRLF, before relying on it as a compensating control.

## Related Articles

- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [GitHub Actions Trivy Compromise](/articles/cicd/github-actions-trivy-compromise/)
- [Branch Protection Code Review](/articles/cicd/branch-protection-code-review/)
- [SCM Identity Choice](/articles/cicd/scm-identity-choice/)
- [Pipeline Config Security](/articles/cicd/pipeline-config-security/)
