---
title: "Kubernetes Operator Security Disclosure: Reporting and Responding to Vulnerabilities in Custom Controllers"
description: "Kubernetes operators ship to production clusters with elevated RBAC permissions and direct API server access — a vulnerability in an operator can compromise the entire cluster. This guide covers how to report operator vulnerabilities responsibly, how operator maintainers should handle disclosures, CVSS scoring for Kubernetes-specific issues, and what cluster operators should do when a vulnerability is published."
slug: kubernetes-operator-security-disclosure
date: 2026-05-08
lastmod: 2026-05-08
category: kubernetes
tags:
  - kubernetes-security
  - operator-security
  - responsible-disclosure
  - cve
  - open-source-security
personas:
  - security-engineer
  - platform-engineer
article_number: 682
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-operator-security-disclosure/
---

# Kubernetes Operator Security Disclosure: Reporting and Responding to Vulnerabilities in Custom Controllers

## Problem

Kubernetes operators are not ordinary applications. They run as long-lived controller processes with persistent watches on the API server, reconcile cluster state on a continuous loop, and frequently hold RBAC permissions that most applications would never be granted. An operator that manages databases may have read access to every Secret in a namespace. An operator that provisions infrastructure may carry cluster-admin binding. An operator that manages certificates may create and delete arbitrary resources across the cluster.

This privilege profile means that a single exploitable vulnerability in an operator can translate directly to full cluster compromise. An attacker who achieves remote code execution inside a cert-manager pod, for example, immediately inherits the ability to read any TLS private key managed by the system. An operator that runs with cluster-admin inherits the ability to create cluster-level RoleBindings, backdoor service accounts, and exfiltrate data from any namespace.

The problem is made worse by a structural gap in how operators are developed and distributed:

**Most operators lack any formal security disclosure process.** A search of popular OperatorHub entries reveals that the majority link to GitHub repositories with no SECURITY.md, no private reporting channel, and no defined response timeline. A security researcher who discovers a critical vulnerability has no clear path to responsible disclosure. Some are forced to file a public GitHub issue — immediately exposing every cluster running that operator to exploitation before a patch exists.

**CNCF vs. non-CNCF operators.** Projects that have graduated or are incubating in the Cloud Native Computing Foundation (CNCF) have access to a shared security response infrastructure: the CNCF Security Technical Advisory Group (TAG Security), the CNCF security advisory mailing list, and established processes that mirror how Kubernetes itself handles CVEs. Prometheus, Argo CD, cert-manager, and Flux all benefit from this structure. The hundreds of independent operators on OperatorHub do not. Their security posture depends entirely on the individual maintainer's knowledge of responsible disclosure practices.

**What researchers need and rarely find.** A security researcher who discovers a vulnerability in a Kubernetes operator needs four things: a private contact to report to without public disclosure, confirmation that the report was received within a reasonable timeframe (typically 48 to 72 hours), a clear timeline for patch development and coordinated release, and credit for the discovery. Without these, researchers face a choice between sitting on a critical vulnerability indefinitely or publishing it publicly to force action — neither outcome serves cluster administrators.

**Target systems:** This article covers Kubernetes operators and custom controllers built with controller-runtime, Operator SDK, Kubebuilder, or similar frameworks. It applies to both maintainers who receive vulnerability reports and cluster administrators who consume operators from OperatorHub, Artifact Hub, or Helm charts.

## Threat Model

**Researcher discovers RCE via CustomResource field injection.** A security researcher is auditing a popular database operator. They notice that the operator reads a `backupCommand` field from a DatabaseBackup CustomResource and passes it directly to `exec.Command("/bin/sh", "-c", userProvidedValue)` without sanitisation. Any cluster user who can create DatabaseBackup resources can execute arbitrary commands in the operator pod. Because the operator runs with a ServiceAccount that has `get secrets` on all namespaces, this gives the attacker access to every Secret in the cluster. The researcher needs to report this privately; the operator has no SECURITY.md.

**Cluster administrator installs an operator with a known critical CVE.** An operations team installs a network policy operator from OperatorHub. The OperatorHub listing shows the latest version, but the operator maintainer published a CVE advisory two weeks ago for versions older than the one currently deployed. The team's Helm chart pins an older version. Without a process to monitor operator CVEs, the vulnerability goes undetected until an automated scanner catches it six months later.

**Attacker chains a low-severity operator vulnerability with cluster privilege escalation.** An operator has a low-severity SSRF vulnerability (CVSS 4.3) that allows an attacker to make the operator issue arbitrary HTTP requests from its pod. The attacker uses this to reach the instance metadata service at `169.254.169.254`, retrieves cloud credentials attached to the node's IAM role, and uses those credentials to escalate to cloud-level administrator. The CVSS score suggested low urgency; the actual blast radius was the entire cloud account.

These scenarios illustrate why Kubernetes-specific context matters when scoring and responding to operator vulnerabilities. CVSS base scores calculated without accounting for operator privilege levels will systematically understate severity.

## Configuration

### Setting Up Security Reporting for an Operator

Every public Kubernetes operator should have a SECURITY.md in its repository root. The following template covers the fields cluster administrators and researchers need:

```markdown
# Security Policy

## Supported Versions

We provide security patches for the following versions:

| Operator Version | Kubernetes Version | Supported |
|---|---|---|
| 1.4.x | 1.28–1.30 | Yes |
| 1.3.x | 1.27–1.29 | Critical only |
| < 1.3.0 | < 1.27 | No |

Note: we follow the Kubernetes N-2 version support policy. Versions
that support only end-of-life Kubernetes releases will not receive
security backports.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via one of the following channels:

- **GitHub private advisory (preferred):** Use the "Report a vulnerability"
  button under the Security tab of this repository. This creates an encrypted
  communication channel visible only to maintainers.
- **Email:** security@example.com (PGP key: https://example.com/pgp.asc)

### What to Include

- Affected versions
- Step-by-step reproduction instructions
- Impact assessment (what an attacker can do)
- Your credit preference (name, GitHub handle, or anonymous)

### Response Timeline

- **48 hours:** We will acknowledge receipt of your report.
- **7 days:** We will provide an initial assessment and severity rating.
- **90 days:** We aim to release a patch. If we need more time, we will
  communicate this and agree on an extended embargo with you.

### Coordinated Disclosure

We follow a coordinated disclosure model. We will notify you before
public disclosure and credit you in the CVE advisory and release notes,
unless you prefer otherwise.
```

The supported versions table is critical for Kubernetes operators specifically. Operators target specific Kubernetes API versions; a patch that works on Kubernetes 1.30 may not compile against the API machinery for 1.27. Maintainers need to decide upfront which Kubernetes version ranges they will backport patches to — and communicate that clearly so cluster administrators know whether they will receive a fix.

### Kubernetes-Specific CVSS Scoring

Standard CVSS v3.1 scoring requires careful adaptation for Kubernetes operators. The default scoring often underestimates severity because it does not account for the aggregate permissions operators hold.

**RCE via CustomResource field (attacker-controlled CR → shell exec):**
- Attack Vector: Network (attacker submits a CR via kubectl or the API)
- Attack Complexity: Low (no preconditions beyond CR create permission)
- Privileges Required: Low (any user with create on the CR type)
- User Interaction: None
- Scope: Changed (the vulnerability in the operator pod leads to compromise of cluster resources beyond the operator's own process)
- Confidentiality: High (access to Secrets)
- Integrity: High (can create/modify resources)
- Availability: High (can delete managed resources)
- **Base Score: 9.9 (Critical)**

**RBAC over-permission (operator requests cluster-admin when it only needs namespace read):**
This is not a traditional CVE — it is a security advisory. There is no exploit in the classic sense, but the misconfiguration increases blast radius for any future vulnerability. Score as informational (no CVSS) but document it as a High-severity advisory requiring immediate RBAC restriction.

**Secret exfiltration via status field (operator writes secret values into CR status):**
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: Low (anyone with `get` on the CR type reads the status)
- Scope: Unchanged (within the operator's managed scope)
- Confidentiality: High
- **Base Score: approximately 7.5 (High)**

When filing a CVE, always include a Kubernetes-specific impact section that describes the operator's RBAC permissions. A CVSS base score of 7.5 with an operator that holds cluster-admin should be escalated to Critical in any internal risk rating.

### The Kubernetes CVE Feed and Security Response Committee

Kubernetes itself publishes CVEs at [https://security.kubernetes.io/cve/](https://security.kubernetes.io/cve/). The Kubernetes Security Response Committee manages the disclosure lifecycle for the core project. Their process — private report → embargo period → coordinated release → public advisory — is the model that operator maintainers should follow.

The Kubernetes Security Response Committee is not responsible for third-party operators. However, their documentation at `kubernetes.io/docs/reference/issues-security/security/` describes the full process in detail and is a good template for operator maintainers building their own response playbook.

### CNCF Security Disclosure Process

For operators that are CNCF projects (graduated or incubating), the disclosure path is structured:

1. Report to `cncf-security@lists.cncf.io` if the project's own SECURITY.md does not specify otherwise. Many CNCF projects (Argo CD, Flux, cert-manager) have their own security contacts; use the project-specific channel first.
2. The CNCF Security TAG ([https://github.com/cncf/tag-security](https://github.com/cncf/tag-security)) does not handle individual vulnerability reports but provides guidance, process templates, and can help facilitate communication if a project is unresponsive.
3. CNCF projects use **GitHub Security Advisories** for the patch development phase. This creates a private fork where collaborators can work on a fix without public visibility. Once the fix is ready, the advisory is published and the CVE is assigned.

For non-CNCF operators, GitHub Security Advisories are still the recommended mechanism. Any repository owner can create a private advisory and request a CVE through GitHub's integration with MITRE.

### Operator-Specific Vulnerability Classes

**Template injection via CustomResource fields.** The most common critical class. An operator reads a user-controlled field from a CR — a `command`, `args`, `template`, or `script` field — and passes it to a shell, a Go `text/template`, or a Helm renderer without sanitisation. Detection: look for `exec.Command` calls that incorporate CR field values, or Go template rendering of CR data with `text/template` (which does not sandbox). Mitigation: use `html/template` for rendering, allowlist command arguments, or move operator logic so it never passes CR fields to a shell.

**RBAC over-permission.** An operator's ClusterRole requests wildcard permissions (`"*"`) or cluster-admin when it only needs to watch a specific CRD and create Deployments in one namespace. This is nearly universal in early-stage operators. Audit with `kubectl auth can-i --list --as system:serviceaccount:<namespace>:<operator-sa>`. Remediation: scope permissions to the minimum required verbs and resources, preferring namespace-scoped Roles over ClusterRoles wherever possible.

**Controller reconciliation loop injection.** A malicious CR triggers an unintended reconciliation code path — for example, a CR with a carefully crafted `name` or `namespace` field that causes the operator to reconcile resources it was not intended to manage. This can lead to denial of service (continuous reconciliation loop) or privilege escalation (reconciling into other namespaces). Detection: ensure the operator validates that reconciled objects belong to the expected scope before acting on them.

**Secret exfiltration via status fields.** An operator reads a Secret (for example, database credentials) and writes derived values or the full credential into a CustomResource's `.status` field to communicate state back to the application. Anyone with `get` permission on the CR — often granted broadly to application developers — can read the credential. This is a design flaw more than a code bug, but it constitutes a real vulnerability in deployed clusters. Fix: never write secret values into status fields; instead write a reference (Secret name) or a non-sensitive derived value (a connection string without the password).

**Supply chain: operator image from a compromised registry.** An operator's deployment pulls `ghcr.io/maintainer/operator:latest` without a digest pin. If the registry account is compromised, an attacker can push a malicious image that is automatically pulled on the next pod restart. Fix: pin images by digest in the operator deployment manifest, use admission policy to enforce digest pinning, and enable image signing verification (Sigstore/cosign) for all operator images.

### How to Report a Vulnerability (As a Researcher)

**Step 1: Find SECURITY.md.** Check the repository root, the `.github/` directory, and the project's documentation site. If SECURITY.md is absent, check the project's website for a security contact.

**Step 2: Contact the private channel.** Use the GitHub private advisory button or the security email listed. Do not open a public issue, post on Slack, or mention it in public forums during the embargo period.

**Step 3: Write a complete report.** Include: the affected versions you tested, step-by-step reproduction instructions (ideally a minimal PoC CustomResource and the observed behaviour), an impact assessment explaining what an attacker can do with the vulnerability (be explicit about the operator's RBAC permissions and what they enable), an optional suggested fix, and your credit preference.

**Step 4: Wait for acknowledgement.** Expect a response within 48 to 72 hours. If you have received nothing after five business days, send a follow-up. A non-response after ten business days justifies escalation.

**Step 5: Negotiate the embargo.** Standard practice is a 90-day embargo from the date of report, with the patch released at the end. If the maintainer needs more time for a complex fix, agree on an extension. If the vulnerability is being actively exploited in the wild, the embargo may need to be shortened.

**If there is no SECURITY.md.** Use GitHub's "Report a vulnerability" button — it works even on repositories with no SECURITY.md configured, and it creates a private channel for communication. If the maintainer is unresponsive after a full embargo period, the `oss-security@openwall.com` mailing list is the community-accepted venue for disclosing unresponsive maintainer situations. Publishing to oss-security notifies the broader security community and can trigger distribution-level action (e.g., package maintainers removing or flagging vulnerable versions).

### How to Respond as an Operator Maintainer

**Acknowledge within 48 hours.** Even if you cannot assess the vulnerability immediately, send a confirmation that you received the report. Silence discourages responsible disclosure in future.

**Create a private GitHub Security Advisory.** Navigate to your repository → Security → Advisories → New draft security advisory. Add the reporter as a collaborator. This opens a private fork where you can develop the fix without leaking the vulnerability. Request a CVE through GitHub's CVE Numbering Authority (CNA) integration — GitHub is now a CNA and can assign CVEs directly.

**Develop and test the fix privately.** Use the private advisory branch. Coordinate with the reporter to verify the fix addresses the root cause. For complex operators, consider whether the vulnerability exists in earlier supported versions and prepare backport patches.

**Coordinate the release.** Publish the GitHub Security Advisory (which publishes the CVE), tag a new release that includes the fix, and update the Helm chart or OLM bundle simultaneously. Write release notes that clearly state: the CVE number, the affected versions, the fixed version, and migration steps if the fix requires configuration changes.

**Notify cluster administrators.** Use every channel available: GitHub release notes, the project's Slack or Discord, any mailing list. If your operator is distributed via OperatorHub, update the OLM ClusterServiceVersion to mark old versions as deprecated and set the `replaces:` field to encourage automatic upgrades. Helm chart maintainers should publish a new chart version that pins the fixed image digest.

**Update OperatorHub.** File a pull request against [https://github.com/operator-framework/community-operators](https://github.com/operator-framework/community-operators) to update your operator's bundle. Include the CVE number in the PR description. OperatorHub does not automatically pull security advisories from GitHub, so the update lag can leave the vulnerable version discoverable and listed as current for days or weeks without this manual step.

### What Cluster Administrators Should Do

**Monitor for operator CVEs.** Subscribe to the GitHub Releases feed for every operator you run — use GitHub's "watch" feature with notifications scoped to releases only. For container image CVEs (vulnerabilities in the operator's base image or dependencies), subscribe to [https://osv.dev](https://osv.dev) or use a tool like Grype or Trivy in a continuous scanning pipeline that alerts on new CVEs in deployed images.

**Audit installed operator versions.** The following command lists all deployments across namespaces with their container images, which you can grep against known vulnerable versions:

```bash
kubectl get deployment -A \
  -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.template.spec.containers[*].image}{"\n"}{end}'
```

For operators deployed via OLM, check the installed ClusterServiceVersion:

```bash
kubectl get csv -A -o custom-columns=\
'NAMESPACE:.metadata.namespace,NAME:.metadata.name,VERSION:.spec.version,PHASE:.status.phase'
```

**Temporary mitigation while waiting for a patch.** If a critical CVE is published for an operator and a patch is not yet available, consider these mitigations in order of safety:

1. **Reduce RBAC permissions.** If the operator holds cluster-admin but the CVE involves only a subset of permissions, edit the ClusterRoleBinding to scope it down to what you can verify the operator actually uses. This may break operator functionality — test in a staging cluster first.

2. **Apply a NetworkPolicy to restrict outbound.** If the vulnerability enables SSRF or data exfiltration, a NetworkPolicy blocking unexpected outbound traffic from the operator pod limits blast radius. Allow only traffic to the Kubernetes API server and the operator's known external dependencies.

3. **Deploy Falco rules.** The Falco runtime security tool can detect anomalous behaviour in the operator pod — unexpected shell execution, suspicious file reads, or outbound connections to unexpected destinations. The following rule detects shell execution in any operator pod:

```yaml
- rule: Shell Executed in Operator Pod
  desc: Detect shell execution in a Kubernetes operator pod
  condition: >
    spawned_process and container and
    proc.name in (shell_binaries) and
    k8s.pod.label.app in (your-operator-label)
  output: >
    Shell executed in operator pod
    (pod=%k8s.pod.name command=%proc.cmdline user=%user.name)
  priority: WARNING
```

4. **Consider disabling the operator temporarily.** If the operator manages non-critical workloads and the CVE is critical, scaling the operator deployment to zero eliminates the attack surface while you wait for a patch. Managed resources will stop reconciling but typically will not be deleted by the operator going offline.

## Expected Behaviour

The following table maps vulnerability class to expected CVSS range, recommended disclosure approach, and cluster administrator response.

| Vulnerability Class | CVSS Range | Disclosure Approach | Cluster Admin Response |
|---|---|---|---|
| RCE via CR field injection | 9.0–10.0 Critical | Private advisory, 90-day embargo, coordinated release | Patch immediately; disable operator if patch unavailable |
| RBAC over-permission (no exploit) | Informational–High | Security advisory (not CVE); public documentation | Audit and restrict RBAC; no emergency patch required |
| Secret exfiltration via status | 7.0–8.5 High | Private advisory, CVE, 60–90 day embargo | Patch within 30 days; audit status fields for existing leaks |
| Reconciliation loop injection | 5.0–8.0 Medium–High | Private advisory; 90 days for design-level fixes | Patch when available; apply NetworkPolicy as interim control |
| Supply chain: image compromise | Context-dependent | Immediate public disclosure often warranted | Redeploy from clean image source; rotate all credentials |
| SSRF via operator outbound | 4.0–7.0 Medium | Private advisory; 90 days | Apply NetworkPolicy egress restriction as immediate mitigation |

## Trade-offs

**Fast disclosure vs. operator patch readiness.** A 90-day embargo is the industry standard, but Kubernetes operators often have small maintainer teams with limited bandwidth. A critical CVE in a popular operator may require backports across three Kubernetes minor versions, each requiring a separate release. If the maintainer cannot prepare backports within 90 days, the choice is between extending the embargo (keeping cluster administrators in the dark) or releasing with partial version coverage (leaving older deployments vulnerable). Researchers should consider the realistic maintenance capacity of the project when negotiating embargo length; maintainers should communicate honestly about what is achievable.

**RBAC reduction as mitigation vs. operator breakage.** Reducing an operator's RBAC permissions is an effective mitigation while waiting for a patch, but operators typically do not test against minimal permission sets. Removing a wildcard binding and replacing it with specific verb/resource pairs may cause reconciliation failures for edge cases that are not exercised in normal operation. Test in a staging cluster that mirrors production. For operators managing stateful workloads (databases, storage), an operator that fails to reconcile can leave workloads in an inconsistent state that is difficult to recover from.

**Operator version pinning vs. security patch adoption.** Many teams pin operator versions in Helm charts or GitOps repositories to prevent unexpected changes. This is good operational practice but creates a friction cost when a security patch needs rapid adoption. Teams should establish a fast-track process for security patches that bypasses the normal change control timeline, while still requiring a staging environment promotion. Consider using a tool like Renovate or Dependabot to automate pull requests for operator version updates, scoped to accept patch versions automatically.

## Failure Modes

**Operator maintainer non-responsive to disclosure.** Maintainers of popular operators may be volunteers with full-time jobs, or small companies with limited security expertise. If the maintainer does not respond after ten business days, the researcher should escalate: send a follow-up to any public contact address, contact the CNCF if the operator is a CNCF project, or post to `oss-security@openwall.com` after the full 90-day embargo expires. Some widely-used operators on OperatorHub are effectively unmaintained; if you are running one, treat it as an unpatched vulnerability permanently and evaluate alternatives.

**Kubernetes version matrix complicating backports.** An operator that supports Kubernetes 1.27, 1.28, and 1.29 must fix a CR injection vulnerability in three separate release branches, each of which may use a different version of the `k8s.io/client-go` module and the `sigs.k8s.io/controller-runtime` framework. A fix that compiles cleanly on `controller-runtime` 0.17 may not compile on 0.14. Maintainers should test backports against the full supported Kubernetes version matrix before release, and clearly document in the CVE advisory which versions have been patched.

**OperatorHub update lag.** OperatorHub and Artifact Hub pull operator metadata from the upstream community-operators repository. Once a security-fixing bundle is merged, it may take 24 to 72 hours for the updated version to appear in cluster OperatorHub listings. During this window, cluster administrators browsing OperatorHub may install the vulnerable version without any warning. Operator maintainers should post prominently to all community channels during this lag period; cluster administrators should always verify the installed version against the CVE advisory rather than relying on OperatorHub to surface vulnerable version warnings automatically.
