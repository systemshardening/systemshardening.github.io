---
title: "NIST CSF 2.0 Implementation Guide for Engineering Teams"
description: "Map NIST Cybersecurity Framework 2.0's six functions—Govern, Identify, Protect, Detect, Respond, Recover—to concrete technical controls and measurable outcomes for production environments."
slug: nist-csf-2-implementation
date: 2026-05-02
lastmod: 2026-05-02
category: cross-cutting
tags: ["nist-csf", "compliance", "governance", "risk-management", "framework", "security-program"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 333
difficulty: intermediate
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cross-cutting/nist-csf-2-implementation/index.html"
---

# NIST CSF 2.0 Implementation Guide for Engineering Teams

## Problem

NIST released Cybersecurity Framework 2.0 in February 2024, the first major revision since CSF 1.1 in 2018. The headline change is a new sixth function — Govern (GV) — that sits above and spans all other functions. GV covers organisational context, risk management strategy, roles and responsibilities, policies, and supply chain risk management. This is not a cosmetic reordering: it reflects NIST's recognition that security controls fail not because of misconfiguration, but because no one owns the decision about what to configure or why.

CSF 1.1's five functions — Identify, Protect, Detect, Respond, Recover — remain in CSF 2.0 but are restructured. Many subcategory identifiers have changed; PR.AC (Access Control in 1.1) is now split across PR.AA (Authentication and Access) and PR.IR (Infrastructure Resilience). Organisations carrying over CSF 1.1 control mappings without re-reviewing them will have gaps where subcategories were renamed, split, or deprecated.

The problem for engineering teams is that every CSF subcategory is deliberately abstract. PR.AA-01 reads: "Identities and credentials for authorized users, services, and hardware are managed by the organization." This does not tell you to run `kubectl get clusterrolebindings`, audit AWS IAM roles for wildcard permissions, or rotate service account tokens quarterly. The gap between the framework subcategory and the configuration that satisfies it is the implementation work that compliance exercises consistently skip.

Most CSF implementations stop at a mapping document: a spreadsheet that assigns a tool or team to each subcategory and declares it "addressed." This produces a checkbox audit that satisfies a governance conversation but does not reduce attack surface. The risk is that the framework creates a false sense of completeness — the column is filled, so the control exists — while the actual technical control is absent, misconfigured, or untested.

CSF 2.0 Tiers (Partial, Risk Informed, Repeatable, Adaptive) are widely misread as a maturity scoring system where every organisation should target Tier 4. They are not. Tiers describe the degree to which cybersecurity risk management is integrated into the organisation's broader risk management decisions. A small engineering team that deliberately operates at Tier 2 (Risk Informed) — with documented risk tolerance and a policy review cycle — is correctly applying the framework. The tier is a description, not a prescription.

The new supply chain risk function (GV.SC) is the most under-implemented part of CSF 2.0. GV.SC-01 through GV.SC-10 require organisations to identify critical suppliers, establish supplier risk criteria, include cybersecurity requirements in contracts, and monitor supplier security posture. Most teams have a vendor list in a spreadsheet. Almost none have a structured supplier assessment process that maps to GV.SC requirements or connects supplier risk to their SBOM pipeline.

**Target systems:** Any production environment. Examples throughout use Linux hosts, Kubernetes clusters, and AWS/GCP/Azure cloud stacks, but the control mappings apply to any production infrastructure.

## Threat Model

The risks of non-implementation map to each function:

1. **No Govern function.** Security decisions are made ad-hoc by whoever is on call, the most senior engineer who happens to have an opinion, or the team that last had an incident. Without a documented risk strategy (GV.RM) and assigned roles (GV.RR), controls are inconsistent across services. One team enforces MFA; another ships a service account with admin-level permissions because no policy said they couldn't.

2. **Gaps in Identify.** Unknown assets cannot be patched. Shadow infrastructure — developer-provisioned cloud resources, forgotten staging environments, unregistered containers — sits outside the asset inventory and outside the vulnerability management programme. The average breach in 2024 involved an asset the organisation did not know it owned.

3. **Weak Protect without measurable baselines.** Deploying a tool (a WAF, a secret scanner, a pod security policy) satisfies the checkbox. An unmeasured control is equivalent to no control: if no one verifies the WAF is processing production traffic, that the secret scanner's findings are remediated within SLA, or that the pod security policy isn't running in audit mode, the control contributes nothing to risk reduction.

4. **Detect/Respond gaps.** Mean time to detect (MTTD) measured in weeks rather than hours means attackers have dwell time to move laterally, exfiltrate data, and establish persistence before any response begins. The Verizon DBIR consistently shows that defenders discover most breaches after external notification, not through internal detection.

Implementing CSF 2.0 with mapped technical controls changes each of these operationally: you know what you own (ID), you can demonstrate controls are active and measurable (PR), you receive alerts within hours of anomalous behaviour (DE), you execute from a tested runbook rather than improvising (RS), and you restore from verified backups within a defined RTO (RC) — all governed by documented policy and assigned ownership (GV).

## Configuration / Implementation

### GV — Govern

The Govern function requires three concrete artefacts before any technical control is meaningful: a policy document, a RACI for security roles, and a supply chain risk register.

**Security policy (`SECURITY.md` in every repository).** GV.PO-01 requires a policy that is approved by leadership, communicated, and enforced. For engineering teams, this means a machine-readable policy committed to source control. Minimum required sections:

```markdown
# Security Policy

## Scope
This repository is subject to [Organisation] security policy v2.1.
Classification: [Internal / Confidential / Restricted]

## Roles and Responsibilities
| Role | Responsibility | Owner |
|------|----------------|-------|
| Security Engineer | Triage P1/P2 findings within 24h | security@example.com |
| Service Owner | Remediate findings within SLA | (team lead) |
| Platform Engineer | Maintain baseline controls | platform@example.com |

## Vulnerability Disclosure
Report vulnerabilities to security@example.com. Response SLA: 5 business days.

## Secret Handling
Secrets must not be committed to this repository. Use [Vault / AWS Secrets Manager].
Rotate all credentials annually; rotate compromised credentials within 4 hours.

## Dependency Policy
All third-party dependencies must have a current CVE scan. CRITICAL findings block merge.
HIGH findings are remediated within 14 days.
```

**RACI matrix (GV.RR-02).** Create and maintain a security RACI mapping each CSF function to owning team. Store as `docs/security-raci.md` in the infrastructure repository.

**Supply chain risk register (GV.SC-01 through GV.SC-10).** Supplier assessment questionnaire template — send to every critical vendor annually:

```yaml
# supplier-assessment-template.yaml
supplier:
  name: ""
  contact: ""
  assessment_date: ""
  criticality: ""  # critical / high / medium / low

questions:
  - id: GV.SC-04
    text: "Does the supplier maintain an ISO 27001 or SOC 2 Type II certification?"
    response: ""
    evidence_required: true

  - id: GV.SC-06
    text: "Does the supplier maintain a software bill of materials (SBOM) for components delivered?"
    response: ""
    evidence_required: true

  - id: GV.SC-07
    text: "What is the supplier's documented process for disclosing security incidents that affect customer data?"
    response: ""
    evidence_required: false

  - id: GV.SC-09
    text: "How does the supplier vet sub-processors and fourth-party suppliers?"
    response: ""
    evidence_required: false
```

---

### ID — Identify

**Asset inventory automation (ID.AM-01, ID.AM-02).** Manual spreadsheets go stale within weeks. Use cloud-native asset inventory APIs:

```bash
# AWS: list all discovered resources across all resource types
aws configservice list-discovered-resources \
  --resource-type AWS::EC2::Instance \
  --output json | jq '.ResourceIdentifiers[].ResourceId'

# List all resource types that AWS Config is tracking
aws configservice describe-configuration-recorders \
  --output json

# GCP: query all assets in a project
gcloud asset search-all-resources \
  --scope="projects/my-project" \
  --format="json" | jq '.[].name'

# Azure: query all resources via Resource Graph
az graph query \
  -q "Resources | project name, type, location, resourceGroup" \
  --output json
```

Schedule these as daily cron jobs and diff the output against the previous day's inventory. Any new resource not in the CMDB triggers a ticket.

**Vulnerability management with SBOM (ID.RA-01, GV.SC-06).** Generate SBOMs at build time and scan them continuously:

```bash
# Generate a CycloneDX SBOM for a directory (application dependencies)
syft dir:. -o cyclonedx-json > sbom.cdx.json

# Generate a CycloneDX SBOM for a container image
syft ghcr.io/my-org/my-app:latest -o cyclonedx-json > sbom-image.cdx.json

# Scan the SBOM for known vulnerabilities
grype sbom:sbom.cdx.json --output json \
  | jq '.matches[] | select(.vulnerability.severity == "Critical") | .vulnerability.id'

# Exit non-zero on critical findings (for CI enforcement)
grype sbom:sbom.cdx.json --fail-on critical
```

Attach the SBOM to every container image using OCI annotations. Store SBOMs in an artefact registry so they are queryable when a new CVE is published.

**Risk assessment cadence (ID.RA).** Document a quarterly risk review meeting with a fixed agenda: review new threats relevant to the business, re-score risks that changed since last quarter, confirm mitigating controls are active. Output is a risk register entry with a date, owner, and next review date.

---

### PR — Protect

**Identity and access (PR.AA — Authentication and Access).** Audit RBAC bindings in Kubernetes to identify over-privileged subjects:

```bash
# List all ClusterRoleBindings that grant cluster-admin
kubectl get clusterrolebindings -o json \
  | jq '.items[] | select(.roleRef.name == "cluster-admin") | {name: .metadata.name, subjects: .subjects}'

# List all subjects with wildcard verb permissions across any resource
kubectl get clusterrolebindings -o json \
  | jq '.items[] | select(.roleRef.name != "cluster-admin") | .metadata.name' \
  | xargs -I{} kubectl get clusterrolebinding {} -o json \
  | jq 'select(.roleRef.name) | .metadata.name'

# Audit IAM roles in AWS for AdministratorAccess
aws iam list-attached-role-policies \
  --role-name my-role \
  | jq '.AttachedPolicies[] | select(.PolicyName == "AdministratorAccess")'
```

Run this audit monthly and track the count of cluster-admin bindings as a metric. The target is zero unexpected bindings; any deviation triggers an immediate review.

**Data security (PR.DS — Data Security).** Encryption at rest checklist:

| Data store | Control | Verification command |
|---|---|---|
| Linux block devices | LUKS2 full-disk encryption | `cryptsetup status /dev/mapper/data` |
| Kubernetes etcd | etcd encryption at rest | `grep -r "aescbc\|secretbox" /etc/kubernetes/encryption-config.yaml` |
| S3 buckets | SSE-KMS with bucket key | `aws s3api get-bucket-encryption --bucket my-bucket` |
| RDS instances | Encrypted storage | `aws rds describe-db-instances --query 'DBInstances[].StorageEncrypted'` |
| Kubernetes secrets | Encrypted in etcd | `kubectl get secret my-secret -o json \| jq '.metadata'` |

For etcd encryption, the configuration must reference a KMS provider or AES-CBC key, and the `--encryption-provider-config` flag must be set on the API server.

**Platform hardening (PR.PS — Platform Security).** Map to CIS Benchmarks and enforce with `kube-bench`:

```bash
# Run kube-bench against a Kubernetes node
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Filter for FAIL results only
kubectl logs job/kube-bench | grep -E '^\[FAIL\]'
```

Track the count of FAIL results over time. Each failing check maps to a CIS Benchmark control; prioritise by risk score. Target: zero FAIL results in the CRITICAL and HIGH categories.

---

### DE — Detect

**Continuous monitoring (DE.CM).** Deploy Falco for syscall-level anomaly detection. Map rules to CSF subcategories:

```yaml
# falco-rule-csf-de-ae-02.yaml
# Maps to DE.AE-02: Potentially adverse events are analyzed to better characterize them

- rule: Unexpected Outbound Network Connection
  desc: >
    A process is making an outbound connection to a non-allowlisted destination.
    CSF: DE.AE-02 — adverse event characterisation.
  condition: >
    outbound and not proc.name in (allowed_outbound_procs)
    and not fd.sip in (allowed_outbound_ips)
  output: >
    Unexpected outbound connection (user=%user.name command=%proc.cmdline
    connection=%fd.name container=%container.name image=%container.image.repository)
  priority: WARNING
  tags: [network, csf-de-ae-02]

- rule: Write to Sensitive Path
  desc: >
    A process has written to a sensitive system path.
    CSF: DE.CM-03 — personnel activity monitoring.
  condition: >
    open_write and fd.name startswith /etc
    and not proc.name in (allowed_etc_writers)
  output: >
    Write to sensitive path (user=%user.name file=%fd.name proc=%proc.name)
  priority: ERROR
  tags: [filesystem, csf-de-cm-03]
```

**MTTD metric definition.** Mean time to detect is measured as: `timestamp(alert generated) - timestamp(anomalous event first occurred)`. Instrument this by:

1. Tagging every security alert in your alerting system with the event start time when it is extractable from logs.
2. Recording the alert generation time automatically.
3. Aggregating the delta weekly via a Prometheus recording rule:

```yaml
# prometheus-recording-rules.yaml
groups:
  - name: security_mttd
    rules:
      - record: security:mttd_seconds:avg7d
        expr: >
          avg_over_time(
            (security_alert_generated_timestamp - security_event_start_timestamp)[7d:1h]
          )
```

Target: MTTD under 4 hours for critical events. Review MTTD weekly in the security metrics dashboard.

---

### RS — Respond

**Incident response plan (RS.RP-01).** A runbook template that references CSF function at each step:

```markdown
# Incident Response Runbook — [Incident Type]
CSF functions: RS.RP, RS.CO, RS.AN, RS.MI

## 1. Detection and Triage (RS.AN-03)
- [ ] Confirm alert is not a false positive
- [ ] Assign severity: P1 (active breach) / P2 (suspected) / P3 (anomaly)
- [ ] Page incident commander if P1

## 2. Containment (RS.MI-01)
- [ ] Isolate affected host: `kubectl cordon <node>` or security group rule
- [ ] Revoke compromised credentials immediately
- [ ] Capture forensic snapshot before remediation

## 3. Communication (RS.CO-02)
- [ ] Notify internal stakeholders within 1 hour of P1 confirmation
- [ ] Assess regulatory notification requirements (GDPR: 72h if data involved)
- [ ] Draft customer communication if service availability affected

## 4. Eradication (RS.MI-02)
- [ ] Remove malicious artefacts from affected systems
- [ ] Patch or mitigate the exploited vulnerability
- [ ] Confirm IOCs are blocked at network perimeter

## 5. Post-Incident Review (RS.IM-01)
- [ ] Schedule blameless post-mortem within 5 business days
- [ ] Document timeline, root cause, and contributing factors
- [ ] Assign action items with owners and due dates
- [ ] Update this runbook with lessons learned
```

Store runbooks in a repository that is accessible without production credentials — your incident responders need these when production is down.

**Post-incident improvement (RS.IM-01).** Every post-mortem must produce at least one improvement to the Detect or Protect function. Track action items in a linear issue with the label `csf-improvement` and review open items monthly.

---

### RC — Recover

**Recovery plan testing cadence (RC.RP-01).** Recovery plans that have never been tested are not recovery plans. Schedule:

- **Monthly:** Restore a single database from backup in a non-production environment. Verify data integrity.
- **Quarterly:** Full DR rehearsal — simulate primary region unavailability and execute failover runbook.
- **Annually:** Table-top exercise for a ransomware scenario affecting backup infrastructure.

**Backup verification (RC.RP-02).** Automate restore verification:

```bash
# Velero dry-run restore to verify backup integrity (Kubernetes)
velero restore create verify-$(date +%Y%m%d) \
  --from-backup daily-backup-$(date +%Y%m%d) \
  --namespace-mappings production:restore-test \
  --dry-run

# Actual restore into an isolated namespace for verification
velero restore create verify-$(date +%Y%m%d) \
  --from-backup daily-backup-$(date +%Y%m%d) \
  --namespace-mappings production:restore-test

# PostgreSQL: restore from WAL archive and verify row count
pg_restore \
  --host restore-test.internal \
  --dbname mydb \
  --verbose \
  /backup/mydb-$(date +%Y%m%d).dump

psql -h restore-test.internal -d mydb \
  -c "SELECT COUNT(*) FROM critical_table;" \
  | tee /var/log/restore-verification-$(date +%Y%m%d).log
```

Record restore success/failure and the time taken. Track RTO (recovery time objective) achievement as a metric.

**Improvement communication (RC.CO-03).** After any recovery event, communicate what changed to stakeholders: what failed, what was restored, what is being done to prevent recurrence. Link the communication to the post-mortem document so the trail is traceable.

---

### CSF 2.0 to Technical Control Mapping Table

| CSF 2.0 Subcategory | Technical Control | Tool / Command | Frequency |
|---|---|---|---|
| GV.PO-01 | Security policy in source control | `SECURITY.md` in every repo | Review annually |
| GV.SC-06 | SBOM for all built artefacts | `syft` + OCI annotation | Every build |
| ID.AM-01 | Cloud asset inventory | AWS Config / GCP Asset Inventory | Daily diff |
| ID.RA-01 | Vulnerability scan of SBOM | `grype sbom:...` | Every build + daily |
| PR.AA-01 | RBAC audit for over-privileged bindings | `kubectl get clusterrolebindings` audit | Monthly |
| PR.DS-01 | Encryption at rest verified | `cryptsetup status`, `aws s3api get-bucket-encryption` | Quarterly audit |
| PR.PS-01 | CIS Benchmark compliance | `kube-bench` | Weekly CI job |
| DE.CM-01 | Syscall anomaly detection | Falco rules with CSF tags | Continuous |
| DE.AE-02 | Alert triage and characterisation | Falco + SIEM correlation | Per alert |
| RS.RP-01 | Incident runbook in source control | Runbook repository | Reviewed quarterly |
| RS.IM-01 | Post-mortem with improvement actions | Linear / Jira `csf-improvement` label | Per incident |
| RC.RP-02 | Backup restore verification | `velero restore`, `pg_restore` | Monthly |

## Expected Behaviour

| CSF 2.0 Function | Key Metric | Before (ad-hoc) | After (CSF 2.0 Implemented) |
|---|---|---|---|
| GV — Govern | Security policy coverage (% of repos with `SECURITY.md`) | 0–20% | 100% |
| GV — Govern | Supplier assessments completed | None | All critical suppliers assessed annually |
| ID — Identify | Asset inventory coverage (% of cloud resources in CMDB) | 40–60% | >95% |
| ID — Identify | SBOM coverage (% of production images with attached SBOM) | 0% | 100% |
| PR — Protect | CIS Benchmark FAIL count (critical/high) | Unknown | 0 critical, <5 high |
| PR — Protect | Patch cadence SLA met (critical CVEs within 24h) | Ad-hoc | >95% within SLA |
| DE — Detect | Mean time to detect (MTTD) — critical events | Days to weeks | <4 hours |
| DE — Detect | Alert false positive rate | Unknown | Tracked; <20% target |
| RS — Respond | Incident response time (time to containment) | Hours to days | <2 hours for P1 |
| RS — Respond | Post-mortems with improvement actions | Informal | 100% of P1/P2 incidents |
| RC — Recover | Backup restore success rate | Untested | >99% monthly verifications pass |
| RC — Recover | RTO achievement (% of DR tests meeting RTO) | Untested | >90% |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Governance overhead (GV function) | Consistent security decisions with clear ownership; policy is auditable and version-controlled | RACI and policy review cycles add process burden; small teams feel overhead disproportionate to team size | Start with minimal policy (`SECURITY.md` + one RACI); expand at next compliance cycle |
| Tier 4 (Adaptive) requirements | Fully integrated risk management; security feeds into business decisions in real time | Tier 4 requires dedicated security staff, automated measurement, and board-level engagement — exceeds small-team capacity | Document your target tier explicitly; Tier 2 is correct for most engineering-led teams |
| CSF mapping documentation burden | Creates auditable evidence for compliance conversations; mapping survives personnel turnover | Mapping documents go stale as controls change; maintaining a 90-subcategory mapping requires ongoing effort | Automate control evidence collection where possible; review mappings at the same cadence as policy |
| CSF 2.0 vs ISO 27001 vs SOC 2 overlap | CSF is freely available and US-government endorsed; maps well to ISO 27001 Annex A and SOC 2 Trust Services Criteria | Maintaining simultaneous mappings to multiple frameworks multiplies documentation overhead | Use CSF 2.0 as the primary framework and publish a crosswalk to ISO 27001 / SOC 2 rather than three separate control sets |
| Supply chain risk (GV.SC) implementation | Reduces risk of third-party compromise; aligns with regulatory expectations post-SolarWinds / XZ Utils | Supplier assessment process requires legal and procurement involvement; suppliers may be slow or unresponsive | Start with critical suppliers only (those with production access or code execution); tier remaining suppliers by risk |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Framework as checkbox | Controls are documented in the mapping spreadsheet but not enforced in production; a PR.AA-01 control maps to "IAM team" but no audit script exists | Penetration test or red team exercise reveals controls that the mapping marks as implemented are absent or bypassable | Require technical evidence (command output, screenshot, CI job result) for each control mapping; reject mappings that cite only a team name |
| Govern function owned by security team, not engineering | GV artefacts (policies, RACI) exist but engineering teams are unaware of them; controls that require engineering action are not implemented because engineers were never assigned | Policy review meeting has no engineering attendees; security findings reference policy that teams haven't read | Embed GV artefacts in engineering workflows: `SECURITY.md` in repo, RACI reviewed in engineering all-hands, policy violations surface in PR checks |
| Asset inventory staleness | Cloud resources provisioned via CLI or direct console access are absent from the CMDB; vulnerability scans miss assets that aren't inventoried | New resource appears in cloud bill but not in security scanning scope; post-incident review reveals compromised asset wasn't being monitored | Enforce infrastructure-as-code via policy (e.g. AWS SCP denying console resource creation); daily inventory diff alerts on unregistered resources |
| MTTD metric gaming | Detection SLA is met on paper by adjusting the event start time to the alert timestamp rather than the actual event timestamp | MTTD improves on paper while dwell time in post-incident timelines remains unchanged | Define MTTD measurement methodology in policy, sourced from immutable log timestamps; audit MTTD calculation against post-incident timelines quarterly |

## Related Articles

- [Compliance as Code](/articles/cross-cutting/compliance-as-code/)
- [DevSecOps Maturity Model](/articles/cross-cutting/devsecops-maturity-model/)
- [Hardening Scorecard](/articles/cross-cutting/hardening-scorecard/)
- [Threat Modeling at Scale](/articles/cross-cutting/threat-modeling-at-scale/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
