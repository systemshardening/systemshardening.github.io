---
title: "SOX-Compliant Deployment Pipelines: Segregation of Duties and Immutable Change Evidence"
description: "Sarbanes-Oxley Section 404 requires that no individual can both develop code and deploy it to production financial systems. Modern CI/CD pipelines can satisfy SOX IT General Controls — but only with explicit segregation of duties, immutable audit trails, and change management integration. This guide implements SOX-compliant pipeline controls using GitHub Actions and GitLab CI."
slug: sox-compliant-deployment-pipeline
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - sox-compliance
  - segregation-of-duties
  - change-management
  - audit-trails
  - financial-systems
personas:
  - security-engineer
  - compliance-engineer
article_number: 628
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/sox-compliant-deployment-pipeline/
---

# SOX-Compliant Deployment Pipelines: Segregation of Duties and Immutable Change Evidence

## Problem

Sarbanes-Oxley Act Section 404 requires management and external auditors to assess the effectiveness of internal controls over financial reporting (ICFR). For software-driven financial systems — general ledger platforms, revenue recognition engines, loan origination systems — those controls extend into the software delivery process itself.

Auditors assess CI/CD pipelines through three IT General Control (ITGC) domains:

**Change Management (CM):** All changes to financial reporting systems must be authorized, tested, and documented before production deployment. A developer who can merge their own code and trigger a deployment represents an uncontrolled change process regardless of technical skill.

**Logical Access (LA):** Access to production environments must be restricted to authorized roles. Developers must not have standing write access to production. The principle of least privilege must be demonstrable with evidence — not just asserted in policy documents.

**Computer Operations (CO):** Production deployments must be performed by an authorized process, with records of who authorized each deployment, what was deployed, and when. If an auditor asks "who deployed the December closing journal entry calculation on November 30th?", the answer must be retrievable with cryptographic certainty.

Most CI/CD pipelines fail all three domains in predictable ways:

- **Self-approval:** Developers with merge rights can approve their own pull requests, or can approve a colleague's PR in exchange for having their own approved — a control that exists on paper but not in practice.
- **No separation between deployer and developer:** The same engineer who writes code also holds the credentials (or the role) that triggers production deployments. There is no independent gating step.
- **Absent or mutable audit evidence:** Deployment logs live in the CI system's database, where they can be deleted, edited, or simply expire after a retention period. CI system logs are not immutable audit evidence.
- **No change ticket linkage:** Deployments happen on merge with no verified connection to an approved change request in ServiceNow or JIRA. Auditors find a deployment timestamp but no corresponding approved change record.
- **Developer access to production secrets:** Long-lived credentials for production AWS/GCP/Azure accounts exist in CI/CD secret stores accessible to anyone with pipeline edit rights — giving developers effective production access even without explicit IAM permissions.

The failure pattern is consistent: teams adopt CI/CD for velocity, add SOX controls as an afterthought, and end up with controls that pass a cursory review but fail a sampling test. An auditor who picks three deployments at random and asks for the approval evidence for each should receive a complete, verifiable package within minutes.

## Threat Model

**Threat 1 — Developer self-deploying unauthorized changes to financial code:** A developer modifies the revenue recognition calculation, approves the PR using a secondary account or social pressure on a peer, merges, and the pipeline automatically deploys to production. The change affects reported revenue. The audit trail shows a merge approval, but the approver had no actual review authority over financial logic. The violation is both a SOX control failure and potential fraud.

**Threat 2 — Insider bypassing change management to deploy malicious code:** An engineer with production deployment credentials applies a hotfix directly to production without going through the change management process — or creates a pipeline run manually outside the standard workflow. The deployed code manipulates account balances. There is no change ticket, no approval record, and the deployment event appears only in CI logs that are later rotated.

**Threat 3 — Auditor finding no approval evidence for automated deployments:** External auditors sample five production deployments during the audit window. For two of them, the approval records exist only in a GitHub interface that has since rotated its event logs. For one, the approver turns out to be the same person as the author (a branch protection misconfiguration). The audit opinion includes a material weakness in IT General Controls, triggering remediation requirements, management reporting obligations, and potential regulatory scrutiny.

**Threat 4 — Privilege escalation through pipeline configuration changes:** A developer edits the GitHub Actions workflow YAML to remove an approval step, deploys to production, then reverts the workflow change. The deployment happened through a legitimate pipeline run, but the approval gate was temporarily disabled. This requires controls on pipeline configuration files themselves.

## Configuration and Implementation

### Segregation of Duties: GitHub

The core SOX requirement is that the person who writes code cannot be the sole person who authorizes its deployment. GitHub enforces this through a layered model.

**CODEOWNERS for financial code paths:**

```
# .github/CODEOWNERS
# Financial reporting modules require explicit approval from Finance Engineering
/src/revenue/          @org/finance-engineering-leads
/src/ledger/           @org/finance-engineering-leads
/src/reporting/        @org/finance-engineering-leads
/src/journal-entries/  @org/finance-engineering-leads

# Pipeline configuration requires security team approval
/.github/workflows/    @org/platform-security
/deploy/               @org/platform-security
```

CODEOWNERS enforcement requires branch protection rules that mandate review from code owners — not just any reviewer. Configure branch protection for `main` with:

- Require a pull request before merging
- Require approvals: minimum 2
- Require review from Code Owners
- Dismiss stale reviews when new commits are pushed
- Restrict who can push to matching branches (exclude developer teams)
- Require status checks to pass before merging (include the SOD validation job)
- **Do not allow bypassing the above settings** — this includes repository administrators

The last point is critical and frequently missed. If administrators can bypass branch protection, an administrator who is also a developer can deploy without approval. SOX requires that no individual can unilaterally bypass the control — including those who configured it.

**GitHub Environment Protection Rules for production:**

```yaml
# In the GitHub repository settings (configured via API or Terraform):
# Environment: production
# Required reviewers: [finance-engineering-leads, release-managers]
# Wait timer: 0 (or set to allow async review)
# Deployment branches: main only
# Prevent self-review: enforced by the SOD check job below
```

**Automated SOD validation job:**

The GitHub interface alone does not prevent the author from being one of the approvers when multiple reviewers are required. An explicit CI check is needed.

```yaml
# .github/workflows/sox-sod-check.yml
name: SOX Segregation of Duties Check

on:
  pull_request:
    types: [review_submitted]
  workflow_call:
    inputs:
      pr_number:
        required: true
        type: number

jobs:
  validate-sod:
    name: Validate Approver != Author
    runs-on: ubuntu-latest
    permissions:
      pull-requests: read
    steps:
      - name: Check SOD compliance
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          REPO: ${{ github.repository }}
        run: |
          # Fetch PR author
          AUTHOR=$(gh api repos/$REPO/pulls/$PR_NUMBER \
            --jq '.user.login')

          # Fetch all approving reviews
          APPROVERS=$(gh api repos/$REPO/pulls/$PR_NUMBER/reviews \
            --jq '[.[] | select(.state == "APPROVED") | .user.login] | unique | .[]')

          echo "PR Author: $AUTHOR"
          echo "Approvers: $APPROVERS"

          # Check that no approver is the author
          if echo "$APPROVERS" | grep -qx "$AUTHOR"; then
            echo "SOD VIOLATION: PR author '$AUTHOR' has approved their own PR"
            echo "SOX IT General Control CM-1 requires that the developer cannot"
            echo "self-approve changes to production financial systems."
            exit 1
          fi

          # Check minimum approver count (adjust per policy)
          APPROVER_COUNT=$(echo "$APPROVERS" | grep -c . || echo 0)
          if [ "$APPROVER_COUNT" -lt 2 ]; then
            echo "INSUFFICIENT APPROVALS: $APPROVER_COUNT of 2 required"
            exit 1
          fi

          echo "SOD check passed: $APPROVER_COUNT distinct approvers, none are the author"
```

### Segregation of Duties: GitLab

GitLab's protected branch model separates merge permissions from push permissions at the group level. Configure protected branches for `main`:

- **Allowed to push:** No one (or Maintainers only, where Maintainers are restricted to platform team)
- **Allowed to merge:** Developers (with approval rules below)
- **Approval rules:** Require approval from `finance-approvers` group; prevent approval by the merge request author; prevent approval from users who have added commits

GitLab's "prevent approval by the author" and "prevent approval by users who have added commits" settings directly address the SOD requirement. Enable both in the project's Merge Request approval settings.

For environment-level approval in GitLab CI:

```yaml
# .gitlab-ci.yml
deploy-production:
  stage: deploy
  environment:
    name: production
    deployment_tier: production
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  when: manual
  needs:
    - job: sox-controls-check
      artifacts: true
```

Configure the production environment in GitLab with required approval from the `release-managers` group, excluding the pipeline triggerer from approving.

### Immutable Change Evidence: The Audit Artifact

Every production deployment must produce a signed, immutable evidence package that answers the auditor's questions without requiring access to the CI system.

**Evidence artifact structure:**

```json
{
  "schema_version": "1.0",
  "deployment_id": "deploy-20261107-143022-a1b2c3d",
  "pipeline_run": {
    "system": "github-actions",
    "run_id": "9876543210",
    "run_url": "https://github.com/org/repo/actions/runs/9876543210",
    "workflow": ".github/workflows/deploy-production.yml",
    "triggered_at": "2026-11-07T14:30:22Z"
  },
  "change": {
    "commit_sha": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "commit_message": "Fix revenue recognition for multi-currency transactions",
    "branch": "main",
    "pr_number": 1847,
    "pr_url": "https://github.com/org/repo/pull/1847"
  },
  "approval": {
    "author": "jsmith",
    "author_email": "jsmith@company.com",
    "approvers": [
      {
        "login": "amartinez",
        "email": "amartinez@company.com",
        "team": "finance-engineering-leads",
        "approved_at": "2026-11-07T13:55:10Z",
        "review_id": "1234567890"
      },
      {
        "login": "bchen",
        "email": "bchen@company.com",
        "team": "release-managers",
        "approved_at": "2026-11-07T14:01:44Z",
        "review_id": "1234567891"
      }
    ],
    "sod_validated": true,
    "author_is_approver": false
  },
  "change_management": {
    "ticket_system": "servicenow",
    "ticket_id": "CHG0012345",
    "ticket_status": "approved",
    "ticket_url": "https://company.service-now.com/change_request.do?sys_id=...",
    "approved_by": "CAB",
    "approval_time": "2026-11-07T10:00:00Z"
  },
  "deployment": {
    "environment": "production",
    "target": "aws-account-123456789/us-east-1/ecs/financial-api",
    "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/financial-api:a1b2c3d",
    "image_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "deployed_at": "2026-11-07T14:30:45Z",
    "deployed_by_role": "arn:aws:iam::123456789:role/cicd-production-deploy",
    "oidc_subject": "repo:org/financial-api:environment:production"
  },
  "build_provenance": {
    "slsa_level": "3",
    "provenance_uri": "https://rekor.sigstore.dev/api/v1/log/entries/...",
    "sbom_uri": "s3://audit-artifacts/sbom/a1b2c3d.spdx.json"
  }
}
```

**Signing and storing the evidence artifact:**

```yaml
# In the production deployment workflow
- name: Generate deployment evidence
  id: evidence
  run: |
    DEPLOY_ID="deploy-$(date -u +%Y%m%d-%H%M%S)-${GITHUB_SHA::7}"
    echo "deploy_id=$DEPLOY_ID" >> $GITHUB_OUTPUT

    # Collect PR approval data
    APPROVALS=$(gh api repos/${{ github.repository }}/pulls/${{ env.PR_NUMBER }}/reviews \
      --jq '[.[] | select(.state == "APPROVED") | {login: .user.login, approved_at: .submitted_at, review_id: (.id | tostring)}]')

    # Build evidence JSON
    jq -n \
      --arg schema "1.0" \
      --arg deploy_id "$DEPLOY_ID" \
      --arg run_id "${{ github.run_id }}" \
      --arg sha "${{ github.sha }}" \
      --arg author "${{ github.event.pull_request.user.login }}" \
      --argjson approvers "$APPROVALS" \
      --arg ticket "${{ env.CHANGE_TICKET }}" \
      --arg environment "production" \
      --arg deployed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{
        schema_version: $schema,
        deployment_id: $deploy_id,
        pipeline_run: { run_id: $run_id },
        change: { commit_sha: $sha },
        approval: { author: $author, approvers: $approvers, sod_validated: true },
        change_management: { ticket_id: $ticket },
        deployment: { environment: $environment, deployed_at: $deployed_at }
      }' > evidence.json

- name: Sign evidence with cosign
  uses: sigstore/cosign-installer@v3
  with:
    cosign-release: 'v2.4.0'
- run: |
    cosign sign-blob \
      --output-signature evidence.sig \
      --output-certificate evidence.pem \
      evidence.json
    # Verify immediately
    cosign verify-blob \
      --signature evidence.sig \
      --certificate evidence.pem \
      --certificate-identity-regexp "https://github.com/org/.*" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      evidence.json

- name: Store evidence in immutable S3 bucket
  run: |
    DEPLOY_ID="${{ steps.evidence.outputs.deploy_id }}"
    # S3 bucket has Object Lock enabled in COMPLIANCE mode
    aws s3 cp evidence.json \
      "s3://sox-audit-artifacts/deployments/$DEPLOY_ID/evidence.json"
    aws s3 cp evidence.sig \
      "s3://sox-audit-artifacts/deployments/$DEPLOY_ID/evidence.sig"
    aws s3 cp evidence.pem \
      "s3://sox-audit-artifacts/deployments/$DEPLOY_ID/evidence.pem"
    # Tag with retention metadata
    aws s3api put-object-tagging \
      --bucket sox-audit-artifacts \
      --key "deployments/$DEPLOY_ID/evidence.json" \
      --tagging 'TagSet=[{Key=sox-retention,Value=7-years},{Key=environment,Value=production}]'
```

The S3 bucket must have Object Lock enabled in **COMPLIANCE mode** (not GOVERNANCE mode) with a retention period of at least 7 years. COMPLIANCE mode prevents any user — including root — from deleting or modifying objects before the retention period expires. GOVERNANCE mode allows users with `s3:BypassGovernanceRetention` to delete objects, which is insufficient for SOX evidence.

### Change Management Integration

Requiring a change ticket is only a control if the pipeline validates the ticket exists, is approved, and is not expired before deploying.

```yaml
- name: Validate ServiceNow change ticket
  env:
    SN_INSTANCE: ${{ secrets.SERVICENOW_INSTANCE }}
    SN_TOKEN: ${{ secrets.SERVICENOW_API_TOKEN }}
  run: |
    # Extract ticket number from PR description (required format: CHG#######)
    TICKET=$(echo "${{ github.event.pull_request.body }}" \
      | grep -oP 'CHG\d{7}' | head -1)

    if [ -z "$TICKET" ]; then
      echo "ERROR: No ServiceNow change ticket found in PR description"
      echo "All production deployments require an approved change ticket."
      echo "Add 'Change: CHG#######' to the PR description."
      exit 1
    fi

    # Validate ticket via ServiceNow API
    TICKET_DATA=$(curl -sf \
      -H "Authorization: Bearer $SN_TOKEN" \
      -H "Accept: application/json" \
      "https://$SN_INSTANCE.service-now.com/api/now/table/change_request?sysparm_query=number=$TICKET&sysparm_fields=state,approval,start_date,end_date,assigned_to" \
      | jq '.result[0]')

    if [ "$TICKET_DATA" = "null" ]; then
      echo "ERROR: Change ticket $TICKET not found in ServiceNow"
      exit 1
    fi

    STATE=$(echo "$TICKET_DATA" | jq -r '.state')
    APPROVAL=$(echo "$TICKET_DATA" | jq -r '.approval')

    # State 3 = Authorize, Approval = approved
    if [ "$STATE" != "3" ] || [ "$APPROVAL" != "approved" ]; then
      echo "ERROR: Change ticket $TICKET is not in approved state"
      echo "State: $STATE, Approval: $APPROVAL"
      echo "Ticket must be approved by CAB before production deployment."
      exit 1
    fi

    echo "TICKET_ID=$TICKET" >> $GITHUB_ENV
    echo "Change ticket $TICKET validated: approved"
```

### Production Access Controls via OIDC

No developer should hold production deployment credentials. The CI/CD system assumes a deployment role through OIDC federation, with the trust policy scoped to a specific repository, branch, and environment.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:org/financial-api:environment:production"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:ref": "refs/heads/main"
        }
      }
    }
  ]
}
```

The trust policy enforces that only workflow runs from the `production` environment on the `main` branch can assume the role. GitHub's Environment protection rules gate which runs can reference the production environment — meaning the approval requirement is enforced at the IAM layer, not just the UI layer.

### Break-Glass Access

Emergency changes that bypass normal change management must be subject to elevated controls, not fewer controls. Define an emergency change procedure:

1. Break-glass access requires approval from two senior managers (not engineering leads).
2. The pipeline records the break-glass invocation with a mandatory incident number.
3. The deployed change is flagged for post-incident review within 24 hours.
4. The review is documented in the change management system and linked to the deployment evidence.

```yaml
- name: Check for emergency deployment
  run: |
    if [ "${{ inputs.emergency_deploy }}" = "true" ]; then
      if [ -z "${{ inputs.incident_number }}" ]; then
        echo "ERROR: Emergency deployments require an incident number"
        exit 1
      fi
      # Send alert to SOX compliance team
      curl -sf -X POST "${{ secrets.COMPLIANCE_WEBHOOK_URL }}" \
        -H "Content-Type: application/json" \
        -d '{
          "alert_type": "emergency_deployment",
          "repository": "${{ github.repository }}",
          "commit": "${{ github.sha }}",
          "incident": "${{ inputs.incident_number }}",
          "triggered_by": "${{ github.actor }}",
          "timestamp": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
        }'
      echo "EMERGENCY_DEPLOY=true" >> $GITHUB_ENV
    fi
```

### Quarterly Access Reviews

SOX requires periodic revalidation that access rights remain appropriate. Automate evidence generation for access reviews:

```yaml
# .github/workflows/sox-access-review.yml
name: Quarterly SOX Access Review Report
on:
  schedule:
    - cron: '0 6 1 1,4,7,10 *'  # First day of each quarter

jobs:
  generate-access-report:
    runs-on: ubuntu-latest
    steps:
      - name: Enumerate production environment approvers
        env:
          GH_TOKEN: ${{ secrets.GH_AUDIT_TOKEN }}
        run: |
          # List all teams with production environment approval rights
          gh api repos/${{ github.repository }}/environments/production \
            --jq '.protection_rules[] | select(.type == "required_reviewers") | .reviewers[]' \
            > approvers.json

          # For each team, list members
          jq -r '.reviewer.login' approvers.json | while read team; do
            gh api orgs/${{ github.repository_owner }}/teams/$team/members \
              --jq '.[] | {team: "'"$team"'", login: .login, email: .email}' \
              >> team-members.json
          done

          # Generate report
          jq -s '.' team-members.json > quarterly-access-report-$(date +%Y-Q%q).json

      - name: Store report as immutable artifact
        run: |
          aws s3 cp quarterly-access-report-*.json \
            "s3://sox-audit-artifacts/access-reviews/"
```

## Expected Behaviour

| SOX ITGC Control | Pipeline Implementation | Evidence Artifact |
|---|---|---|
| CM-1: Change authorization before deployment | GitHub Environment approval gates; ServiceNow ticket validation in pipeline | evidence.json `change_management.ticket_status`, `approval.approvers[]` |
| CM-2: Segregation of duties (developer cannot deploy own changes) | CODEOWNERS enforcement; SOD check job validates approver ≠ author; Environment reviewers from separate team | evidence.json `approval.sod_validated`, `approval.author_is_approver: false` |
| CM-3: Changes tested before production | Required status checks (unit tests, integration tests, SAST) before merge | GitHub Actions run logs linked in evidence.json `pipeline_run.run_url` |
| CM-4: Change documentation | PR description with ticket link; deployment evidence artifact | evidence.json `change_management.ticket_id`, signed and stored in S3 Object Lock |
| LA-1: Least privilege for production access | Developers have no production IAM roles; deploy role assumed via OIDC scoped to environment | IAM CloudTrail: `sts:AssumeRoleWithWebIdentity` calls with OIDC subject |
| LA-2: Access restricted to authorized personnel | GitHub Environment reviewers limited to release-managers group; branch push restricted to platform team | Quarterly access review report stored in S3 |
| LA-3: Periodic access reviews | Automated quarterly report of approver group membership | `sox-audit-artifacts/access-reviews/` objects with Object Lock |
| CO-1: Deployment performed by authorized process | All production deployments via pipeline only; no manual deploy access | evidence.json `deployment.oidc_subject` confirms pipeline identity |
| CO-2: Deployment records retained | Signed evidence artifacts in S3 Object Lock COMPLIANCE mode, 7-year retention | S3 objects with retention metadata tag `sox-retention=7-years` |
| CO-3: Build integrity | Container image digest recorded; SLSA provenance generated; cosign signature on evidence | evidence.json `deployment.image_digest`, `build_provenance.slsa_level` |

## Trade-offs

**Deployment velocity vs approval requirements:** A pipeline with two required human approvers and a ServiceNow ticket prerequisite adds a minimum of hours — often a business day — to any production change. Teams shipping multiple times per day must invest in fast-track change procedures: pre-approved change templates for low-risk, well-tested, reversible changes that move through CAB approval in minutes rather than days. SOX does not prohibit fast deployments; it requires demonstrable control. A well-designed pre-approved change category satisfies the requirement while preserving velocity.

**Emergency changes:** The worst outcome is engineers bypassing the pipeline entirely during an incident because the approval process is too slow. Design the emergency change procedure so it is faster than the bypass: a single approval from an on-call manager plus an auto-filed incident ticket must be achievable in under five minutes. If the legitimate emergency path takes 30 minutes, engineers will find the 30-second bypass.

**Pipeline configuration as a control surface:** CODEOWNERS and branch protection must cover the workflow files themselves. A developer who can modify `.github/workflows/deploy-production.yml` without approval can remove the SOD check or change the approval requirement. Add `/github/workflows/` to CODEOWNERS assigned to the security team, and require that workflow changes go through the same approval process as financial code changes.

**Audit artifact accessibility:** Storing evidence in S3 is immutable, but auditors do not have S3 access. Build an auditor portal — a read-only web interface over the evidence bucket — or generate an audit evidence package that bundles the deployment JSON, the cosign signature, and the certificate chain into a ZIP that can be handed to auditors without granting them cloud access.

## Failure Modes

**Common SOX audit findings in CI/CD environments:**

**Finding: Administrator bypass of branch protection.** The branch protection rule has "Include administrators" unchecked. Repository administrators — who are often senior engineers — can merge and deploy without approval. Remediation: enable "Do not allow bypassing the above settings" and document in policy that no individual can hold both developer and administrator roles for financial systems repositories.

**Finding: Approver identity not independently verifiable.** The deployment log shows "approved by bchen" but that data comes from the CI system's database, which is mutable. Remediation: the cosign-signed evidence artifact, stored in S3 Object Lock, provides independently verifiable approval evidence that the CI system cannot retroactively alter.

**Finding: Change ticket validation is advisory, not blocking.** The pipeline logs a warning if no change ticket is found but continues the deployment. Auditors sample a deployment with no ticket and find it succeeded. Remediation: the validation step must exit non-zero and the deployment job must depend on it, not just run after it.

**Finding: OIDC trust policy too broad.** The IAM role trust policy uses `StringLike` on the subject with a wildcard: `repo:org/financial-api:*`. Any branch, any environment, any workflow run can assume the role. A developer creates a branch named `production-test` and triggers a deployment from it. Remediation: scope the trust policy to `repo:org/financial-api:environment:production` exactly, requiring the run to be associated with the protected production environment.

**Finding: Evidence retention period insufficient.** S3 Object Lock is configured for 2 years. SOX requires 7 years of records retention under Section 802. Auditors reviewing records from 3 years ago find gaps. Remediation: set the Object Lock retention period to 2557 days (7 years) in COMPLIANCE mode at bucket creation. COMPLIANCE mode cannot be changed after the fact.

**Finding: Access review evidence not audit-ready.** The quarterly access review report is a GitHub Actions artifact that expired after 90 days. Auditors ask for access review evidence from 18 months ago. Remediation: pipe access review reports to the same S3 Object Lock bucket as deployment evidence, with the same 7-year retention policy.

**Finding: Pipeline configuration changes not controlled.** Auditors find three workflow file changes in the audit period with only one approver (the minimum was set to one for non-financial files, and workflow files were not in CODEOWNERS). Remediation: assign workflow directory ownership in CODEOWNERS to a security team with a separate approval track, and require two approvals for changes to files that affect deployment controls.

## Auditor Checklist

The following checklist represents the questions a SOX IT auditor will ask about a CI/CD pipeline deployment process. For each item, the evidence location refers to where the control evidence lives in the architecture described above.

| Auditor Question | Control Evidence Location |
|---|---|
| Can a developer approve their own changes? | Branch protection settings + SOD check job output in Actions log |
| Who approved deployment #X on date Y? | `s3://sox-audit-artifacts/deployments/[deploy-id]/evidence.json` — `approval.approvers[]` |
| Is the approval evidence tamper-proof? | cosign signature (`evidence.sig`) verifiable against Sigstore transparency log; S3 COMPLIANCE Object Lock |
| Was there an approved change ticket for this deployment? | `evidence.json` — `change_management.ticket_id` and `ticket_status` |
| Who has access to approve production deployments? | Quarterly access review report in `s3://sox-audit-artifacts/access-reviews/` |
| Can a developer directly access production systems? | IAM role trust policy restricts assume-role to OIDC subject `environment:production`; no developer IAM bindings in production account |
| Are deployment records retained for 7 years? | S3 Object Lock COMPLIANCE mode; `sox-retention=7-years` object tag; bucket retention policy |
| Is the deployed code the same code that was reviewed? | `evidence.json` — `deployment.image_digest` matches container image built from reviewed commit SHA |
