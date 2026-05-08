---
title: "Just-in-Time CI Access for Production Deploys: Approval Flows and Bounded Permissions"
description: "Standing CI permissions are a liability. JIT mints production permissions only at deploy time, with explicit approval and short lifetime."
slug: "jit-ci-access"
date: 2026-04-29
lastmod: 2026-04-29
category: "cicd"
tags: ["jit", "cicd", "production-access", "approval", "access-management"]
personas: ["platform-engineer", "security-engineer", "devops"]
article_number: 218
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/jit-ci-access/index.html"
---

# Just-in-Time CI Access for Production Deploys: Approval Flows and Bounded Permissions

## Problem

CI / CD pipelines that deploy to production typically have standing access: an IAM role, a Vault token, a database password sitting in a CI secret, ready to use whenever a deploy fires. The model is fast — push a button, deploy goes — but the security implications scale poorly:

- **Standing permissions** mean any compromise of the CI environment grants production access immediately.
- **Approval is implicit:** "merging the PR" is the approval signal, but the PR review may have been about code, not about whether deploy should run.
- **Audit is coarse:** "deploy ran at time T" but not "who approved this specific production change."
- **Out-of-hours risk:** an attacker who compromises CI can deploy at 3 AM with no human in the loop.
- **Drift over time:** roles accumulate permissions; the pipeline ends up with more access than current deploys need.

Just-in-time access flips this. The CI's standing role is enough to *request* production permissions; the actual permissions are minted per deploy with explicit approval, short lifetime, and bounded scope.

By 2026 the patterns are mature:

- **GitHub Environments + required reviewers.** Built-in: a workflow targeting an Environment with reviewers waits for human approval before continuing. Combined with environment-scoped secrets, the deploy job has access only after approval.
- **HashiCorp Vault dynamic secrets with deploy approval.** Vault issues a short-lived AWS / GCP credential at deploy time; integrate with a Slack-bot approval flow.
- **OpenBao / Boundary + JIT engines.** Open-source approach.
- **StepSecurity Harden-Runner with deploy gates.** Commercial offering with built-in JIT semantics.
- **Custom JIT approval gates.** A separate workflow / service that issues short-lived credentials only after approval.

The specific gaps in standing-access pipelines:

- Production credentials in CI secrets, valid 24/7 even when no deploy is in flight.
- Deploy can fire at any time; no human-in-the-loop for production changes.
- Audit trail blends CI activity with deploy activity; difficult to answer "who authorized this specific production change."
- New deployers added to the pipeline inherit full standing access.

This article covers GitHub Environments + reviewers, Vault dynamic credentials with approval gates, structured audit, and the patterns for breaking glass when the JIT mechanism itself is unavailable.

**Target systems:** GitHub Actions Environments, HashiCorp Vault 1.18+ with approval-required policies, AWS IAM Identity Center, Slack / Teams approval bots, Tines / Torq for SOAR-style workflows. Concepts apply to GitLab CI environments, CircleCI contexts, Jenkins approval steps.

## Threat Model

- **Adversary 1 — Compromised CI environment:** an attacker with code execution on the CI runner. Wants to use the runner's standing credentials to deploy to production.
- **Adversary 2 — Compromised CI service-account credential:** stolen API key for the CI system. Wants to mint and run workflows.
- **Adversary 3 — Out-of-hours attack:** an attacker who has either of the above, but operates at a time when no human would notice.
- **Adversary 4 — Insider with merge access:** legitimate developer who wants to push an unauthorized production change without separate-of-duties review.
- **Access level:** Adversary 1 has CI shell. Adversary 2 has CI API access. Adversary 3 has either. Adversary 4 has source-merge rights.
- **Objective:** Trigger production-affecting actions without explicit, recent approval.
- **Blast radius:** With standing permissions, any compromise = immediate production access. With JIT + approval: compromise grants only the ability to *request*; actual access requires a human approval that the attacker cannot satisfy.

## Configuration

### Step 1: GitHub Environments With Required Reviewers

The simplest, native-Kubernetes-friendly pattern.

```yaml
# .github/workflows/deploy-prod.yml
name: Deploy to production
on:
  workflow_dispatch:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh
      - uses: actions/upload-artifact@v4
        with:
          name: artifact
          path: dist/

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://www.example.com
    permissions:
      id-token: write       # needed for OIDC federation
      contents: read
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: artifact
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-prod-deploy
          aws-region: us-east-1
      - run: aws s3 sync ./dist s3://prod.example.com/
```

Configure the `production` environment in repo settings:

```yaml
environment_protection_rules:
  - type: required_reviewers
    reviewers: [security-team, platform-team]
    prevent_self_review: true
  - type: deployment_branch_policy
    protected_branches: true   # only main / tags
  - type: wait_timer
    minutes: 5                 # cooling-off period
```

Workflow execution pauses at the `deploy` job until a reviewer approves in the GitHub UI. The OIDC-federated AWS role is assumed only after approval. No standing AWS credentials in the CI environment.

### Step 2: Vault Dynamic Credentials With Approval

For systems where GitHub Environments isn't enough (multi-step approvals, business-hours gate, integration with PagerDuty), use Vault.

```hcl
# vault-prod-deployer-policy.hcl
path "aws/sts/prod-deployer" {
  capabilities = ["read"]
  required_parameters = ["jit_token"]
}
```

The CI workflow requests credentials, providing a `jit_token` minted by a separate approval service:

```yaml
# In the deploy workflow.
- name: Request JIT token
  env:
    APPROVAL_API: https://jit.internal.example.com
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    JIT_RESPONSE=$(curl -X POST "$APPROVAL_API/request" \
      -H "Authorization: Bearer $GITHUB_OIDC_TOKEN" \
      -d '{
        "deploy_id": "${{ github.run_id }}",
        "repo": "${{ github.repository }}",
        "actor": "${{ github.actor }}",
        "ref": "${{ github.ref }}",
        "purpose": "Production deploy of ${{ github.sha }}"
      }')
    JIT_TOKEN=$(echo $JIT_RESPONSE | jq -r .token)
    echo "::add-mask::$JIT_TOKEN"
    echo "JIT_TOKEN=$JIT_TOKEN" >> $GITHUB_ENV

- name: Get AWS credentials from Vault
  run: |
    VAULT_TOKEN=$(vault write -field=token \
      auth/oidc/login \
      role=ci-prod-deployer \
      jit_token=$JIT_TOKEN)
    AWS_CREDS=$(vault read -format=json aws/sts/prod-deployer)
    # Use AWS_CREDS for the deploy.
```

The approval service:

1. Receives the request with full context (who, what, why).
2. Posts to Slack: "Deploy of v1.2.3 by alice; approve? [link]"
3. Waits for a human approver (excluding `actor`); approval can be conditional on time-of-day, on-call status, etc.
4. Issues a JIT token bound to this specific deploy.

The JIT token is consumed by Vault to authorize the actual credential issuance. Once consumed, it cannot be reused.

### Step 3: Approval Service Implementation Sketch

```python
# jit_approval_service.py
from datetime import datetime, timedelta, timezone
import secrets, jwt
from fastapi import FastAPI, HTTPException

app = FastAPI()

# In-memory store for demo; use Redis or a database in production.
pending_approvals = {}

@app.post("/request")
async def request_approval(req: Request):
    payload = await req.json()
    request_id = secrets.token_urlsafe(16)
    deadline = datetime.now(timezone.utc) + timedelta(minutes=15)

    pending_approvals[request_id] = {
        "deploy_id": payload["deploy_id"],
        "repo": payload["repo"],
        "actor": payload["actor"],
        "ref": payload["ref"],
        "purpose": payload["purpose"],
        "deadline": deadline,
        "approved_by": None,
        "consumed": False,
    }

    # Notify approvers (Slack, etc.).
    await notify_approvers(request_id, payload)

    # Return the request ID; CI polls for approval.
    return {"request_id": request_id, "deadline": deadline.isoformat()}

@app.post("/approve/{request_id}")
async def approve(request_id: str, approver: str):
    record = pending_approvals.get(request_id)
    if not record: raise HTTPException(404)
    if record["actor"] == approver:
        raise HTTPException(403, "Cannot self-approve")
    if datetime.now(timezone.utc) > record["deadline"]:
        raise HTTPException(410, "Expired")
    record["approved_by"] = approver
    record["approved_at"] = datetime.now(timezone.utc)
    return {"ok": True}

@app.post("/token/{request_id}")
async def get_token(request_id: str):
    record = pending_approvals.get(request_id)
    if not record or not record["approved_by"] or record["consumed"]:
        raise HTTPException(403, "Not approved or already consumed")
    record["consumed"] = True
    # Mint a short-lived JWT bound to this specific request.
    token = jwt.encode({
        "iss": "jit.internal.example.com",
        "sub": record["deploy_id"],
        "aud": "vault",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        "approved_by": record["approved_by"],
        "approval_id": request_id,
    }, JWT_SIGNING_KEY, algorithm="EdDSA")
    return {"token": token}
```

The CI workflow polls / blocks on approval; once the approver signs off in Slack (which calls `/approve`), the CI fetches the token via `/token` and uses it.

Vault validates the JWT signature, checks audience and expiration, and issues the short-lived AWS credential. Without a current, consumed-once JIT token, no AWS credential is ever issued.

### Step 4: Time-Boxed and Capability-Bounded Tokens

The minted credential's scope and lifetime should match the deploy:

```hcl
# vault-policy: prod-deployer.
path "aws/sts/prod-deployer" {
  capabilities = ["read"]
}

# AWS role in Vault.
vault write aws/roles/prod-deployer \
  credential_type=federation_token \
  policy_arns=arn:aws:iam::123456789012:policy/prod-deploy-minimal \
  default_sts_ttl=15m \
  max_sts_ttl=30m
```

Credential lifetime is 15 minutes — enough for the deploy to complete, not enough for an attacker to use later. The IAM policy `prod-deploy-minimal` grants only the specific actions the deploy needs (S3:PutObject on one bucket, CloudFront:CreateInvalidation on one distribution). No broader permissions.

### Step 5: Audit Across the Flow

Every step is auditable. Wire the audit pipelines:

- **Approval service:** every request, approval, denial, expiration logged with timestamp + actor.
- **Vault:** every credential issuance logged.
- **AWS CloudTrail:** every API call performed with the credential logged.
- **GitHub Actions:** every workflow run, every environment-approval action logged.

Cross-correlate by deploy ID:

```sql
-- Find all activity for a specific deploy.
SELECT 'approval' AS source, timestamp, actor, action, details
FROM approval_audit WHERE deploy_id = 'abc123'
UNION ALL
SELECT 'vault' AS source, timestamp, actor, action, request
FROM vault_audit WHERE 'deploy_id=abc123' = ANY(metadata)
UNION ALL
SELECT 'aws' AS source, eventTime, userIdentity, eventName, requestParameters
FROM cloudtrail WHERE userIdentity.sessionContext.sessionIssuer.userName LIKE 'github-%' AND
  user_identity.session_context.attributes.deploy_id = 'abc123';
```

A complete chain: who pushed the code → who approved → who issued credentials → what AWS calls happened. Every link signed.

### Step 6: Break-Glass Procedure

The JIT system is a dependency. When it's down (cert expired, Slack outage, approval team offline), legitimate emergencies need an alternative path.

Define a break-glass:

```yaml
# break-glass-policy.yaml
purpose: Production access during JIT system outage
trigger_condition: JIT system unavailable AND active SEV1 incident
required_approvers:
  - role: Engineering VP
  - role: CTO
mechanism:
  - method: Manually-issued AWS root role assumption with 1-hour TTL
  - method: Recorded in incident ticket
  - method: Auto-revoked at 1 hour
post_use_required:
  - Incident retrospective explaining usage
  - Audit log review within 24 hours
```

Break-glass is rare; once-a-quarter at most. Each use generates a P0 ticket for review. The audit log provides forensic traceability even when the JIT system isn't available.

### Step 7: Telemetry

```
jit_request_total{repo, environment}
jit_approval_total{result="approved|denied|expired"}
jit_token_consumed_total
jit_token_unused_total            # tokens issued but never consumed
jit_approval_duration_seconds     # time from request to approval
break_glass_use_total{reason}
```

Alert on:
- `jit_token_unused_total` rising — workflows requesting and not using; potentially an attacker probing.
- `jit_approval_duration_seconds` rising — approvers slow; SLA risk.
- `break_glass_use_total` non-zero — investigate every use.

## Expected Behaviour

| Signal | Standing access | JIT |
|--------|------------------|-------|
| 24/7 production credential availability | Yes | No; ~15 min after approval |
| Out-of-hours attacker access | Possible | Blocked unless approver is up |
| Audit of "who authorized this deploy" | Implicit (PR merge) | Explicit (named approver per deploy) |
| Compromised CI runner | Immediate prod access | Cannot satisfy approval; bounded to request capability |
| Self-approval | Possible | Blocked at policy |
| Deploy speed | Instant | +human approval time |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Required reviewers | Human-in-the-loop for prod changes | Slows deploys | Bound approval SLA (e.g., < 15 min); off-hours rotation. |
| Vault dynamic credentials | Short lifetime; bounded scope | Vault availability dependency | Vault HA; cache last-known credentials briefly for short outages. |
| Approval service | Rich context; programmable rules | Service to operate | Use existing tooling (incident.io, Tines) where possible. |
| Self-approval prevention | Separation of duties | Solo developers can't deploy | Pair-programming or pair-approval for solo work. |
| Auditable flow | Forensic evidence | Audit pipeline complexity | Standardize on one log aggregation (SIEM); deploy ID as common key. |
| Break-glass | Emergency continuity | Risk of misuse | High-bar approval; quarterly review of all uses. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Approver unavailable | Deploy blocks | Workflow times out | Use the break-glass; investigate why no approver was available. |
| Approver auto-approves | Deploys go through without real review | Approval-duration metric near zero | Train; add audit log for fast approvals; rotate approvers. |
| JIT token leak | Attacker uses an issued token | Vault audit shows unexpected credential issuance | Tokens are single-use and short-lived; impact bounded. Review audit; tighten policy if needed. |
| Vault unavailable | Deploys cannot get credentials | Workflow stalls at credential step | Break-glass; investigate Vault health. |
| Approval service compromised | Adversary issues self-approved tokens | Audit log shows tokens for unfamiliar deploys | Rotate signing key; investigate; redeploy. |
| Drift in IAM policy | Vault role grants too much | IAM Access Analyzer flags overpermissive policy | Tighten the role's policy; review quarterly. |
| Workflow bypassing JIT | Direct AWS-keys-in-secret usage outside JIT flow | Audit shows credentials assumed without JIT request | Grep CI workflows for hardcoded credential patterns; lint. |

## Related Articles

- [GitHub Apps vs PATs vs Deploy Keys vs OIDC](/articles/cicd/scm-identity-choice/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [Branch Protection and Repo Policy as Code](/articles/cicd/repo-policy-as-code/)
- [Production Access Management with Teleport / Boundary](/articles/cross-cutting/production-access-management/)
- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
