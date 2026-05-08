---
title: "OIDC Federation Hardening: Locking Down CI-to-Cloud Trust Policies"
description: "OIDC federation between CI and cloud removes long-lived secrets. The trust policies that grant the access are the new attack surface, and most are too loose."
slug: "oidc-federation-hardening"
date: 2026-04-27
lastmod: 2026-04-27
category: "cicd"
tags: ["oidc", "github-actions", "aws", "iam", "federation", "supply-chain"]
personas: ["platform-engineer", "security-engineer", "devops"]
article_number: 173
difficulty: "intermediate"
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/cicd/oidc-federation-hardening/index.html"
---

# OIDC Federation Hardening: Locking Down CI-to-Cloud Trust Policies

## Problem

OIDC federation between CI providers (GitHub Actions, GitLab, CircleCI, Buildkite) and cloud providers (AWS, GCP, Azure) replaced the era of long-lived access keys stored as CI secrets. Every workflow run mints a fresh, short-lived token with the permissions it needs. No keys to rotate, no keys to leak.

The trade-off is that the trust policy on the cloud side becomes the load-bearing security control. A misconfigured trust policy is silently equivalent to a leaked credential — sometimes worse, because attackers can mint legitimate tokens at will rather than racing the rotation clock.

The class of incidents seen through 2024–2025 — multiple public reports of GitHub→AWS misconfigurations granting an entire organization's access to a single fork's pull request — share the same shape:

- The trust policy used `token.actions.githubusercontent.com:sub` as `repo:org/*` (wildcard) instead of pinning a specific repo, branch, or environment.
- It validated the issuer (`iss`) and audience (`aud`) but not the `sub` claim's specificity.
- It gave the federated role broader permissions than the workflow needed (production deploy access for a workflow that only built artifacts).
- It allowed pull-request-triggered workflows to assume the role, so any external contributor opening a PR could mint a token.
- It had no audit alerting on anomalous role-assumption patterns (tokens minted from unexpected branches, repositories, or workflows).

This article covers the structure of OIDC trust policies for AWS, GCP, and Azure, the specific subject-claim patterns that prevent the common misconfigurations, RBAC-on-the-cloud-side scoping, and detection of anomalous federated assumptions.

**Target systems:** GitHub Actions OIDC issuer (`https://token.actions.githubusercontent.com`), GitLab CI OIDC, AWS IAM, Google Cloud Workload Identity Federation, Azure Workload Identity Federation. Most patterns generalize across CI providers.

## Threat Model

- **Adversary 1 — Pull-request injection:** opens a PR against your repository containing a workflow change that runs malicious actions. If the trust policy permits PR-triggered workflows to mint tokens, the PR's code runs with cloud privileges.
- **Adversary 2 — Repository takeover:** compromises a maintainer account or merges a malicious PR; they push directly to the default branch and mint legitimate tokens.
- **Adversary 3 — Internal lateral movement:** has access to a low-value repository but the trust policy uses wildcards across the org; they create a workflow in their repo that assumes a high-value role from another product.
- **Adversary 4 — Branch-to-branch escalation:** has merge access to a feature branch; the trust policy allows any branch (not just `main`) to assume the role; they push code on the feature branch that escalates to production.
- **Access level:** Adversary 1 has no organization access at all. Adversary 2 has compromised one account. Adversary 3 has legitimate access to one repository. Adversary 4 has legitimate merge access to a non-production branch.
- **Objective:** Mint short-lived cloud credentials and use them to read secrets, modify infrastructure, or pivot to other resources.
- **Blast radius:** Bounded by what the federated role can do. A correctly-scoped role limits the blast to one resource type in one environment. A mis-scoped role with `iam:*`, `s3:*`, or `*:*` translates to "the entire account" — including other workloads and other environments that share the cloud account.

## Configuration

### AWS: Tight Trust Policy on the IAM Role

The AWS IAM trust policy is the mechanism that decides which OIDC tokens can assume the role. Common-but-wrong vs. tight versions side-by-side.

**Common-but-wrong:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:my-org/*"
        }
      }
    }
  ]
}
```

The wildcard `repo:my-org/*` means *any* workflow in *any* repository in the org, on *any* branch, including pull-request workflows, including new repositories the org adds tomorrow.

**Tight:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub":
            "repo:my-org/my-app:environment:production"
        }
      }
    }
  ]
}
```

`StringEquals` (not `StringLike`), pinned to a specific repository and a specific GitHub Actions environment. Workflows trigger this role only when running in the `production` environment, which can have its own protection rules (required reviewers, branch restrictions, deployment time windows).

For workflows that need access from multiple specific contexts:

```json
{
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
  },
  "StringLike": {
    "token.actions.githubusercontent.com:sub": [
      "repo:my-org/my-app:ref:refs/heads/main",
      "repo:my-org/my-app:environment:production",
      "repo:my-org/my-app:environment:staging"
    ]
  }
}
```

The `sub` field is a structured string. Use it with explicit prefixes:

| Sub format | What it grants |
|------------|----------------|
| `repo:org/repo:ref:refs/heads/main` | Workflows running on push to `main` |
| `repo:org/repo:environment:production` | Workflows targeting the `production` environment |
| `repo:org/repo:pull_request` | Workflows triggered by a pull request — **almost always wrong to allow** |
| `repo:org/repo:ref:refs/tags/v*` | Tag-triggered workflows |
| `repo:org/repo:job_workflow_ref:org/repo/.github/workflows/deploy.yml@refs/heads/main` | A specific workflow file at a specific ref — strictest |

The strictest form (`job_workflow_ref`) pins to the workflow file at a specific git ref. An attacker who modifies that workflow on a branch other than the pinned ref cannot assume the role.

### GitHub Actions: Use Reusable Workflows for Centralized Trust

Tightening every repository's trust policy independently leads to drift. Centralize via reusable workflows pinned to a known-good repository:

```yaml
# .github/workflows/deploy.yml in product repo
jobs:
  deploy:
    uses: my-org/ci-templates/.github/workflows/aws-deploy.yml@v1
    with:
      role-arn: arn:aws:iam::123456789012:role/ProductionDeploy
      environment: production
    permissions:
      id-token: write
      contents: read
```

The trust policy on the AWS role pins to the reusable workflow:

```json
{
  "StringEquals": {
    "token.actions.githubusercontent.com:job_workflow_ref":
      "my-org/ci-templates/.github/workflows/aws-deploy.yml@refs/heads/main"
  }
}
```

Now product repositories cannot deploy without going through the reviewed reusable workflow. The deploy logic, CodeQL gates, signed-image checks, and deploy-permission boundaries all live in a single audited file.

### GCP: Workload Identity Federation with Attribute Conditions

GCP's Workload Identity Federation supports attribute conditions that filter on OIDC token claims before allowing impersonation.

```bash
gcloud iam workload-identity-pools providers create-oidc github-actions \
  --location=global \
  --workload-identity-pool=ci-pool \
  --display-name="GitHub Actions" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
  --attribute-condition="attribute.repository=='my-org/my-app' && attribute.ref=='refs/heads/main'"
```

The `attribute-condition` is evaluated on every token; tokens not matching are rejected before they reach IAM. Bind the service account that the workflow impersonates with a fully-qualified subject:

```bash
gcloud iam service-accounts add-iam-policy-binding \
  ci-deployer@my-project.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/ci-pool/subject/repo:my-org/my-app:ref:refs/heads/main"
```

The combination of attribute condition + principal-specific binding closes the wildcard gap.

### Azure: Federated Identity Credentials with Subject Pinning

Azure AD federated credentials are configured per managed identity:

```bash
az identity federated-credential create \
  --name github-actions-prod \
  --identity-name my-app-prod-identity \
  --resource-group my-rg \
  --issuer https://token.actions.githubusercontent.com \
  --subject "repo:my-org/my-app:environment:production" \
  --audience api://AzureADTokenExchange
```

The `--subject` is a string match — wildcards are not supported. Each (repo, ref or environment) combination needs its own federated-credential entry. This is operationally heavier than IAM trust-policy wildcards but eliminates the wildcard misconfiguration class.

### Permission Scoping on the Cloud Side

A tight trust policy is necessary but not sufficient — the role itself must grant minimal permissions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeployArtifactsToProductionBucket",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::my-app-production-artifacts",
        "arn:aws:s3:::my-app-production-artifacts/*"
      ]
    },
    {
      "Sid": "InvalidateCloudFrontCache",
      "Effect": "Allow",
      "Action": "cloudfront:CreateInvalidation",
      "Resource": "arn:aws:cloudfront::123456789012:distribution/E1234ABCD"
    }
  ]
}
```

No `iam:*`. No `s3:*` across all buckets. No region wildcards on resources that exist per-region. Each statement targets the exact resource the workflow modifies.

### Detect Anomalous Assumptions

CloudTrail logs every `AssumeRoleWithWebIdentity` call. Build a baseline and alert on deviations.

```bash
# Query: which workflows have assumed which roles in the last 7 days?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity \
  --start-time $(date -u -d "7 days ago" +%s) \
  --max-items 1000 \
  --output json | jq -r '
    .Events[] | .CloudTrailEvent | fromjson |
    {
      time: .eventTime,
      role: .requestParameters.roleArn,
      sub: (.requestParameters.providerOptions.token | split(".")[1]
            | @base64d | fromjson | .sub)
    }'
```

Build a Sigma or Splunk rule:

```
event_name=AssumeRoleWithWebIdentity
| stats values(sub) as subs by role
| where mvcount(subs) > 1
| eval anomaly_subs=mvfilter(NOT match(subs, "^repo:my-org/expected-app:.*"))
| where mvcount(anomaly_subs) > 0
```

Alert on roles assumed from unexpected `sub` values, especially repositories outside the expected owner or workflow files outside the pinned ref.

## Expected Behaviour

| Signal | Loose trust policy | Tight trust policy |
|--------|---------------------|---------------------|
| PR-triggered workflow assumes role | Succeeds | Fails (sub does not match `environment` or `ref:main`) |
| Forked repo assumes role | Succeeds | Fails (sub repo prefix mismatch) |
| New repository in same org assumes role | Succeeds | Fails (repo not in allowlist) |
| Token use latency overhead | None | None — the check is single-policy lookup |
| Audit-log clarity on assumption | Generic role assumption | Includes full sub identifying repo/ref/env |
| Operational friction | Set once, never touch | Each new env/role/workflow needs explicit allowlist |

Verify a workflow assumes the right role only:

```yaml
# In the deploy workflow, log the OIDC token claims for traceability.
- name: Log token claims
  run: |
    TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value)
    echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{sub, repository, ref, environment}'
```

The output is the source of truth for which `sub` values your workflows use; design trust policies around the observed values, not assumptions.

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `StringEquals` over `StringLike` | Eliminates wildcard misconfigurations | Each (repo, env, branch) tuple needs an explicit entry | Generate trust policies via Terraform/Pulumi from a code-owned source of truth, not hand-edited. |
| Reusable workflow + `job_workflow_ref` pin | Centralized review of all deploy logic | Migration time; product repos lose flexibility | The lost flexibility is the security feature. Frame deploy as a paved-road service. |
| GitHub Environments + protection rules | Adds required reviewers, deploy windows | Configuration overhead per environment | Set up in the org template repository; new environments inherit. |
| Per-job role minimization | Smaller blast radius per role | More roles to manage | Group by environment + product; use SCPs (AWS Organizations) to bound the worst case. |
| Anomaly detection on CloudTrail | Catches drift and active abuse | Detection logic to maintain | Pipe CloudTrail to your SIEM; alert on unexpected `sub` claims. |
| GCP attribute-condition / Azure subject | Provider-side filter complements role binding | Each cloud has its own dialect | Document the patterns once per cloud; reuse in templates. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Wildcard sub in trust policy | Anyone in the org can assume the role | CloudTrail shows `sub` from unexpected repos | Replace `StringLike` with `StringEquals`; redeploy via Terraform. Audit subject history to identify any unauthorized assumption that already happened. |
| Trust policy missing `aud` check | Tokens minted for one cloud accepted by another | Tokens with wrong audience succeed in assume calls | Always include `token.actions.githubusercontent.com:aud == sts.amazonaws.com` (or the appropriate cloud audience). |
| Pull request granted production role | External contributor mints prod token | New role assumption from PR-triggered workflow shown in CloudTrail | Remove `pull_request` triggers from production workflows. Use `workflow_dispatch` or `push` to protected branches only. |
| Federated identity provider URL drift | New issuer URL not registered as OIDC provider | Workflows fail to assume role with `WebIdentityCertificateRevoked` or similar | Update the OIDC provider thumbprint when GitHub rotates its certificate. Subscribe to GitHub's `meta` API endpoint for changes. |
| Role policy too broad | Compromised CI step does more than expected | CloudTrail shows API calls outside the role's intended scope | Tighten the role's policy to least privilege. Use IAM Access Analyzer to identify unused permissions. |
| Reusable workflow ref unpinned | Deploy workflow modified by an attacker on a branch | Audit log shows assumption from an unexpected `job_workflow_ref` | Pin to commit SHA, not branch. Require CODEOWNERS approval on changes to the reusable workflow. |
| Branch protection bypassed via repo admin | Admin pushes directly to main, skipping reviewers | Push event without an associated PR; sub matches expected ref | Use `Require pull request reviews before merging` and `Restrict who can push to matching branches` on the default branch. |

## When to Consider a Managed Alternative

Hand-rolling federation across multi-cloud, multi-product, multi-team environments requires Terraform modules, drift detection, anomaly alerting, and continuous policy review (4-10 hours/month for an org with 20+ repos and 3 cloud accounts).

- **[GitHub Actions Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) + protection rules:** built-in; combine with cloud trust policies.
- **[StepSecurity Harden-Runner](https://stepsecurity.io):** reports OIDC token claims and policy compliance for each run.
- **[Hashicorp Vault dynamic AWS credentials](https://www.vaultproject.io/docs/secrets/aws):** issues per-pipeline credentials gated by a Vault-side policy, useful when cloud-side trust policies are too rigid for your model.
- **AWS IAM Identity Center + Access Analyzer:** centralizes role definition; Access Analyzer flags overpermissive policies.

## Related Articles

- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [Securing Self-Hosted CI/CD Runners](/articles/cicd/securing-cicd-runners/)
- [CI/CD Pipeline Egress Control](/articles/cicd/pipeline-egress-control/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [SLSA Build Provenance: Source-to-Registry Integrity](/articles/cicd/slsa-provenance/)
