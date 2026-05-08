---
title: "Replacing Long-Lived CI/CD Cloud Credentials with Ephemeral OIDC Tokens"
description: "Long-lived AWS, GCP, and Azure credentials stored as CI secrets are a permanent liability. OIDC token exchange lets your pipeline mint short-lived cloud credentials per run, with no stored secrets and a complete audit trail."
slug: ephemeral-cloud-credentials-cicd
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - oidc
  - ephemeral-credentials
  - aws-irsa
  - workload-identity
  - zero-trust
personas:
  - security-engineer
  - platform-engineer
article_number: 523
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/ephemeral-cloud-credentials-cicd/
---

# Replacing Long-Lived CI/CD Cloud Credentials with Ephemeral OIDC Tokens

## Problem

The standard setup for cloud access in CI/CD pipelines is still, at most organisations, a long-lived AWS access key pair or a GCP service-account JSON key stored as a repository secret. The same credential persists for months or years, is valid from any IP address, and is often never rotated. It has no expiry enforced by the cloud provider. It is available as an environment variable to every step in every workflow in the repository, including the step that installs third-party dependencies — the same step most likely to run untrusted code.

The failure modes have been well demonstrated. A developer adds a `console.log(process.env)` in a test helper and the access key scrolls past in a public build log. A transitive npm package contains a postinstall hook that reads environment variables and HTTP-POSTs them to an attacker-controlled endpoint. A workflow prints the contents of a failed deployment response, which includes the credential used in the request. A departing employee still has the key in their local `~/.aws/credentials` because it was never rotated. In each case, the attacker gains a permanent credential that remains valid until someone notices and manually revokes it — typically long after the breach.

The permissions attached to these keys compound the risk. Teams frequently over-provision CI credentials with broad IAM policies because it is easier than enumerating exactly which S3 buckets the deploy job needs. A credential scoped to `s3:*` and `ecs:*` across an entire AWS account gives an attacker who compromises a single workflow job a large lateral-movement surface. There is rarely any alerting on who assumed the credential or from where, because static access keys do not produce the same CloudTrail event structure as assumed roles.

OpenID Connect (OIDC) federation eliminates stored cloud credentials from CI entirely. The CI provider acts as an OIDC identity provider: it issues a short-lived, signed JWT that asserts the identity of the current workflow run — which repository, which branch, which environment, which workflow file. The cloud provider is configured to trust that issuer and, when presented with a valid token, issues a short-lived cloud credential (AWS temporary credentials valid for one hour, a GCP access token, an Azure federated token) scoped to a specific role. The JWT is used once, is non-replayable after its validity window, and is never stored anywhere. If a build log captures the cloud credential, it expires within an hour. If a dependency exfiltrates the credential mid-run, the window of usefulness is bounded by the remaining token lifetime.

## Threat Model

- **Adversary 1 — Log-scraping attacker:** reads public or leaked build logs. With a long-lived access key, this yields permanent cloud access. With an OIDC-issued temporary credential, they have at most the remaining lifetime of the token (typically less than 60 minutes) and only the permissions of the narrowly-scoped role.
- **Adversary 2 — Malicious dependency:** a compromised package's postinstall or build hook reads the environment at install time. A stored `AWS_ACCESS_KEY_ID` in the environment is immediately useful. An OIDC-issued credential is still useful within the session, so the threat is not fully eliminated — but the credential expires quickly and cannot be refreshed without a new pipeline run through the trust policy.
- **Adversary 3 — Fork/pull-request attacker:** opens a PR to a public repository. If the CI workflow uses a stored secret, and if the workflow runs on `pull_request` events, the secret is available to the fork's code (subject to GitHub's fork-secret restrictions, which apply to repository secrets but not organisation secrets in all configurations). With OIDC, the trust policy on the cloud side controls which workflows can mint tokens; a PR-scoped `sub` claim can be explicitly excluded.
- **Adversary 4 — Overly broad credential scope:** even if the credential is obtained legitimately (by an insider, or through a compromised account with repository access), a broadly-permissioned IAM user or service account can access far more than the pipeline job requires. Per-workflow OIDC roles can be restricted to the exact resources the job touches.
- **Objective:** Obtain persistent, reusable cloud access to read secrets, exfiltrate data, pivot to other resources, or modify infrastructure.
- **Blast radius:** With stored long-lived credentials, one compromised pipeline exposes every cloud resource the credential can reach, indefinitely. With OIDC-issued ephemeral credentials, the blast radius is bounded by the role's permissions and the token's remaining lifetime.

## Configuration

### How the OIDC Token Exchange Works

Every major CI provider now operates as an OIDC identity provider. When a workflow job begins, the runner holds an ID token request token that it can use to fetch a signed JWT from the provider's OIDC endpoint. That JWT contains standard OIDC claims (`iss`, `sub`, `aud`, `exp`) and provider-specific extension claims: for GitHub Actions, the `repository`, `ref`, `environment`, `job_workflow_ref`, and `workflow` claims; for GitLab CI, the `namespace_path`, `project_path`, `ref`, `ref_type`, and `environment` claims.

The cloud provider has an OIDC trust configuration that names the issuer URL, specifies the expected `aud` value, and defines conditions on the `sub` or extension claims. When the CI runtime calls `AssumeRoleWithWebIdentity` (AWS), the Workload Identity Pool token exchange endpoint (GCP), or the workload identity federation endpoint (Azure) with the JWT, the cloud provider verifies the signature against the issuer's published JWKS endpoint, checks the conditions, and — if everything matches — returns short-lived cloud credentials. No secret ever crosses the network in the direction of the cloud provider; only a signed assertion of identity does.

### GitHub Actions OIDC with AWS

The workflow must request `id-token: write` permission. The official action `aws-actions/configure-aws-credentials` handles the token fetch and STS call internally.

```yaml
# .github/workflows/deploy.yml
name: Deploy to AWS

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeployRole
          role-session-name: github-deploy-${{ github.run_id }}
          aws-region: us-east-1

      - name: Deploy application
        run: aws s3 sync dist/ s3://my-app-production/
```

The IAM role's trust policy is what enforces which workflows can assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:my-org/my-app:environment:production"
        }
      }
    }
  ]
}
```

The critical fields: `aud` must be `sts.amazonaws.com` (not a wildcard); `sub` must use `StringEquals`, not `StringLike`, and must name the specific repository and environment. Using `StringLike` with `repo:my-org/*` allows any workflow in any repository in the organisation to assume this role — a common misconfiguration that effectively gives every developer broad cloud access.

To register the OIDC provider in AWS (required once per account):

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

The thumbprint may change if GitHub rotates its certificate. Track `https://token.actions.githubusercontent.com/.well-known/openid-configuration` for changes and update the registered thumbprint when it does.

### GitHub Actions OIDC with GCP

GCP's Workload Identity Federation requires creating a pool (a logical grouping of external identities), a provider within it (pointing to the GitHub OIDC issuer), and a service-account binding.

```bash
# Create the Workload Identity Pool
gcloud iam workload-identity-pools create "github-actions-pool" \
  --project="my-project" \
  --location="global" \
  --display-name="GitHub Actions Pool"

# Create the OIDC provider inside the pool
gcloud iam workload-identity-pools providers create-oidc "github-actions-provider" \
  --project="my-project" \
  --location="global" \
  --workload-identity-pool="github-actions-pool" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref,attribute.environment=assertion.environment" \
  --attribute-condition="attribute.repository=='my-org/my-app' && attribute.environment=='production'"

# Allow the specific identity to impersonate the service account
gcloud iam service-accounts add-iam-policy-binding \
  ci-deployer@my-project.iam.gserviceaccount.com \
  --project="my-project" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions-pool/subject/repo:my-org/my-app:environment:production"
```

The `--attribute-condition` is evaluated server-side on every token. Tokens from the wrong repository or a branch that is not the `production` environment are rejected before IAM evaluation. The corresponding workflow:

```yaml
- name: Authenticate to GCP via OIDC
  uses: google-github-actions/auth@v2
  with:
    project_id: my-project
    workload_identity_provider: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions-pool/providers/github-actions-provider
    service_account: ci-deployer@my-project.iam.gserviceaccount.com

- name: Deploy to Cloud Run
  uses: google-github-actions/deploy-cloudrun@v2
  with:
    service: my-service
    region: us-central1
    image: gcr.io/my-project/my-app:${{ github.sha }}
```

No GCP key JSON is stored anywhere. The `google-github-actions/auth` action requests the OIDC token internally and exchanges it with the Workload Identity Federation endpoint.

### GitHub Actions OIDC with Azure

Azure uses Workload Identity Federation on managed identities. The setup involves creating a user-assigned managed identity, adding federated credentials to it, and granting it the Azure RBAC roles the workflow needs.

```bash
# Create the managed identity
az identity create \
  --name github-actions-deploy \
  --resource-group my-rg \
  --location eastus

# Add a federated credential scoped to a specific GitHub environment
az identity federated-credential create \
  --name github-production \
  --identity-name github-actions-deploy \
  --resource-group my-rg \
  --issuer https://token.actions.githubusercontent.com \
  --subject "repo:my-org/my-app:environment:production" \
  --audience api://AzureADTokenExchange

# Grant the identity access to the Azure resources it needs
az role assignment create \
  --role "Contributor" \
  --assignee-object-id $(az identity show --name github-actions-deploy --resource-group my-rg --query principalId -o tsv) \
  --scope /subscriptions/SUBSCRIPTION_ID/resourceGroups/my-rg
```

The `--subject` is an exact string match in Azure; wildcards are not supported, which means each distinct combination of repository, branch, or environment requires its own federated credential entry. This is operationally heavier but eliminates wildcard misconfiguration. The corresponding workflow:

```yaml
- name: Log in to Azure via OIDC
  uses: azure/login@v2
  with:
    client-id: ${{ vars.AZURE_CLIENT_ID }}
    tenant-id: ${{ vars.AZURE_TENANT_ID }}
    subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
```

`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_ID` are non-secret configuration values — they identify *which* identity to authenticate as, not a credential that authenticates. They can be stored as repository variables (not secrets), making them visible in the repository settings without the secrecy overhead. The login action handles the OIDC token fetch and the Azure token exchange internally.

### GitLab CI OIDC with AWS

GitLab CI's built-in OIDC support uses the `CI_JOB_JWT_V2` variable (GitLab 14.9+) or the more recent `id_tokens` block (GitLab 16.0+). The `id_tokens` approach is preferred because it allows specifying a custom `aud` claim and is not deprecated:

```yaml
# .gitlab-ci.yml
deploy:
  stage: deploy
  image: amazon/aws-cli:latest
  id_tokens:
    AWS_OIDC_TOKEN:
      aud: sts.amazonaws.com
  script:
    - >
      export $(printf "AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s"
      $(aws sts assume-role-with-web-identity
      --role-arn arn:aws:iam::123456789012:role/GitLabCIDeployRole
      --role-session-name gitlab-deploy-${CI_JOB_ID}
      --web-identity-token ${AWS_OIDC_TOKEN}
      --duration-seconds 3600
      --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]"
      --output text))
    - aws s3 sync dist/ s3://my-app-production/
  environment: production
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
```

The GitLab OIDC `sub` claim format is `project_path:my-org/my-app:ref_type:branch:ref:main`. The corresponding trust policy condition:

```json
{
  "StringEquals": {
    "gitlab.com:aud": "sts.amazonaws.com",
    "gitlab.com:sub": "project_path:my-org/my-app:ref_type:branch:ref:main"
  }
}
```

Register the GitLab OIDC provider in AWS:

```bash
aws iam create-open-id-connect-provider \
  --url https://gitlab.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 1f90a47a7e01d9a4e8d9f5c4b3c9d7e1a2b4f6e8
```

For self-hosted GitLab instances, substitute the instance URL for `https://gitlab.com`. Each GitLab instance has its own JWKS endpoint and thumbprint.

### GitLab CI OIDC with GCP

The pattern mirrors the GitHub Actions setup, with different claim names:

```yaml
deploy:
  stage: deploy
  id_tokens:
    GCP_OIDC_TOKEN:
      aud: https://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/gitlab-pool/providers/gitlab-provider
  script:
    - echo "${GCP_OIDC_TOKEN}" > /tmp/oidc_token.txt
    - gcloud auth login --cred-file=/tmp/oidc_token.txt
    - gcloud run deploy my-service --image gcr.io/my-project/my-app:${CI_COMMIT_SHA} --region us-central1
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
```

The Workload Identity Pool attribute condition for GitLab:

```bash
gcloud iam workload-identity-pools providers create-oidc "gitlab-provider" \
  --workload-identity-pool="gitlab-pool" \
  --issuer-uri="https://gitlab.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.project_path=assertion.project_path,attribute.ref=assertion.ref" \
  --attribute-condition="attribute.project_path=='my-org/my-app' && attribute.ref=='main'"
```

### Scoping Trust Policies to Prevent Fork and Branch Escalation

The single most important hardening step after enabling OIDC is ensuring that the trust policy does not allow fork workflows or non-production branches to assume production roles. The `sub` claim structure for GitHub Actions provides fine-grained control:

| Sub value | What can assume the role |
|---|---|
| `repo:org/repo:ref:refs/heads/main` | Only pushes to `main` |
| `repo:org/repo:environment:production` | Only workflows running in the `production` environment |
| `repo:org/repo:ref:refs/tags/v*` | Tag-triggered workflows only (use `StringLike`) |
| `repo:org/repo:job_workflow_ref:org/repo/.github/workflows/deploy.yml@refs/heads/main` | A specific workflow file at a specific ref — the strictest form |
| `repo:org/repo:pull_request` | PR-triggered workflows — **almost always wrong to allow for cloud access** |

GitHub Actions environments add a second enforcement layer: configure the `production` environment in repository settings with required reviewers and a branch filter that restricts deployments to pushes from `main` only. This prevents a workflow that somehow passes the trust policy check from running at all without human approval. The environment name appears in the OIDC `sub` claim only when the job explicitly declares `environment: production`, which must match the trust policy condition.

For GitLab, use the `environment` claim (available in the OIDC token when the job is assigned a GitLab environment) and project-level protected environments to restrict who can trigger deployments. A deployment job gated by a protected environment requires a maintainer-level approval before the runner starts — before the OIDC token is requested.

### Audit Trails: Connecting Pipeline Runs to Cloud Actions

A significant operational benefit of ephemeral role-based credentials over static access keys is that CloudTrail and GCP Audit Logs record the full identity chain. Every AWS API call made with an OIDC-issued credential appears in CloudTrail with the role ARN and the role-session-name, which can be set to include the pipeline run identifier.

Using `role-session-name: github-deploy-${{ github.run_id }}` in the workflow means every S3, ECS, or IAM call in that run is tagged with the specific GitHub Actions run ID. To correlate:

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity \
  --start-time $(date -u -d "24 hours ago" +%s) \
  --output json | jq -r '
    .Events[] |
    .CloudTrailEvent | fromjson |
    {
      time: .eventTime,
      role: .requestParameters.roleArn,
      session: .requestParameters.roleSessionName,
      sub: (.additionalEventData.webIdentityToken // "N/A")
    }'
```

To alert on assumptions from unexpected sources, add a CloudWatch metric filter and alarm:

```bash
# Filter pattern targeting unexpected sub values in role assumption events
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name UnexpectedOIDCAssumption \
  --filter-pattern '{ ($.eventName = AssumeRoleWithWebIdentity) && ($.requestParameters.roleArn = "arn:aws:iam::*:role/GitHubActionsDeployRole") && ($.responseElements.assumedRoleUser.arn NOT EXISTS) }' \
  --metric-transformations metricName=UnexpectedAssumption,metricNamespace=SecurityAlerts,metricValue=1
```

On GCP, the Cloud Audit Log entry for `GenerateAccessToken` (the Workload Identity Federation call) includes the `principalSubject` field containing the full OIDC `sub` claim. This creates an unambiguous record linking a GCP API call to a specific pipeline run in a specific repository at a specific commit. Search for unexpected subjects:

```bash
gcloud logging read \
  'protoPayload.methodName="GenerateAccessToken" AND protoPayload.request.name:"workloadIdentityPools"' \
  --project my-project \
  --format json | jq '.[] | {time: .timestamp, subject: .protoPayload.authenticationInfo.principalSubject}'
```

### Handling OIDC Unavailability Gracefully

The OIDC endpoint at the CI provider is an external dependency for every workflow run. If `token.actions.githubusercontent.com` or GitLab's OIDC endpoint is unavailable, the token fetch fails and the workflow cannot obtain cloud credentials. This is a deliberate trade-off: unavailability is visible, whereas a compromised static credential may be silently abused for months.

Practical steps to handle degraded availability:

1. **Set explicit timeout on the credential step.** The `aws-actions/configure-aws-credentials` action will hang if the OIDC endpoint is slow. Add a step-level timeout:

   ```yaml
   - name: Configure AWS credentials via OIDC
     uses: aws-actions/configure-aws-credentials@v4
     timeout-minutes: 2
     with:
       role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeployRole
       aws-region: us-east-1
   ```

2. **Separate build from deploy jobs.** If OIDC is temporarily unavailable, the build and test jobs can still run and produce artifacts. Only the deploy job (which needs cloud credentials) fails. This avoids blocking the entire pipeline on a cloud credential issue.

3. **Do not fall back to static credentials.** A fallback that restores a long-lived credential on OIDC failure defeats the security model and creates a permanent vulnerability: an attacker who can cause OIDC to fail (by disrupting the network path or by other means) forces the pipeline into a less-secure mode. The correct response to OIDC unavailability is to fail the deploy job and retry when the service recovers.

4. **Monitor OIDC provider status.** Subscribe to the GitHub Status page (`https://www.githubstatus.com`) and the GitLab status page for incidents affecting `Actions` or `CI/CD`. For production deployments, consider a health check that pings the OIDC discovery endpoint before the deploy step attempts authentication.

## Expected Behaviour

| Signal | Long-lived stored credential | OIDC ephemeral credential |
|---|---|---|
| Credential captured in build log | Permanent cloud access for attacker | Access expires within the remaining token lifetime (typically under 60 minutes) |
| Malicious dependency reads environment | `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` exfiltrated and reusable indefinitely | Temporary credential exfiltrated; expires within session window |
| Fork PR workflow attempts cloud access | Depends on repository secret isolation settings; organisation secrets accessible to forks in some configurations | Trust policy explicitly excludes `pull_request` sub claim; cloud provider rejects the token |
| Non-main branch assumes production role | Credential does not check branch; any pipeline job that can read the secret has access | Trust policy pins to `ref:refs/heads/main` or `environment:production`; side-branch workflows receive a 403 from STS |
| Credential rotation | Manual; typically not done; creates risk window during rotation | Not required; every token is fresh; token is never stored |
| Audit trail for cloud API calls | CloudTrail records the static IAM user; no pipeline run context | CloudTrail records role assumption with session name encoding the run ID; full traceability to commit SHA |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| No stored cloud credential | Eliminates the primary exfiltration surface for cloud access keys | All cloud access now depends on OIDC endpoint availability at runtime | Monitor CI provider status; design pipelines to fail-closed (not fall back to static keys) on OIDC errors |
| Trust policy as security boundary | Cloud-side enforcement of which pipelines can access which resources | Trust policy misconfigurations (wildcards in `sub`, missing `aud` check) create broad access; errors are silent until abused | Manage trust policies via Terraform or Pulumi with policy-as-code review; use IAM Access Analyzer to flag overly permissive conditions |
| One-hour token lifetime | Captured credential has bounded usefulness | Slow builds that take longer than one hour may need to refresh credentials mid-pipeline | Break long pipelines into stages; use `aws-actions/configure-aws-credentials` with `--duration-seconds` increased to the maximum the role allows; ensure deploy steps run immediately after credential issuance |
| Per-environment roles | Each environment (dev, staging, prod) gets a distinct role with appropriate permissions | More IAM roles to manage; cross-account deployments require additional role chaining configuration | Standardise on a Terraform module for OIDC roles; generate roles programmatically per environment from a shared template |
| Audit trail depth | Every cloud API call is traceable to a specific pipeline run and commit | Requires structured log analysis to extract the pipeline run ID from session names | Use consistent session-name conventions; feed CloudTrail to your SIEM; create dashboards on role assumption frequency per repository |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Trust policy uses `StringLike` with org wildcard | Any workflow in the organisation can assume the role; a compromised or malicious repository lateral-moves into production | CloudTrail shows role assumptions from unexpected repository names in the `sub` claim | Replace `StringLike` with `StringEquals`; pin to repository and environment or ref; redeploy via Terraform; audit CloudTrail history for unexpected assumptions |
| Missing `aud` condition in trust policy | A token minted for a different cloud provider's audience can be replayed against this role | STS accepts tokens with audience values other than `sts.amazonaws.com` | Always include `StringEquals` on the `aud` claim; test by generating a token with a mismatched audience and confirming STS rejects it |
| `pull_request` sub allowed in trust policy | A contributor opening a PR from a fork can mint a short-lived production credential | CloudTrail shows assumptions from `sub` values containing `pull_request` | Remove `pull_request` from the trust policy immediately; audit every assumption from PR sub values; rotate any resources the credential could have accessed |
| OIDC provider thumbprint outdated after certificate rotation | Workflows fail with `WebIdentityCertificateRevoked` or a signature verification error | CloudTrail shows failed `AssumeRoleWithWebIdentity` calls; workflow logs show OIDC token fetch or STS call failures | Fetch the new thumbprint from the issuer's JWKS endpoint; update the OIDC provider in IAM; for GitHub Actions, consult the published thumbprint in the GitHub documentation |
| Token lifetime too short for slow builds | Deploy step runs after the one-hour mark; AWS STS returns `ExpiredTokenException` | Workflow fails at the first cloud API call after the credential step, not during credential issuance | Move the `configure-aws-credentials` step to immediately precede the cloud API calls; split build and deploy into separate jobs so deployment always starts with a fresh credential |
| Reusable workflow ref unpinned | The reusable workflow referenced in the trust policy's `job_workflow_ref` condition is modified on a non-protected branch | Audit log shows assumption from an unexpected `job_workflow_ref` commit SHA | Pin reusable workflow references to a commit SHA; require CODEOWNERS approval for changes to any workflow used in trust policy conditions |

## Related Articles

- [OIDC Federation Hardening: Locking Down CI-to-Cloud Trust Policies](/articles/cicd/oidc-federation-hardening/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [GitLab CI Security Hardening](/articles/cicd/gitlab-ci-security/)
- [SLSA Build Provenance: Source-to-Registry Integrity](/articles/cicd/slsa-provenance/)
