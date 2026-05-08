---
title: "Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation"
description: "Static credentials in CI/CD pipelines are the leading cause of secret sprawl. Teams store long-lived API keys, database passwords, and cloud provider."
slug: "cicd-secret-management"
date: 2026-04-21
lastmod: 2026-04-21
category: "cicd"
tags: ["secrets", "vault", "sops", "oidc", "cicd", "supply-chain"]
personas: ["devops-engineer", "platform-engineer"]
article_number: 52
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "vault-oidc-pipeline-setup"
published: true
layout: article.njk
permalink: "/articles/cicd/cicd-secret-management/index.html"
---

# Secret Management in CI/CD Pipelines: Vault, [SOPS](https://github.com/getsops/sops), and OIDC Federation

## Problem

Static credentials in CI/CD pipelines are the leading cause of secret sprawl. Teams store long-lived API keys, database passwords, and cloud provider credentials as pipeline environment variables. These secrets leak through build logs, persist on runner filesystems between jobs, and spread across dozens of repositories with no central inventory. When a secret is compromised, teams cannot answer a basic question: which pipelines use this credential?

GitHub Actions stores secrets as repository or organization variables. GitLab CI uses CI/CD variables. Both mechanisms share the same weakness: the secrets are long-lived, broadly scoped, and difficult to rotate. A single compromised runner can exfiltrate every secret available to every workflow in the repository. A careless `echo` or a dependency that writes environment variables to stdout puts credentials in build logs that persist for 90 days.

The fix involves three complementary strategies: short-lived credentials via OIDC federation (no static secrets at all), encrypted secret files in Git via SOPS (secrets travel with the code but remain encrypted), and dynamic secrets via Vault (credentials generated on demand and automatically revoked).

## Threat Model

- **Adversary:** Attacker who compromises a CI runner, a malicious dependency that reads environment variables, or an insider who can view pipeline logs.
- **Objective:** Exfiltrate cloud credentials, database passwords, or API keys to gain persistent access outside the pipeline.
- **Blast radius:** With static credentials, one compromised pipeline exposes every secret in the repository. Secrets often have broad IAM permissions. A single leaked AWS access key can lead to full account compromise.

## Configuration

### GitHub Actions OIDC with AWS (No Static Credentials)

Replace static AWS access keys with short-lived tokens issued through OIDC federation. GitHub Actions presents a JWT token to AWS STS, which exchanges it for temporary credentials scoped to a specific role.

```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write  # Required for OIDC token request

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1

      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502  # v4.0.2
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
          aws-region: eu-west-1
          # No access key or secret key. The action exchanges
          # the GitHub OIDC token for temporary STS credentials.

      - name: Deploy
        run: aws ecs update-service --cluster prod --service api --force-new-deployment
```

Configure the AWS IAM trust policy to restrict which repositories and branches can assume the role:

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
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### GitLab CI OIDC with GCP

```yaml
# .gitlab-ci.yml
deploy:
  stage: deploy
  image: google/cloud-sdk:slim
  id_tokens:
    GITLAB_OIDC_TOKEN:
      aud: https://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/gitlab-pool/providers/gitlab-provider
  script:
    - echo "$GITLAB_OIDC_TOKEN" > /tmp/oidc_token.json
    - gcloud iam workload-identity-pools create-cred-config
        projects/123456789/locations/global/workloadIdentityPools/gitlab-pool/providers/gitlab-provider
        --service-account=deploy@project-id.iam.gserviceaccount.com
        --output-file=/tmp/cred_config.json
        --credential-source-file=/tmp/oidc_token.json
    - gcloud auth login --cred-file=/tmp/cred_config.json
    - gcloud run deploy api --image=gcr.io/project-id/api:$CI_COMMIT_SHA
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### SOPS for Encrypted Secrets in Git

SOPS encrypts specific values in YAML/JSON files while leaving keys in plaintext. This lets you store secrets alongside application configuration in Git, with decryption happening only in the pipeline.

```yaml
# .sops.yaml - SOPS configuration (committed to the repository)
creation_rules:
  - path_regex: secrets/production/.*\.yaml$
    kms: arn:aws:kms:eu-west-1:123456789012:key/abcd-1234-efgh
    # Alternative: use age for local development
    # age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - path_regex: secrets/staging/.*\.yaml$
    kms: arn:aws:kms:eu-west-1:123456789012:key/staging-key-5678
```

```yaml
# secrets/production/api.yaml (encrypted with SOPS, safe to commit)
database_url: ENC[AES256_GCM,data:abc123...,iv:...,tag:...,type:str]
api_key: ENC[AES256_GCM,data:def456...,iv:...,tag:...,type:str]
sops:
    kms:
        - arn: arn:aws:kms:eu-west-1:123456789012:key/abcd-1234-efgh
          created_at: "2026-01-15T10:00:00Z"
          enc: AQICAHh...
    lastmodified: "2026-01-15T10:30:00Z"
    version: 3.9.0
```

Decrypt in CI with OIDC credentials (no static KMS key needed):

```yaml
# .github/workflows/deploy.yml (relevant steps)
- name: Configure AWS credentials via OIDC
  uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
  with:
    role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
    aws-region: eu-west-1

- name: Decrypt secrets
  run: |
    sops --decrypt secrets/production/api.yaml > /tmp/decrypted-secrets.yaml
    # Load into environment without echoing
    export DATABASE_URL=$(yq '.database_url' /tmp/decrypted-secrets.yaml)
    # Use the secret, then clean up
    ./deploy.sh
    rm -f /tmp/decrypted-secrets.yaml
```

### Vault Dynamic Secrets in CI

For databases and other systems that support dynamic credential generation, Vault can issue short-lived credentials per pipeline run:

```yaml
# .github/workflows/migrate.yml
- name: Authenticate to Vault via OIDC
  run: |
    export VAULT_ADDR=https://vault.internal.company.com:8200
    VAULT_TOKEN=$(vault write -field=token auth/jwt/login \
      role=github-actions-migrate \
      jwt=$ACTIONS_ID_TOKEN_REQUEST_TOKEN)
    echo "VAULT_TOKEN=$VAULT_TOKEN" >> "$GITHUB_ENV"

- name: Get dynamic database credentials
  run: |
    # Vault generates a new PostgreSQL user with a 1-hour TTL
    CREDS=$(vault read -format=json database/creds/migrate-role)
    export PGUSER=$(echo "$CREDS" | jq -r '.data.username')
    export PGPASSWORD=$(echo "$CREDS" | jq -r '.data.password')
    # Run migration with short-lived credentials
    ./run-migrations.sh
    # Credentials auto-expire after 1 hour. No cleanup needed.
```

Vault role configuration restricting which pipelines can request credentials:

```hcl
# vault-policy.hcl
path "database/creds/migrate-role" {
  capabilities = ["read"]
}

# Bind to GitHub Actions OIDC claims
resource "vault_jwt_auth_backend_role" "github_actions_migrate" {
  backend        = vault_jwt_auth_backend.github.path
  role_name      = "github-actions-migrate"
  token_policies = ["github-actions-migrate"]
  token_ttl      = 3600  # 1 hour

  bound_claims = {
    repository = "your-org/your-repo"
    ref        = "refs/heads/main"
  }

  user_claim = "repository"
  role_type  = "jwt"
}
```

### Detecting Secret Leaks in Build Logs

```yaml
# Add gitleaks to every pipeline
- name: Scan for leaked secrets
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    args: detect --source=. --verbose
```

```bash
# trufflehog as a pre-commit hook or CI step
trufflehog git file://. --since-commit HEAD~1 --only-verified --fail
```

## Expected Behaviour

- No static cloud credentials stored in CI/CD variables. All cloud access uses OIDC federation with short-lived tokens.
- SOPS-encrypted files are committed to the repository. Decryption requires OIDC-authenticated access to KMS.
- Vault-issued credentials have a maximum TTL of 1 hour and are scoped to the specific pipeline task.
- IAM trust policies restrict OIDC token exchange to specific repositories and branches.
- Every pipeline run includes a secret leak scan. Builds fail if verified secrets are detected.
- Secret rotation requires no pipeline changes since credentials are generated dynamically.

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| OIDC federation | Eliminates static credentials entirely | IAM trust policy misconfiguration could allow unauthorized repos to assume the role | Use exact match on `sub` claim (not wildcard). Review trust policies quarterly. |
| SOPS encrypted files | Secrets versioned alongside code; diffs show which secrets changed | KMS key compromise decrypts all SOPS files | Separate KMS keys per environment. Rotate KMS keys annually. |
| Vault dynamic secrets | Credentials auto-expire; no rotation needed | Vault unavailability blocks all pipelines | Run Vault in HA mode. Cache last-known-good credentials for read-only operations. |
| gitleaks/trufflehog in CI | Catches leaked secrets before they reach production logs | False positives slow down builds | Use `--only-verified` flag. Maintain an allowlist for known false positives. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| OIDC provider misconfigured | `AssumeRoleWithWebIdentity` returns AccessDenied | Pipeline fails at credential exchange step with clear error | Verify OIDC provider thumbprint, audience, and subject claim format. |
| KMS key inaccessible | SOPS decryption fails with `KMS access denied` | Pipeline fails at decrypt step | Verify the pipeline's OIDC role has `kms:Decrypt` permission for the key. |
| Vault seal or unavailability | `vault write auth/jwt/login` times out | Pipeline fails at Vault auth step; Vault health check alerts | Unseal Vault (if sealed) or failover to standby node. |
| Secret leaked in logs | Credential visible in build output | gitleaks/trufflehog scan flags the leak; monitoring alerts on credential use from unexpected IP | Rotate the leaked credential immediately. Add masking for the specific output pattern. |
| OIDC trust policy too broad | Any branch (not just main) can assume the production deploy role | Audit log shows role assumption from unexpected branch | Tighten `sub` claim condition to exact branch match. |

## When to Consider a Managed Alternative

Self-managed Vault requires high-availability configuration, unsealing procedures, audit logging, and ongoing maintenance. For teams running fewer than 50 pipelines, the operational overhead may exceed the benefit. HCP [Vault](https://www.vaultproject.io) provides managed Vault with built-in HA, auto-unseal, and audit logging. [Infisical](https://infisical.com) and [Doppler](https://www.doppler.com) offer secret management purpose-built for CI/CD with native integrations for GitHub Actions and GitLab CI. For teams already invested in a cloud provider, AWS Secrets Manager and GCP Secret Manager provide simpler alternatives to Vault, though without Vault's multi-cloud and dynamic secret capabilities.

**Premium content pack:** [Terraform](https://www.terraform.io) module for Vault + OIDC pipeline setup. Includes IAM trust policies, Vault JWT auth configuration, dynamic database secret backends, and SOPS integration for GitHub Actions and GitLab CI.


## Related Articles

- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
- [Securing CI/CD Runners: Isolation, Credential Scoping, and Ephemeral Environments](/articles/cicd/securing-cicd-runners/)
- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
