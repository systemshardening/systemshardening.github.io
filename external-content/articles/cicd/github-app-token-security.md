---
title: "GitHub App Installation Token Security"
description: "Replace long-lived Personal Access Tokens with scoped, short-lived GitHub App installation tokens, and harden App private key storage, permission minimization, and token rotation."
slug: github-app-token-security
date: 2026-05-02
lastmod: 2026-05-02
category: cicd
tags: ["github", "github-app", "tokens", "pat", "supply-chain", "secret-management", "ci-cd"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 330
difficulty: intermediate
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cicd/github-app-token-security/index.html"
---

# GitHub App Installation Token Security

## Problem

Personal Access Tokens (PATs) became the default workaround for GitHub automation the moment the GitHub API launched. They are easy to generate, immediately usable in a `curl` header, and require no ceremony beyond copy-pasting a token value into a CI secret. That convenience has turned PATs into one of the most pervasive sources of long-lived credential exposure in the software supply chain.

Classic PATs carry several fundamental problems. First, they are scoped to the generating user's account, not to a specific repository or organization role. A token with `repo` scope has full read/write access to every private repository that user can see. Second, they are long-lived by design: classic PATs can be set to never expire, and even the newer expiry mechanism defaults to one year. Third, they are tied to a human identity. When an engineer who owns the automation PAT leaves the organization, their account is deprovisioned and every pipeline consuming that token silently breaks — or worse, the token is not revoked and continues working against a deprovisioned account. Fourth, there is no installation-level scoping: a single classic PAT cannot be restricted to one repository within an organization without relying on the human account's own repository access.

Fine-grained PATs, introduced in late 2022, address some of these problems. They can be scoped to specific repositories, given expiry up to one year, and require approval from the resource owner (the organization). They are a meaningful improvement over classic PATs for human-driven operations. However, they remain tied to a human account, they still expire on a timescale of months rather than hours, and they require organization-owner approval on each issuance — making them clumsy for fully automated workflows. They are a useful stepping stone, not a destination.

GitHub Apps are the correct long-term solution for machine-to-machine automation. A GitHub App is a first-class identity separate from any human account. It can be installed into an organization or individual repository with a precisely defined permission set: `contents: read`, `pull_requests: write`, `checks: write`, and so on, each declared independently. Critically, Apps issue installation tokens rather than permanent tokens. Each installation token has a maximum lifetime of one hour, after which it is automatically invalid. There is no persistent credential floating around in your environment; workflows must generate a fresh token on each run.

The installation model also enables repository-level scoping at generation time. When calling the GitHub API to generate an installation token, you can pass a `repositories` list to restrict the token to a subset of the repositories the App is installed on. This means a single App installation can serve multiple pipelines, while each pipeline's token is restricted to only the repository it operates on.

The weakness that GitHub Apps introduce is a new class of long-lived secret: the App's RSA-2048 private key. The private key is a PEM file generated once in the App settings UI and used to sign JWT assertions that the GitHub API exchanges for installation tokens. If this private key is compromised, an attacker can generate unlimited installation tokens for every repository the App is installed on, for as long as the key remains valid. The private key does not expire automatically; it must be rotated manually. The private key is therefore the new crown jewel, and protecting it correctly is the central challenge of GitHub App token security.

Common mistakes replicate the same problems PATs introduced: storing the private key as a plaintext GitHub Actions secret (`${{ secrets.APP_PRIVATE_KEY }}`), granting the App `permissions: write-all` at installation time, and installing the App against all repositories in the organization as a convenience shortcut. Each of these mistakes negates the security properties that motivated migrating from PATs in the first place.

Target systems: GitHub.com and GitHub Enterprise Server 3.9+, GitHub Actions, `actions/create-github-app-token` v1+.

## Threat Model

1. **Attacker exfiltrates a plaintext long-lived PAT from a `.env` file or CI secret store.** A misconfigured repository, a leaked workflow log, or a compromised developer laptop exposes a `repo`-scoped classic PAT. The attacker now has persistent read/write access to every private repository visible to that human account, with no time limit, until someone notices and revokes the token — which may not happen for months or ever.

2. **Former employee's PAT continues to work after offboarding.** HR completes deprovisioning and removes the employee from the SSO group, but the classic PAT they generated two years ago for an automation pipeline is not linked to the SSO session. It continues authenticating against the API. CI pipelines owned by the employee account may break, or a token held by the former employee may continue granting access to repositories they should no longer reach.

3. **Attacker steals the App private key from a CI runner's disk or environment and generates unlimited installation tokens.** A compromised GitHub Actions runner, a mislogged environment variable, or a leaked artifact exposes the raw PEM content of the App's private key. Unlike an installation token that expires in an hour, the private key allows the attacker to generate fresh tokens at will for every repository the App is installed on, for an indefinite period, without any additional access to the GitHub UI or API.

4. **Overpermissioned App installation allows attacker with a stolen token to push to protected branches across all repositories.** An App installed with `contents: write` across all organization repositories, combined with branch protection bypass permissions, means any compromised installation token — even one that expires in an hour — can be used to push directly to `main` in every repository, potentially injecting malicious code into releases before the token expires.

The blast radius comparison is stark. A compromised classic PAT gives an attacker persistent access scoped to one human account's permissions, which in many organizations is broad and indefinite. A compromised App private key gives an attacker token-generation capability scoped to the App's installed permissions and repositories, which is typically narrower but still requires active key rotation to remediate. A compromised installation token gives an attacker access scoped to one token's repository list and permissions for at most one hour. Moving from PATs to App tokens narrows the blast radius from "persistent and broad" to "bounded by expiry and installation scope," but only if the private key is stored and managed correctly.

## Configuration / Implementation

### Creating a GitHub App with minimal permissions

Navigate to **GitHub.com > Settings > Developer settings > GitHub Apps > New GitHub App** (or for an organization: **Org Settings > Developer settings > GitHub Apps**).

Key settings:

- **GitHub App name**: use a name that describes the specific automation use case, not a generic name like `ci-bot`. Example: `acme-release-token-issuer`.
- **Homepage URL**: required but not security-sensitive; use your org's internal documentation URL.
- **Webhook**: disable entirely unless the App actively needs to receive webhook events. An App used only for token issuance never needs a webhook endpoint. Uncheck "Active" under Webhook settings.
- **Permissions**: grant only what the specific workflow requires. Do not use the App settings UI to "add permissions we might need later." Common minimal sets:

  | Use case | Minimum permissions |
  |---|---|
  | Read repository contents in CI | `Contents: Read` |
  | Open or update pull requests | `Pull requests: Write` |
  | Post status checks | `Checks: Write` |
  | Publish GitHub Packages | `Packages: Write` |
  | Create releases | `Contents: Write` |

- **Where can this GitHub App be installed?**: select **Only on this account**. This prevents the App from being installed by third parties.
- Generate the private key immediately after creation. The UI downloads a `.pem` file. Do not save it to disk; pipe it directly to your secrets manager (see next section). Delete the local file afterward.

For an organization with multiple pipelines having different permission requirements, create a separate App per permission boundary rather than one App with a superset of permissions.

### Private key storage

The private key must never be stored as a plaintext GitHub Actions secret if a secrets manager is available. The preferred storage hierarchy:

**Tier 1: Retrieve via OIDC at runtime (no static secret at all)**

Configure your GitHub Actions workflow to authenticate to AWS, GCP, or HashiCorp Vault using OIDC federation, then retrieve the private key from the secrets manager at runtime. This means no long-lived credential exists in GitHub Actions settings at all.

```yaml
jobs:
  build:
    permissions:
      id-token: write   # required for OIDC
      contents: read
    steps:
      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-token-role
          aws-region: us-east-1

      - name: Retrieve App private key from Secrets Manager
        id: get-key
        run: |
          APP_PRIVATE_KEY=$(aws secretsmanager get-secret-value \
            --secret-id prod/github-app/private-key \
            --query SecretString \
            --output text)
          # Mask the key so it never appears in logs
          echo "::add-mask::$APP_PRIVATE_KEY"
          echo "app-private-key=$APP_PRIVATE_KEY" >> "$GITHUB_OUTPUT"

      - name: Generate GitHub App installation token
        id: app-token
        uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ steps.get-key.outputs.app-private-key }}
          repositories: my-target-repo
```

**Tier 2: GitHub Actions secret (acceptable for simpler setups)**

If OIDC to a secrets manager is not yet available, store the PEM content as a GitHub Actions secret at the organization or repository level. Use a dedicated secret name that makes the value's nature explicit:

```bash
# Store the PEM content as an Actions secret using the gh CLI
gh secret set APP_PRIVATE_KEY_PEM \
  --org acme-corp \
  --body "$(cat /path/to/app.private-key.pem)" \
  --visibility private
```

When using the secret directly in a workflow, mask it immediately and pass it only to the token-generation step:

```yaml
      - name: Generate GitHub App installation token
        id: app-token
        uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.APP_PRIVATE_KEY_PEM }}
          repositories: my-target-repo
```

Storing in HashiCorp Vault follows the same OIDC pattern with the Vault JWT auth method:

```bash
# Write the private key to Vault (one-time setup)
vault kv put secret/github-app/private-key \
  pem="$(cat /path/to/app.private-key.pem)"

# Retrieve in CI
APP_PRIVATE_KEY=$(vault kv get -field=pem secret/github-app/private-key)
```

### Generating installation tokens in Actions

The `actions/create-github-app-token@v1` action handles JWT signing and the GitHub API exchange to produce an installation token. Pin the action to a full commit SHA in production workflows:

```yaml
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Generate scoped installation token
        id: app-token
        uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ vars.RELEASE_APP_ID }}
          private-key: ${{ secrets.APP_PRIVATE_KEY_PEM }}
          # Restrict token to only this repository
          repositories: ${{ github.event.repository.name }}

      - name: Use token for authenticated git operations
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
        run: |
          gh release create v1.2.3 --title "Release v1.2.3" --notes "..."
```

The token returned by `steps.app-token.outputs.token` expires after one hour. For workflows that run longer than one hour (rare but possible in matrix builds or long-running deploy pipelines), generate the token as late as possible in the workflow, or restructure long operations into separate jobs that each generate a fresh token at start.

The action also supports generating a token scoped to the owner level (all repositories in the installation) by omitting the `repositories` input, but this should be avoided unless the workflow genuinely needs to operate across multiple repositories in a single step.

### Installation scoping

When installing the App in an organization, do not select "All repositories." Select "Only select repositories" and enumerate exactly the repositories the App needs access to. If the list grows over time, each addition requires a deliberate installation update — which is a useful forcing function for reviewing whether new access is necessary.

For multi-environment organizations, create separate App installations per environment boundary:

```bash
# List current App installations for your organization
gh api /orgs/acme-corp/installations \
  --jq '.installations[] | {app_slug: .app_slug, repository_selection: .repository_selection, id: .id}'

# List repositories accessible under a specific installation
gh api /app/installations/{installation_id}/repositories \
  --jq '.repositories[].full_name'
```

Use a separate App (or at minimum a separate installation with different repository scoping) for staging and production pipelines. This prevents a compromise in the staging environment from generating tokens that work against production repositories.

### Replacing PATs in existing workflows

Audit current PAT usage before migrating:

```bash
# List all secrets in an organization (names only, values are never returned)
gh secret list --org acme-corp

# Find secrets whose names suggest they are PATs
gh secret list --org acme-corp | grep -iE 'PAT|TOKEN|ACCESS_KEY|GH_TOKEN'

# List all App installations in the org to understand existing App usage
gh api /orgs/acme-corp/installations \
  --jq '.installations[] | {id: .id, app_slug: .app_slug}'

# Find workflow files that reference token secrets directly
grep -rn 'secrets\..*TOKEN\|secrets\..*PAT' .github/workflows/
```

Migration checklist:

1. Create the GitHub App with minimal permissions for the specific use case.
2. Store the private key in the secrets manager or as an Actions org secret.
3. Update workflow files to use `actions/create-github-app-token@v1`.
4. Test in a branch workflow run and confirm the generated token has access to only the intended repository.
5. Remove the old PAT secret from the organization or repository secrets store.
6. Revoke the PAT in the generating user's GitHub account settings under **Settings > Developer settings > Personal access tokens**.
7. Confirm dependent workflows are not broken by checking Actions run history.

### Fine-grained PAT as intermediate step

When GitHub App setup is not immediately feasible (for example, when organization policy requires admin approval for new App registrations), fine-grained PATs are a viable intermediate step.

Configure under **Settings > Developer settings > Fine-grained tokens**:

- Set **Resource owner** to the organization, which triggers an approval workflow from org admins.
- Under **Repository access**, select "Only select repositories" and list each repository explicitly.
- Set **Permissions** to the minimum required (e.g., `Contents: Read and write` only).
- Set the expiry to the shortest acceptable period (30 days is reasonable for a token requiring manual renewal).

Fine-grained PATs are still tied to a human account and expire on a monthly timescale rather than hourly. They are not suitable for long-term automation in environments that require continuous uptime without manual intervention. Use them as a bridge while the GitHub App registration and secrets manager integration are completed.

### Auditing App token usage

GitHub's audit log records App token issuance and usage. Query it using the `gh` CLI or the Audit Log API:

```bash
# Stream audit log events for App token creation (last 7 days)
gh api "/orgs/acme-corp/audit-log?phrase=action:oauth_application.create_access_token&per_page=100" \
  --jq '.[] | {action: .action, actor: .actor, created_at: .created_at, app: .oauth_application_name}'

# Check rate limit headers to detect token overuse
curl -si -H "Authorization: Bearer $INSTALLATION_TOKEN" \
  https://api.github.com/rate_limit \
  | grep -i 'x-ratelimit'

# List all active installations for your App
gh api /app/installations \
  --jq '.[] | {id: .id, account: .account.login, repository_selection: .repository_selection}'
```

Set up a GitHub Actions scheduled workflow to export audit log events for App token activity to your SIEM on a daily basis. Alert on: installation tokens generated outside of known CI runner IP ranges, unusually high token generation frequency, and App permission changes.

## Expected Behaviour

| Signal | PAT approach | GitHub App tokens |
|---|---|---|
| Token lifetime | Up to 1 year (classic) or up to 1 year (fine-grained); never-expiring classic PATs still common | Maximum 1 hour per installation token; automatically invalid after expiry |
| Scope after employee departure | Token continues working until manually revoked; deprovisioning the account may break automation that depended on the account | App identity is independent of any human account; employee departure has no effect on App token issuance |
| Per-repository restriction | Classic PATs: none below the account visibility level; fine-grained PATs: configurable but still tied to a user | Configurable at installation time (repo selection) and at token generation time (`repositories` input); enforceable at both layers |
| Secret rotation surface | Rotating requires generating a new PAT, distributing it to all consumers, and revoking the old one; no central rotation point | Rotating the private key requires updating one secret in the secrets manager; all subsequent token generation picks up the new key automatically |
| Audit trail | Actions attributed to the human user account; may be confused with human-initiated actions | Actions attributed to the App bot account (`app-name[bot]`); cleanly distinguishable in audit logs and commit history |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| App private key is long-lived | Enables offline JWT signing without network calls to GitHub | Private key becomes the new crown jewel; compromise allows unlimited token generation until key is rotated | Store in a dedicated secrets manager (Vault, AWS Secrets Manager) with access logging; rotate quarterly or on suspected compromise; restrict access to the secret to only the CI role that needs it |
| 1-hour token expiry | Dramatically limits the window of usefulness for a stolen token | Workflows longer than 1 hour must re-generate tokens mid-run or restructure into multiple jobs | Design workflows to generate tokens as late as possible; split long workflows into jobs that each generate a fresh token at start |
| App setup complexity vs PAT simplicity | Enforces deliberate permission declaration and separation of machine vs human identity | Initial setup requires App registration, private key handling, and secrets manager integration; higher operational overhead than `gh auth token` | Document the setup as a one-time platform template; use a shared GitHub App per team rather than per-pipeline to amortize the overhead |
| Rate limits per App installation | Installation-level rate limits (5,000 requests/hour for standard Apps) are separate from user rate limits | High-frequency pipelines hitting the same installation token may exhaust the rate limit | Scope tokens to individual repositories (which share the installation limit but allows monitoring); consider multiple App installations for very high-throughput organizations |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Private key rotated in App settings but old secret not updated in CI | Workflow step using `actions/create-github-app-token@v1` fails with HTTP 401 Unauthorized; error message references JWT validation failure | Alert on `401` responses in workflow logs; audit log shows failed token issuance attempts attributed to the App | Update the secret in the secrets manager or Actions secret store with the new PEM content; re-run the failed workflow |
| App suspended by an organization admin | All workflows consuming tokens from that App fail immediately at the token generation step with HTTP 403; error message: "App is suspended" | Monitor App status in **Org Settings > GitHub Apps > Installed GitHub Apps**; alert on bulk workflow failures across multiple repositories | Investigate the reason for suspension (security incident, policy violation); unsuspend via **Org Settings > GitHub Apps** if suspension was in error; coordinate with the org admin |
| Installation token expires mid-workflow (long-running job) | A late API call in the workflow returns HTTP 401 or `git` authentication failure after the 1-hour mark | Token expiry time is visible in the API response from token generation (`expires_at` field); log this value and compare to expected workflow duration | Restructure long-running jobs to generate tokens at the start of each job rather than once at workflow start; for sequential jobs, pass the token only within the job that generates it |
| App not installed on the target repository | `actions/create-github-app-token@v1` fails with HTTP 404 or "No installation found for the repository" | Check App installation repository list in **Org Settings > GitHub Apps > [App name] > Repository access**; `gh api /app/installations/{id}/repositories` | Add the repository to the App's installation scope; if using "Only select repositories," explicitly add the missing repository through the App settings UI |

## Related Articles

- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [OIDC Federation Hardening](/articles/cicd/oidc-federation-hardening/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [GitHub Advanced Security](/articles/cicd/github-advanced-security/)
- [API Key Lifecycle Management](/articles/cross-cutting/api-key-lifecycle/)
