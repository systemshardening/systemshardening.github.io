---
title: "Secret Sprawl Detection and Remediation: Finding and Eliminating Credentials Across Your Infrastructure"
description: "Secrets accumulate in git history, CI environment variables, container images, configuration files, and employee laptops. Secret sprawl creates persistent credential exposure that static scanning misses. This guide covers systematic secret discovery across all attack surfaces, prioritised remediation, and architectural changes to eliminate sprawl at the source."
slug: secret-sprawl-detection
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - secret-sprawl
  - credential-detection
  - secrets-management
  - gitleaks
  - vault
personas:
  - security-engineer
  - platform-engineer
article_number: 622
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/secret-sprawl-detection/
---

# Secret Sprawl Detection and Remediation: Finding and Eliminating Credentials Across Your Infrastructure

## Problem

Credentials don't stay where they're put. A database password starts in an `.env` file, gets hardcoded in a CI script when the env var isn't threading through correctly, ends up in a Docker image layer during a debugging session, gets committed to a feature branch that was force-pushed to main three years ago, and is still sitting in the Terraform state file that nobody touched because it works. Every one of those locations is a live exposure point — and none of them will appear in Vault.

Secret sprawl is the condition where credentials exist across many unmanaged locations simultaneously. The dangerous property is persistence: unlike a breach where an attacker exfiltrates a credential and uses it, sprawl means credentials are continuously accessible to anyone who reaches any of those locations. Git history is permanent by design. Docker image layers are immutable by design. Terraform state is shared by design. These properties that make infrastructure work reliably are the same properties that make sprawl durable.

The 2025 GitGuardian "State of Secrets Sprawl" report found over 35 million secrets exposed in public GitHub repositories in a single year. The private-repository figure, estimated from enterprise tooling telemetry, is substantially higher. Most organisations that run a first-time sweep of their git history and CI/CD environment surface find hundreds of credentials they didn't know existed.

The specific failure modes from unaddressed sprawl:

- **Long tail exposure.** A credential committed to a private repo four years ago was valid then and is still valid now. Attackers scrape repositories continuously; a repo that was briefly public is permanently compromised.
- **Invisible blast radius.** When an incident requires credential rotation, there's no inventory of where the credential exists. Rotating Vault doesn't rotate the copy in the Jenkins credential store, the Helm chart, and the developer's `.bashrc`.
- **Compliance gaps.** SOC 2 CC6.1, PCI DSS Req 3, ISO 27001 A.9 all require that access credentials be protected at rest. A credential in an unencrypted ConfigMap or a Terraform state file plaintext block is a finding regardless of whether it's been exploited.
- **Offboarding risk.** When a developer leaves, their laptop contains years of accumulated credentials from every repo they've cloned. Without an inventory, nothing can be rotated.

This article covers the attack surface map, systematic discovery across each surface, and the remediation sequence — with the architectural changes that prevent future accumulation.

**Target tools:** TruffleHog v3, gitleaks, Trivy, checkov, git-filter-repo, Sealed Secrets, External Secrets Operator, HashiCorp Vault, AWS Secrets Manager.

## Threat Model

- **Adversary 1 — External git scraper:** continuously monitors GitHub, GitLab, and Bitbucket for committed credentials using pattern matching and entropy detection.
- **Adversary 2 — Compromised developer endpoint:** malware or a malicious insider exfiltrates local clones containing historical credentials and `.env` files.
- **Adversary 3 — Container registry access:** an attacker with pull access to a registry extracts image layers and scans them for baked-in credentials.
- **Adversary 4 — Kubernetes cluster read access:** an attacker with `get secret` RBAC permissions reads base64-decoded credentials from the etcd-backed Secrets API.
- **Adversary 5 — Terraform state reader:** an attacker with access to S3/GCS backend reads state files that contain plaintext `sensitive` values for RDS passwords, IAM keys, and TLS certificates.
- **Access level:** Adversaries 1 and 3 are external. Adversaries 2, 4, and 5 require some initial access (laptop, cluster, cloud storage).
- **Objective:** Obtain valid credentials; authenticate to production systems; escalate privilege; exfiltrate data or establish persistence.
- **Blast radius:** A single exposed credential in any sprawl location gives access equivalent to however that credential was scoped — often broader than intended, because sprawled credentials are typically long-lived and were created without least-privilege.

## The Sprawl Attack Surface

Before scanning, map where secrets accumulate in your environment. Every location below is a real finding in real security reviews.

**Git repositories**
The highest-volume source. Secrets committed and immediately reverted are still in git history. Force-pushed branches are recoverable with `git fsck`. Private repos that were temporarily public are indexed by scrapers within seconds.

**CI/CD environment variables**
GitHub Actions `secrets`, GitLab CI variables, Jenkins credential stores, and CircleCI environment variables. Access control is often weaker than assumed: `ACTIONS_RUNTIME_TOKEN` can read secrets in the same workflow context; pipelines that print environment variables in debug mode write secrets to build logs; secrets set as "unmasked" in GitLab CI appear in logs.

**Container image layers**
Every `RUN` instruction in a Dockerfile creates a layer. A `RUN npm install && aws configure --profile prod` instruction bakes credentials into a layer even if a subsequent `RUN rm ~/.aws/credentials` removes the file — the credentials remain in the intermediate layer and are readable with `docker save`.

**Kubernetes Secrets and ConfigMaps**
Kubernetes Secrets are base64-encoded, not encrypted, by default. `kubectl get secret my-secret -o json | jq '.data | map_values(@base64d)'` recovers all values in plaintext. ConfigMaps have no encoding at all. Unless etcd encryption at rest is configured and External Secrets or Sealed Secrets are in use, every secret in the cluster is accessible to anyone with RBAC read access.

**Helm chart values**
`values.yaml` files committed to repositories frequently contain database connection strings, API keys, and webhook secrets. Helm chart tarballs stored in registries inherit the same issues. Helm upgrade history in-cluster (stored as Kubernetes Secrets by default) contains the full rendered values from every release.

**Terraform state files**
Terraform writes `sensitive` outputs and `sensitive` variables to state in plaintext JSON. An S3 backend without server-side encryption and bucket policy restrictions is accessible to anyone with AWS credentials in the account. The state file for an AWS RDS resource contains the master password in plaintext.

**Application configuration files**
`config.yaml`, `application.properties`, `settings.py`, `database.yml` — any format used by an application framework. These accumulate in deployment artifacts, S3 config buckets, and developer home directories.

**Employee dotfiles and local clones**
Developer laptops contain `.env` files, `~/.aws/credentials`, `~/.kube/config` with embedded tokens, and local git clones with full history. Without endpoint management, this surface is invisible to central scanning.

**Cloud instance metadata**
Applications running on EC2, GCE, or Azure VMs can reach the instance metadata service to obtain IAM role credentials. An SSRF vulnerability in a web application can expose these credentials to an external attacker — they're not "sprawled" but they're similarly invisible to static scanning.

**Team wikis and documentation**
Confluence pages, Notion documents, and internal wikis frequently contain connection strings, token examples with real values, and runbooks that were written with a live credential as an example and never updated.

## Discovery: Git History Scanning

### TruffleHog: Deep History Scanning

TruffleHog v3 uses both pattern matching and Shannon entropy to detect secrets across full git history. Run it against the complete history of every repository, not just the current branch.

```bash
# Scan full history of a local repository.
trufflehog git file://. --since-commit HEAD~1000 --only-verified

# Scan a remote repository including all branches and tags.
trufflehog git https://github.com/org/repo --include-detached

# Scan a GitHub organisation (requires GITHUB_TOKEN).
trufflehog github --org=your-org \
  --token="${GITHUB_TOKEN}" \
  --include-members \
  --only-verified \
  --json | tee trufflehog-org-$(date +%Y%m%d).json
```

The `--only-verified` flag reduces false positives by attempting to validate detected credentials against their APIs before reporting. Remove it for an exhaustive sweep — unverified detections still represent committed secrets even if they've since been rotated.

### gitleaks: Branch-Scoped and Targeted Scanning

gitleaks is faster for targeted scans and produces structured output that integrates with SIEM pipelines.

```bash
# Scan specific branch range — useful for auditing a PR before merge.
gitleaks detect \
  --log-opts="main..feature/new-auth" \
  --report-format json \
  --report-path gitleaks-pr.json

# Scan with entropy threshold tuning for high-value secrets.
gitleaks detect \
  --log-opts="--all" \
  --min-entropy 3.5 \
  --report-format sarif \
  --report-path gitleaks-full-history.sarif

# Protect mode: scan staged changes before commit (install as pre-commit hook).
gitleaks protect --staged --verbose
```

Install the pre-commit hook across all developer machines to prevent new secrets entering history. Existing sprawl requires the retrospective scan.

### Prioritisation

Not every detected secret warrants the same urgency. Sort findings by:

1. **Entropy and pattern match confidence.** TruffleHog verified detections first; high-entropy strings matching known key formats second.
2. **Recency.** A credential committed last week is more likely to still be valid than one from 2019.
3. **Reach.** A credential in a public repository or a widely-cloned internal repository has higher exposure than one in a private repo with three contributors.
4. **Scope.** An AWS root access key is more urgent than a read-only Datadog API key.

## Discovery: CI/CD Secret Audit

### GitHub Actions

```bash
# List all repository secrets (requires admin:repo scope).
gh secret list --repo org/repo

# List all organisation-level secrets and their repository visibility.
gh secret list --org your-org

# Audit Actions workflow files for direct secret references.
grep -r "env:" .github/workflows/ | grep -v "secrets\." | grep -iE "(password|key|token|secret)"

# Find workflows that print environment variables (common debug mistake).
grep -r "env\b" .github/workflows/ | grep -iE "(printenv|echo.*\$|set -x)"
```

GitHub Actions secrets are masked in logs but accessible as environment variables within the runner process. Any action with `runs-on: ubuntu-latest` and `env: MY_SECRET: ${{ secrets.MY_SECRET }}` can exfiltrate the secret. Audit third-party actions pinned by SHA, not tag.

### GitLab CI Variable Enumeration

```bash
# List CI/CD variables for a project (requires maintainer role).
curl --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  "https://gitlab.com/api/v4/projects/${PROJECT_ID}/variables" \
  | jq '.[] | {key: .key, protected: .protected, masked: .masked, environment_scope: .environment_scope}'

# Check group-level variables.
curl --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" \
  "https://gitlab.com/api/v4/groups/${GROUP_ID}/variables" \
  | jq '.[] | select(.masked == false) | {key: .key}'
```

Unmasked variables appear in job logs. Variables scoped to `*` (all environments) are accessible from every pipeline, including branches created by external contributors if the project is public.

### Jenkins Credential Store

```groovy
// Run in Jenkins Script Console to enumerate credentials.
// Access: Manage Jenkins > Script Console.
import com.cloudbees.plugins.credentials.CredentialsProvider
import jenkins.model.Jenkins

def creds = CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardCredentials.class,
    Jenkins.instance,
    null,
    null
)

creds.each { c ->
    println "ID: ${c.id} | Class: ${c.class.simpleName} | Description: ${c.description}"
}
```

Jenkins Credentials Plugin stores credentials encrypted on disk, but credentials exposed via `withCredentials` blocks are decrypted into environment variables during pipeline execution. Check pipeline logs for `set -x` trace output or explicit `echo` statements.

## Discovery: Container Image Scanning

### Trivy: Layer-Level Secret Detection

```bash
# Scan an image for secrets baked into any layer.
trivy image \
  --scanners secret \
  --secret-config trivy-secret.yaml \
  --format json \
  --output trivy-secrets.json \
  your-registry/your-image:latest

# Scan all images in a registry namespace (requires skopeo).
skopeo list-tags docker://your-registry/your-namespace | \
  jq -r '.Tags[]' | \
  xargs -P4 -I{} trivy image --scanners secret \
    --format json \
    --output "trivy-{}.json" \
    "your-registry/your-namespace:{}"
```

Configure `trivy-secret.yaml` to add custom patterns for internal credential formats (internal service tokens, private API gateway keys) that the default ruleset won't match.

```yaml
# trivy-secret.yaml
rules:
  - id: internal-service-token
    category: InternalCredential
    title: Internal service token
    severity: CRITICAL
    regex: "svc_[0-9a-f]{32}"
    keywords:
      - "svc_"
```

To manually inspect layers without running Trivy, use `docker save` to export a tar archive and examine each layer:

```bash
docker save your-image:tag | tar -xO --wildcards '*/layer.tar' | \
  tar -t | grep -iE "\.(env|pem|key|credentials)$"
```

## Discovery: Kubernetes Secrets Sprawl

```bash
# Find secrets that are not managed by External Secrets or Sealed Secrets.
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.metadata.annotations["sealedsecrets.bitnami.com/managed"] == null) |
      select(.metadata.annotations["secrets.external-secrets.io/managed"] == null) |
      {namespace: .metadata.namespace, name: .metadata.name, type: .type}'

# Detect credentials in ConfigMaps (should be zero).
kubectl get configmaps --all-namespaces -o json | \
  jq -r '.items[].data // {} | to_entries[] | .value' | \
  grep -iE "(password|passwd|secret|token|key).*=.*[^*]{8,}"

# Check etcd encryption at rest configuration.
kubectl get apiserver -o json 2>/dev/null | \
  jq '.items[].spec.encryption' || \
  kubectl get configmap -n kube-system -o json 2>/dev/null | \
  jq '.items[] | select(.metadata.name | test("encryption"))'
```

Kubernetes Secrets of type `Opaque` created by `kubectl create secret generic` are base64-encoded plaintext unless etcd encryption at rest is enabled with `aescbc` or `aesgcm` providers. Even with etcd encryption, the Kubernetes API serves the secret decrypted — etcd encryption protects against physical access to the etcd data directory, not against authorised API reads.

## Discovery: Terraform State Scanning

```bash
# Download and scan state with checkov for sensitive value exposure.
terraform state pull > current.tfstate
checkov -f current.tfstate \
  --check CKV_TF_1,CKV_TF_2 \
  --output json | jq '.results.failed_checks[]'

# Find sensitive outputs written to state in plaintext.
jq '.outputs | to_entries[] | select(.value.sensitive == false) |
    {name: .key, value: .value.value}' current.tfstate

# Search for common credential patterns in state.
jq '.. | strings' current.tfstate | \
  grep -iE "(password|secret|token|key)" | \
  grep -v "arn:aws" | head -50
```

Terraform state backend must use server-side encryption and access logging. For AWS S3 backends:

```hcl
terraform {
  backend "s3" {
    bucket         = "org-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true          # AES-256 SSE-S3 at minimum.
    kms_key_id     = "arn:aws:kms:us-east-1:123456789:key/..." # Prefer SSE-KMS.
    dynamodb_table = "terraform-state-lock"
  }
}
```

## Remediation Workflow

### Rotate First, Then Remove

**Never remove a secret from a location without rotating it first.** If you delete a credential from git history without rotating, the credential is still valid and an attacker who obtained it before you deleted it retains access indefinitely. The remediation sequence:

1. **Detect and verify.** Confirm the credential is real and potentially valid.
2. **Assess blast radius.** What does this credential access? What other systems might hold a copy?
3. **Rotate the credential.** Issue a new credential at the source (AWS IAM, GitHub, Stripe, database server). Configure both old and new credentials to work simultaneously for a transition window.
4. **Update all consuming systems.** Update CI/CD variables, Vault entries, Kubernetes Secrets, and application configuration to use the new credential.
5. **Revoke the old credential.** Only after all consumers are confirmed to be using the new credential.
6. **Remove from sprawl locations.** Rewrite git history, purge log archives, remove from wikis.
7. **Document the incident.** Log the credential ID, where it was found, when it was rotated, and what architectural change prevents recurrence.

### Git History Rewriting with git-filter-repo

`git filter-branch` is deprecated and slow. Use `git-filter-repo` for history rewriting.

```bash
pip install git-filter-repo

# Remove a specific file from all history.
git filter-repo --path path/to/file-with-secret --invert-paths

# Replace a specific credential string across all history.
# Create a replacements file first.
echo 'AKIAIOSFODNN7EXAMPLE==>REMOVED_CREDENTIAL' > replacements.txt
git filter-repo --replace-text replacements.txt

# After rewriting, force-push to all remotes.
# This requires coordination — every contributor must re-clone.
git push origin --force --all
git push origin --force --tags
```

Force-pushing rewrites history for everyone. Coordinate with the team, notify all contributors to re-clone, and check for any forks of the repository. GitHub allows contacting support to run a garbage collection sweep to purge cached objects in pull request diffs and other views.

## Architectural Changes: Preventing Future Sprawl

Remediation without architecture changes results in the same sprawl accumulating again within months.

### Central Secrets Manager as Single Source of Truth

All credentials must live in one authoritative system — Vault, AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault — and applications must pull credentials at runtime, not deploy time.

```bash
# Vault: configure AppRole authentication for an application.
vault auth enable approle
vault write auth/approle/role/payments-service \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=720h \
  token_policies="payments-service-policy"

# Application pulls at startup, not from environment or config file.
VAULT_ADDR=https://vault.internal:8200
ROLE_ID=$(cat /run/secrets/vault-role-id)
SECRET_ID=$(cat /run/secrets/vault-secret-id)

VAULT_TOKEN=$(vault write -field=token auth/approle/login \
  role_id="${ROLE_ID}" \
  secret_id="${SECRET_ID}")

DB_PASSWORD=$(VAULT_TOKEN="${VAULT_TOKEN}" vault kv get \
  -field=password secret/payments/database)
```

The critical architectural principle: **applications receive credentials, not configuration that contains credentials.** The difference is that an application binary that calls Vault at startup contains no credentials at rest. A `config.yaml` with `db_password: "..."` does.

### External Secrets Operator: Kubernetes Integration

Replace manually created Kubernetes Secrets with ExternalSecret resources that sync from a central secrets manager.

```yaml
# ExternalSecret pulls from AWS Secrets Manager into a Kubernetes Secret.
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: payments-db-credentials
  namespace: payments
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: payments-db-credentials   # Name of the resulting Kubernetes Secret.
    creationPolicy: Owner
  data:
    - secretKey: password
      remoteRef:
        key: prod/payments/database
        property: password
    - secretKey: username
      remoteRef:
        key: prod/payments/database
        property: username
```

With this pattern, `kubectl get secret payments-db-credentials -o yaml` shows a real Kubernetes Secret, but it's regenerated from the authoritative source on every refresh. The Secret in Kubernetes is a cache, not a source of truth. Removing access to the AWS Secrets Manager entry invalidates all derived Kubernetes Secrets on the next refresh cycle.

### Sealed Secrets for GitOps Workflows

Where secrets must live in git (GitOps workflows that can't reach an external secret store at sync time), Sealed Secrets encrypts secrets with a cluster-specific key.

```bash
# Encrypt a secret before committing.
kubectl create secret generic payments-api-key \
  --from-literal=api-key="sk_live_..." \
  --dry-run=client -o yaml | \
  kubeseal --controller-name=sealed-secrets \
            --controller-namespace=kube-system \
            --format yaml > sealed-payments-api-key.yaml

# The SealedSecret is safe to commit; only the target cluster can decrypt it.
git add sealed-payments-api-key.yaml
git commit -m "add sealed payments API key"
```

A SealedSecret committed to a repository is useless without the controller's private key. The private key stays in the cluster, never in git. This eliminates the pattern of encrypting secrets manually with a shared key stored in a `secrets.yaml.gpg` file where the GPG private key is also in the repository.

### CI/CD: Dynamic Credentials Over Stored Secrets

Replace long-lived CI/CD secrets with dynamic credentials generated at pipeline execution time using OIDC federation.

```yaml
# GitHub Actions: use OIDC to get short-lived AWS credentials.
# No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY stored in GitHub Secrets.
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # Required to request the OIDC token.
      contents: read
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
          aws-region: us-east-1
          # role-session-name tied to the workflow run ID for audit.
          role-session-name: deploy-${{ github.run_id }}
```

The IAM role is configured with a trust policy that accepts only GitHub Actions OIDC tokens for the specific repository and workflow. No static credential exists to be sprawled.

## Metrics and Ongoing Detection

Secret sprawl is not a one-time scan. New commits, new pipeline configurations, and new team members continuously introduce new exposure. Instrument the discovery tools in the CI/CD pipeline and ship results to a central dashboard.

Key metrics to track:
- **New secrets detected per week** in pre-commit hooks (target: zero reaching main).
- **Time to remediation** from detection to rotation and removal.
- **Coverage** — percentage of repositories, images, and namespaces with active scanning.
- **Sprawl surface reduction** — count of locations outside the secrets manager that contain credentials, trending over time.

The architectural goal is a state where the secrets manager is the only location where unencrypted credentials exist, and the scanning tools confirm that state continuously. That state is achievable — but only by treating sprawl as an ongoing operational property, not a one-time audit finding.
