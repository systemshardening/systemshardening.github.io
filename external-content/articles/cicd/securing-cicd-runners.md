---
title: "Securing CI/CD Runners: Isolation, Credential Scoping, and Ephemeral Environments"
description: "CI/CD runners are the most privileged, least monitored components in most infrastructure."
slug: "securing-cicd-runners"
date: 2026-03-14
lastmod: 2026-03-14
category: "cicd"
tags: ["cicd", "runners", "github-actions", "oidc", "ephemeral", "supply-chain"]
personas: ["devops-engineer", "security-engineer"]
article_number: 49
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "cicd-hardening-templates"
published: true
layout: article.njk
permalink: "/articles/cicd/securing-cicd-runners/index.html"
---

# Securing CI/CD Runners: Isolation, Credential Scoping, and Ephemeral Environments

## Problem

CI/CD runners are the most privileged, least monitored components in most infrastructure. A self-hosted runner has persistent access to deployment credentials, can reach production networks, and executes arbitrary code from every pull request. A compromised runner gives an attacker everything: secrets, deployment keys, container registry access, and a direct path to production.

The specific gaps:

- **Persistent runners** accumulate state between jobs, a malicious job can leave a backdoor that executes during the next job on the same runner.
- **Over-scoped credentials:** runners have access to all secrets in the repository/project, not just the ones the current job needs.
- **No network isolation:** runners can reach production infrastructure, internal services, and the internet.
- **No monitoring:** runner activity is not audited. A compromised runner operates undetected until someone notices the damage.

**Target systems:** GitHub Actions self-hosted runners, GitLab CI runners. Principles apply to Jenkins, Drone, Buildkite, and Woodpecker.

## Threat Model

- **Adversary:** Attacker submitting a malicious pull request (open-source projects), compromised developer account (enterprise), or compromised third-party CI action/step.
- **Access level:** Code execution on the CI runner with access to all pipeline secrets and network connectivity.
- **Objective:** Extract secrets (cloud credentials, signing keys, registry tokens). Inject malicious code into build artifacts. Pivot to production infrastructure via deployment credentials.
- **Blast radius:** All secrets accessible to the runner. All infrastructure the runner can deploy to. All container images the runner can push to.

## Configuration

### Ephemeral Runners

The most impactful change: every job runs on a fresh runner instance that is destroyed after the job completes. No state persists between jobs.

**GitHub Actions: Ephemeral self-hosted runners**

```bash
# Register a self-hosted runner with --ephemeral flag.
# After one job, the runner deregisters and the VM/container is destroyed.
./config.sh --url https://github.com/your-org/your-repo \
  --token YOUR_REGISTRATION_TOKEN \
  --ephemeral \
  --name "ephemeral-runner-$(date +%s)"

./run.sh
# Runner accepts one job, executes it, then exits.
# The orchestrator (systemd, K8s Job, or cloud autoscaler) creates a new instance.
```

**GitHub Actions: Autoscaling ephemeral runners with Actions Runner Controller (ARC):**

```yaml
# runner-deployment.yaml - ARC on Kubernetes
apiVersion: actions.summerwind.dev/v1alpha1
kind: RunnerDeployment
metadata:
  name: ephemeral-runners
spec:
  replicas: 3
  template:
    spec:
      ephemeral: true
      repository: your-org/your-repo
      labels:
        - self-hosted
        - linux
        - ephemeral
      resources:
        requests:
          cpu: "1"
          memory: "2Gi"
        limits:
          cpu: "2"
          memory: "4Gi"
      # Security context for the runner pod
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        readOnlyRootFilesystem: false  # Runner needs write access
        seccompProfile:
          type: RuntimeDefault
```

**GitLab CI: [Docker](https://www.docker.com) executor with ephemeral containers**

```toml
# /etc/gitlab-runner/config.toml
[[runners]]
  name = "ephemeral-docker"
  executor = "docker"
  [runners.docker]
    image = "ubuntu:24.04"
    privileged = false
    # Each job gets a fresh container - destroyed after completion
    pull_policy = ["always"]
    # Disable Docker socket access (prevents container escape)
    volumes = []
    # Network isolation
    network_mode = "bridge"
    # Resource limits
    cpus = "2"
    memory = "4g"
```

### OIDC Federation (No Static Credentials)

Replace static AWS/GCP credentials with OIDC federation. The runner receives a short-lived token that expires in minutes.

**GitHub Actions → AWS via OIDC:**

```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

permissions:
  id-token: write   # Required for OIDC
  contents: read

jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy
          aws-region: eu-west-1
          # No static credentials stored anywhere.
          # The role trust policy restricts to this specific repo and branch.

      - name: Deploy
        run: |
          aws ecs update-service --cluster prod --service app --force-new-deployment
```

**AWS IAM trust policy for the OIDC role:**

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

The `Condition` block is critical: it restricts the role to a specific repository AND branch. A different repository or a pull request branch cannot assume this role.

### Runner Network Isolation

Runners should only be able to reach: the container registry, the cloud provider APIs, and the artifact storage. Nothing else.

```yaml
# runner-network-policy.yaml (for ARC runners on Kubernetes)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: runner-egress-restrict
  namespace: actions-runner-system
spec:
  podSelector:
    matchLabels:
      app: runner
  policyTypes:
    - Egress
  egress:
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Allow HTTPS to GitHub API
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
    # Block everything else (no SSH to production, no internal services)
```

### Runner Compromise Detection

```yaml
# Prometheus alert rules for CI/CD runner monitoring
groups:
  - name: cicd-runner-security
    rules:
      - alert: UnexpectedRunnerRegistration
        expr: increase(github_runner_registration_total[1h]) > 5
        labels:
          severity: warning
        annotations:
          summary: "Unusual number of runner registrations in the past hour"
          runbook: "Check for unauthorized runner registration. Verify all runners are expected."

      - alert: LongRunningJob
        expr: github_job_duration_seconds > 3600
        labels:
          severity: warning
        annotations:
          summary: "CI job running for over 1 hour, possible compromise or stuck job"

      - alert: SecretsAccessedByUnexpectedWorkflow
        expr: increase(github_secret_access_total{workflow!~"deploy|release|build"}[1h]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Secrets accessed by unexpected workflow: {{ $labels.workflow }}"
```

## Expected Behaviour

- Every CI job runs on a fresh, ephemeral runner instance, no state persists between jobs
- No static cloud credentials stored on runners or in repository secrets; OIDC tokens expire in minutes
- Runner network restricted to container registry, cloud APIs, and artifact storage only
- Monitoring alerts on: unexpected runner registrations, long-running jobs, secrets access by unusual workflows
- `GITHUB_TOKEN` permissions explicitly declared per-job (not default write-all)

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Ephemeral runners | 10-30 second cold start per job; cache miss for dependencies | Slower CI; no persistent build cache | Use external cache (S3, GCS) for dependency caching. Cache hits restore in 5-10 seconds. |
| OIDC federation | No static credentials; automatic rotation | Requires AWS/GCP OIDC trust setup (4-8 hours per provider per repo) | Document the setup once; template for new repos. |
| Network egress restrictions | Blocks unexpected outbound connections | `npm install` or `pip install` from public registries may be blocked | Allow egress to port 443 (HTTPS) broadly, but block non-HTTPS egress. For stricter control: proxy all dependency downloads through an internal registry. |
| Runner monitoring | Visibility into runner activity | Alert fatigue from legitimate long-running jobs | Tune thresholds per workflow. Exclude known long jobs (integration tests, large builds). |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| OIDC token request fails | CI job fails with "unable to assume role" | Job logs show 401/403 on AWS STS; `configure-aws-credentials` step fails | Check OIDC trust policy: verify repo, branch, and audience conditions match. Check the IAM role exists and has the correct permissions. |
| Ephemeral runner doesn't clean up | Old runner instances accumulate; cost and security risk | Runner instance count exceeds expected; stale instances visible in cloud console | Implement max-lifetime policy (terminate instances older than 2 hours). Add cleanup cron job. |
| Network policy blocks dependency download | `npm install`, `pip install`, or `docker pull` fails in CI | Job fails at dependency installation step; network timeout in job logs | Add the registry domain to the egress allowlist. Or proxy dependencies through an internal registry. |
| Compromised CI action | Third-party action exfiltrates secrets | Secrets appear in unexpected locations; unusual API calls from runner IP | Pin all actions by SHA (not tag). Review action source code. Use `permissions` to limit `GITHUB_TOKEN` scope. |

## When to Consider a Managed Alternative

Self-hosted runners require VM/container infrastructure, patching, and monitoring. GitHub-hosted larger runners ($0.008-0.064/minute) provide managed isolation, ephemeral by default, with no infrastructure to maintain. [Buildkite](https://buildkite.com) provides managed orchestration with self-hosted runner security (you control where jobs run; Buildkite handles scheduling and monitoring).

For runner audit logging: [Grafana Cloud](https://grafana.com/cloud) or [Axiom](https://axiom.co) for centralized CI/CD audit log analysis. [Sysdig](https://sysdig.com) for runtime monitoring of runner containers on Kubernetes.

**Premium content pack:** CI/CD hardening templates. GitHub Actions workflow templates with OIDC, minimal permissions, and pinned actions; GitLab CI config with ephemeral Docker executor; ARC runner deployment manifests with security context and network policies.


## Related Articles

- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Pipeline-as-Code Security: Preventing CI Configuration Tampering](/articles/cicd/pipeline-config-security/)
- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
