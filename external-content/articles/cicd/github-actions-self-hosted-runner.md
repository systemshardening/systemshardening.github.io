---
title: "GitHub Actions Self-Hosted Runner Hardening: Registration, Isolation, and Ephemeral Patterns"
description: "Self-hosted runners execute arbitrary workflow code on infrastructure you own. Hardening the runner binary, isolating the host, restricting network egress, and enforcing ephemeral patterns closes the gap between CI convenience and production-grade security."
slug: github-actions-self-hosted-runner
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - github-actions
  - self-hosted-runner
  - ci-security
  - ephemeral-runners
  - network-isolation
personas:
  - security-engineer
  - platform-engineer
article_number: 516
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/github-actions-self-hosted-runner/
---

# GitHub Actions Self-Hosted Runner Hardening: Registration, Isolation, and Ephemeral Patterns

## Problem

GitHub-hosted runners are ephemeral by design and managed by GitHub. Self-hosted runners are not. When you bring your own runner, you own every security property that GitHub previously provided: process isolation, network egress controls, the runner user account, credential lifecycle, and host OS hardening. Most self-hosted runner deployments skip most of these.

The specific gaps that make self-hosted runners dangerous:

- **Persistent runner state.** A runner that processes multiple jobs accumulates state: shell history, cached credentials, workspace remnants, and potentially attacker-planted backdoors from a previous malicious job. The next job on the same runner inherits all of it.
- **Runner registered with long-lived tokens.** Registration tokens from the GitHub UI expire in one hour, but the resulting runner credential (`credentials` file in `.runner` directory) persists indefinitely. A compromised runner host exposes this credential, allowing an attacker to re-register malicious runners.
- **Over-broad runner group assignment.** Runner groups control which repositories can use which runners. A runner assigned to an "All repositories" group in a GitHub organisation is reachable from any repository in that org, including forked repositories triggered by external pull requests.
- **Runner executing as root or a shared user.** Many runners are installed as the user who ran `config.sh`. If that is root or a developer's account, a malicious workflow step can read SSH keys, cloud credentials, and other sensitive files in the home directory.
- **Unrestricted network egress.** A runner with full outbound internet access is a beachhead: a compromised job can exfiltrate secrets to arbitrary endpoints, probe internal networks, and download additional payloads.
- **Label collision.** A workflow's `runs-on: [self-hosted, linux]` matches any self-hosted runner with those labels. In organisations where multiple teams register runners, a job intended for a trusted production runner may execute on a less-hardened development runner.

**Target systems:** GitHub Actions self-hosted runner binary (v2.x), runner hosts on Linux (Ubuntu 22.04+, RHEL 9+), Kubernetes-based runners via Actions Runner Controller (ARC v0.9+), organisation-level and repository-level runner groups.

## Threat Model

- **Adversary 1 — Poisoned pipeline execution (PPE) via pull request:** An external contributor forks a public repository and opens a pull request. A workflow triggered by `pull_request` (or misconfigured `pull_request_target`) runs on a self-hosted runner. The attacker's code reads `/proc`, network-scans the internal subnet, and exfiltrates secrets from the environment.
- **Adversary 2 — Persistent runner backdoor:** A malicious workflow job writes a cron entry or systemd unit to the runner host. Subsequent jobs on the same non-ephemeral runner execute the backdoor with runner-user permissions, exfiltrating cloud credentials from every future build.
- **Adversary 3 — Runner label hijacking:** An attacker who can register a runner in the organisation registers one with labels `[self-hosted, linux, production]`. Workflows intended for hardened production runners now route to the attacker's runner, which captures all environment variables and secrets passed to those jobs.
- **Adversary 4 — Registration token theft:** A registration token is committed to a repository, passed in plaintext over an insecure channel, or captured from CI logs. The attacker registers a rogue runner against the target repository or organisation, positioning it to intercept future workflow jobs.
- **Access level:** Adversaries 1 and 2 require code execution in a workflow. Adversary 3 requires GitHub organisation membership with runner registration permission. Adversary 4 requires access to the registration token.
- **Objective:** Extract cloud credentials and signing keys, inject malicious code into build artefacts, pivot to internal infrastructure via the runner's network position.
- **Blast radius:** A compromised self-hosted runner exposes every secret passed to jobs it processes, every internal endpoint reachable from the runner host, and the integrity of every build artefact it produces.

## Configuration

### Step 1: Runner Registration Token Hygiene

Never register runners manually with tokens that outlive their use. Use Just-in-Time (JIT) registration tokens via the GitHub API — the token is valid for exactly one runner registration and the runner deregisters itself after one job.

```bash
# Generate a JIT runner token via the GitHub REST API.
# This token is single-use: it registers one runner and is then invalid.
curl -s -X POST \
  -H "Authorization: Bearer ${GITHUB_PAT}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/orgs/${ORG}/actions/runners/registration-token" \
  | jq -r '.token'
# Returns: AAAAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# Valid for: 1 hour (registration only — the registered runner credential persists separately)
```

For organisation-level automation, use a GitHub App instead of a PAT. A GitHub App credential is scoped to specific repositories and permissions, automatically rotates, and leaves an audit trail:

```bash
# Exchange a GitHub App JWT for an installation token.
# The installation token scopes to the repositories the App is installed on.
APP_JWT=$(python3 -c "
import jwt, time
payload = {'iat': int(time.time()), 'exp': int(time.time()) + 600, 'iss': '${APP_ID}'}
print(jwt.encode(payload, open('${APP_PRIVATE_KEY}').read(), algorithm='RS256'))
")

curl -s -X POST \
  -H "Authorization: Bearer ${APP_JWT}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/app/installations/${INSTALLATION_ID}/access_tokens" \
  | jq -r '.token'
```

Protect the runner's persisted credential directory. After `config.sh` completes, the `.runner` and `credentials` files under `_diag/` must not be world-readable:

```bash
# Lock down runner credential files after registration.
chmod 600 /home/runner-svc/_work/_runner_credentials
chmod 700 /home/runner-svc/actions-runner
chown -R runner-svc:runner-svc /home/runner-svc/actions-runner
```

### Step 2: Dedicated Non-Root Runner User

Create a dedicated service account with no login shell, no sudo rights, and no access to other users' home directories. The runner binary and workspace must be confined to this account.

```bash
# Create a dedicated runner service account.
useradd \
  --system \
  --shell /usr/sbin/nologin \
  --home-dir /home/runner-svc \
  --create-home \
  --comment "GitHub Actions runner service account" \
  runner-svc

# The runner user must NOT be in sudo, wheel, docker, or adm groups.
# Verify group membership is minimal:
groups runner-svc
# Expected: runner-svc (no additional groups)

# If the runner needs Docker, use rootless Docker or a container socket proxy
# (docker-proxy) — never add runner-svc to the docker group, which is root-equivalent.
```

Install and configure the runner binary as this user:

```bash
sudo -u runner-svc bash -c "
  cd /home/runner-svc/actions-runner
  ./config.sh \
    --url https://github.com/${ORG} \
    --token ${REGISTRATION_TOKEN} \
    --name ephemeral-runner-\$(hostname)-\$(date +%s) \
    --labels self-hosted,linux,x64,hardened \
    --runnergroup production-runners \
    --work /home/runner-svc/_work \
    --ephemeral \
    --unattended
"
```

Install the runner as a systemd service with a hardened unit file:

```ini
# /etc/systemd/system/github-runner.service
[Unit]
Description=GitHub Actions Runner (ephemeral)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=runner-svc
Group=runner-svc
WorkingDirectory=/home/runner-svc/actions-runner

ExecStart=/home/runner-svc/actions-runner/run.sh
ExecStopPost=/bin/rm -rf /home/runner-svc/_work

# Hardening: no new privileges, private /tmp, no write to /usr /boot /etc
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/runner-svc
PrivateDevices=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
CapabilityBoundingSet=

# Restart behaviour: ephemeral runners exit after one job.
# Restart=on-success causes the orchestrator to respawn a new registration.
Restart=on-success
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Step 3: Ephemeral Runners with JIT Tokens

The `--ephemeral` flag makes the runner deregister itself from GitHub after processing exactly one job. Combined with a systemd `Restart=on-success` or a Kubernetes Job, this gives you a fresh, uncontaminated runner for every job execution.

For VM-based runners, pair `--ephemeral` with an immutable base image. The orchestrator creates a new VM from the hardened image, runs one job, then terminates the VM:

```bash
#!/usr/bin/env bash
# runner-bootstrap.sh — runs at VM startup via cloud-init or user-data.
# Called once per ephemeral VM instance.
set -euo pipefail

# 1. Fetch a fresh JIT registration token from the GitHub API.
REG_TOKEN=$(curl -sf -X POST \
  -H "Authorization: Bearer ${GITHUB_APP_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/orgs/${ORG}/actions/runners/registration-token" \
  | jq -r '.token')

# 2. Configure the runner (ephemeral: deregisters after one job).
sudo -u runner-svc \
  /home/runner-svc/actions-runner/config.sh \
    --url "https://github.com/${ORG}" \
    --token "${REG_TOKEN}" \
    --name "ephemeral-$(curl -sf http://169.254.169.254/latest/meta-data/instance-id)" \
    --labels "self-hosted,linux,x64,${RUNNER_LABELS}" \
    --runnergroup "${RUNNER_GROUP}" \
    --ephemeral \
    --unattended

# 3. Start the runner; it will process one job and exit.
sudo systemctl start github-runner

# 4. After the runner exits, the orchestrator terminates this VM.
# No state persists: the entire VM is discarded.
```

### Step 4: Network Egress Controls

A self-hosted runner needs exactly three outbound destinations: the GitHub Actions API (to poll for jobs and report results), GitHub package downloads, and your own package registries. Everything else should be blocked.

For VM-based runners, apply egress filtering at the VPC/security group level. For container-based runners on Kubernetes, use a NetworkPolicy:

```yaml
# runner-network-policy.yaml
# Applied to the namespace where ARC runner pods execute.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: runner-egress-allowlist
  namespace: arc-runners
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: runner
  policyTypes:
    - Egress
    - Ingress
  ingress: []  # Runners initiate outbound only; no inbound required.
  egress:
    # DNS resolution (required for everything below).
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53

    # GitHub Actions API and runner communication endpoints.
    # github.com, api.github.com, *.actions.githubusercontent.com
    - to:
        - ipBlock:
            cidr: 140.82.112.0/20   # github.com AS
        - ipBlock:
            cidr: 192.30.252.0/22   # github.com AS (secondary)
      ports:
        - protocol: TCP
          port: 443

    # Your internal package registry (Artifactory, Nexus, etc.).
    - to:
        - ipBlock:
            cidr: 10.0.10.0/24      # Internal registry subnet
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 8443

    # Block all other egress (no arbitrary internet, no prod subnet).
```

For AWS-hosted runners, use a VPC security group that allows TCP/443 to GitHub's published IP ranges only, with no other outbound rules. GitHub publishes its IP ranges via the `/meta` API endpoint:

```bash
# Fetch GitHub's current IP ranges for runner egress allowlisting.
curl -s https://api.github.com/meta \
  | jq -r '.actions[]'
# Output: CIDR blocks to allow in your security group / firewall egress rules.
# Re-run this periodically; GitHub updates the ranges.
```

### Step 5: Runner Group Access Policies

Runner groups control which repositories can route jobs to which runners. Misconfigured groups are how jobs from untrusted repositories reach hardened production runners.

In the GitHub organisation settings (Settings → Actions → Runner groups), apply these policies:

- **Never assign runners to "All repositories."** Create named groups — `production-runners`, `staging-runners`, `pr-validation-runners` — and assign only the repositories that legitimately need that runner tier.
- **Disable public repository access.** In the runner group settings, ensure "Allow public repositories" is unchecked. This prevents forks and public repositories from routing to your runners.
- **Separate PR validation runners from deployment runners.** PR validation runners (`pull_request` trigger) execute untrusted external code. Deployment runners (`push` to main, `release`) execute trusted code with cloud credentials. These must be distinct runner groups with separate network access.

```yaml
# In your workflow: use specific runner labels that resolve only to
# the intended runner group. Avoid generic labels like "self-hosted".
jobs:
  build-and-test:
    # Resolves to runners in the pr-validation group only.
    # These runners have NO cloud credentials, NO production network access.
    runs-on: [self-hosted, linux, x64, pr-validation]

  deploy:
    needs: build-and-test
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    # Resolves to runners in the production-runners group only.
    # Protected by a GitHub environment approval gate.
    runs-on: [self-hosted, linux, x64, production]
    environment: production
```

Labels must be unique and opaque — not guessable by external contributors. A label like `prod-runner-a7f2c` is harder to target than `production`.

### Step 6: Defending Against Poisoned Pipeline Execution (PPE)

PPE attacks exploit workflows that run on self-hosted runners in response to pull requests from untrusted forks. The attacker submits a PR; the `pull_request` trigger fires on the self-hosted runner; the attacker's Makefile, test script, or build system executes with access to runner environment variables, network, and sometimes secrets.

Mitigations are layered:

```yaml
# 1. Never trigger self-hosted runners from pull_request on public repositories.
#    Use pull_request_target only for operations that do NOT check out the PR code.
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  label-pr:
    # Uses pull_request_target for GitHub API access (labelling).
    # Does NOT check out the PR branch. Safe on self-hosted runners.
    runs-on: [self-hosted, linux, pr-ops]
    permissions:
      pull-requests: write
    steps:
      - uses: actions/labeler@v5  # Reads PR metadata only; no code checkout.
```

```yaml
# 2. For workflows that must build PR code on self-hosted runners,
#    require manual approval for first-time contributors.
on:
  pull_request:
    types: [opened, synchronize]
jobs:
  validate:
    runs-on: [self-hosted, linux, pr-validation]
    # The "pr-sandbox" environment requires approval from a maintainer
    # for contributors who have never had a PR merged.
    environment: pr-sandbox
```

```yaml
# 3. Explicitly restrict GITHUB_TOKEN permissions.
#    A PR validation job on a self-hosted runner needs only read access.
permissions:
  contents: read
  pull-requests: read
  # No: id-token, packages, deployments, secrets (not a permission, but verify
  # environment secrets are not attached to PR validation environments).
```

At the host level, prevent PR validation runners from reaching your internal network:

```bash
# iptables rules for PR validation runner hosts.
# These runners have no business reaching your production or staging subnets.
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP       # No RFC1918 egress
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
# Allow only GitHub IPs (see /meta API) and DNS.
```

### Step 7: Kubernetes Ephemeral Runners with Actions Runner Controller

Actions Runner Controller (ARC) is the recommended pattern for Kubernetes-based ephemeral runners. ARC manages the runner lifecycle: it creates a runner pod, the pod processes one job (with `--ephemeral`), and Kubernetes garbage-collects the pod.

```yaml
# arc-runner-set.yaml — ARC RunnerSet for ephemeral runners.
# Requires: actions-runner-controller v0.9+ with the new "autoscaling" mode.
apiVersion: actions.github.com/v1alpha1
kind: AutoscalingRunnerSet
metadata:
  name: production-runners
  namespace: arc-runners
spec:
  githubConfigUrl: https://github.com/${ORG}
  githubConfigSecret: arc-github-secret   # Contains GITHUB_APP credentials.
  minRunners: 2
  maxRunners: 20
  runnerGroup: production-runners
  template:
    spec:
      # Non-root runner user (matches dedicated account in container image).
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault

      containers:
        - name: runner
          image: your-registry.example.com/actions-runner:2.315.0-hardened
          imagePullPolicy: Always   # Always pull — never use a cached potentially-stale image.
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: false   # Runner workspace requires writes.
            capabilities:
              drop: ["ALL"]
          env:
            - name: ACTIONS_RUNNER_CONTAINER_HOOKS
              value: /home/runner/k8s/index.js
            - name: ACTIONS_RUNNER_POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: ACTIONS_RUNNER_REQUIRE_JOB_CONTAINER
              value: "true"   # Each job step runs in its own container, not on the runner pod.
          resources:
            requests:
              cpu: "500m"
              memory: "1Gi"
            limits:
              cpu: "2"
              memory: "4Gi"

      # Prevent scheduling on nodes that also run production workloads.
      tolerations:
        - key: dedicated
          operator: Equal
          value: ci-runners
          effect: NoSchedule
      nodeSelector:
        node-role: ci-runner
```

The `ACTIONS_RUNNER_REQUIRE_JOB_CONTAINER=true` setting forces every job to run inside a container image defined by the workflow's `container:` block. The runner pod itself does not execute job steps directly — each step runs in an isolated container, limiting blast radius from a compromised step.

### Step 8: Immutable Runner Host OS

For VM-based runners, the host OS should be immutable: built from a versioned base image, no SSH access after boot, no package manager access during runtime, and discarded after each job.

```bash
# Packer template snippet for an immutable runner AMI.
# Build this image in CI; all runners boot from this exact AMI.

# In the provisioner block, lock down after runner binary installation:
sudo apt-get remove -y --purge openssh-server   # No SSH on runner hosts.
sudo systemctl disable --now snapd               # No package installation at runtime.
sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer

# Remove package management tools the runner user could exploit.
sudo chmod 750 /usr/bin/apt /usr/bin/apt-get /usr/bin/dpkg
sudo chown root:runner-admin /usr/bin/apt /usr/bin/apt-get /usr/bin/dpkg
# runner-svc is not in runner-admin.

# Lock down /etc/passwd and crontabs.
sudo chmod 644 /etc/passwd
sudo chmod 000 /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron
sudo chown root:root /etc/cron.d

# Verify: runner-svc cannot modify system files or install packages.
sudo -u runner-svc apt-get install curl   # Must fail with permission denied.
```

Enable auditd to log filesystem writes and exec events from the runner user:

```bash
# /etc/audit/rules.d/runner.rules
# Monitor all exec events by the runner service account (UID 1001).
-a always,exit -F arch=b64 -F uid=1001 -S execve -k runner_exec
-a always,exit -F arch=b64 -F uid=1001 -S open -F success=1 -k runner_open
# Monitor writes outside the workspace directory.
-w /etc -p wa -k runner_etc_write
-w /home/runner-svc/actions-runner -p wa -k runner_binary_write
```

## Expected Behaviour

- Every job executes on a runner registered with a single-use JIT token; the runner deregisters and the underlying host or pod is discarded after one job.
- The runner process runs as a dedicated non-root user (`runner-svc`, UID 1001) with no sudo rights, no group memberships beyond its own, and a systemd unit with `NoNewPrivileges=true`.
- Outbound network from runner hosts is restricted: TCP/443 to GitHub's published IP ranges and internal package registries only; all RFC1918 egress blocked for PR validation runners.
- Runner groups are named and scoped; no group allows "All repositories" or public repositories; PR validation runners are in a separate group with no cloud credentials.
- Workflows use specific, non-generic runner labels that resolve only to the intended group; `pull_request` triggers from forks do not route to runners with cloud credentials or internal network access.
- ARC-based runners run with `runAsNonRoot`, `allowPrivilegeEscalation: false`, `capabilities: drop: ALL`, and `ACTIONS_RUNNER_REQUIRE_JOB_CONTAINER=true`.

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Ephemeral runners with JIT tokens | 30–60 second cold start per job; no warm tool cache | Slower CI feedback for small teams; JIT token API call adds a bootstrap step | Cache build dependencies in S3/GCS using `actions/cache` with an external backend. Parallelise the token request with early build steps. |
| Dedicated non-root runner user | Cannot run Docker-in-Docker natively; rootless Docker adds complexity | Build workflows that assume root may break | Migrate builds to `docker buildx` with rootless mode, or use Kaniko / ko / buildah inside the job container. |
| Network egress restrictions | Package installs from arbitrary registries fail | Dependency downloads blocked during CI | Mirror all required packages to an internal registry. Allow specific registry FQDNs if a strict IP allowlist is not feasible. |
| PR validation runner isolation | Separate runner fleet for PRs adds infrastructure overhead | Two fleets to maintain, patch, and monitor | Use ARC to manage both fleets from a single RunnerSet manifest; differentiate by runner group and label only. |
| `ACTIONS_RUNNER_REQUIRE_JOB_CONTAINER` | All jobs must specify a `container:` image | Workflows without a `container:` block fail | Add `container: ubuntu:22.04` (or a pinned internal image) to all job definitions as a standard template. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| JIT token fetch fails at bootstrap | VM boots but runner never registers; job queues indefinitely | GitHub Actions queue shows queued jobs with no runner; bootstrap script exits non-zero | Check GitHub App installation permissions: `actions: write` scope required. Verify the App is installed on the target org. Rotate App credentials if suspected compromise. |
| Runner registers but exits immediately | Runner appears in GitHub UI for seconds then disappears; job never starts | GitHub runner audit log shows registration followed by immediate offline event | Check systemd journal: `journalctl -u github-runner`. Common cause: `--ephemeral` flag combined with a configuration error causes immediate exit before job acquisition. |
| NetworkPolicy blocks GitHub API polling | Runner stays in "Idle" state indefinitely; no jobs processed | Runner logs show TCP timeout connecting to `*.actions.githubusercontent.com` | Add GitHub's Actions IP ranges (from `/meta` API) to the NetworkPolicy egress block. Verify DNS resolves `*.actions.githubusercontent.com` from inside the pod. |
| Label collision routes job to wrong runner | A job intended for a production runner executes on a PR validation runner (or vice versa) | Job logs show unexpected environment: missing secrets, unexpected network; `RUNNER_NAME` env variable reveals the wrong runner | Rename labels to include group identifiers (`prod-a7f2c`, not `production`). Audit runner group membership. Review who has runner registration permissions in the organisation. |
| PPE attack via malicious PR | Runner executes attacker-controlled build commands; secrets accessed or internal network probed | Unusual outbound connections in runner network logs; unexpected environment variable access; alerts on denied iptables egress | Immediately offline the affected runner group. Rotate all secrets accessible to that runner. Review GitHub audit log for the workflow run. Enforce manual approval for first-time contributors. |
| ARC pod scheduled on production node | Runner pod co-located with production workloads; compromised runner can probe pod network | Node affinity check: `kubectl get pod -n arc-runners -o wide` shows nodes without `node-role: ci-runner` label | Add `requiredDuringSchedulingIgnoredDuringExecution` node affinity to ARC RunnerSet; taint CI nodes with `dedicated=ci-runners:NoSchedule`. |

## Related Articles

- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
- [Securing CI/CD Runners: Isolation, Credential Scoping, and Ephemeral Environments](/articles/cicd/securing-cicd-runners/)
- [JIT CI Access: Ephemeral Credentials for Pipeline Jobs](/articles/cicd/jit-ci-access/)
- [Pipeline Egress Control: Restricting Outbound Traffic from CI/CD Pipelines](/articles/cicd/pipeline-egress-control/)
- [OIDC Federation Hardening: Scoping Short-Lived Cloud Credentials to CI Workflows](/articles/cicd/oidc-federation-hardening/)
