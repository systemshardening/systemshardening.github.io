---
title: "Shared-Kernel CI Runners: How Jobs Leak Secrets Across the Isolation Boundary"
description: "GitHub-hosted and self-hosted runners share a Linux kernel across concurrent jobs. Techniques including /proc filesystem traversal, cgroup namespace confusion, ptrace across job boundaries, and tmpfs timing attacks let one CI job read another job's environment variables and secrets — without any CVE required."
slug: shared-kernel-ci-runner-escape
date: 2026-05-08
lastmod: 2026-05-08
category: cicd
tags:
  - github-actions
  - runner
  - kernel
  - secrets
  - container-escape
personas:
  - platform-engineer
  - security-engineer
article_number: 692
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/shared-kernel-ci-runner-escape/
---

# Shared-Kernel CI Runners: How Jobs Leak Secrets Across the Isolation Boundary

## The Problem

Every CI runner that uses containers rather than full virtual machines has the same fundamental property: the jobs share a kernel. This is not a misconfiguration. It is the architectural baseline for the Docker executor in GitLab CI, for GitHub Actions container jobs, for most self-hosted runner deployments, and for the majority of commercial CI platforms that deliver speed by skipping VM boot time. The kernel is shared. The question is what you can do with that shared kernel from inside one job that you are not supposed to be able to do.

The answer is: quite a lot.

**`/proc` filesystem traversal** is the most direct path. The Linux `/proc` pseudo-filesystem exposes per-process state for every process visible within your PID namespace. When a container job runs without proper PID namespace isolation — which is the default for Docker containers unless the daemon or the container runtime is specifically configured otherwise — `ls /proc` from inside the container shows PID directories for every process running on the host, including processes belonging to concurrent CI jobs. Reading `/proc/<pid>/environ` for any of those PIDs returns the complete environment variable block for that process, null-byte-separated. Processes inherit environment variables from their parent. The GitHub Actions runner injects `GITHUB_TOKEN`, and any secrets mapped to the job via `env:` or `secrets:`, into the environment of every step process. From inside a different container job on the same host, those secrets are directly readable if the PID namespace is not isolated:

```bash
# From inside a malicious CI job running on the same host as a deployment job
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    environ="/proc/${pid}/environ"
    if [ -r "${environ}" ]; then
        # Print environment as newline-separated key=value pairs
        tr '\0' '\n' < "${environ}" 2>/dev/null | grep -E '(GITHUB_TOKEN|AWS_|GCP_|AZURE_|NPM_TOKEN|DOCKER_)'
    fi
done
```

This requires no CVE. No exploit. No kernel vulnerability. It is a standard POSIX operation on a world-readable file in a filesystem that is present because the container runtime did not ask for a private PID namespace.

The world-readability of `/proc/<pid>/environ` depends on process ownership. If the target process runs as a different UID than your process, the read will be denied — unless the runner is running jobs as root (common) or as the same UID across jobs (also common on self-hosted runners that do not isolate users per job). GitHub-hosted runners run the actions runner binary as `runner` (UID 1001) and steps as root or the job's `runs-on` user. Self-hosted runners frequently run as a dedicated service account but execute job steps as that same account. Two concurrent jobs on the same runner typically share the same UID. `/proc/<pid>/environ` for a process owned by UID 1001 is readable by another process also running as UID 1001. The traversal works.

**cgroup namespace confusion** provides a secondary observation channel even when `/proc/environ` reads fail. Docker containers on self-hosted runners without explicit cgroup namespace isolation share the cgroup hierarchy with the host. From inside a container, reading `/proc/self/cgroup` shows the container's cgroup path:

```
12:devices:/docker/3f8a2b1c4d...
11:memory:/docker/3f8a2b1c4d.../job-deploy-production
10:cpu,cpuacct:/docker/3f8a2b1c4d.../job-deploy-production
```

On hosts using cgroup v1 without namespace isolation (`--cgroupns=private` not set), `/proc/<pid>/cgroup` for processes belonging to other containers may be visible and may include the GitLab CI job ID, the GitHub Actions run ID, or the pipeline name in the cgroup path — depending on how the runner names its cgroup hierarchies. This leaks job metadata: you can identify that a concurrent job is a deployment to production before attempting any further access. GitLab Runner's Docker executor names cgroup slices using the job ID (`gitlab-runner/<job_id>`), making this identification trivial on unpatched deployments.

**tmpfs timing attacks** exploit the fact that CI jobs frequently write intermediate state — credentials fetched from Vault, temporary OIDC tokens, kubeconfig files, decrypted secrets — to shared temporary filesystems. On a host where multiple jobs run concurrently, `/dev/shm` and `/tmp` may not be namespaced per container. A job that watches for file creation events on these paths using `inotifywait` can observe the timing and names of credential files written by concurrent jobs:

```bash
# Watch /tmp for credential-adjacent file writes from concurrent jobs
inotifywait -m -r -e create,moved_to /tmp /dev/shm --format '%T %w%f %e' --timefmt '%s' 2>/dev/null \
  | grep -Ei '(kube|token|cred|secret|auth|aws|gcp|azure|vault|oidc|kubeconfig|\.pem|\.key)'
```

If a concurrent deployment job writes a kubeconfig to `/tmp/kube-config-${RANDOM}` before running `kubectl apply`, the inotify event reveals the path. A subsequent `cat` of that path — readable because it was written under a shared UID — yields the cluster credentials. This attack pattern requires no privilege escalation. It is a race condition between job execution and file cleanup, exploitable via standard Linux filesystem notification APIs.

**Real incident context**: In 2022, a disclosure to GitHub described a scenario where the GitHub Actions runner's agent temp directory — used to store step scripts and intermediate outputs — was not isolated between concurrent jobs on a shared VM in certain GitHub-hosted runner configurations. Files written by one job to the runner's temp directory were potentially visible to concurrent jobs before deletion. GitHub's response clarified that hosted runners use VM-per-job isolation for standard plans, but the disclosure highlighted that the isolation guarantee was not uniformly documented and that edge cases existed.

In 2023, Legit Security published research on GitHub Actions self-hosted runner isolation failures, demonstrating that jobs sharing a runner host could observe each other's processes and environment variables through standard `/proc` traversal when PID namespace isolation was absent. The research specifically targeted the runner configuration pattern common in Kubernetes-based self-hosted runner deployments using the actions-runner-controller, where runner pods on the same node share the node's kernel and, without explicit namespace configuration, can observe each other's process trees.

GitHub's own documentation and 2021 security advisory were explicit on the underlying point: "Self-hosted runners do not have the same level of isolation as GitHub-hosted runners." The advisory warns specifically against using self-hosted runners on public repositories because any contributor can submit a pull request that triggers a workflow job on the runner — and that job runs with the same kernel access as every other concurrent job.

The shared kernel is not one attack surface among several. It is the root cause that makes all of these techniques possible. PID namespaces, cgroup namespaces, and mount namespace isolation exist in Linux precisely to prevent cross-process observation. Container runtimes must be explicitly configured to use them. Most CI runner deployments do not configure them correctly, and most operators do not check.

## Threat Model

**Malicious pull request on a self-hosted runner.** An attacker submits a pull request to a public repository that uses a self-hosted runner. The PR's CI job runs on the same runner host as a concurrent deployment job triggered by a merge to main. The deployment job has `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in its environment for deploying to production. The PR job iterates `/proc` and reads the deployment job's environment. The attacker now has production cloud credentials. This does not require the PR to be merged or reviewed — `on: pull_request` triggers are sufficient.

**Supply chain compromised action targeting a privileged concurrent job.** A compromised third-party action runs in a low-privilege job (e.g., a linting step on a pull request). The same runner host simultaneously executes a deployment job with elevated credentials. The compromised action uses `/proc` traversal to harvest the deployment job's `GITHUB_TOKEN` and cloud credentials, then exfiltrates them over HTTPS. The action was not granted any special permissions — it used only the ambient kernel access available to any process on a shared-kernel host.

**Shared `/tmp` between concurrent jobs.** A deployment job fetches a short-lived OIDC token from AWS STS and writes it to `/tmp/aws-creds-${JOB_ID}` before use. A concurrent job running on the same host registers an inotify watch on `/tmp` before the deployment job starts. The inotify event fires, naming the credential file. The concurrent job reads the file before it is deleted. The write-read-delete window is measured in milliseconds; the OIDC token is valid for an hour.

**Multi-tenant self-hosted runner pool.** An organization runs a shared runner pool used by multiple teams. Team A's deployment pipeline has production credentials. Team B's repository has a compromised dependency or developer. Team B's CI job, scheduled to run concurrently with Team A's deployment, uses `/proc` traversal to read Team A's job environment. Kubernetes-based runner pools using actions-runner-controller without pod-level PID namespace isolation are particularly exposed: all runner pods on the same node share that node's process namespace unless `shareProcessNamespace: false` is explicitly enforced and pod security policies prevent override.

**Artifact store timing attack on workspace directories.** Some self-hosted runner configurations use a shared workspace directory (configured via `RUNNER_WORKSPACE`) on a host filesystem with jobs writing to subdirectories. A job that reads intermediate artifacts written by a concurrent step in a different job — before that job's workspace is cleaned — can exfiltrate build secrets that are not otherwise accessible through the GitHub Actions secret API.

## Hardening Configuration

### 1. PID Namespace Isolation for Every Job

For GitLab CI's Docker executor, the `config.toml` configuration controls how the runner launches containers. By default, GitLab Runner does not set `--pid` on the Docker container, which means containers see the host PID namespace:

```toml
# /etc/gitlab-runner/config.toml
[[runners]]
  name = "production-runner"
  url = "https://gitlab.example.com"
  executor = "docker"
  [runners.docker]
    image = "ubuntu:22.04"
    # Enforce private PID namespace — jobs cannot see host process list
    pid = "private"
    # Enforce private cgroup namespace — jobs cannot traverse host cgroup hierarchy
    cgroupns = "private"
    # Prevent privilege escalation
    privileged = false
    security_opt = ["no-new-privileges:true"]
    # Isolated /tmp per job via tmpfs mount
    tmpfs = {"/tmp" = "rw,noexec,nosuid,size=512m", "/dev/shm" = "rw,noexec,nosuid,size=64m"}
```

The `pid = "private"` setting passes `--pid=private` to Docker, which creates a new PID namespace for the container. `ls /proc` inside the job now shows only the job's own processes — PID 1 is the container init, and no other job's PIDs are visible. The `cgroupns = "private"` setting prevents cgroup hierarchy traversal. The explicit `tmpfs` mounts give each job its own isolated `/tmp` and `/dev/shm`, preventing the shared-tmpfs timing attack.

For GitHub Actions self-hosted runners using Docker, the runner's container job invocation can be wrapped to enforce namespace isolation. The `DOCKER_HOST` socket approach with a custom wrapper script:

```bash
#!/usr/bin/env bash
# /usr/local/bin/docker-hardened — wrapper placed earlier in PATH than /usr/bin/docker
# Injects namespace isolation flags into every container run

if [[ "$1" == "run" ]]; then
    shift
    exec /usr/bin/docker run \
        --pid=private \
        --cgroupns=private \
        --security-opt=no-new-privileges \
        --tmpfs /tmp:rw,noexec,nosuid,size=512m \
        --tmpfs /dev/shm:rw,noexec,nosuid,size=64m \
        "$@"
else
    exec /usr/bin/docker "$@"
fi
```

This is a defence-in-depth measure, not a complete solution — it does not prevent a job from using the Docker socket to launch privileged containers unless socket access is also restricted. The authoritative fix is configuring the runner's Docker daemon with `userns-remap` enabled and ensuring the runner uses `--pid=private` at the daemon configuration level:

```json
// /etc/docker/daemon.json
{
  "userns-remap": "default",
  "no-new-privileges": true,
  "default-runtime": "runc"
}
```

`userns-remap` maps the container's root user to an unprivileged host UID, preventing privilege escalation even if a job escapes the container namespace.

### 2. Dedicated Ephemeral Runners Per Job

The most robust mitigation is architectural: one runner per job, destroyed after the job completes. No runner state persists between jobs. No concurrent jobs share a runner. The shared-kernel attack surface collapses to the node level, and at the node level, a Kubernetes pod security policy or RuntimeClass can enforce VM-level isolation.

The actions-runner-controller AutoscalingRunnerSet provides this pattern for GitHub Actions:

```yaml
apiVersion: actions.github.com/v1alpha1
kind: AutoscalingRunnerSet
metadata:
  name: production-runners
  namespace: arc-runners
spec:
  githubConfigUrl: https://github.com/your-org/your-repo
  githubConfigSecret: arc-github-secret
  maxRunners: 20
  minRunners: 0
  template:
    spec:
      # Each runner pod handles one job then terminates
      containers:
        - name: runner
          image: ghcr.io/actions/actions-runner:latest
          resources:
            requests:
              cpu: "500m"
              memory: "512Mi"
            limits:
              cpu: "2"
              memory: "4Gi"
      # Prevent process namespace sharing between containers in the same pod
      shareProcessNamespace: false
      # Run as non-root
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
        seccompProfile:
          type: RuntimeDefault
```

The `minRunners: 0` combined with `maxRunners: 20` creates runners on demand and destroys them after each job. There is no runner available to receive a second job. The runner pod's lifetime is bounded by a single job execution. `shareProcessNamespace: false` is critical: the default in Kubernetes is `false`, but explicitly setting it prevents any future default change from silently re-enabling cross-container process visibility within the pod.

For GitLab CI, the equivalent is the `concurrent = 1` runner configuration combined with the `--ephemeral` flag introduced in GitLab Runner 15.7, combined with autoscaling:

```toml
# config.toml for GitLab Runner Fleeting autoscaler
concurrent = 1
check_interval = 0

[session_server]
  session_timeout = 1800

[[runners]]
  name = "ephemeral-docker-runner"
  url = "https://gitlab.example.com"
  executor = "docker-autoscaler"
  [runners.autoscaler]
    plugin = "fleeting-plugin-aws"
    capacity_per_instance = 1
    max_instances = 20
    max_use_count = 1  # destroy instance after one job
    [runners.autoscaler.plugin_config]
      name = "ci-runner-asg"
      region = "us-east-1"
```

`max_use_count = 1` is the key parameter — it destroys the instance after a single job execution, providing VM-level ephemeral isolation equivalent to GitHub-hosted runners.

### 3. Secrets in Ephemeral Memory, Not Environment Variables

The `/proc/<pid>/environ` attack is only possible because secrets are present in the process environment. Moving secret delivery out of environment variables removes the primary attack vector.

HashiCorp Vault Agent as a sidecar in the runner pod fetches secrets at job start and writes them to an in-memory tmpfs mount:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ci-runner
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/agent-inject-secret-aws-creds: "secret/ci/aws-deploy"
    vault.hashicorp.com/agent-inject-template-aws-creds: |
      {{- with secret "secret/ci/aws-deploy" -}}
      export AWS_ACCESS_KEY_ID="{{ .Data.data.access_key_id }}"
      export AWS_SECRET_ACCESS_KEY="{{ .Data.data.secret_access_key }}"
      {{- end }}
    vault.hashicorp.com/secret-volume-path: "/vault/secrets"
    vault.hashicorp.com/agent-pre-populate-only: "true"
spec:
  serviceAccountName: ci-runner-vault-sa
  containers:
    - name: runner
      image: ghcr.io/actions/actions-runner:latest
      # Source secrets at step start from vault-written file, not from ENV
      # Step scripts: source /vault/secrets/aws-creds before using AWS CLI
```

The secrets are written to `/vault/secrets/` — an in-memory tmpfs volume — rather than injected as environment variables visible in `/proc/self/environ`. A job step that needs AWS credentials sources the file explicitly: `source /vault/secrets/aws-creds`. A concurrent job reading that step's `/proc/<pid>/environ` sees the runner's baseline environment, not the AWS credentials.

For AWS-native CI pipelines, AWS Secrets Manager with IRSA (IAM Roles for Service Accounts) provides an equivalent pattern. The runner pod's service account is annotated with an IAM role that has read access to the specific secrets required for that job's deployment target. Credentials are fetched at step execution time using the AWS SDK, never injected as environment variables, and rotate automatically:

```bash
# Step script: fetch credentials at runtime, not via ENV injection
aws secretsmanager get-secret-value \
  --secret-id "ci/production/deploy-creds" \
  --query 'SecretString' \
  --output text | jq -r '.aws_access_key_id'
```

This approach means that `/proc/<pid>/environ` for any step process shows only the IRSA web identity token path — not the actual credentials. The IRSA token is scoped to a specific IAM role and expires; lateral movement from an intercepted token requires the attacker to also compromise the Kubernetes service account trust relationship.

### 4. gVisor or Kata Containers for Runner Pods

For multi-tenant or high-assurance environments, the only complete mitigation for shared-kernel attacks is providing each job with its own kernel. gVisor's `runsc` runtime intercepts Linux syscalls in userspace, providing a separate kernel interface per container. Kata Containers launch a lightweight VM per container with hardware isolation.

RuntimeClass configuration for gVisor runner pods in Kubernetes:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor-runner
handler: runsc
---
apiVersion: actions.github.com/v1alpha1
kind: AutoscalingRunnerSet
metadata:
  name: isolated-runners
  namespace: arc-runners
spec:
  githubConfigUrl: https://github.com/your-org/your-repo
  githubConfigSecret: arc-github-secret
  maxRunners: 10
  minRunners: 0
  template:
    spec:
      runtimeClassName: gvisor-runner
      containers:
        - name: runner
          image: ghcr.io/actions/actions-runner:latest
```

With `runtimeClassName: gvisor-runner`, the runner container executes under gVisor's `runsc` runtime. `ls /proc` inside the job shows only that job's own processes — gVisor maintains a per-sandbox process table that is completely isolated from the host. `/proc` traversal to another job's processes is impossible because those processes exist in a different `runsc` sandbox with its own kernel state. There is no shared `/proc`. inotify on `/tmp` observes only the sandbox's own tmpfs. cgroup traversal shows only the sandbox's own cgroup namespace.

Kata Containers provides equivalent isolation via hardware virtualisation. Each container gets a full QEMU or Cloud Hypervisor VM with its own kernel image. The configuration is analogous — install the Kata runtime, create a `RuntimeClass` pointing to it, annotate runner pods accordingly. Kata has lower syscall compatibility issues than gVisor but higher memory overhead per job.

### 5. Network Policy Blocking Inter-Runner Communication

Namespace isolation prevents direct process observation. Network policy prevents credential exfiltration via inter-runner channels (e.g., a compromised job listening on a port for credentials forwarded from another job's process):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: runner-isolation
  namespace: arc-runners
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: runner
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Deny all inbound connections to runner pods
    - from: []
  egress:
    # Allow DNS
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    # Allow GitHub API and registry access
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              # Block RFC1918 — prevents exfiltration to attacker infrastructure
              # on the same private network (compromised CI job cannot reach
              # other runner pods or internal services)
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - port: 443
          protocol: TCP
```

This policy denies all ingress to runner pods and restricts egress to DNS and external HTTPS only, preventing a compromised runner job from reaching internal services or other runner pods directly.

### 6. Auditd: Detect `/proc` Traversal Attempts

Even with namespace isolation, a defence-in-depth audit layer should detect unexpected `/proc/<pid>/environ` reads. The audit rule targets the specific file access pattern:

```bash
# Load audit rules — add to /etc/audit/rules.d/ci-runner.rules

# Detect reads of /proc/<pid>/environ from CI runner processes
# -F path=/proc is insufficient; use dir match with key for the environ file specifically
-a always,exit -F arch=b64 -S openat,open -F dir=/proc -F a2&01 -F success=1 -k proc_traverse

# More targeted: detect environ file reads (requires auditd 3.0+ with path filtering)
-a always,exit -F arch=b64 -S openat -F path~=/proc/[0-9]*/environ -F success=1 -k proc_environ_read

# Detect inotify setup on /tmp and /dev/shm (unusual in CI job processes)
-a always,exit -F arch=b64 -S inotify_init,inotify_init1 -F uid=1001 -k inotify_watch
```

After loading these rules with `auditctl -R /etc/audit/rules.d/ci-runner.rules`, a traversal attempt generates audit log entries:

```
type=SYSCALL msg=audit(1746700000.123:4521): arch=c000003e syscall=257 success=yes
  exit=4 a0=ffffff9c a1=7f4c28001020 a2=0 a3=0 items=1 ppid=12345 pid=12389
  auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001
  fsgid=1001 tty=(none) ses=2 comm="bash" exe="/usr/bin/bash"
  subj=unconfined key="proc_environ_read"
type=PATH msg=audit(1746700000.123:4521): item=0 name="/proc/12344/environ"
  inode=0 dev=00:04 mode=0100400 ouid=1001 ogid=1001 rdev=00:00
  nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fflags=0
```

The `key="proc_environ_read"` tag makes these events trivially searchable. Export to a SIEM or alerting pipeline:

```bash
# Stream matching audit events to alerting
ausearch -k proc_environ_read --interpret --format csv \
  | awk -F',' '{print "ALERT: proc/environ read by pid=" $6 " comm=" $14 " path=" $NF}'
```

Alert immediately on any `proc_environ_read` event from a CI runner process. Legitimate CI jobs do not read `/proc/<pid>/environ` for processes they did not spawn.

## Expected Behaviour

**With PID namespace isolation correctly configured**, a job's view of `/proc` is narrow. Running `ls /proc` from inside a correctly isolated GitLab CI Docker executor job with `pid = "private"` shows:

```
1    cmdline  cpuinfo  devices  filesystems  interrupts  ...
```

— a sparse `/proc` with no numeric PID directories beyond the job's own process tree. The PID of the runner's step shell is typically `1` or a small number. There are no directories for host processes or concurrent job processes. The traversal loop finds nothing to read.

**With auditd rules active**, a deliberate traversal attempt from inside an unprotected container — before namespace isolation is deployed — generates a burst of `proc_environ_read` events. The audit log shows the exact PIDs accessed, the committing process, and the UID. This serves as both a detection signal and a post-incident forensic record: you can reconstruct exactly which job, at what timestamp, attempted to read which process's environment.

**With ephemeral runners**, the window for concurrent execution on a shared runner shrinks to zero. The runner pod that handles job A is terminated before job B starts. The PID namespace for job A's processes ceases to exist. There is nothing for job B to observe.

**With gVisor**, `cat /proc/1/environ` from inside a runner pod shows only that pod's own environment. A process in a different gVisor sandbox — even on the same Kubernetes node — does not appear in `/proc` because each sandbox maintains its own kernel process table. The inotify watch on `/tmp` sees only that sandbox's tmpfs mount, which is not shared with any other sandbox.

## Trade-offs

**Ephemeral runners** introduce per-job startup latency. On bare metal, Firecracker microVMs boot in roughly 125ms; on Kubernetes, a new runner pod requires image pull (from cache: 2–5 seconds) plus container init. For pipelines with many short jobs, this overhead accumulates. The actions-runner-controller runner scale sets mitigate this by pre-pulling the runner image and keeping a warm pod ready, but at the cost of one idle pod being billed continuously. For bursty workloads with high concurrency, the infrastructure cost of 20 ephemeral runners active simultaneously exceeds the cost of 4 persistent runners handling queued jobs — though the security tradeoff is clear.

**gVisor** does not support every syscall. The [compatibility matrix](https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/) documents hundreds of syscalls but has gaps, particularly around performance-sensitive paths (io_uring is unsupported), certain network interfaces, and kernel modules. CI jobs that invoke native binaries with unusual syscall patterns — certain compilers, profilers, low-level test frameworks — will fail under gVisor with `ENOSYS` or `EPERM`. A test matrix run of your job inventory against a gVisor node pool is required before migrating all runners. The failure mode is generally clean (the syscall returns an error code) rather than silent.

**Vault Agent sidecar** adds dependency on Vault availability to every CI job. A Vault HA cluster with high uptime is required, or job start-up fails waiting for the agent to authenticate. Teams running "simple" jobs that currently inject one or two secrets via `secrets:` in the workflow file resist this pattern as over-engineered. The resistance is understandable but the risk is concrete: the simplest jobs often run on the same runner host as the most privileged jobs. Partial deployment — Vault only for deployment jobs, ENV injection for test jobs — creates a tiered model where test jobs remain exposed to reading deployment jobs' environments.

**userns-remap** at the Docker daemon level causes all containers to run as remapped UIDs. The root user inside a container maps to an unprivileged host UID (e.g., UID 100000). This breaks Docker-in-Docker and any CI job that expects to bind-mount host paths and write files as host UID 0. Volume mount permissions become a source of friction, and some actions that internally use Docker will fail. Each incompatibility requires an explicit exception, which creates pressure to disable userns-remap under operational load.

## Failure Modes

**Using self-hosted runners for public repositories.** GitHub's security documentation is explicit: self-hosted runners should not be used with public repositories unless every pull request is reviewed before CI runs (`pull_request_target` with an approval gate). The attack described above — a malicious contributor submitting a PR that triggers a job on the same runner host as a privileged deployment job — requires only that `on: pull_request` triggers are enabled. This is the default for most repositories. The consequences range from leaked `GITHUB_TOKEN` to leaked production cloud credentials. GitHub-hosted runners avoid this by providing VM-per-job isolation, but that guarantee requires using hosted runners on GitHub's infrastructure. Self-hosted runners on shared hardware do not inherit this guarantee.

**Assuming container isolation is kernel isolation.** The single most common failure mode. Teams deploy Docker-based runner configurations, confirm that jobs run in containers, and conclude that isolation is sufficient. Docker containers are process groups with namespace and cgroup controls applied at container start. They do not provide separate kernels. The Linux kernel that processes `openat("/proc/12345/environ")` inside a container is identical to the kernel that manages process 12345 in a concurrent container. The isolation is real — namespaces do work when correctly configured — but it is not automatically applied. Docker's default container invocation does not set `--pid=private`. GitLab Runner's Docker executor does not set `pid = "private"` by default. The default is the insecure configuration.

**Not isolating the runner temp directory.** GitHub Actions stores step scripts, pre-job outputs, and action source code in `$RUNNER_TEMP` (default: `/home/runner/work/_temp`). On a self-hosted runner handling concurrent jobs, if `RUNNER_TEMP` is not isolated per job (e.g., via a per-job subdirectory on an isolated tmpfs mount), step scripts from one job are readable by concurrent jobs as long as the runner process has not yet cleaned them up. The runner deletes temp files at job completion, not at step completion — so scripts written early in job A's execution are visible for the full duration of job A, which may overlap significantly with job B.

**Trusting log masking for secret security.** GitHub Actions and GitLab CI both mask registered secret values in log output — any string matching a registered secret is replaced with `***`. This masking applies only to log output streams. It has no effect on process environment variables. A secret that is masked in a CI log is still present in plaintext in the step process's environment, readable via `/proc/<pid>/environ` by any process with appropriate namespace access. Log masking is a cosmetic control, not a security boundary. Operators who rely on masking to justify not implementing namespace isolation are accepting significant risk.

**Overlooking the `--privileged` flag.** Some CI workflows require Docker-in-Docker and set `privileged: true` on the runner container. A privileged container has `CAP_SYS_PTRACE`, which allows one process to ptrace any other process on the host with the same UID — including processes in other containers. `ptrace(PTRACE_ATTACH, <pid>)` followed by `ptrace(PTRACE_PEEKDATA)` reads arbitrary memory from the target process, including secrets that were passed as arguments rather than environment variables. The argument vector is visible in `/proc/<pid>/cmdline`, which is world-readable (truncated to 4096 bytes) and accessible even without ptrace. Privileged containers also have access to the host's block devices and can mount the host filesystem directly. The attack surface of a `--privileged` runner container is effectively equivalent to code execution on the host. Do not use privileged containers for multi-tenant runner hosts.

## Related Articles

- [GitHub Actions Self-Hosted Runner Hardening](/articles/cicd/github-actions-self-hosted-runner/)
- [Ephemeral CI Runners with Firecracker and Kata](/articles/cicd/firecracker-kata-ci-runners/)
- [Securing CI/CD Runners: Isolation, Credential Scoping, and Ephemeral Environments](/articles/cicd/securing-cicd-runners/)
- [Ephemeral Cloud Credentials in CI/CD](/articles/cicd/ephemeral-cloud-credentials-cicd/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
