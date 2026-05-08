---
title: "Ephemeral CI Runners with Firecracker and Kata: VM-Level Isolation for Build Jobs"
description: "Container-based CI runners share a host kernel. Firecracker and Kata give each job its own kernel and a fresh VM — large blast-radius reduction, modest cost."
slug: "firecracker-kata-ci-runners"
date: 2026-04-27
lastmod: 2026-04-27
category: "cicd"
tags: ["cicd", "firecracker", "kata", "runners", "isolation"]
personas: ["platform-engineer", "security-engineer", "devops"]
article_number: 194
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cicd/firecracker-kata-ci-runners/index.html"
---

# Ephemeral CI Runners with Firecracker and Kata: VM-Level Isolation for Build Jobs

## Problem

Self-hosted CI runners are typically Linux containers (GitHub Actions Runner Controller, GitLab Runner with Docker executor, Buildkite agents in containers). The model: each job runs in a fresh container that exits when the job completes. The container's filesystem is wiped between jobs.

Container isolation is shallow for CI because:

- **Shared kernel.** A kernel CVE that lets a container escape lands the attacker on a host running tens of other tenants' jobs in parallel. Container-escape CVEs (CVE-2019-5736, CVE-2022-0492, CVE-2024-21626) have appeared multiple times per year through 2024–2025.
- **Shared cache directories.** Most CI systems share build caches (Docker layer cache, language-specific caches) across jobs for performance. A malicious job can poison the cache for subsequent jobs.
- **Host-shared kernel features.** seccomp, AppArmor, and capabilities help, but a container with `privileged: true` (often required for Docker-in-Docker builds) trivially defeats them.
- **Persistent runners.** Even with "ephemeral" containers, the runner host stays up across many jobs. Cross-job persistence via `/tmp`, `/var/lib/docker`, or environment files is possible.

Firecracker (AWS) and Kata Containers (CNCF) replace the container with a tiny VM. Each CI job gets its own kernel, its own memory, its own block device. The host kernel is shielded by a hardware virtualization boundary. The VM boots in 100-300ms; the cost difference vs. a container is small (~50ms per job + a few MB of memory).

By 2026, deployment patterns are mature: GitLab supports Firecracker via `runner-driver-firecracker`, GitHub Actions Runner Controller supports Kata via runtimeClassName, Buildkite has firecracker-agent, and platform teams at companies running tens of thousands of jobs/day deploy Firecracker for the highest-trust pipelines.

This article covers Firecracker and Kata deployment for CI, the security boundary each provides, image and snapshot management for fast cold-start, network isolation for the VMs, and the operational trade-offs.

**Target systems:** Firecracker 1.7+, Kata Containers 3.4+, GitLab Runner 17+, Actions Runner Controller 0.10+, Buildkite Agent 3.80+. Linux KVM-capable host (bare-metal or nested-virt cloud instance).

## Threat Model

- **Adversary 1 — Compromised dependency or action:** a malicious npm/PyPI package or GitHub Action runs during a job. Wants to escape to the runner host or other concurrent jobs.
- **Adversary 2 — Container-escape via runtime CVE:** a `runc` / containerd CVE provides container-to-host escape; attacker reaches the runner host's kernel.
- **Adversary 3 — Cache-poisoning attack:** malicious job writes corrupted layers into the shared Docker cache; subsequent jobs use the corrupted cache.
- **Adversary 4 — Runner-image rootkit:** a long-lived runner image contains compromised binaries; persists across job invocations on the same host.
- **Access level:** Adversary 1 has code execution inside one CI job. Adversary 2 has the same plus a runtime CVE. Adversary 3 has cache write access. Adversary 4 has access to the runner image build pipeline.
- **Objective:** Pivot from one job's compromised dependency to other jobs, the runner host, or upstream cloud credentials accessible from the host.
- **Blast radius:** Container-only: a kernel exploit lands as root on the runner host with all credentials and all concurrent jobs reachable. Firecracker/Kata: a kernel exploit inside the VM lands inside that VM only. Escape from the VM requires a hypervisor or KVM exploit, which is a much higher bar than a Linux kernel exploit.

## Configuration

### Step 1: Firecracker on a GitLab Runner

Install the `firecracker-runner-driver`:

```bash
# On the runner host.
sudo apt install -y qemu-kvm    # for KVM kernel module
sudo modprobe kvm
sudo modprobe kvm_intel         # or kvm_amd

# Install firecracker.
curl -LO https://github.com/firecracker-microvm/firecracker/releases/download/v1.7.0/firecracker-v1.7.0-x86_64.tgz
sudo tar -xzf firecracker-v1.7.0-x86_64.tgz -C /usr/local/bin --strip-components=1

# Install GitLab's firecracker driver.
curl -LO https://gitlab.com/gitlab-org/firecracker-runner/releases/download/v0.4.0/firecracker-runner-driver
sudo install firecracker-runner-driver /usr/local/bin/
```

Configure the GitLab runner:

```toml
# /etc/gitlab-runner/config.toml
[[runners]]
  name = "firecracker-prod"
  url = "https://gitlab.example.com/"
  token = "..."
  executor = "custom"
  builds_dir = "/builds"
  cache_dir = "/cache"

  [runners.custom]
    config_exec = "/usr/local/bin/firecracker-runner-driver"
    config_args = ["config"]
    prepare_exec = "/usr/local/bin/firecracker-runner-driver"
    prepare_args = ["prepare"]
    run_exec = "/usr/local/bin/firecracker-runner-driver"
    run_args = ["run"]
    cleanup_exec = "/usr/local/bin/firecracker-runner-driver"
    cleanup_args = ["cleanup"]
```

Each `prepare` invocation boots a fresh microVM from a snapshot. `run` injects the job's commands. `cleanup` discards the VM entirely. The host runner process never executes job code directly.

### Step 2: Kata Containers on Actions Runner Controller

Kata Containers integrates as a Kubernetes RuntimeClass. Install kata-deploy:

```bash
kubectl apply -f https://raw.githubusercontent.com/kata-containers/kata-containers/main/tools/packaging/kata-deploy/kata-deploy/base/kata-deploy.yaml
kubectl label node worker-1 worker-2 katacontainers.io/kata-runtime=true
```

This installs Kata's containerd shim on labeled nodes and creates the RuntimeClass:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
handler: kata
scheduling:
  nodeSelector:
    katacontainers.io/kata-runtime: "true"
```

Configure ARC to use it:

```yaml
# AutoscalingRunnerSet for GitHub Actions ARC.
apiVersion: actions.github.com/v1alpha1
kind: AutoscalingRunnerSet
metadata:
  name: production-builds
spec:
  template:
    spec:
      runtimeClassName: kata
      tolerations:
        - key: katacontainers.io/kata-runtime
          operator: Exists
      containers:
        - name: runner
          image: ghcr.io/myorg/runner-image:latest
          resources:
            requests:
              cpu: 1
              memory: 2Gi
            limits:
              cpu: 4
              memory: 8Gi
```

Each runner Pod becomes a microVM rather than a Linux container. The Kubernetes API surface is identical; the kernel boundary is added underneath.

### Step 3: Snapshot-Backed Cold Start

Naive Firecracker boot takes 100-300ms — fine for human-triggered builds but not for high-volume pipelines. Use snapshot-resume to boot in 5-20ms.

```bash
# Boot once, snapshot, kill.
firecracker --api-sock /tmp/fc.sock &
# (configure VM, wait for boot)
curl -X PUT --unix-socket /tmp/fc.sock http://localhost/snapshot/create \
  -d '{"snapshot_path": "/var/lib/firecracker/snapshots/runner.snap",
       "mem_file_path": "/var/lib/firecracker/snapshots/runner.mem"}'
kill %1

# Each job: resume from snapshot.
firecracker --api-sock /tmp/fc-job.sock &
curl -X PUT --unix-socket /tmp/fc-job.sock http://localhost/snapshot/load \
  -d '{"snapshot_path": "/var/lib/firecracker/snapshots/runner.snap",
       "mem_backend": {"backend_type": "File",
                        "backend_path": "/var/lib/firecracker/snapshots/runner.mem"}}'
# VM is alive in <20ms.
```

The snapshot includes a clean filesystem and a partially-warmed kernel. Each resumed VM is identical to the snapshotted state; cross-job contamination is impossible.

### Step 4: Network Isolation for Build VMs

Each build VM should have egress controls applied at the host network namespace before traffic reaches the broader network. Pair with the egress-allowlist patterns from [Pipeline Egress Control](/articles/cicd/pipeline-egress-control/):

```bash
# Create a per-VM TAP interface; attach to a host bridge with egress filtering.
ip tuntap add tap-vm-001 mode tap
ip link set tap-vm-001 master ci-build-bridge

# Apply nftables rules on the bridge: only allowlisted egress.
nft add rule inet filter ci_egress \
  iifname "ci-build-bridge" oifname != "ci-build-bridge" \
  ip daddr != { 140.82.112.0/20, 104.16.0.0/12, ... } drop
```

The VM cannot reach hosts the bridge does not allow. DNS resolution goes through a per-bridge resolver with the same allowlist.

### Step 5: Image and Snapshot Lifecycle

Build VM images deterministically and rotate frequently:

```bash
# Build the runner image.
debootstrap stable /tmp/runner-rootfs
chroot /tmp/runner-rootfs apt install -y git curl build-essential ...

# Convert to ext4.
mkfs.ext4 /var/lib/firecracker/images/runner.ext4
mount /var/lib/firecracker/images/runner.ext4 /mnt
cp -a /tmp/runner-rootfs/* /mnt/
umount /mnt

# Boot once and snapshot.
./make-snapshot.sh /var/lib/firecracker/images/runner.ext4
```

Rotate weekly: a fresh snapshot bakes in latest security updates. Old snapshots are deleted, eliminating any cumulative drift.

### Step 6: Telemetry per Job and per VM

Track per-VM metrics:

```
ci_vm_boot_seconds                    histogram
ci_vm_run_duration_seconds            histogram
ci_vm_memory_max_bytes                histogram
ci_vm_egress_bytes_total              counter
ci_vm_egress_drops_total              counter
ci_vm_kvm_exits_total                 counter
ci_jobs_completed{outcome="..."}     counter
ci_vm_kernel_version                  gauge
```

Alert on:
- `ci_vm_egress_drops_total` — VM tried to reach blocked host. May be malicious.
- `ci_vm_boot_seconds` rises — snapshot corruption or host-side resource pressure.
- `ci_vm_run_duration_seconds` p99 increases dramatically — possible DoS via crafted job.

## Expected Behaviour

| Signal | Container runner | Firecracker / Kata runner |
|--------|------------------|----------------------------|
| Job's view of kernel | Shared with all other jobs and host | Own kernel, isolated |
| Container-escape CVE impact | Lands on shared host | Lands inside the VM only |
| Cross-job filesystem state | Possible via shared cache | Each VM gets fresh ephemeral disk |
| Cross-job network observation | Possible via host network ns | Per-VM TAP, host network ns isolated |
| Boot time | <50ms (start container) | 5-20ms with snapshot, 100-300ms cold |
| Memory overhead per job | ~50MB | ~150-300MB (kernel + initial heap) |
| Storage per VM | Layers on host | Backing image + per-VM diff |

Verify the boundary holds:

```bash
# Inside the VM:
uname -a
# Linux runner-vm-fc-001 5.10.197 ... (a different kernel than the host)

# Network egress test:
curl -m 5 https://attacker.example.com
# Connection refused (host network bridge drops)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Kernel-level isolation | Defeats container-escape CVEs | Memory per job ~3x higher | Acceptable for high-trust pipelines; mix VM-isolated and container runners by trust level. |
| Snapshot-backed boot | Sub-100ms job startup | Snapshot lifecycle to manage | Automate snapshot rebuild weekly; treat snapshots as immutable, content-addressed. |
| KVM dependency | Strong isolation | Some cloud instance types disable nested virtualization | Use bare-metal or `*.metal` instances; check cloud provider's nested-virt policy. |
| Per-VM network bridge | Strong network isolation | More host-side networking config | Use a Kubernetes-native CNI (Cilium) that integrates with Kata; offloads bridge management. |
| Image rotation | Latest security updates baked in | Image build and distribution overhead | Run nightly snapshot builds; only changed packages trigger a roll. |
| Operational complexity | Higher than containers | Steep learning curve | Use a managed offering (Fly.io, Codespaces, gitpod-meta) for low-volume; self-host only for high-volume. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| KVM module unavailable on host | Firecracker fails to start | systemd journal shows `unable to open /dev/kvm` | Verify nested virtualization enabled on the host's instance type; fall back to bare-metal. |
| Snapshot corruption | Resumed VM behaves unpredictably | Job failures correlate with one snapshot revision | Rollback to previous snapshot; rebuild from clean image. |
| VM kernel CVE | Firecracker host kernel patches don't help; VM kernel is what matters | New CVE; VM kernel out-of-date | Bake patched kernels into the snapshot image; rotate snapshots on advisory. |
| Memory exhaustion at host | New jobs queue or fail to start | Prometheus shows host memory at limit | Reduce concurrent VM count or upsize host. Monitor memory headroom continuously. |
| Per-VM egress allowlist drift | New legitimate job target unblocked | Job fails with network errors at a specific step | Update the bridge nftables ruleset; document the new allowed target. |
| Kata + Pod Security Standards interaction | Pods with restricted PSA fail to schedule under Kata | Some `securityContext` fields not honored by Kata's hypervisor stack | Audit the Kata documentation for PSA compatibility; adjust profiles per workload. |

## When to Consider a Managed Alternative

Self-hosted Firecracker / Kata at scale requires KVM hosts, snapshot pipelines, network bridges, and ongoing kernel patching (10-20 hours/month for a high-volume CI program).

- **[Fly.io Machines for CI](https://fly.io/):** Firecracker-backed; pay per CPU-second; integrates with GitHub Actions via custom runner.
- **[Codespaces / Cloud Build](https://github.com/features/codespaces):** Microsoft-managed isolated runners; cost scales with usage.
- **[Buildkite Hosted Agents](https://buildkite.com/docs/agent/v3/aws/elastic-ci-stack-for-aws):** managed agent fleet with one-job-per-host options.
- **[Earthly Satellites](https://earthly.dev/satellites):** purpose-built remote build agents with strong isolation.

## Related Articles

- [Securing Self-Hosted CI/CD Runners](/articles/cicd/securing-cicd-runners/)
- [CI/CD Pipeline Egress Control](/articles/cicd/pipeline-egress-control/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [Container Registry Security](/articles/cicd/container-registry-security/)
