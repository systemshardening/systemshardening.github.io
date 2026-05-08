---
title: "runc Container Runtime Security and CVE Hardening"
description: "Harden runc-based container runtimes against escape CVEs, mount namespace attacks, and process injection—with guidance on tracking silent security fixes in runc's public git history."
slug: runc-container-runtime-security
date: 2026-05-02
lastmod: 2026-05-02
category: linux
tags: ["runc", "container-runtime", "cve", "mount-namespace", "seccomp", "apparmor", "supply-chain"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 343
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/linux/runc-container-runtime-security/index.html"
---

# runc Container Runtime Security and CVE Hardening

## Problem

runc is the OCI-compliant low-level container runtime that sits beneath Docker, containerd, Podman, and CRI-O. When a container engine receives a request to start a container, it constructs an OCI runtime bundle — a root filesystem and a `config.json` — and hands execution to runc. runc is responsible for creating Linux namespaces (mount, PID, network, UTS, IPC, user), setting up cgroups for resource limits, applying seccomp syscall filters and AppArmor profiles, pivoting the root filesystem, and finally exec-ing the container's entrypoint process. It is the last Go binary with elevated privileges before the container process starts. That boundary is where most container escape vulnerabilities live.

The CVE history of runc is a study in how a small, critical piece of infrastructure accumulates high-severity vulnerabilities in logic that operators rarely examine. CVE-2019-5736 (CVSS 8.6) demonstrated that a malicious container process could overwrite the host runc binary itself via `/proc/self/exe` by exploiting the window when runc's file descriptor remained open inside the container's mount namespace during exec. A container with write access to `/proc/self/exe` could replace runc on the host, compromising every subsequent container started on that node. CVE-2021-30465 exploited a TOCTOU (time-of-check/time-of-use) race condition in runc's mount handling: a container could use symlinks inside its rootfs to redirect a bind mount in flight, causing runc to bind-mount a host directory into the container's filesystem. This was a container escape through mount namespace manipulation, usable by any container that could trigger a volume mount. CVE-2024-21626 (the "Leaky Vessels" class) exposed yet another file descriptor leak: runc was resolving working directories via `/proc/self/fd` before completing the pivot to the container root, and a container configured with a `workingDir` of `/proc/self/fd/N` could inherit a file descriptor pointing to the host filesystem, granting read access to host paths accessible to the runc process. These are not obscure edge cases — they are fundamental to how runc sets up container filesystems, and each required changes to core logic in `libcontainer/`.

The open-source nature of runc creates a security monitoring problem that few operators appreciate. runc's CVE disclosure pattern has been inconsistent with its commit history. CVE-2024-21626 was fixed in runc 1.1.12, but the fixing commit — described as "Internally use `/proc/thread-self` rather than `/proc/self` for new configs" — was merged to the public GitHub repository at `https://github.com/opencontainers/runc` and visible for over a week before the coordinated disclosure date. Security researchers who monitor `https://github.com/opencontainers/runc/commits/main` were able to identify the commit as security-relevant from the changed code paths and the specific `/proc/` substitution before any advisory was published. CVE-2021-30465 was originally classified as low severity by several Linux distributions, despite being an exploitable container escape — the runc maintainers and distribution packagers disagreed on severity assessment, creating a window where some systems received no urgent patch signal.

Beyond named CVEs, several commits to runc's `libcontainer/` directory in the past two years have fixed clearly security-relevant race conditions and filesystem handling bugs without a CVE being filed. Commit messages like "fix symlink resolution in rootfs setup", "use `O_PATH` for directory open to avoid TOCTOU", or "ensure mount targets are validated before bind" describe changes to exactly the code paths that previous CVEs exploited — but they arrive as maintenance commits, not security advisories. An operator with no CVE-monitoring pipeline would never flag them. The implication is that operators cannot rely solely on CVE feeds to track runc security posture; they must also monitor the upstream commit stream directly.

To monitor runc security effectively, operators should maintain subscriptions across multiple channels: subscribe to `https://github.com/opencontainers/runc/security/advisories` for the GitHub advisory feed, watch `opencontainers/runc` release notes for all patch releases, use `https://osv.dev` to query runc vulnerabilities by querying `ecosystem=Go&package=github.com/opencontainers/runc`, and run `runc --version` across nodes to confirm deployed versions. The `pkg.go.dev/vuln` database also surfaces runc vulnerabilities with Go module version ranges. None of these channels is individually sufficient; the patch-gap between upstream fix and distribution package update means version auditing must run continuously.

The compounding operational factor is that operators cannot update runc in isolation. runc is bundled inside Docker Engine, containerd, and CRI-O as a vendored binary — updating runc requires updating the parent container engine package. On a system running Docker Engine 24.x, `apt upgrade runc` may install a standalone runc package that is never actually invoked, while the Docker-bundled runc at `/usr/bin/docker-runc` or inside containerd's snapshotter directory remains at the old version. Operators must upgrade the container engine itself and verify the bundled runc version post-upgrade, not assume that OS package updates reach the runc binary actually in use.

Target systems: runc 1.1.x, containerd 1.7+, Docker Engine 25+, CRI-O 1.28+, Linux kernel ≥ 5.15.

## Threat Model

1. **Working directory / file descriptor leak (CVE-2024-21626 class):** A container workload is deployed with a crafted `workingDir` or volume configuration that causes runc to leave a file descriptor referencing the host filesystem open inside the container's mount namespace. The container process reads `/proc/self/fd/` to enumerate open descriptors, identifies one pointing to a host path, and uses it to traverse the host filesystem — reading secrets, SSH keys, or cloud credential files accessible to the runc process (typically root).

2. **Mount namespace symlink race (CVE-2021-30465 class):** A container with the ability to influence its own volume mounts — either through a privileged container spec or through a Kubernetes admission path that allows user-controlled `hostPath` volumes — sets up symlinks inside its rootfs that redirect a bind mount target while runc is processing the mount list. The race causes a host directory to be bind-mounted into the container, giving the container process read/write access to host filesystem paths outside its intended root.

3. **Patch-gap attacker:** An attacker monitors `https://github.com/opencontainers/runc/commits/main`, watching for commits that touch `libcontainer/rootfs*.go`, `libcontainer/mount*.go`, or `libcontainer/nsenter/`. When a commit appears that modifies `/proc/self` to `/proc/thread-self` or replaces an `os.Open` with `os.OpenFile` using `O_PATH|O_NOFOLLOW`, the attacker recognises it as a security fix and begins constructing a proof-of-concept before the coordinated disclosure date. Organisations still running the runc version bundled with Docker Engine 24.x or an older containerd release are exploitable throughout the patch-gap period, which has historically ranged from days to weeks.

4. **Supply chain attacker:** runc is distributed as a compiled binary embedded in container engine packages. A compromised package repository — or a compromised build pipeline for a downstream distribution of Docker or containerd — could deliver a runc binary with a backdoor in the namespace setup path, the seccomp application logic, or the pivot_root call. Because runc executes with elevated privileges and operators rarely checksum the runc binary against upstream releases, a modified runc binary could persist undetected across container engine upgrades.

The blast radius of a successful runc escape is the full privileges of the runc process on the host — typically root or a near-root user with `CAP_SYS_ADMIN`. From the host, the attacker can pivot to any workload on the node, access secrets mounted into other containers, and move laterally to the control plane if the node carries kubeconfig credentials or instance metadata credentials with cluster permissions. Blast radius reduction requires defence in depth: seccomp, AppArmor, no-new-privileges, and rootless mode each add a layer that may prevent exploitation even when runc itself is vulnerable.

## Configuration / Implementation

### Checking runc version and CVE exposure

The first step is establishing what version of runc is actually executing on each node, not what the OS package manager reports.

```bash
# Check the runc binary invoked by the system
runc --version

# Check containerd's bundled runc
containerd --version

# On Docker systems, check the Docker-bundled runc
docker info --format '{{.RuncCommit.ID}}'

# Locate all runc binaries on a node (there may be multiple)
find /usr /opt -name "runc" -type f 2>/dev/null | while read -r bin; do
  echo "$bin: $($bin --version 2>&1 | head -1)"
done
```

To audit runc versions across a Kubernetes cluster, use ephemeral debug containers:

```bash
kubectl get nodes -o wide | awk 'NR>1 {print $1}' | \
  xargs -I{} kubectl debug node/{} \
    -it --image=busybox:latest -- \
    sh -c "chroot /host runc --version"
```

Cross-reference the installed version against the OSV database:

```bash
# Query OSV for runc vulnerabilities affecting a specific version
curl -s "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "1.1.9",
    "package": {"name": "github.com/opencontainers/runc", "ecosystem": "Go"}
  }' | jq '.vulns[].id'
```

### Seccomp profiles

The default Docker/containerd seccomp profile blocks approximately 44 syscalls. For higher-assurance workloads, create a custom restrictive profile that additionally blocks syscalls relevant to credential theft, NUMA manipulation, and key material access:

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": ["accept", "accept4", "access", "bind", "brk", "clone",
                "close", "connect", "dup", "dup2", "execve", "exit",
                "exit_group", "fcntl", "fstat", "futex", "getcwd",
                "getdents64", "getegid", "geteuid", "getgid", "getpid",
                "getppid", "getrandom", "getuid", "ioctl", "listen",
                "lseek", "mmap", "mprotect", "munmap", "nanosleep",
                "newfstatat", "open", "openat", "pipe", "pipe2",
                "poll", "prctl", "pread64", "pwrite64", "read",
                "readlink", "readlinkat", "recvfrom", "recvmsg",
                "rename", "rt_sigaction", "rt_sigprocmask",
                "rt_sigreturn", "sendmsg", "sendto", "set_tid_address",
                "setgid", "setgroups", "setuid", "socket", "stat",
                "statfs", "symlink", "tgkill", "uname", "unlink",
                "wait4", "write", "writev"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["add_key", "keyctl", "request_key",
                "mbind", "move_pages", "set_mempolicy",
                "perf_event_open", "ptrace",
                "process_vm_readv", "process_vm_writev",
                "kexec_load", "kexec_file_load",
                "create_module", "init_module", "finit_module",
                "delete_module"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
```

Apply this profile in Docker:

```bash
docker run --security-opt seccomp=/etc/docker/seccomp-restrictive.json \
  --name myapp myimage:latest
```

Apply via Kubernetes using a `SeccompProfile` object (Kubernetes 1.22+):

```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/restrictive.json
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
```

Verify seccomp is active for a running container process:

```bash
# Get the PID of the container process from the host
CPID=$(docker inspect --format '{{.State.Pid}}' myapp)
grep Seccomp /proc/$CPID/status
# Output: Seccomp:        2   (2 = filter mode, 1 = strict, 0 = disabled)
```

### AppArmor profile for containers

The `docker-default` AppArmor profile provides a baseline, but hardened workloads benefit from a custom profile that denies `mount`, restricts `/proc` and `/sys` writes, and blocks dangerous file paths:

```
#include <tunables/global>

profile hardened-container flags=(attach_disconnected, mediate_deleted) {
  #include <abstractions/base>

  # Allow network
  network,

  # Deny writes to kernel interfaces
  deny /proc/sysrq-trigger w,
  deny /proc/sys/** w,
  deny /sys/** w,

  # Deny mount operations entirely
  deny mount,
  deny umount,
  deny pivot_root,

  # Deny writes to /proc/self/exe (mitigate CVE-2019-5736 class)
  deny /proc/*/exe w,
  deny /proc/*/mem w,

  # Deny access to host device nodes
  deny /dev/sd* rwklx,
  deny /dev/nvme* rwklx,

  # Allow container filesystem access
  / r,
  /** rwkl,
  /tmp/** rwkl,
  /run/** rwkl,

  # Allow container runtime signals
  signal (send, receive) peer=unconfined,
  ptrace (trace) peer=unconfined,
}
```

Load and apply the profile:

```bash
# Load the profile
apparmor_parser -r -W /etc/apparmor.d/hardened-container

# Apply to a Docker container
docker run --security-opt apparmor=hardened-container \
  --name myapp myimage:latest

# Verify the profile is applied
CPID=$(docker inspect --format '{{.State.Pid}}' myapp)
cat /proc/$CPID/attr/current
# Output: hardened-container (enforce)
```

Apply to Kubernetes pods via annotation:

```yaml
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/hardened-container
```

### No-new-privileges enforcement

The `no-new-privileges` secbit prevents a container process from gaining additional privileges through setuid binaries or file capabilities after it starts:

```bash
# Docker
docker run --security-opt=no-new-privileges:true myimage:latest

# Verify from the host
CPID=$(docker inspect --format '{{.State.Pid}}' myapp)
grep NoNewPrivs /proc/$CPID/status
# Output: NoNewPrivs:     1
```

In Kubernetes pod specs, enforce this at both the pod and container level:

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

Enforce `no-new-privileges` cluster-wide using a `PodSecurityAdmission` standard or a validating webhook that rejects pods where `allowPrivilegeEscalation` is `true` or unset.

### Read-only root filesystem

A read-only root filesystem prevents a container escape from using the container filesystem to stage payloads, and stops many post-exploitation techniques that require writing to `/tmp` or application directories:

```bash
# Docker: read-only root with writable tmpfs for runtime directories
docker run \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /run:rw,noexec,nosuid,size=16m \
  myimage:latest
```

In Kubernetes:

```yaml
containers:
- name: app
  securityContext:
    readOnlyRootFilesystem: true
  volumeMounts:
  - name: tmp
    mountPath: /tmp
  - name: run
    mountPath: /run
volumes:
- name: tmp
  emptyDir:
    medium: Memory
    sizeLimit: 64Mi
- name: run
  emptyDir:
    medium: Memory
    sizeLimit: 16Mi
```

### Rootless containers as mitigation

Running containerd or Podman in rootless mode means runc itself executes within a user namespace, mapping the container's root user to an unprivileged UID on the host. A successful runc escape gives the attacker the host UID of the rootless user — typically UID 100000+ — rather than UID 0. This dramatically reduces the blast radius of container escape CVEs.

```bash
# Check if containerd is running rootless
systemctl --user status containerd

# Run a rootless container with Podman (uses runc or crun in user namespace)
podman run --rm -it alpine sh

# Verify the host UID mapping
podman unshare cat /proc/self/uid_map
# Output: 0    100000    65536
```

The trade-off is real: rootless mode requires `/etc/subuid` and `/etc/subgid` configuration, breaks workloads that require `CAP_NET_ADMIN` or `CAP_SYS_ADMIN`, and is incompatible with GPU operator configurations that rely on device access at UID 0. Assess per-cluster workload requirements before enforcing rootless globally.

### Monitoring runc for silent security fixes

Because security-relevant runc changes arrive as maintenance commits without CVE assignment, a commit-monitoring script adds a detection layer that CVE feeds miss:

```bash
#!/usr/bin/env bash
# monitor-runc-commits.sh
# Run daily via cron. Requires: gh CLI authenticated, jq

REPO="opencontainers/runc"
SINCE=$(date -d "1 day ago" --iso-8601=seconds)
ALERT_PATHS=(
  "libcontainer/rootfs"
  "libcontainer/mount"
  "libcontainer/nsenter"
  "libcontainer/process_linux"
  "libcontainer/container_linux"
)

# Fetch recent commits
COMMITS=$(gh api "repos/${REPO}/commits?since=${SINCE}&per_page=50" \
  --jq '.[] | {sha: .sha, message: .commit.message, url: .html_url}')

# For each commit, check if it touches sensitive paths
echo "$COMMITS" | jq -r '.sha' | while read -r sha; do
  FILES=$(gh api "repos/${REPO}/commits/${sha}" \
    --jq '.files[].filename')

  for path in "${ALERT_PATHS[@]}"; do
    if echo "$FILES" | grep -q "$path"; then
      MSG=$(echo "$COMMITS" | jq -r --arg sha "$sha" \
        'select(.sha == $sha) | .message | split("\n")[0]')
      URL=$(echo "$COMMITS" | jq -r --arg sha "$sha" \
        'select(.sha == $sha) | .url')
      echo "ALERT: Commit ${sha} touches ${path}"
      echo "  Message: ${MSG}"
      echo "  URL: ${URL}"
      # Send to alerting system (Slack webhook, PagerDuty, etc.)
      # curl -s -X POST "$SLACK_WEBHOOK" \
      #   -d "{\"text\":\"runc security-relevant commit: ${MSG}\n${URL}\"}"
      break
    fi
  done
done
```

Install as a daily cron job:

```bash
# /etc/cron.d/runc-monitor
0 8 * * * secops /usr/local/bin/monitor-runc-commits.sh >> /var/log/runc-monitor.log 2>&1
```

Cross-reference any flagged commits with the OSV API to determine if a CVE already exists:

```bash
# Check if a specific runc version has known vulns
RUNC_VERSION=$(runc --version | awk '/runc version/{print $3}')
curl -s "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d "{
    \"version\": \"${RUNC_VERSION}\",
    \"package\": {\"name\": \"github.com/opencontainers/runc\", \"ecosystem\": \"Go\"}
  }" | jq '.vulns // [] | length'
```

Use Dependabot or Renovate to track container engine packages that bundle runc. In a Renovate configuration:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["containerd/containerd", "moby/moby"],
      "matchUpdateTypes": ["patch", "minor"],
      "automerge": false,
      "labels": ["security", "container-runtime"],
      "prPriority": 10
    }
  ]
}
```

## Expected Behaviour

| Signal | Unpatched / default runc | Hardened runc |
|--------|--------------------------|---------------|
| `/proc/self/fd` escape attempt (CVE-2024-21626 class) | Container process reads host filesystem path via inherited fd; escape succeeds | runc uses `/proc/thread-self` internally; fd closed before container exec; no host path accessible |
| Symlink race in volume mount (CVE-2021-30465 class) | Attacker-controlled symlink redirects bind mount to host directory during runc mount processing | Mount targets validated with `O_PATH|O_NOFOLLOW`; symlink race window eliminated; mount rejected |
| `setuid` binary execution inside container | Container process gains elevated capabilities via setuid binary | `no-new-privileges` secbit set; setuid binary executes without privilege elevation; `NoNewPrivs: 1` in `/proc/pid/status` |
| Container attempts `mount()` syscall | Mount succeeds if container has `CAP_SYS_ADMIN`; potential namespace escape vector | AppArmor `deny mount` rule triggers; mount syscall denied with `EACCES`; kernel audit log entry generated |
| New security-relevant commit to `libcontainer/rootfs*.go` | No alert; patch gap opens silently; operators unaware until CVE published or exploitation observed | `monitor-runc-commits.sh` fires within 24 hours; commit flagged for review; version pinning evaluated before patch available |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Rootless mode | runc escape yields unprivileged host UID, not root; dramatically reduces blast radius of CVE-2024-21626-class exploits | Incompatible with GPU operator, many `hostNetwork` workloads, and containers requiring `CAP_NET_ADMIN`; requires `subuid`/`subgid` configuration per user | Enable rootless selectively on stateless workload node pools; keep GPU and network-intensive nodes on root containerd with compensating controls |
| Strict seccomp allowlist | Blocks large class of kernel exploitation primitives; removes `ptrace`, `process_vm_readv`, key management syscalls | Legitimate applications that call `keyctl` (e.g., SSSD, some crypto libraries) or `perf_event_open` (profiling tools) will receive `ENOSYS` or `EPERM` at runtime | Run containers in `SCMP_ACT_LOG` mode first; collect denied syscalls with `ausearch -m SECCOMP`; add required syscalls back to profile before enforcing |
| Read-only root filesystem | Eliminates post-exploitation payload staging on container filesystem; reduces attack surface for web shells | Many application frameworks write to `/tmp`, `/var`, or application directories at startup; containers fail to start or crash at runtime | Mount writable `emptyDir` or `tmpfs` volumes at specific paths; work with application team to identify required write paths before enforcing |
| Monitoring runc commits | Detects security-relevant changes before CVE assignment; reduces patch gap from weeks to days | Engineering overhead to triage false positives; refactoring commits in `libcontainer/` touch the same paths as security fixes | Tune `ALERT_PATHS` to the highest-risk files; add keyword filtering for commit messages containing `TOCTOU`, `symlink`, `fd leak`, `O_PATH`; deduplicate against known CVEs via OSV API |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Seccomp profile blocks legitimate application syscall | Container starts but application crashes at runtime with `operation not permitted` or exits with code 1; strace shows `EPERM` on a syscall not in the allowlist | `ausearch -m SECCOMP -ts recent` on the node; `dmesg | grep seccomp`; application logs showing unexpected permission errors | Switch profile to `SCMP_ACT_LOG` temporarily; capture denied syscalls; add them to profile allowlist; redeploy with updated profile; do not remove seccomp entirely |
| AppArmor profile denies container start | `docker run` or pod admission fails with "permission denied" during container startup; runc exits non-zero; Kubernetes shows `CreateContainerError` | `journalctl -k | grep apparmor`; `dmesg | grep apparmor`; `aa-status` showing profile in enforce mode | Switch profile to complain mode with `aa-complain /etc/apparmor.d/hardened-container`; collect denials; update profile rules; reload with `apparmor_parser -r`; switch back to enforce |
| runc version mismatch after containerd upgrade | New containerd installed but runc binary inside containerd's path is different version from system runc; `docker info` reports different runc commit than `runc --version` | `find /usr /opt -name runc -type f -exec {} --version \;`; compare SHA against containerd release notes; `containerd-shim-runc-v2 --version` | Reinstall containerd from official package to ensure bundled runc matches release; pin containerd version in package manager; verify with `docker info --format '{{.RuncCommit.ID}}'` post-upgrade |
| Rootless mode breaks GPU workloads | CUDA containers fail with device access errors; NVIDIA device plugin cannot enumerate GPUs for rootless containers; pod remains in `Pending` or `CrashLoopBackOff` | `nvidia-smi` inside container fails; node logs show device cgroup permission denied; Kubernetes events on pod | Separate node pools: rootless for stateless workloads, root containerd for GPU nodes; use Kubernetes node labels and `nodeSelector` to route GPU workloads to root-containerd nodes |
| Patch-gap exploited before monitoring alert fires | Anomalous host filesystem access from container process; unexpected files read from `/proc/self/fd/` paths; audit logs show container UID accessing host paths | `auditd` rules on `/proc/*/fd/**` access from container PIDs; Falco rule for `fd.typechar = f and proc.name = runc`; network anomaly from compromised node | Isolate affected node immediately; drain with `kubectl drain`; preserve forensic evidence before reimaging; rotate all credentials accessible from the node; post-incident: reduce monitoring interval from daily to hourly |

## Related Articles

- [Linux User Namespace Security](/articles/linux/linux-user-namespace-security/)
- [seccomp-bpf for Non-Container Workloads](/articles/linux/seccomp-bpf-non-container/)
- [AppArmor Profiles for Custom Applications](/articles/linux/apparmor/)
- [RuntimeClass: gVisor and Kata Containers](/articles/kubernetes/runtimeclass-gvisor-kata/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
