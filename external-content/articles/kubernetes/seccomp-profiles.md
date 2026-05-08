---
title: "Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles"
description: "The default container runtime allows approximately 300 syscalls. A compromised container can use unshare to create new namespaces, clone to spawn..."
slug: "seccomp-profiles"
date: 2026-02-09
lastmod: 2026-02-09
category: "kubernetes"
tags: ["kubernetes", "seccomp", "syscalls", "container-security", "runtime-security"]
personas: ["platform-engineer", "security-engineer"]
article_number: 19
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Aqua"
    id: 123
    category: "runtime-security"
premium_pack: "seccomp-profile-collection"
published: true
layout: article.njk
permalink: "/articles/kubernetes/seccomp-profiles/index.html"
---

# Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles

## Problem

The default container runtime allows approximately 300 syscalls. A compromised container can use `unshare` to create new namespaces, `clone` to spawn processes in those namespaces, `mount` to attach host filesystems, and `ptrace` to trace and manipulate other processes. These are the building blocks of container escape exploits.

Seccomp (secure computing mode) is a Linux kernel feature that restricts which system calls a process can make. When applied to containers, it reduces the kernel attack surface from 300+ syscalls down to the 40-80 that the workload actually needs. If a compromised container tries to call `unshare` or `ptrace` and the profile blocks it, the exploit fails.

The challenges are real:

- **Profile generation is manual and slow.** Tracing a workload with `strace` or reading OCI runtime logs to discover which syscalls it needs takes 2-4 hours per workload. Miss a syscall and the application crashes. Include too many and you have not meaningfully reduced the attack surface.
- **RuntimeDefault is a starting point, not a solution.** [Kubernetes](https://kubernetes.io) ships with a `RuntimeDefault` profile that blocks about 50 of the most dangerous syscalls. It is a reasonable baseline, but it still allows 250+ syscalls that most workloads never use.
- **Testing is fragile.** A profile that works during normal operation may fail during edge cases: garbage collection spikes, TLS renegotiation, or signal handling under load.
- **Deployment across workloads does not scale.** Each application (nginx, postgres, redis, node.js, go binaries) needs a different profile. Maintaining per-workload profiles across dozens of services is a management burden.

This article covers generating profiles from observed syscall usage, writing custom profiles for common workloads, deploying them in Kubernetes, and testing them without breaking production.

**Target systems:** Kubernetes 1.29+ with [containerd](https://containerd.io) or [CRI-O](https://cri-o.io). Seccomp support is built into the kernel (Linux 3.17+) and enabled by default in all modern container runtimes.

## Threat Model

- **Adversary:** Attacker with code execution inside a container (RCE via application vulnerability, compromised dependency, or malicious container image).
- **Access level:** Unprivileged process inside a container with access to all syscalls allowed by the runtime.
- **Objective:** Container escape via kernel exploitation. Common techniques include namespace manipulation (`unshare`, `clone`), filesystem escape (`mount`, `open_by_handle_at`), process manipulation (`ptrace`, `process_vm_writev`), and kernel module loading (`init_module`, `finit_module`).
- **Blast radius:** Without seccomp, a kernel vulnerability reachable via any allowed syscall can lead to full node compromise. With a tight seccomp profile, the attacker can only reach kernel code paths for the 40-80 allowed syscalls, reducing the exploitable surface by 70-80%.

## Configuration

### Step 1: Enable RuntimeDefault as Minimum Baseline

Before writing custom profiles, ensure every pod runs with at least the `RuntimeDefault` profile. This blocks the most dangerous syscalls (`unshare`, `mount`, `ptrace`, `init_module`) with zero per-workload effort.

```yaml
# pod-with-runtime-default.yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-app
  namespace: production
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: web
      image: registry.example.com/web-app:1.4.2
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 1000
```

To enforce `RuntimeDefault` cluster-wide, use Pod Security Standards:

```bash
# Enforce restricted PSS (requires RuntimeDefault or Localhost seccomp)
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

### Step 2: Generate a Custom Profile from Observed Syscalls

Use the Security Profiles Operator (SPO) to record syscalls from a running workload. SPO runs as a DaemonSet and uses eBPF or audit logs to capture syscall usage.

```bash
# Install Security Profiles Operator
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/main/deploy/operator.yaml

# Wait for operator to be ready
kubectl -n security-profiles-operator wait --for=condition=ready pod -l app=security-profiles-operator --timeout=120s
```

Create a recording profile for a workload:

```yaml
# seccomp-recording.yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: SeccompProfile
metadata:
  name: nginx-recording
  namespace: production
  annotations:
    spo.x-k8s.io/recording: "true"
spec:
  defaultAction: SCMP_ACT_LOG
  architectures:
    - SCMP_ARCH_X86_64
    - SCMP_ARCH_AARCH64
```

Alternatively, use `strace` to discover syscalls manually:

```bash
# Run the container with strace to capture all syscalls
# Do this in a test environment, not production
docker run --rm -it --security-opt seccomp=unconfined \
  strace -c -f -S name registry.example.com/nginx:1.27.0 &

# Exercise the application: send HTTP requests, trigger all code paths
curl http://localhost:8080/
curl http://localhost:8080/api/health
# Run your full test suite against the application

# strace output shows syscall counts:
# % time  seconds  usecs/call  calls  errors  syscall
# 15.23   0.002341      11      213          epoll_wait
# 12.87   0.001978       3      659          write
# ...
```

### Step 3: Write a Custom Profile

Based on the recorded syscalls, write a seccomp profile in JSON format.

**Custom profile for nginx:**

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "accept4", "access", "arch_prctl", "bind", "brk",
        "capget", "capset", "chdir", "clone", "close",
        "connect", "dup2", "epoll_create", "epoll_ctl",
        "epoll_wait", "eventfd2", "execve", "exit",
        "exit_group", "fchmod", "fchown", "fcntl",
        "fstat", "fstatfs", "futex", "getdents64",
        "getegid", "geteuid", "getgid", "getpid",
        "getppid", "getuid", "ioctl", "listen",
        "lseek", "madvise", "mmap", "mprotect",
        "munmap", "nanosleep", "newfstatat", "openat",
        "pipe2", "prctl", "pread64", "prlimit64",
        "pwrite64", "read", "recvfrom", "recvmsg",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "sched_getaffinity", "sendfile", "sendmsg",
        "set_robust_list", "set_tid_address", "setgid",
        "setgroups", "setuid", "setsockopt", "shutdown",
        "sigaltstack", "socket", "socketpair", "stat",
        "statfs", "sysinfo", "uname", "unlink",
        "wait4", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Custom profile for a Go HTTP service (minimal):**

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "accept4", "arch_prctl", "bind", "brk", "clone",
        "clone3", "close", "connect", "epoll_create1",
        "epoll_ctl", "epoll_pwait", "execve", "exit",
        "exit_group", "fcntl", "fstat", "futex",
        "getdents64", "getpid", "getppid", "getrandom",
        "getsockname", "getsockopt", "listen", "lseek",
        "madvise", "mmap", "mprotect", "munmap",
        "nanosleep", "newfstatat", "openat", "pipe2",
        "prctl", "pread64", "read", "recvfrom",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "sched_getaffinity", "sched_yield", "sendto",
        "set_robust_list", "set_tid_address", "setgid",
        "setgroups", "setsockopt", "setuid", "sigaltstack",
        "socket", "tgkill", "uname", "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

### Step 4: Deploy Profiles to Nodes

Seccomp profiles must exist on the node filesystem. Place them in the kubelet seccomp directory (default: `/var/lib/kubelet/seccomp/`).

**Option A: Use the Security Profiles Operator (recommended)**

```yaml
# seccomp-profile-nginx.yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: SeccompProfile
metadata:
  name: nginx-hardened
  namespace: production
spec:
  defaultAction: SCMP_ACT_ERRNO
  architectures:
    - SCMP_ARCH_X86_64
    - SCMP_ARCH_AARCH64
  syscalls:
    - names:
        - accept4
        - access
        - arch_prctl
        - bind
        - brk
        - close
        - connect
        - epoll_create
        - epoll_ctl
        - epoll_wait
        - exit
        - exit_group
        - fcntl
        - fstat
        - futex
        - getdents64
        - getpid
        - ioctl
        - listen
        - mmap
        - mprotect
        - munmap
        - nanosleep
        - newfstatat
        - openat
        - read
        - recvfrom
        - rt_sigaction
        - rt_sigprocmask
        - sendfile
        - setsockopt
        - socket
        - write
        - writev
      action: SCMP_ACT_ALLOW
```

**Option B: DaemonSet to distribute profiles**

```yaml
# seccomp-installer.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: seccomp-profile-installer
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: seccomp-installer
  template:
    metadata:
      labels:
        app: seccomp-installer
    spec:
      initContainers:
        - name: install-profiles
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              cp /profiles/*.json /host-seccomp/
              echo "Seccomp profiles installed"
          volumeMounts:
            - name: profiles
              mountPath: /profiles
            - name: host-seccomp
              mountPath: /host-seccomp
      containers:
        - name: pause
          image: registry.k8s.io/pause:3.9
      volumes:
        - name: profiles
          configMap:
            name: seccomp-profiles
        - name: host-seccomp
          hostPath:
            path: /var/lib/kubelet/seccomp
            type: DirectoryOrCreate
```

### Step 5: Apply Profiles to Pods

```yaml
# pod-with-custom-profile.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  namespace: production
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/nginx-hardened.json
  containers:
    - name: nginx
      image: registry.example.com/nginx:1.27.0
      ports:
        - containerPort: 8080
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        runAsUser: 101
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
          add:
            - NET_BIND_SERVICE
```

Or when using the Security Profiles Operator:

```yaml
# pod-with-spo-profile.yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  namespace: production
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/production/nginx-hardened.json
  containers:
    - name: nginx
      image: registry.example.com/nginx:1.27.0
```

### Step 6: Testing Profiles Before Enforcement

Start with `SCMP_ACT_LOG` instead of `SCMP_ACT_ERRNO` to log blocked syscalls without killing the process:

```json
{
  "defaultAction": "SCMP_ACT_LOG",
  "syscalls": [
    {
      "names": ["accept4", "read", "write"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

```bash
# Check kernel audit logs for seccomp violations
sudo journalctl -k | grep "seccomp"
# or
sudo dmesg | grep "seccomp"
# Output: audit: type=1326 audit(...): auid=4294967295 uid=101
#   gid=101 ses=4294967295 pid=1234 comm="nginx"
#   sig=0 syscall=39 compat=0 ip=0x... code=0x7ffc0000

# Decode syscall number to name:
ausyscall 39
# Output: getpid
```

Run your full test suite with the profile in log mode, then review the audit log for any syscalls that were logged (would be blocked in enforce mode). Add those syscalls to the allowlist.

```bash
# Count violations per syscall during testing:
sudo dmesg | grep seccomp | awk '{print $NF}' | sort | uniq -c | sort -rn
```

## Expected Behaviour

After deploying seccomp profiles:

- Pods start normally and pass all health checks
- Application test suites pass with zero seccomp violations
- `dmesg | grep seccomp` shows no audit entries for profiled pods (in enforce mode, blocked calls return EPERM; in log mode, they appear in the audit log)
- Attempting a blocked syscall returns `EPERM` (Operation not permitted)
- Container escape exploits that rely on `unshare`, `mount`, or `ptrace` fail immediately
- The Security Profiles Operator status shows profiles as "Installed" on all nodes

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| RuntimeDefault for all pods | Blocks ~50 dangerous syscalls with zero per-workload effort | May block legitimate syscalls in specialized workloads (JVM, eBPF tools) | Start with RuntimeDefault; create custom profiles only for workloads that fail |
| Custom per-workload profiles | Reduces syscall surface by 70-80% | Profile may miss syscalls used in rare code paths (GC, TLS renegotiation, signal handling) | Test under load, during garbage collection, and during TLS operations. Use SCMP_ACT_LOG for 1-2 weeks before enforcing |
| SCMP_ACT_ERRNO (hard block) | Blocked syscalls immediately fail | Application crashes if the profile is incomplete | Always test with SCMP_ACT_LOG first. Keep the RuntimeDefault profile as a quick fallback |
| Profile maintenance per workload | Each application update may introduce new syscalls | Application updates break if new syscalls are not in the profile | Include seccomp profile testing in the CI/CD pipeline. Re-record profiles when upgrading major versions |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Profile too restrictive | Application crashes with EPERM errors; pods enter CrashLoopBackOff | Application logs show "operation not permitted"; `dmesg` shows seccomp audit entries | Switch to SCMP_ACT_LOG, identify the missing syscall, add it to the profile, redeploy |
| Profile not found on node | Pod fails to start with "cannot load seccomp profile" error | `kubectl describe pod` shows the error; pod stays in ContainerCreating state | Verify the profile exists at `/var/lib/kubelet/seccomp/<path>` on the node. Re-deploy the DaemonSet or SPO profile |
| Profile applied to wrong architecture | Syscall numbers differ between x86_64 and ARM64; wrong calls are blocked | Pods crash on ARM nodes but work on x86 nodes | Include both `SCMP_ARCH_X86_64` and `SCMP_ARCH_AARCH64` in the profile |
| Runtime upgrade changes default profile | Container runtime update changes which syscalls RuntimeDefault blocks | Application failures after node upgrade | Pin container runtime versions. Test RuntimeDefault behaviour after upgrades in staging |
| SPO operator crash | New profiles are not distributed to nodes; existing profiles continue to work | SPO pods in CrashLoopBackOff; new SeccompProfile resources stay in "Pending" state | Restart SPO. Existing profiles on nodes are not affected (they are files on disk) |

## When to Consider a Managed Alternative

**Transition point:** Generating custom seccomp profiles for 20+ workloads at 2-4 hours each is 40-80 hours of effort. Maintaining those profiles across application updates, runtime upgrades, and new services becomes a continuous task. When profile generation and maintenance consume more than 8 hours per month, automated profiling tools pay for themselves.

**Recommended providers:**

- **[Sysdig](https://sysdig.com):** Automated seccomp profile generation from observed runtime behaviour. Profiles are generated from production traffic without manual strace sessions. Includes drift detection when an application starts using new syscalls after an update.
- **[Aqua](https://www.aquasec.com):** Runtime profiling that builds seccomp profiles automatically. Integrates with CI/CD to validate profiles against test suite runs before deployment.

**What you still control:** The decision of which profile to apply to each workload, the testing and validation process, and the enforcement mode (log vs. block). Managed tools automate the discovery and generation steps.

**Premium content pack:** Pre-built, tested seccomp profiles for nginx, postgres, redis, Node.js, Go HTTP services, and Python Flask/Django. Each profile includes the syscall list, architecture support, and a test script to validate the profile against the running workload.


## Related Articles

- [Runtime Security with Falco on Kubernetes: Rules, Tuning, and Response Automation](/articles/kubernetes/falco-runtime-security/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
- [Kubernetes API Server Hardening: Flags, Authentication, and Audit Logging](/articles/kubernetes/api-server-hardening/)
- [Kubelet Security Configuration: Authentication, Authorization, and Read-Only Port](/articles/kubernetes/kubelet-security/)
