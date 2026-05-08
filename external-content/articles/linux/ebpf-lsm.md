---
title: "eBPF-LSM (lsm_bpf): Kernel Security Policy as Hot-Loadable BPF Programs"
description: "lsm_bpf attaches eBPF programs to LSM hooks. Define security policy in code, push without reboot, audit at the syscall boundary. AppArmor for cloud-native systems."
slug: "ebpf-lsm"
date: 2026-04-29
lastmod: 2026-04-29
category: "linux"
tags: ["ebpf", "lsm", "linux", "security", "kernel", "cloud-native"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 215
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/ebpf-lsm/index.html"
---

# eBPF-LSM (lsm_bpf): Kernel Security Policy as Hot-Loadable BPF Programs

## Problem

Linux Security Modules (LSMs) — AppArmor, SELinux, Smack — define security policy at kernel hooks: every file open, network operation, capability check passes through the LSM, which decides allow / deny. Two long-standing limits:

- **Policy authoring is painful.** SELinux policy is a custom DSL; AppArmor is more readable but limited; both require recompilation or restart for substantial changes.
- **Policy distribution is operational.** Updating an AppArmor profile means updating filesystem files; cluster-wide propagation is a per-host concern; no atomic rollout.

`lsm_bpf` (kernel 5.7+) attaches eBPF programs to LSM hooks. The same hooks AppArmor and SELinux use are now programmable in C / Rust / via libbpf, loaded at runtime, and observable through normal eBPF tooling. By 2026 the production examples are mature:

- **Cilium Tetragon** uses BPF LSM for runtime enforcement of process and file policies.
- **Falco's BPF probes** can attach to LSM hooks for richer event capture.
- **Cilium's Network policy** (in some configurations) uses BPF LSM for socket-level enforcement.
- **Custom internal policies** in cloud providers' Linux base images.

Compared to AppArmor:

- BPF LSM policies compile to BPF bytecode; loaded via `bpf()` syscall; live on the kernel's verifier-checked path.
- Hot reload: replacing a policy doesn't reboot or restart anything.
- Policy is C / Rust source, version-controlled like any other code.
- Same observability primitives as eBPF tracing — counters, perf events, ring buffers.
- Strict cloud-native shape: a single binary contains the policy; deploy via DaemonSet.

The specific gaps in default Linux:

- AppArmor / SELinux profiles are filesystem-based; require config-management for distribution.
- Profile updates require reload (AppArmor) or full system relabel (SELinux).
- Policy debugging is per-host; no native observability into rule hits.
- Custom policies for ephemeral-shaped infrastructure (per-Pod, per-tenant) are awkward to express.

This article covers writing BPF LSM programs, deploying via libbpf-bootstrap or BCC, integration with Cilium / Tetragon, performance characteristics, and the hardening patterns that BPF LSM uniquely enables.

**Target systems:** Linux kernel 5.13+ (KFunc support); 6.0+ for stable BPF token authentication; `CONFIG_BPF_LSM=y`, `CONFIG_LSM` includes `bpf`. Most distributions in 2026 ship this enabled (Ubuntu 24.04, RHEL 10, Fedora 41+).

## Threat Model

- **Adversary 1 — Compromised root inside a container:** wants to bypass standard syscall filters via uncommon paths (uncovered by seccomp).
- **Adversary 2 — Container escape attempt via known kernel CVE:** seeks to perform unusual capability or namespace operations.
- **Adversary 3 — Insider with privileged access** modifying critical files outside expected work areas.
- **Adversary 4 — Workload anomaly** doing legitimate-looking but risky operations (mounting hostPath, opening /proc/<pid>/mem, etc.).
- **Access level:** Adversary 1-2 have root inside a container. Adversary 3 has interactive shell. Adversary 4 has standard workload privilege.
- **Objective:** Bypass the workload's intended capability surface, escape the container, persist on the host, exfiltrate sensitive data.
- **Blast radius:** Without LSM enforcement, the kernel grants the operation if standard DAC permits. With BPF LSM, every operation passes through the policy; deny decisions are immediate.

## Configuration

### Step 1: Verify Kernel Support

```bash
# Check that BPF LSM is enabled.
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
# CONFIG_BPF_LSM=y

cat /sys/kernel/security/lsm
# capability,landlock,lockdown,yama,integrity,apparmor,bpf

# bpf must appear in the active LSM list. If absent, edit kernel cmdline:
# lsm=...,bpf
```

### Step 2: Write a Simple Policy

Example: deny `/etc/shadow` reads from any process named `unprivileged`.

```c
// shadow_protect.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define EACCES 13

SEC("lsm/file_open")
int BPF_PROG(file_open_check, struct file *file)
{
    char filename[256] = {};
    char comm[16] = {};
    bpf_probe_read_kernel_str(filename, sizeof(filename),
        BPF_CORE_READ(file, f_path.dentry, d_name.name));
    bpf_get_current_comm(comm, sizeof(comm));

    /* Match: process named "unprivileged" trying to read "shadow". */
    bool is_target = (
        __builtin_memcmp(comm, "unprivileged", 12) == 0 &&
        __builtin_memcmp(filename, "shadow", 6) == 0
    );

    if (is_target) {
        bpf_printk("DENY: %s tried to open %s\n", comm, filename);
        return -EACCES;
    }
    return 0;   /* allow */
}

char LICENSE[] SEC("license") = "GPL";
```

Compile with libbpf-bootstrap:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I /usr/include/x86_64-linux-gnu \
  -c shadow_protect.bpf.c \
  -o shadow_protect.bpf.o
```

### Step 3: Load the Policy

```bash
# bpftool load + attach.
sudo bpftool prog load shadow_protect.bpf.o /sys/fs/bpf/shadow_protect
sudo bpftool prog attach pinned /sys/fs/bpf/shadow_protect lsm

# Verify attached.
sudo bpftool prog show
# 213: lsm  name file_open_check  tag ... gpl
#   loaded_at 2026-04-29T10:00:00+0000  uid 0
#   xlated 1024B  jited 768B  memlock 4096B
#   btf_id 41
```

The policy is now active. A process named `unprivileged` reading `/etc/shadow` will get `EACCES`.

```bash
# Verify.
cp /usr/bin/cat /tmp/unprivileged
/tmp/unprivileged /etc/shadow
# /tmp/unprivileged: /etc/shadow: Permission denied

# Audit messages.
sudo cat /sys/kernel/debug/tracing/trace_pipe
# unprivileged-12345 [001] DENY: unprivileged tried to open shadow
```

### Step 4: Deploy via Cilium Tetragon

Tetragon manages BPF LSM policies declaratively via Kubernetes CRDs.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: deny-shadow-read
spec:
  kprobes:
    - call: "security_file_open"
      syscall: false
      args:
        - index: 0
          type: "file"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Postfix"
              values:
                - "/shadow"
          matchActions:
            - action: Override
              argError: -13   # EACCES
```

Tetragon compiles the CRD into a BPF LSM program, loads it on every node, and reports policy hits. New policies roll out via `kubectl apply` — no reboot or pod restart.

### Step 5: Per-Cgroup / Per-Container Policy

BPF LSM programs can scope policy by cgroup (and therefore by container or Pod):

```c
SEC("lsm/file_open")
int BPF_PROG(file_open_check, struct file *file)
{
    /* Get the cgroup ID of the current process. */
    u64 cgroup_id = bpf_get_current_cgroup_id();

    /* Look up policy for this cgroup. */
    struct policy *p = bpf_map_lookup_elem(&cgroup_policies, &cgroup_id);
    if (!p) return 0;   /* no policy for this cgroup */

    /* Check the file path against the policy's denied paths. */
    char filename[256] = {};
    bpf_probe_read_kernel_str(filename, sizeof(filename),
        BPF_CORE_READ(file, f_path.dentry, d_name.name));
    if (path_matches_denylist(filename, p)) {
        return -EACCES;
    }
    return 0;
}
```

Userspace populates `cgroup_policies` map per Pod / per Container. Different workloads on the same host run under different policies without separate AppArmor profiles per workload.

### Step 6: Auditable Logging

Every policy hit emits an event. Userspace consumes via perf event or ring buffer:

```c
struct lsm_event {
    u64 timestamp;
    u32 pid;
    u32 cgroup_id;
    char comm[16];
    char filename[256];
    int decision;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(file_open_check, struct file *file)
{
    /* ... policy check ... */
    if (deny) {
        struct lsm_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->timestamp = bpf_ktime_get_ns();
            e->pid = bpf_get_current_pid_tgid() >> 32;
            e->cgroup_id = bpf_get_current_cgroup_id();
            bpf_get_current_comm(e->comm, sizeof(e->comm));
            bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
                BPF_CORE_READ(file, f_path.dentry, d_name.name));
            e->decision = -EACCES;
            bpf_ringbuf_submit(e, 0);
        }
        return -EACCES;
    }
    return 0;
}
```

Userspace daemon reads the ring buffer, ships events to Loki / Splunk / your SIEM. Per-event detail richer than auditd; lower overhead than AppArmor `audit` mode.

### Step 7: Common Patterns

Beyond file access:

- **Capability checks** (`lsm/capable`): deny `CAP_SYS_PTRACE` to specific containers.
- **Socket creation** (`lsm/socket_create`): block raw sockets in containers without the audit-permission flag.
- **Bprm checks** (`lsm/bprm_check_security`): block execution of binaries from `/tmp` or `/dev/shm`.
- **Mount checks** (`lsm/sb_mount`): refuse hostPath mounts at the kernel level even when Pod Security Admission permits them.

Each of these is 50-100 lines of BPF code and a userspace loader — distributed via DaemonSet.

### Step 8: Performance

BPF LSM programs run on every relevant syscall path. Performance matters.

```bash
# Benchmark per-syscall overhead.
sudo perf stat -e cycles,instructions ./benchmark
# without policy: 1.2 us/syscall
# with policy:    1.4 us/syscall  (+15%)
```

Typical overhead: 50-200 ns per check. For most workloads the impact is invisible. For latency-critical paths (high-frequency network sockets, many small file reads), measure before deploying.

Optimize:

- Avoid `bpf_probe_read_kernel_str` for variable-length paths in the hot path; use cached values.
- Use BPF maps for lookup-heavy decisions rather than recomputing.
- Limit the per-program complexity (verifier rejects programs over 1M instructions).

## Expected Behaviour

| Signal | AppArmor / SELinux | BPF LSM |
|--------|---------------------|----------|
| Update propagation | Filesystem-based; per-host | Kernel-loaded; atomic; cluster-wide via DaemonSet |
| Policy authoring | Custom DSL | C / Rust / libbpf |
| Per-container policy | Profile per workload (operational nightmare) | Per-cgroup map lookup; uniform program |
| Hot reload | Reload command, sometimes restart | Replace BPF program; no restart |
| Observability | auditd messages | Ring-buffer events; eBPF tracing |
| Compatibility with existing LSMs | Stack with bpf as one of multiple | Same: bpf is a co-resident LSM |
| Performance | Comparable | Comparable; verifier-bounded |

Verify a policy is active:

```bash
sudo bpftool prog show | grep lsm
# 213: lsm  name file_open_check ...

sudo bpftool prog tracelog
# (live trace of policy hits)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Policy as code | Version-controlled, reviewable | Requires BPF / kernel familiarity | Use Tetragon / Cilium for declarative wrapper; teams write CRDs, not BPF directly. |
| Hot reload | No restart for policy changes | Operator must understand load / attach lifecycle | Standard via libbpf-bootstrap or higher-level tools. |
| Per-cgroup scoping | Per-workload policy | Map maintenance per Pod | Automate via container runtime hooks; tools like Tetragon handle this. |
| BPF verifier strictness | Prevents kernel panics | Some natural code patterns rejected (loops, complex pointer arithmetic) | Use BPF helpers; structure code for verifier; libbpf macros help. |
| Performance overhead | Low but non-zero | Latency-critical paths impacted | Benchmark before deploying; optimize hot path. |
| Stack with existing LSMs | Defense in depth | Policy interactions can be subtle | Test thoroughly; understand which LSM denies first (each LSM evaluates independently; any deny wins). |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| BPF verifier rejects policy | Load fails | bpftool returns verifier error | Read verifier output; restructure code (typically: bound loops, simplify pointer arithmetic). |
| Policy too restrictive | Legitimate workload breaks | App reports EACCES on unexpected paths | Review hit logs; loosen policy; deploy with audit-only mode first. |
| BPF map memory exhausted | Lookups fail | Map dump shows max-entries reached | Increase map size; LRU maps for cache-style use. |
| Kernel BPF LSM not in active list | Policy loads but doesn't enforce | `cat /sys/kernel/security/lsm` lacks `bpf` | Add `lsm=...,bpf` to kernel cmdline; reboot. |
| Policy bug crashes verifier | Some legitimate ops blocked | Specific pattern of failures | Verifier wouldn't accept actual buggy code; if odd behavior, check userspace policy-loading logic. |
| Per-cgroup map drift | New Pods don't have policy | New workloads run unprotected | Userspace daemon must populate map on Pod start; test the integration. |
| Stale policy after pod terminates | Map entries leak | Map size grows | Cleanup on Pod terminate; periodic GC. |

## Related Articles

- [Landlock LSM: Unprivileged Kernel Sandboxing](/articles/linux/landlock-lsm/)
- [Hardening the Linux Kernel Attack Surface with sysctl](/articles/linux/sysctl-kernel-hardening/)
- [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/)
- [eBPF Runtime Security with Tetragon](/articles/observability/ebpf-tetragon/)
- [seccomp Profiles for Kubernetes Workloads](/articles/kubernetes/seccomp-profiles/)
