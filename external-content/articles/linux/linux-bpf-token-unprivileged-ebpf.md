---
title: "Linux BPF Token: Delegated Unprivileged eBPF Without CAP_BPF on the Host"
description: "Linux 6.10+ ships BPF token, a delegation mechanism that lets unprivileged user namespaces load and attach a curated subset of eBPF programs without CAP_BPF on the host. Production hardening guide for runtimes, observability agents, and developer workstations."
slug: "linux-bpf-token-unprivileged-ebpf"
date: 2026-05-08
lastmod: 2026-05-08
category: "linux"
tags: ["ebpf", "bpf-token", "user-namespaces", "capabilities", "kernel", "linux"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 657
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/linux/linux-bpf-token-unprivileged-ebpf/index.html"
---

# Linux BPF Token: Delegated Unprivileged eBPF Without CAP_BPF on the Host

## Problem

eBPF is now the default observability and runtime-security plumbing on Linux: every Cilium, Tetragon, Pixie, Parca, and bpftrace deployment loads programs through `bpf(2)`. The capability model that gates `bpf(2)` has not kept up. For most useful program types — including `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, `BPF_PROG_TYPE_PERF_EVENT`, and `BPF_PROG_TYPE_TRACING` — the kernel still requires `CAP_BPF` plus `CAP_PERFMON` (or, on older kernels, the all-encompassing `CAP_SYS_ADMIN`) in the *initial* user namespace. Unprivileged users in a child user namespace cannot load these programs even when their workload genuinely needs to.

The historical workaround was to either (a) run the loader as full host root, (b) drop a custom uid into the `kernel.unprivileged_bpf_disabled=0` ungated path (which on most distributions is now `=2`, hard-disabled), or (c) build a privileged sidecar that loaded BPF on the workload's behalf and shared the resulting map fd. All three break the principle of giving the workload the smallest set of privileges that still lets it work, and the third in particular has produced a long string of CVEs where the privileged loader exposed an attack surface the unprivileged caller could abuse.

`BPF token` (merged in Linux 6.10, mainstream in 6.12+ distributions and the focus of this article) is a different shape. It introduces a kernel object — an fd of type `BPF_TYPE_TOKEN` — that grants a child user namespace permission to perform a *bounded subset* of `bpf(2)` operations using only `CAP_BPF` *inside that user namespace*. The token is created by a privileged process in the parent namespace, pinned in BPF FS, and inherited or delegated into the child. Once present, the unprivileged loader can call `BPF_PROG_LOAD`, `BPF_MAP_CREATE`, `BPF_BTF_LOAD`, etc. — but only for the program types, attach types, map types, helpers, and CMD operations the token's bitmap allows.

This is the right primitive for the job and it changes how production eBPF should be deployed. The trade-off is that the bitmap is large, the failure modes are subtle (a missing `allowed_attach_types` bit produces a generic `EPERM` at attach time, not at load), and the wrong configuration silently grants more privilege than intended.

Target systems: Linux 6.10+ as the minimum, Linux 6.12+ for stability (RHEL 10 / Fedora 41+ / Ubuntu 25.04+ / Debian Trixie / SUSE Leap 16). Container runtimes need libbpf 1.5+, runc 1.2+, and a recent enough cgroup v2 setup.

## Threat Model

1. **Untrusted application code that wants to use eBPF** (developer-mode profilers, user-installed Falco rules, browser-class WASM-to-eBPF bridges). Goal: load probes that read kernel addresses or attach to syscalls beyond its own scope. Without BPF token, these run as host root or not at all; with a misconfigured token they can attach to `bpf_probe_read_kernel` against arbitrary addresses.
2. **Compromised observability agent in a multi-tenant Kubernetes node.** Goal: pivot from a tenant pod's profiler into reading other tenants' memory or installing persistent rootkit-class probes. A coarse token (`prog_type=kprobe`, no allowlist on attach points) effectively grants this.
3. **Container-escape primitive via the `bpf(2)` syscall surface itself.** Historic CVEs (CVE-2021-31440, CVE-2021-3490, CVE-2022-0185, CVE-2024-1086) exploited verifier bugs reachable from any process holding the right caps. A token exposes a bounded subset of program types; verifier bugs in that subset are still reachable, but the attack surface is smaller.
4. **Insider misuse of an over-permissive token pin.** A token left at `chmod 0644 /sys/fs/bpf/tokens/observability` is usable by any process whose user namespace can open it.

With a tightly-scoped token, adversary 1 is constrained to exactly the program/attach/helper combinations it needs; 2 cannot read outside the cgroup it was scoped to; 3 has a smaller attackable verifier surface; 4 is detectable via auditd watches on the pin path.

## Configuration / Implementation

### Step 1 — Confirm kernel and tooling readiness

```bash
# Kernel version and BPF token support.
uname -r                                   # need >= 6.10
zgrep -E 'BPF_TOKEN|CONFIG_BPF_SYSCALL' /proc/config.gz 2>/dev/null \
  || grep -E 'BPF_TOKEN|CONFIG_BPF_SYSCALL' /boot/config-$(uname -r)
# Want:
#   CONFIG_BPF_SYSCALL=y
#   CONFIG_BPF_TOKEN=y       (introduced in 6.10)

# libbpf with token helpers.
pkg-config --modversion libbpf            # need >= 1.5

# bpftool with `token` subcommand.
bpftool token help 2>&1 | head -1
```

If `bpftool token` returns "Unknown command", you are on a pre-6.10 build of bpftool even if the kernel is recent — install the in-tree bpftool from the matching kernel headers package.

### Step 2 — Mount a dedicated BPF FS instance for the token

You should *not* place the token on the default `/sys/fs/bpf` mount that other workloads share. Mount a separate BPF FS with `delegate_*` options that constrain what the token can grant:

```bash
sudo mkdir -p /run/bpf-tokens
sudo mount -t bpf bpf-tokens /run/bpf-tokens \
    -o nosuid,nodev,noexec,mode=0755 \
    -o delegate_cmds=prog_load:map_create:btf_load:link_create \
    -o delegate_progs=kprobe:tracepoint:perf_event \
    -o delegate_attachs=trace_kprobe:trace_tracepoint:perf_event \
    -o delegate_maps=hash:array:perf_event_array:ringbuf
```

Each `delegate_*` option scopes the maximum privileges any token created on this FS can hand out. A token cannot grant operations the FS does not delegate, so the FS mount is the outer bound and the token is the inner bound. Keep both lists tight.

The `delegate_cmds` allowlist deserves special care. `prog_load` and `map_create` are necessary for any loader. `btf_load` is needed by every libbpf program because CO-RE relocations reference BTF. `link_create` is needed to attach via the modern bpf_link API. *Do not* delegate `prog_run` (also called `BPF_PROG_TEST_RUN`) unless you specifically want untrusted code to invoke programs synchronously — it has historically been a source of verifier-state-confusion CVEs.

### Step 3 — Create the token

```bash
# As root in the parent namespace.
sudo bpftool token pin /run/bpf-tokens/observability \
    allowed_cmds prog_load,map_create,btf_load,link_create \
    allowed_progs kprobe,tracepoint,perf_event \
    allowed_attachs trace_kprobe,trace_tracepoint,perf_event \
    allowed_maps hash,array,perf_event_array,ringbuf

# Restrict who can open the pin.
sudo chgrp ebpf-loader /run/bpf-tokens/observability
sudo chmod 0640 /run/bpf-tokens/observability
```

The `allowed_*` lists must be subsets of the FS-level `delegate_*` lists. If you ask for more, `bpftool` returns `EINVAL`. If you ask for less, the token is *more* restrictive than the FS — which is the desired direction.

The pin's DAC permissions matter. The kernel does check capability bits inside the user namespace, but it also requires the loader to *open* the pin path, so a `0640` pin owned by group `ebpf-loader` ensures only members of that group (typically a single service account) can use the token even if they happen to acquire `CAP_BPF` later.

### Step 4 — Wire the token into the unprivileged workload

For a libbpf-based loader, the token fd is passed via `bpf_object_open_opts.token_path`:

```c
#include <bpf/libbpf.h>

int main(void) {
    struct bpf_object_open_opts opts = {
        .sz = sizeof(opts),
        .token_path = "/run/bpf-tokens/observability",
    };
    struct bpf_object *obj = bpf_object__open_file("probe.bpf.o", &opts);
    if (!obj) return 1;
    if (bpf_object__load(obj)) return 2;
    /* ... attach via bpf_link ... */
    return 0;
}
```

For a Cilium-style Go loader using `cilium/ebpf` v0.16+:

```go
spec, err := ebpf.LoadCollectionSpec("probe.bpf.o")
if err != nil { return err }
coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
    Programs: ebpf.ProgramOptions{
        TokenPath: "/run/bpf-tokens/observability",
    },
})
```

For a systemd-managed service, the token is delegated through the unit file:

```ini
# /etc/systemd/system/profiler.service
[Service]
User=profiler
Group=ebpf-loader
AmbientCapabilities=CAP_BPF CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_PERFMON
NoNewPrivileges=yes
PrivateUsers=yes
BPF=token:/run/bpf-tokens/observability
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
LockPersonality=yes
ExecStart=/usr/local/bin/profiler
```

`PrivateUsers=yes` puts the service in its own user namespace, where `CAP_BPF` is meaningful only inside that namespace. The token bridges that namespace's `CAP_BPF` to actual `bpf(2)` syscalls in the host namespace — but only for the operations the token allows.

### Step 5 — Verify the boundary

After deploying, test that the loader can do what it should and *cannot* do what it should not.

```bash
# Should succeed:
sudo -u profiler bpftool prog load probe.bpf.o /sys/fs/bpf/probe \
    token /run/bpf-tokens/observability

# Should fail with EPERM (program type not delegated):
sudo -u profiler bpftool prog load xdp.bpf.o /sys/fs/bpf/xdp \
    token /run/bpf-tokens/observability

# Should fail with EPERM (cmd not delegated):
sudo -u profiler bpftool prog test run pinned /sys/fs/bpf/probe
```

The third command exercises `BPF_PROG_TEST_RUN`, which we deliberately excluded from `delegate_cmds` in Step 2. Confirming the failure mode is an explicit part of the deployment test plan.

### Step 6 — Auditing token use

Two mechanisms together give a defensible audit trail:

```bash
# auditd watch on the pin path catches token consumers.
sudo auditctl -w /run/bpf-tokens/observability -p r -k bpf-token-use

# bpftrace check for any process opening token pins.
sudo bpftrace -e '
  tracepoint:syscalls:sys_enter_openat /
    str(args->filename) == "/run/bpf-tokens/observability" / {
    printf("%s (pid %d uid %d) opened bpf token\n",
           comm, pid, uid);
  }
'
```

In SIEM, alert on (a) any open of the pin by a process not in the expected `ebpf-loader` group, (b) `bpf` syscall returning success from a UID outside the allowlist, and (c) `delegate_*` mount option changes on the BPF FS.

## Expected Behaviour

| Signal | Before BPF token | After BPF token (this config) |
|---|---|---|
| eBPF loader UID | root (0) on host | unprivileged service account inside user ns |
| Capabilities required on host | `CAP_BPF + CAP_PERFMON` in init userns | None — caps are granted inside the child userns only |
| Syscall surface reachable from loader | All `bpf(2)` cmds + all program/map/attach types | 4 cmds, 3 program types, 4 map types, 3 attach types |
| `BPF_PROG_TEST_RUN` reachable | yes | no (returns `EPERM`) |
| Audit trail of who loaded what | `bpf` syscall audit by uid 0 (uninformative) | Distinct uid per loader; auditd watch on pin |
| Verifier bug blast radius | All program types | Only the 3 delegated types |

Verification snippet (smoke test you can wire into CI):

```bash
#!/usr/bin/env bash
set -euo pipefail
PIN=/run/bpf-tokens/observability
test -e "$PIN" || { echo "token pin missing"; exit 2; }
bpftool token show pinned "$PIN" \
  | grep -E 'allowed_progs.*kprobe' \
  | grep -E 'allowed_progs.*tracepoint' >/dev/null
sudo -u profiler timeout 5 \
  bpftool prog load /usr/share/bpf/tests/probe.bpf.o /sys/fs/bpf/test \
  token "$PIN"
sudo bpftool prog show pinned /sys/fs/bpf/test \
  | grep -q "loaded_at"
sudo rm /sys/fs/bpf/test
echo OK
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Kernel version requirement | Stronger isolation than CAP-based | Locks out hosts on RHEL 9 / Ubuntu 22.04 LTS | Run a parallel privileged-loader path for older fleets; flip per-host once upgraded |
| Token pin file management | DAC + capability double-gate | Operational complexity (mount options, pin perms, group membership) | Manage via Ansible role; treat the mount as immutable infra |
| Delegation list breadth | Tight subsets reduce CVE blast radius | Each new probe type may require a new token mount | Have one token per workload class, not one token per probe |
| Failure modes | Surface bugs at deploy time, not runtime | `EPERM` does not say *which* bit was missing | Build a `bpftool token check program.bpf.o` step into CI |
| User namespace requirement | Forces real privilege separation | `PrivateUsers=yes` interacts oddly with some cgroup controllers | Test cgroup attach paths under user namespace before rollout |
| Audit trail granularity | Per-uid attribution | More auditd events to retain | Filter on `key=bpf-token-use` and ship only those |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Token pin missing or wrong path | `bpf_object__load` returns `-ENOENT`/`-EACCES` | Loader logs `failed to open token: ...` | Re-create pin via systemd `tmpfiles` rule on boot |
| Pin permissions too open | Unauthorised process gains BPF privileges | auditd `key=bpf-token-use` from unexpected uid | `chmod 0640` + recreate; investigate process |
| FS `delegate_*` narrower than token request | Token creation fails with `EINVAL` | `bpftool token pin` returns nonzero | Widen FS delegation, narrow token to actual need |
| Verifier rejects program after kernel upgrade | `BPF_PROG_LOAD` returns `-EINVAL` with verifier log | Loader stderr; CI smoke test fails | Recompile with newer libbpf; pin kernel version in fleet config |
| Userns is in fact init userns | Token has no effect; caps required as before | Loader still works as root, fails as unprivileged | Confirm `PrivateUsers=yes` and check `/proc/self/uid_map` |
| `delegate_cmds` includes `prog_run` | Verifier-bypass primitive available to loader | Manual review of mount options | Remove `prog_run` from the FS mount; remount |
| Token pin in default `/sys/fs/bpf` | Other workloads can use it | `lsof /sys/fs/bpf/<pin>` shows unexpected pids | Move pin to a per-workload BPF FS mount |

## When to Consider a Managed Alternative

- **Cilium Hubble / Tetragon** ship their own privileged DaemonSets and do not currently consume tokens; for cluster-wide observability run them under their existing model and only use BPF token for *user-installed* probes layered on top.
- **GKE Cloud Profiler / AWS CodeGuru Profiler** avoid the syscall entirely by collecting `perf_events` in a vendor agent and uploading samples — operationally simpler if you do not need custom programs.
- **Datadog Universal Service Monitoring** uses kernel modules + privileged sidecars; if regulatory constraints forbid host-root agents, BPF token is the better path.

## Related Articles

- [eBPF LSM hooks for runtime policy](/articles/linux/ebpf-lsm/)
- [eBPF verifier security and recent CVE patterns](/articles/linux/ebpf-verifier-security/)
- [Linux capability hardening](/articles/linux/linux-capability-hardening/)
- [Linux user namespace security](/articles/linux/linux-user-namespace-security/)
- [Tetragon eBPF runtime security](/articles/observability/ebpf-tetragon/)
