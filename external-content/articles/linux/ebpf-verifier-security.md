---
title: "eBPF Verifier Security Hardening"
description: "Harden Linux systems against eBPF verifier bypass vulnerabilities—like GHSA-hfqc-63c7-rj9f's register tracking bug—by restricting BPF access, monitoring silent kernel fixes, and validating verifier behaviour."
slug: ebpf-verifier-security
date: 2026-05-02
lastmod: 2026-05-02
category: linux
tags: ["ebpf", "verifier", "kernel", "lpe", "bpf", "ghsa-hfqc-63c7-rj9f", "privilege-escalation"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 359
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/linux/ebpf-verifier-security/index.html"
---

# eBPF Verifier Security Hardening

## Problem

The eBPF verifier is the kernel subsystem that statically analyses every eBPF program before it is loaded into the kernel. Before a program can be attached to a kprobe, TC hook, XDP driver, or LSM hook, the verifier walks every possible execution path through the program's bytecode and must prove that the program cannot perform out-of-bounds memory accesses, cannot loop unboundedly, and cannot perform illegal pointer arithmetic. The verifier is the primary and often only security boundary between user-submitted eBPF programs and the kernel's own memory. If an attacker can trick the verifier into accepting a program it has incorrectly declared safe, the attacker gains the ability to read and write arbitrary kernel memory from user space — which in practice means full local privilege escalation to root, and often container escape.

The verifier's job is harder than it sounds. It does not execute the program; it maintains an abstract model of every register's possible value range at every instruction. For each ALU operation, pointer dereference, or map lookup, the verifier must track whether the resulting register could hold a value outside a safe range. This abstract interpretation is implemented in roughly 15,000 lines of `kernel/bpf/verifier.c`, supported by a range-tracking library in `kernel/bpf/tnum.c` (tristate numbers, tracking which bits are definitely zero, definitely one, or unknown). The correctness of this model depends on precise handling of every ALU opcode, every conditional branch, and every type-narrowing inference. A single edge case where the abstract model diverges from what the hardware actually computes is sufficient for an attacker to break the security guarantee.

**GHSA-hfqc-63c7-rj9f** (April 2026, discovered by Google Security Research) is exactly this class of bug. The verifier's tracking of register value ranges had an edge case in the handling of certain ALU operations on 32-bit sub-registers. The Linux eBPF architecture defines both 64-bit (`r0`–`r10`) and 32-bit (`w0`–`w10`) register views; operations on 32-bit sub-registers are supposed to be zero-extended to 64 bits before the result is used in pointer arithmetic. The bug: certain ALU operations on 32-bit registers were being widened to 64-bit ranges by the verifier's abstract model without correctly re-constraining the upper 32 bits. An attacker could construct a crafted eBPF program in which the verifier believed a memory offset was bounded within a safe range, while at runtime the actual 64-bit value of the register — after the silent widening — held an attacker-controlled offset. The result: the verifier would declare the program safe, and at runtime the program could dereference a kernel pointer with an attacker-controlled offset, enabling arbitrary kernel reads and writes. The fix was committed to the kernel's `bpf` tree and the full advisory is published at `https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f`.

A critical operational reality — and the central open-source angle of this article — is the gap between when a verifier fix lands in the upstream kernel tree and when it reaches a distribution kernel package. Many eBPF verifier bug fixes are committed to the `bpf-next` or `bpf` kernel trees with commit messages like `bpf: fix verifier range tracking for 32-bit ALU ops`. No CVE is mentioned. No security advisory accompanies the commit. The commit appears in the log of `https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git` within hours of being merged, but a sysadmin running Ubuntu 24.04 or RHEL 9 may wait 2–8 weeks before the fix appears in a distribution kernel update. During that window, a patch-gap attacker who monitors the `bpf` tree can read the diff, understand the verifier's corrected abstract model, and construct a proof-of-concept that triggers the unpatched path. Google's Project Zero and the broader research community have documented multiple eBPF verifier bugs with this pattern; several have had 6–12 week windows between upstream fix and distribution shipping. GHSA-hfqc-63c7-rj9f is more transparent than most — Google Security Research published a structured advisory — but even here the kernel commit predated the coordinated public disclosure.

Monitoring for verifier fixes before they acquire a CVE requires watching the right channels. The canonical source is the `bpf` kernel tree itself: `https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/log/` — filter commits touching `kernel/bpf/verifier.c` and `kernel/bpf/tnum.c`. The OSV database (`https://osv.dev`) indexes kernel CVEs and can be queried for BPF-tagged advisories. The `oss-security@openwall.com` mailing list is where coordinated kernel security disclosures are made public; BPF disclosure threads appear there for bugs that do get CVEs. Subscribe to `linux-kernel-announce` for major kernel releases, and watch your distribution's kernel security mailing list (Ubuntu's `ubuntu-security-announce`, Red Hat's errata feed) for the downstream fix notification. Combining upstream tree monitoring with OSV queries gives the earliest possible warning.

**Target systems:** Linux kernel >= 4.4 with `CONFIG_BPF_JIT=y` and `kernel.unprivileged_bpf_disabled=0` (the default on most distributions), including Ubuntu 22.04+, Ubuntu 24.04+, Debian 12+, and RHEL 9/10. Any system where an unprivileged user can call `bpf(BPF_PROG_LOAD, ...)` is in scope. Systems that have already set `kernel.unprivileged_bpf_disabled=2` are protected from unprivileged exploitation but remain at risk from any process holding `CAP_BPF` or `CAP_SYS_ADMIN`.

## Threat Model

1. **Unprivileged local user privilege escalation.** An attacker with a shell account — or code execution in any process running as a non-root UID — calls `bpf(BPF_PROG_LOAD, ...)` with a crafted eBPF program that exploits a verifier register range tracking bug. The verifier accepts the program as safe. At runtime the program performs kernel arbitrary read/write using an attacker-controlled pointer offset. The attacker reads kernel credentials structures, overwrites `task_struct.cred`, and escalates to root. This is the direct exploitation path for GHSA-hfqc-63c7-rj9f.

2. **Container workload with `CAP_BPF` escaping to the host.** A Kubernetes pod with `securityContext.capabilities.add: ["BPF"]` — or a DaemonSet running Cilium, Tetragon, or Falco with elevated privileges — is compromised through application-layer code injection. The attacker uses the process's existing `CAP_BPF` to load a crafted BPF program that exploits the verifier. Because BPF programs share the host kernel's address space regardless of container namespacing, a successful verifier bypass inside a container is a container escape: the attacker can read or write host kernel memory.

3. **Patch-gap attacker.** A sophisticated attacker monitors `git.kernel.org/bpf` for commits touching `kernel/bpf/verifier.c`. When a commit appears that changes register range tracking logic — particularly around 32-bit sub-register ALU operations or `tnum` range constraints — the attacker reads the diff, identifies the pre-fix logical path, and constructs an eBPF program that exercises that path. Distribution kernels typically lag the upstream `bpf` tree by 2–8 weeks. The attacker holds a working proof-of-concept during this window, targeting systems where unprivileged BPF is enabled and the distribution kernel has not yet shipped the fix.

4. **CI/CD runner as BPF loading vector.** Many CI/CD platforms deploy observability agents (Cilium for network visibility, Tetragon for process auditing, Falco for syscall monitoring) that require `CAP_BPF` or `CAP_SYS_ADMIN`. An attacker who achieves code injection in the CI pipeline — through a compromised build script, a malicious dependency, or a poisoned container image — gains the ability to load BPF programs with the runner's capabilities. The runner's elevated BPF access becomes a privilege escalation primitive if the kernel verifier is unpatched.

The blast radius of a successful verifier bypass is unbounded: arbitrary kernel read/write means the attacker can extract secrets from kernel memory (including other tenants' process memory via `/proc/kcore` or direct mapping), modify kernel credentials for any process, install a kernel-level rootkit, or disable security mechanisms (SELinux enforcement mode, audit rules) by patching kernel data structures in place.

## Configuration / Implementation

### Disabling Unprivileged BPF

The most effective single mitigation is preventing unprivileged processes from loading BPF programs. The `kernel.unprivileged_bpf_disabled` sysctl controls this:

- Value `0` (default on most distributions): any unprivileged user can call `bpf(BPF_PROG_LOAD, ...)`.
- Value `1`: unprivileged BPF is disabled, but root can reset this to `0` at runtime.
- Value `2`: unprivileged BPF is permanently disabled — no process can re-enable it without a reboot, even root.

Always set value `2` on production systems. Value `1` provides weak protection because any process that achieves root (through another vulnerability) can re-enable unprivileged BPF before loading a BPF exploit.

```bash
# Apply immediately
sysctl -w kernel.unprivileged_bpf_disabled=2

# Verify
sysctl kernel.unprivileged_bpf_disabled
# Expected: kernel.unprivileged_bpf_disabled = 2

# Persist across reboots
cat > /etc/sysctl.d/90-bpf-hardening.conf << 'EOF'
# Permanently disable unprivileged BPF loading.
# Value 2 cannot be reset to 0 without reboot, unlike value 1.
kernel.unprivileged_bpf_disabled = 2

# Harden BPF JIT: enable constant blinding, mitigate JIT spraying.
kernel.bpf_jit_harden = 2

# Hide JIT-compiled program symbols from non-root.
kernel.bpf_jit_kallsyms = 0
EOF

sysctl -p /etc/sysctl.d/90-bpf-hardening.conf
```

### BPF JIT Hardening

Even when BPF programs require privilege to load, the JIT compiler introduces additional attack surface. `kernel.bpf_jit_harden=2` enables constant blinding (replacing immediate constants in JIT-compiled code with XOR-masked values, defeating JIT spraying attacks) and additional JIT mitigations. `kernel.bpf_jit_kallsyms=0` prevents non-root from reading JIT-compiled symbol addresses via `/proc/kallsyms`, limiting an attacker's ability to locate JIT-compiled code in kernel address space.

```bash
# Confirm JIT is enabled (value 1 or 2)
cat /proc/sys/net/core/bpf_jit_enable

# Confirm harden level
sysctl kernel.bpf_jit_harden
# Expected: kernel.bpf_jit_harden = 2

# Confirm JIT symbols hidden from non-root
sysctl kernel.bpf_jit_kallsyms
# Expected: kernel.bpf_jit_kallsyms = 0

# Confirm in dmesg after boot
dmesg | grep -i "bpf jit"
```

### Auditing Processes with BPF Capabilities

`kernel.unprivileged_bpf_disabled=2` protects against unprivileged users, but processes holding `CAP_BPF` or `CAP_SYS_ADMIN` can still load BPF programs. Audit the capability surface regularly:

```bash
# Check capabilities of a specific process
getpcaps <pid>

# Find all processes with CAP_BPF or CAP_SYS_ADMIN
for pid in /proc/[0-9]*/status; do
  caps=$(grep -E "^CapEff:" "$pid" 2>/dev/null | awk '{print $2}')
  if [ -n "$caps" ]; then
    # CAP_BPF = bit 39 (0x8000000000), CAP_SYS_ADMIN = bit 21 (0x200000)
    dec_caps=$(printf "%d" "0x$caps" 2>/dev/null)
    if (( (dec_caps & (1 << 39)) || (dec_caps & (1 << 21)) )); then
      echo "PID $(basename $(dirname $pid)): $(cat $(dirname $pid)/comm 2>/dev/null) has CAP_BPF or CAP_SYS_ADMIN"
    fi
  fi
done
```

In Kubernetes, identify pods with elevated BPF capabilities:

```bash
# Find pods adding BPF or SYS_ADMIN capabilities
kubectl get pods --all-namespaces -o json | jq -r '
  .items[] |
  . as $pod |
  .spec.containers[] |
  select(
    .securityContext.capabilities.add? |
    arrays |
    any(. == "BPF" or . == "SYS_ADMIN")
  ) |
  [$pod.metadata.namespace, $pod.metadata.name, .name] |
  join("/")
'
```

Kubernetes Pod Security Admission (PSA) `restricted` profile prohibits both `CAP_BPF` and `CAP_SYS_ADMIN`. Apply it to namespaces that do not run observability DaemonSets:

```bash
# Label namespace to enforce restricted PSA profile
kubectl label namespace <namespace> \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
```

### BPF Program Allowlisting with LSM Hooks

For environments that require BPF access for observability tools but want to restrict which processes can load programs, a BPF LSM policy can allowlist by UID, PID namespace, or binary path. The LSM hook `bpf` fires before every BPF syscall:

```c
// Example BPF LSM program restricting BPF_PROG_LOAD to specific UIDs
SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_load, int cmd, union bpf_attr *attr, unsigned int size)
{
    __u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    if (cmd == BPF_PROG_LOAD) {
        // Only allow UID 0 and the observability service UID (e.g., 1001)
        if (uid != 0 && uid != ALLOWED_OBS_UID) {
            return -EPERM;
        }
    }
    return 0;
}
```

On Ubuntu kernels with AppArmor BPF mediation, the AppArmor profile can additionally restrict which profiles may perform BPF map operations via `kernel.bpf_map_permission` controls. Consult Ubuntu's AppArmor BPF documentation for profile syntax.

### Monitoring the BPF Kernel Tree for Verifier Fixes

Track upstream verifier changes before they acquire CVEs or appear in distribution kernels:

```bash
# Clone the bpf stable tree (one-time setup)
git clone https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git /opt/bpf-kernel-tree
cd /opt/bpf-kernel-tree

# Check for recent verifier commits (run weekly or via cron)
git fetch origin 2>/dev/null
git log --oneline --since="30 days ago" -- kernel/bpf/verifier.c kernel/bpf/tnum.c
```

Automated alerting script (`/opt/bpf-monitor/check-verifier.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/opt/bpf-kernel-tree"
ALERT_EMAIL="security@example.com"
STATE_FILE="/opt/bpf-monitor/last-seen-commit"

cd "$REPO_DIR"
git fetch origin --quiet

LATEST=$(git rev-parse origin/master)
LAST_SEEN=$(cat "$STATE_FILE" 2>/dev/null || echo "")

if [ "$LATEST" != "$LAST_SEEN" ]; then
    NEW_COMMITS=$(git log --oneline "${LAST_SEEN:+${LAST_SEEN}..}origin/master" \
        -- kernel/bpf/verifier.c kernel/bpf/tnum.c 2>/dev/null || \
        git log --oneline --since="7 days ago" origin/master \
        -- kernel/bpf/verifier.c kernel/bpf/tnum.c)

    if [ -n "$NEW_COMMITS" ]; then
        echo "$NEW_COMMITS" | mail -s "[BPF VERIFIER ALERT] New commits in bpf tree" "$ALERT_EMAIL"
    fi

    echo "$LATEST" > "$STATE_FILE"
fi
```

```bash
# Run weekly via cron
echo "0 8 * * 1 root /opt/bpf-monitor/check-verifier.sh" > /etc/cron.d/bpf-verifier-monitor
chmod 644 /etc/cron.d/bpf-verifier-monitor

# Cross-reference with oss-security disclosures
# Subscribe: https://www.openwall.com/lists/oss-security/
# Query OSV for BPF kernel CVEs:
curl -s 'https://api.osv.dev/v1/query' \
  -H 'Content-Type: application/json' \
  -d '{"package": {"name": "linux", "ecosystem": "Linux"}}' | \
  jq '.vulns[] | select(.id | startswith("CVE")) | {id, summary: .summary}' 2>/dev/null | head -40
```

### Blocking the BPF Syscall with Seccomp

For workloads that do not use BPF at all, block the `bpf` syscall entirely via seccomp. The syscall number is 321 on x86-64.

Seccomp profile JSON (save as `/etc/seccomp/no-bpf.json`):

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": ["bpf"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1
    }
  ]
}
```

Apply to a container at runtime:

```bash
# Docker
docker run --security-opt seccomp=/etc/seccomp/no-bpf.json <image>

# Kubernetes pod spec — use RuntimeDefault which blocks BPF in most CRI implementations
# or reference a custom profile via a SeccompProfile object
```

Kubernetes pod seccomp configuration:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-workload
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault   # Blocks bpf syscall for most workloads
  containers:
  - name: app
    image: app:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
```

For observability DaemonSets that legitimately need BPF (Cilium, Tetragon, Falco), use `seccompProfile.type: Unconfined` with a tightly scoped `CAP_BPF`-only capability grant, and ensure the host kernel is patched:

```yaml
securityContext:
  seccompProfile:
    type: Unconfined
  capabilities:
    add: ["BPF", "PERFMON"]
    drop: ["ALL"]
```

### Testing Verifier Hardening in CI

Run the kernel's own BPF selftests against the hardened configuration:

```bash
# Build and run BPF verifier selftests (requires kernel source)
make -C tools/testing/selftests/bpf run_tests 2>&1 | grep -E "(PASS|FAIL|ERROR)"

# Verify JIT blinding is active via bpftrace
bpftrace -e 'BEGIN { printf("JIT active\n"); exit(); }'

# Check JIT harden level reported by kernel
dmesg | grep -i "bpf jit"

# Confirm unprivileged BPF is blocked — run as non-root
sudo -u nobody bpftool prog load /dev/null /sys/fs/bpf/test 2>&1
# Expected: Operation not permitted
```

## Expected Behaviour

| Signal | Unpatched kernel, BPF unrestricted | Patched + hardened |
|---|---|---|
| Unprivileged user calls `bpf(BPF_PROG_LOAD, ...)` | Program accepted by verifier; loads successfully | `EPERM` immediately; `kernel.unprivileged_bpf_disabled=2` blocks the call before the verifier runs |
| Crafted verifier bypass program (GHSA-hfqc-63c7-rj9f pattern) submitted by `CAP_BPF` process | Verifier incorrectly declares safe; runtime achieves kernel arbitrary read/write | Patched kernel: verifier correctly rejects due to fixed 32-bit range widening logic; `EACCES` returned |
| Non-root process reads `/proc/kallsyms` for JIT symbols | JIT-compiled BPF program addresses visible; useful for gadget location | `kernel.bpf_jit_kallsyms=0` suppresses JIT symbols; non-root reads zeros |
| Container with `CAP_BPF` loads an observability BPF program | Loads successfully; if kernel is unpatched, verifier bypass yields host kernel access | Loads successfully (CAP_BPF permitted); if kernel is patched, bypass rejected; monitor audit log for unexpected BPF loads outside known DaemonSet PIDs |
| New commit to `kernel/bpf/verifier.c` in `bpf` upstream tree | No alert; operator unaware until distribution ships kernel update weeks later | Monitoring script detects new commit within 24 hours; alert triggers; operator evaluates diff and assesses urgency against distribution patch ETA |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| `kernel.unprivileged_bpf_disabled=2` | Eliminates the primary exploitation path for all verifier bugs; unprivileged users cannot reach the verifier | Breaks any unprivileged eBPF use: `bpftrace` without sudo, unprivileged observability agents, some eBPF-based network tools in user namespaces | Run observability tools as root or with `CAP_BPF`; audit which tools actually require unpriv BPF — most production tools run privileged anyway |
| `kernel.bpf_jit_harden=2` | Constant blinding defeats JIT spraying; mitigates code-reuse attacks against JIT-compiled BPF programs | 5–15% performance overhead on JIT-compiled BPF programs in hot paths (high-frequency XDP or TC programs may be affected) | Benchmark before enforcing in latency-sensitive environments; consider `bpf_jit_harden=1` (user programs only) as a middle ground |
| Seccomp BPF syscall block (`SCMP_ACT_ERRNO` on `bpf`) | Completely eliminates BPF attack surface for workloads that do not need BPF | Breaks Cilium, Falco, Tetragon, and any eBPF-based observability or networking tool in the affected container or host | Apply only to workloads that explicitly do not use BPF; use a separate seccomp profile for observability DaemonSets; never apply to Cilium or CNI plugin pods |
| Kernel update cadence for BPF verifier fixes | Applying distribution kernel updates promptly closes the vulnerability window | Kernel updates require node drain and reboot in Kubernetes environments; disrupts running workloads; maintenance windows constrain frequency | Use live-patching where available (kpatch on RHEL, livepatch on Ubuntu) for critical verifier fixes; automate kernel update testing in a staging cluster |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Cilium or Falco fails after setting `kernel.unprivileged_bpf_disabled=2` | Cilium agent CrashLoopBackOff; Falco fails to load probes; DaemonSet pods restart repeatedly | `kubectl logs -n kube-system <cilium-pod>` shows `Operation not permitted` on BPF prog load; `systemctl status falco` shows probe load failure | Expected for unprivileged configurations: Cilium and Falco require privileged BPF. Verify they run as root with `CAP_BPF`; `unprivileged_bpf_disabled=2` does not affect privileged BPF loads. Confirm pods have `securityContext.capabilities.add: ["BPF"]` and are not running as non-root UID |
| JIT hardening (`bpf_jit_harden=2`) breaks existing BPF maps after major kernel update | BPF programs return unexpected errors after kernel upgrade; map lookups fail; XDP programs drop packets incorrectly | `dmesg | grep -i bpf` shows JIT errors; `bpftool prog list` shows programs in error state; application-level packet drops or metric gaps | Set `bpf_jit_harden=0` temporarily to isolate the cause; recompile BPF programs for the new kernel; check if the program uses constant values that are affected by blinding; re-enable harden after recompilation |
| Seccomp BPF block breaks observability DaemonSet | Falco or Tetragon DaemonSet pods fail to start; node-level visibility gaps; security alerts stop arriving from affected nodes | `kubectl describe pod <falco-pod>` shows `execve failed: Operation not permitted` or BPF syscall error; Falco dashboard shows node as offline | Apply a separate seccomp profile for the observability DaemonSet that permits the `bpf` syscall; do not use a blanket host-level seccomp profile that blocks BPF; use Kubernetes `SeccompProfile` objects scoped to specific pods |
| Monitoring script generates false positives on non-security verifier commits | Alert fatigue; operators begin ignoring BPF verifier alerts | High alert volume; commits being flagged are performance fixes, test additions, or documentation changes in `verifier.c` | Tune the monitoring script to filter commit subjects: add a grep for terms associated with security fixes (`range`, `tnum`, `ALU`, `scalar`, `ptr`, `unsafe`, `bypass`); require manual triage for all alerts but reduce noise with subject filtering; cross-reference with OSV and oss-security before escalating |

## Related Articles

- [eBPF-LSM: Kernel Security Policy as Hot-Loadable BPF Programs](/articles/linux/ebpf-lsm/)
- [Linux Kernel Keyring Security](/articles/linux/linux-kernel-keyring-security/)
- [Seccomp-BPF for Non-Container Workloads](/articles/linux/seccomp-bpf-non-container/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
