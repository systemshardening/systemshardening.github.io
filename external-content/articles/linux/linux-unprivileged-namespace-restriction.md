---
title: "Restricting Unprivileged User Namespaces: Closing the 3.4x Kernel Attack Surface"
description: "Edera's research shows unprivileged user namespace creation expands reachable kernel attack surface by 3.4x and enabled 40+ CVEs in 2020–2025. Disable unprivileged namespace creation on servers, understand the trade-offs, and apply per-service exceptions where rootless containers are required."
slug: linux-unprivileged-namespace-restriction
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - user-namespaces
  - kernel-hardening
  - container-security
  - attack-surface
  - privilege-escalation
personas:
  - platform-engineer
  - security-engineer
article_number: 455
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-unprivileged-namespace-restriction/
---

# Restricting Unprivileged User Namespaces: Closing the 3.4x Kernel Attack Surface

## The Problem

Edera's 2026 analysis of Linux kernel CVEs from 2020 to 2025 quantified what kernel developers have known informally for years: unprivileged user namespace creation is a primary structural enabler of local privilege escalation. The mechanism is precise. An unprivileged process without user namespaces can reach 8 of the 40 kernel operations Edera catalogued. With user namespaces enabled — the default on Ubuntu, Debian, Fedora, and most container-hosting distributions — the same process can reach 27 of those 40 operations. That is a 3.4x expansion in kernel attack surface triggered by a single `unshare(CLONE_NEWUSER)` syscall that requires no privileges to execute.

The reason for this expansion is how capabilities interact with kernel code. When a process calls `unshare(CLONE_NEWUSER)`, the kernel grants it `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, and other capabilities scoped to the new namespace. Those capabilities are namespace-scoped. The kernel code they unlock is not. When the process then calls into the netfilter subsystem — loading nf_tables rules, manipulating conntrack entries, configuring network namespaces — it executes the same host kernel netfilter code that root would execute. The namespace does not sandbox the kernel code path. It gates access to it. The result is that a completely unprivileged attacker, starting with nothing more than a local shell, can load arbitrarily complex nf_tables expressions against the host kernel's packet filtering engine by first creating a user namespace to acquire the needed capability, then calling into the netfilter code through the capability-gated interface.

Of the 40+ kernel CVEs from 2020 to 2025 where user namespaces enabled or directly facilitated exploitation, Edera found that 43% were concentrated in netfilter and nf_tables. The remainder were distributed across overlayfs, the networking stack, and other subsystems that become reachable through user namespace capabilities. This is not a coincidence of timing — it reflects the structural reality that netfilter's expression evaluation engine and overlayfs's UID mapping logic both present large, complex, capability-gated code paths that were not designed with the assumption that arbitrary unprivileged processes would reach them.

The policy implication that Edera's research makes explicit: user namespaces are a valuable mechanism for UID remapping — allowing containers to run as non-root — but they are not a security boundary. They are an attack surface amplifier. A container running with UID remapping via user namespaces is running as non-root inside the container while simultaneously granting its process the ability to reach 3.4 times more host kernel code than it could without that namespace. The security benefits of UID remapping and the security costs of expanded kernel attack surface are separable, and on servers where rootless container workflows are not required, the costs outweigh the benefits.

This article is specifically about disabling unprivileged user namespace creation — setting the kernel to deny the initial `clone(CLONE_NEWUSER)` from unprivileged processes — as a hardening posture for servers and container hosts. The existing [Linux User Namespace Security](/articles/linux/linux-user-namespace-security/) article covers the broader topic of delegation, auditing, and selective enabling. This article argues for the more aggressive position: disable by default, grant exceptions only where operationally necessary, and understand exactly what breaks.

## Threat Model

Unprivileged user namespace creation as an attack enabler appears across multiple adversary archetypes, all sharing the same starting condition: local unprivileged code execution.

**Unprivileged container breakout.** A compromised container process that has not been given additional capabilities executes inside a container runtime that relies on user namespaces for UID remapping. The process calls `unshare(CLONE_NEWUSER)` to create a second, nested user namespace, acquires namespace-scoped `CAP_NET_ADMIN`, then loads a crafted nf_tables ruleset targeting a kernel vulnerability in the netfilter expression evaluator. The vulnerability yields an arbitrary kernel write primitive. The attacker overwrites a credential structure or calls `commit_creds()` to gain host root. Without user namespaces, the initial `unshare` call fails with `EPERM` and the chain stops at the first step.

**Multi-tenant Kubernetes node.** A malicious tenant on a shared node — either a compromised container or a deliberately hostile workload — uses unprivileged user namespace creation to reach kernel code paths that a fully unprivileged process cannot access. Even if the container's own seccomp profile and AppArmor policy are correctly configured, if the host kernel allows unprivileged user namespace creation, a container that breaks out of its runtime confinement retains the ability to call `unshare(CLONE_NEWUSER)` as any non-root UID and re-acquire kernel attack surface. The multi-tenant scenario is particularly dangerous because the exploitation target is not just the compromised tenant's workload — a successful host root compromise from one tenant's container affects every workload on the node.

**CI/CD runners on shared infrastructure.** Unprivileged build jobs executing on shared infrastructure have the same kernel access as any other unprivileged local process. Build pipelines routinely pull external code — dependencies, build tools, container images — that may carry exploit payloads. A compromised build dependency that executes arbitrary code during the build process has access to `unshare(CLONE_NEWUSER)` and all the kernel attack surface that follows. CI/CD hosts are high-value targets because a successful host compromise provides access to build secrets, signing keys, and the ability to tamper with artifacts before they are pushed to production. The attack surface reduction from disabling unprivileged user namespace creation is particularly valuable on runner hosts precisely because they execute untrusted code as part of their normal operation.

**Rootless container daemons.** Podman in rootless mode, rootless Docker, and rootless containerd all rely on unprivileged user namespace creation as part of their container lifecycle. This is a legitimate and intentional use of the feature. The trade-off must be explicit: a server running rootless Podman inherently expands the reachable kernel attack surface by 3.4x for any process on that host, not just the Podman process itself. The question is whether the operational convenience of rootless containers on a particular host justifies that exposure.

## Hardening Configuration

### 1. Disable Unprivileged User Namespace Creation System-Wide

Two separate sysctl knobs control unprivileged user namespace creation, and the right one depends on the distribution.

On Debian and Ubuntu, the kernel carries a downstream patch that adds `kernel.unprivileged_userns_clone`. Setting it to zero disables the `clone(CLONE_NEWUSER)` call for unprivileged processes:

```bash
sysctl -w kernel.unprivileged_userns_clone=0
```

On RHEL, Fedora, Rocky Linux, AlmaLinux, and mainline kernels without the Debian patch, the equivalent control is `user.max_user_namespaces`. Setting it to zero prevents any new user namespaces from being created by unprivileged processes:

```bash
sysctl -w user.max_user_namespaces=0
```

On Ubuntu specifically, both settings may exist simultaneously. Setting only `kernel.unprivileged_userns_clone=0` without also setting `user.max_user_namespaces=0` can leave a residual path for namespace creation depending on the kernel version. Set both on Ubuntu to ensure complete coverage:

```conf
# /etc/sysctl.d/99-namespace-hardening.conf
kernel.unprivileged_userns_clone = 0
user.max_user_namespaces = 0
```

Apply immediately without rebooting:

```bash
sysctl -p /etc/sysctl.d/99-namespace-hardening.conf
```

Verify the restriction is active:

```bash
unshare -U id
```

Expected output:

```text
unshare: unshare failed: Operation not permitted
```

Verify as a specific non-root user to confirm the restriction applies universally:

```bash
sudo -u nobody unshare -U id
```

Expected output: the same `Operation not permitted` error. If this succeeds and returns a UID mapping, the restriction is not fully applied.

### 2. Audit What Breaks Before Disabling

Applying the restriction without first identifying which processes on the host rely on unprivileged user namespace creation will cause unexpected breakage. The audit step should run on a staging host or during a maintenance window before any production change.

Identify processes currently running inside user namespaces that are not the initial namespace:

```bash
init_userns=$(readlink /proc/1/ns/user)
find /proc -maxdepth 3 -name 'ns' -type d 2>/dev/null | while read nsdir; do
  pid=$(echo "$nsdir" | cut -d/ -f3)
  proc_userns=$(readlink "$nsdir/user" 2>/dev/null)
  if [[ -n "$proc_userns" && "$proc_userns" != "$init_userns" ]]; then
    comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    uid=$(awk '/^Uid:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
    echo "PID=$pid UID=$uid COMM=$comm NS=$proc_userns"
  fi
done
```

Search audit logs for recent user namespace creation events (requires auditd with the rule below):

```bash
ausearch -k user_namespaces --start today 2>/dev/null | grep -E 'uid|comm|exe'
```

Add the audit rule if it is not already present:

```bash
auditctl -a always,exit -F arch=b64 -S unshare -F a0\&0x10000000 -k user_namespaces
auditctl -a always,exit -F arch=b64 -S clone  -F a0\&0x10000000 -k user_namespaces
```

`0x10000000` is the `CLONE_NEWUSER` flag. These rules capture every call that creates a user namespace, regardless of the calling UID.

Common processes that will break when unprivileged user namespace creation is disabled:

- Rootless Podman, rootless Docker, rootless Buildah, rootless containerd
- `bubblewrap` — the sandboxing tool used by Flatpak
- Chrome and Chromium renderer process sandboxes (on desktop systems)
- Firefox content process isolation (on desktop systems)
- Some network testing and debugging tools that use network namespace isolation

### 3. Per-Service Exception via AppArmor

For services that have a legitimate operational requirement for user namespace creation — a specific CI pipeline tool, a single rootless container workflow — the correct response is not to re-enable the feature globally. On Debian and Ubuntu with kernel 6.1+ and AppArmor, the `userns` permission can be granted to specific binaries through an AppArmor profile, leaving the sysctl-level restriction in place.

Enable the AppArmor-level user namespace restriction independently of the sysctl (this is complementary, not a replacement):

```bash
sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
echo "kernel.apparmor_restrict_unprivileged_userns = 1" >> /etc/sysctl.d/99-namespace-hardening.conf
```

Create a scoped AppArmor profile that grants `userns` only to the specific binary that requires it. The following example grants user namespace creation to rootless Podman's supporting helper binaries:

```
# /etc/apparmor.d/local/allow-rootless-podman
/usr/bin/newuidmap flags=(allow_incomplete) {
  userns,
}

/usr/bin/newgidmap flags=(allow_incomplete) {
  userns,
}

/usr/bin/podman flags=(allow_incomplete) {
  userns,
}
```

Load the profile:

```bash
apparmor_parser -r /etc/apparmor.d/local/allow-rootless-podman
```

Verify the profile is enforcing:

```bash
aa-status | grep -A2 allow-rootless-podman
```

The critical point: do not write the exception to apply to processes in the `unconfined` AppArmor profile. An exception scoped to `unconfined` grants user namespace access to every process on the system that does not have an explicit AppArmor profile — which is effectively every process. This re-enables the feature globally through AppArmor while leaving the sysctl restriction technically in place. The exception must name the specific binary.

### 4. Kubernetes Node Hardening

On Kubernetes nodes, the host kernel's `user.max_user_namespaces=0` setting applies to processes running in pods unless overridden by the kubelet. Apply the restriction at the host level and configure the kubelet accordingly.

Set the restriction persistently on each node:

```conf
# /etc/sysctl.d/99-namespace-hardening.conf (node-level)
user.max_user_namespaces = 0
```

Configure the kubelet to apply the sysctl to nodes via `KubeletConfiguration`:

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
allowedUnsafeSysctls: []
```

For pods that require UID remapping — which is the primary legitimate use case for user namespaces in Kubernetes — use the Kubernetes User Namespaces feature (`hostUsers: false` in the pod spec), which became stable in Kubernetes 1.30. This feature uses a kernel path controlled by the kubelet with elevated privileges, not by the pod process itself. It provides UID remapping without granting the pod the ability to call `clone(CLONE_NEWUSER)` from within the container:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: uid-remapped-pod
spec:
  hostUsers: false
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
```

With `hostUsers: false`, the pod runs with a remapped UID without the pod process having unprivileged user namespace creation capability on the host. The distinction matters: the kubelet creates the user namespace using its own elevated privileges, not by granting the pod process the ability to call `unshare(CLONE_NEWUSER)`. Setting `user.max_user_namespaces=0` on the host and using `hostUsers: false` in pods are compatible — the kubelet's namespace creation is not subject to the unprivileged namespace limit.

### 5. Verify nf_tables and overlayfs Exposure

Confirm that the highest-risk subsystems catalogued in Edera's research are no longer reachable from unprivileged processes. The test sequence verifies that the kernel entry point for both the netfilter and overlayfs attack paths is blocked.

Test nf_tables reachability:

```bash
unshare --user --net nft list tables
```

With unprivileged namespace creation disabled, this fails at the `unshare` step before nf_tables is ever reached:

```text
unshare: unshare failed: Operation not permitted
```

If the command instead returns an empty table list or any nft output, the restriction is not fully applied.

Test overlayfs reachability via the user namespace path:

```bash
unshare --user --mount --map-root-user mount -t overlay overlay \
  -o lowerdir=/tmp,upperdir=/tmp/upper,workdir=/tmp/work /mnt/test
```

Again, with the restriction in place, this fails at `unshare` with `Operation not permitted`. The mount operation is never attempted.

Verify that the kernel's reported attack surface has contracted by checking which capabilities an unprivileged process holds after the restriction:

```bash
grep CapEff /proc/self/status
```

Without user namespaces, an unprivileged process should show `CapEff: 0000000000000000` — no effective capabilities. With user namespaces enabled, the same process after `unshare -U` would show a non-zero `CapEff` value representing namespace-scoped capabilities.

## Expected Behaviour After Hardening

After disabling unprivileged user namespace creation, `unshare -U id` returns `Operation not permitted` for all non-root users. The nf_tables and overlayfs kernel code paths reachable via namespace escalation are no longer accessible to unprivileged processes — not because those code paths were patched, but because the capability-gating mechanism that grants access to them is no longer reachable without privilege.

The practical consequence for kernel CVEs in the netfilter and overlayfs subsystems: any CVE in those subsystems that lists user namespace creation as a prerequisite for exploitation is effectively mitigated on the restricted host, regardless of whether the kernel package has been updated. This is not a substitute for patching — the vulnerability remains in the kernel code — but the 2–7 day window between upstream patch availability and working public exploit, combined with the 15–30 day enterprise patching cycle, means that structural attack surface reduction provides meaningful protection during the gap.

The kernel CVEs where user namespaces are a prerequisite — which represent 43% of the netfilter CVEs Edera catalogued and a substantial fraction of the overlayfs CVEs — become unreachable through normal unprivileged access patterns. CVEs that do not require user namespaces as a prerequisite are unaffected by this control and require independent mitigations.

## Trade-offs and Operational Considerations

Disabling unprivileged user namespace creation is an operationally significant change. The following categories of software stop working or degrade without additional compensating configuration.

Rootless container workflows — rootless Podman, rootless Docker, rootless Buildah, rootless containerd — all rely on unprivileged user namespace creation for their UID mapping mechanism. On developer workstations where these tools are in daily use, disabling user namespaces without a per-binary AppArmor exception or an alternative approach causes all rootless container operations to fail. On production servers running only containerised workloads managed by a privileged daemon such as containerd or CRI-O, this is typically not a concern — privileged daemons create namespaces with their own elevated rights, not by relying on unprivileged user namespace creation.

Flatpak uses `bubblewrap` as its sandboxing layer, and `bubblewrap` depends on user namespaces. Disabling user namespaces on a system running Flatpak breaks application sandboxing and may prevent Flatpak applications from launching entirely. Flatpak is essentially absent from server environments, making this a desktop-specific concern.

Browser sandboxes present a more nuanced trade-off. Chrome, Chromium, and Firefox all use user namespaces as part of their renderer process sandboxing on Linux. Disabling user namespaces does not prevent the browser from running, but it degrades the renderer sandbox from namespace-based isolation to seccomp-only isolation. On servers, browsers are not present. On developer workstations, the per-binary AppArmor exception approach allows browser sandboxing to continue working while maintaining the system-wide restriction for all other processes.

Kubernetes User Namespaces for Pods — the `hostUsers: false` feature in pod specs — uses a kubelet-controlled path that does not rely on host-level unprivileged user namespace creation. Enabling this Kubernetes feature at the pod level while disabling unprivileged user namespace creation at the host level is explicitly supported and the correct configuration for Kubernetes nodes that need UID remapping without expanding the kernel attack surface.

The highest-value targets for this restriction are CI/CD runner hosts and multi-tenant Kubernetes nodes. On CI runners, untrusted code executes routinely; the attack surface reduction is most valuable precisely because the threat model includes adversarial code in the build environment. On multi-tenant nodes, lateral movement between tenants is the primary concern, and reducing the kernel attack surface available to any individual tenant's workload directly reduces the blast radius of a successful container escape.

Developer workstations require more careful management. The correct approach is to inventory which tools each developer actively uses that depend on user namespaces, implement per-binary AppArmor exceptions for those tools, then enable the system-wide restriction. This is more operational work than a server rollout but leaves developers with functional tooling and the security posture intact.

## Failure Modes

**Partial disablement on Ubuntu.** On Ubuntu, `kernel.unprivileged_userns_clone=0` and `user.max_user_namespaces=0` are both relevant. Setting only the first while leaving `user.max_user_namespaces` at its default positive value (typically 1000 or 65536) may leave a residual path for user namespace creation on certain kernel versions. Always set both on Ubuntu. Verify by testing `unshare -U id` after applying both settings.

**AppArmor exception scoped too broadly.** An AppArmor exception that references the `unconfined` profile or uses an overly broad path glob (such as `/usr/bin/*`) grants `userns` access to every process matched by that pattern. An exception intended to allow Chrome that is written as `/usr/bin/*` effectively re-enables user namespace creation for every binary in `/usr/bin`. Write exceptions as narrowly as possible — name the specific binary — and verify the resulting AppArmor policy with `aa-status` and by testing that unintended processes cannot create user namespaces.

**Container runtime internal requirements.** Some versions of containerd, CRI-O, and other container runtimes use unprivileged user namespace operations for specific internal lifecycle operations — image layer inspection, rootfs setup, or plugin invocation. These operations may fail silently rather than producing obvious errors. Before applying the restriction to any Kubernetes node, test the full container lifecycle end-to-end: pull an image, start a pod, exec into it, and confirm graceful termination. Test with the specific runtime version deployed on the node. A failed runtime operation that prevents pod scheduling produces errors in the kubelet log rather than at the sysctl configuration step, and may only surface under specific workload patterns.

**sysctl settings not persisted.** Settings applied with `sysctl -w` at runtime are lost on reboot. Confirm the `/etc/sysctl.d/99-namespace-hardening.conf` file exists, contains the correct values, and is loaded by the init system. After any kernel update or system reboot, verify the active values:

```bash
sysctl kernel.unprivileged_userns_clone user.max_user_namespaces
```

If either value differs from the expected setting, check for conflicting files in `/etc/sysctl.d/` or `/usr/lib/sysctl.d/` that are loaded after the hardening file and override it:

```bash
sysctl --system 2>&1 | grep -E "unprivileged_userns|max_user_namespaces"
```

The last file to set a given key wins. A distribution-provided file in `/usr/lib/sysctl.d/` that re-enables user namespaces will silently override the hardening file if it sorts later alphabetically. Rename the hardening file to a higher sort order (for example, `99-zz-namespace-hardening.conf`) if conflicts are found.

## Related Articles

- [Linux User Namespace Security](/articles/linux/linux-user-namespace-security/)
- [Linux LPE Defence in Depth](/articles/linux/linux-lpe-defence-in-depth/)
- [AppArmor](/articles/linux/apparmor/)
- [nftables Container Privilege Escalation](/articles/network/nftables-container-privilege-escalation/)
- [Kubernetes LLM Escape Hardening](/articles/kubernetes/kubernetes-llm-escape-hardening/)
