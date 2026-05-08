---
title: "Linux netfilter and nf_tables Security Hardening"
description: "Harden Linux netfilter and nf_tables against CVE-2026-31414-class connection tracking bugs, privilege escalation via nf_tables, and the recurring pattern of silent kernel netfilter fixes."
slug: linux-netfilter-security
date: 2026-05-02
lastmod: 2026-05-02
category: linux
tags: ["netfilter", "nftables", "nf-tables", "cve-2026-31414", "kernel", "lpe", "connection-tracking"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 367
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/linux/linux-netfilter-security/index.html"
---

# Linux netfilter and nf_tables Security Hardening

## Problem

Linux netfilter is the kernel framework that underpins every form of packet filtering and network address translation on Linux systems. iptables, nftables, conntrack, ipset, and every stateful firewall feature the kernel exposes are built on top of netfilter hooks embedded in the network stack. Since kernel 3.13, nf_tables has been the modern packet filtering subsystem, replacing iptables with a more expressive rule set language evaluated by a register-based virtual machine inside the kernel. Unlike iptables, which used fixed match/target modules, nf_tables allows userspace to compose arbitrary rule expressions — comparisons, arithmetic operations, set lookups, map lookups, and verdict expressions — that the kernel evaluates inline in the packet path. This flexibility is powerful for firewall authors and catastrophic when the expression evaluation engine has a bug.

**CVE-2026-31414** was reserved on March 9, 2026 and published in May 2026. The vulnerability resides in the netfilter connection tracking expectations mechanism, specifically in `nf_conntrack_expect`. Connection tracking helpers are kernel modules that inspect application-layer protocols (FTP, SIP, IRC, H.323) and create "expectations" — pre-authorised connection entries in the conntrack table — to allow the secondary data connections these protocols establish. The unsafe helper lookup procedure in CVE-2026-31414 permitted improper access to connection tracking helpers through the expectation creation path, potentially allowing a local attacker to trigger privilege escalation or a denial of service by crafting malformed expectations. The vulnerability affects kernels in the 6.1–6.10 range. The nearly two-month gap between CVE reservation (March 9) and public disclosure (May 2026) gave major distributions adequate time to prepare kernel updates — but the reservation itself was publicly visible on MITRE from March 9, clearly signalling that a netfilter security fix was in progress to anyone watching the MITRE CVE feed.

The netfilter subsystem has a long and consistent history of high-severity CVEs. CVE-2022-1972 was an out-of-bounds write in nf_tables. CVE-2023-32233 was a use-after-free in nf_tables that enabled local privilege escalation to root and was demonstrated in working exploit code within days of disclosure. CVE-2024-1086 was another nf_tables use-after-free that was widely exploited in the wild; a working public exploit achieved local root on kernels from 5.14 to 6.6. CVE-2026-31414 continues this pattern. The attack surface is structurally large: nf_tables accepts complex rule expressions from userspace via netlink sockets; any process with `CAP_NET_ADMIN` can load nf_tables rules; because unprivileged user namespace creation grants `CAP_NET_ADMIN` within the new network namespace, and many distributions enable this by default, a completely unprivileged local user can reach the nf_tables expression engine. Bugs in expression evaluation, set/map lookup, or the verdict interpreter yield kernel arbitrary read/write primitives.

The open-source visibility problem with netfilter is well-documented and operationally relevant. The netfilter developers maintain two public git trees: `git.kernel.org/pub/scm/linux/kernel/git/netfilter/nf.git` (the stable fixes tree) and `nf-next.git` (the development tree). Security fixes land in the `nf` tree and are visible in its commit log before being pulled into Linus's mainline tree and subsequently into distribution kernels. CVE-2024-1086 illustrates the pattern precisely: the fix was committed to the `nf` tree on January 31, 2024 with commit `f342de4e2f33e0e39165d8639387aa6c19dff660`, touching `nft_verdict_init()` in `nf_tables_api.c`. The commit message described a use-after-free fix but carried no CVE reference. This commit was publicly visible in the `nf` tree for approximately three weeks before the CVE was formally assigned and before the fix propagated into Ubuntu, Debian, or RHEL kernel packages. Researchers monitoring `nf.git` identified the fix type from the diff — freeing a reference that was being held past its valid lifetime in the verdict path — and developed working exploits during this window. The same early-visibility pattern is expected to recur for every future netfilter security fix, including the class of bug addressed by CVE-2026-31414.

Effective defence against this class of vulnerability has two tracks. The first is architectural: eliminate or restrict the conditions under which unprivileged code can reach the nf_tables expression engine. The second is operational: monitor the `nf` tree for security-relevant commits and use that signal to trigger accelerated kernel patching, before distribution packages arrive. Neither track alone is sufficient. Monitoring the `nf` tree at `https://git.kernel.org/pub/scm/linux/kernel/git/netfilter/nf.git/log/` for commits touching `net/netfilter/nf_conntrack*.c` and `net/netfilter/nf_tables*.c`, and subscribing to `netfilter-devel@vger.kernel.org`, provides early warning. Cross-referencing commits against `https://www.openwall.com/lists/oss-security/` for netfilter disclosure threads completes the picture.

Target systems: Linux kernel 6.1–6.10 for CVE-2026-31414 specifically; all kernels with nf_tables enabled and unprivileged user namespace creation permitted for the broader nf_tables LPE attack class — this covers Ubuntu 22.04 and later, Debian 11 and later, RHEL 9 and later, Fedora 37 and later, and most container-hosting systems.

## Threat Model

1. **Local unprivileged user via user namespace.** An attacker with a local shell account runs `unshare -n` — which requires no privileges on most modern distributions — gaining `CAP_NET_ADMIN` within a new network namespace. The attacker then loads a crafted nf_tables ruleset that triggers CVE-2026-31414 or a related expression evaluation bug in the kernel. The result is a kernel arbitrary write primitive, used to overwrite a process credential structure or a function pointer, achieving full local privilege escalation to root.

2. **Container escape via `CAP_NET_ADMIN`.** Kubernetes pods running network plugins (Calico, Cilium, Flannel) frequently require `CAP_NET_ADMIN` within their network namespace. An attacker who achieves code execution inside such a pod — through a vulnerable application or a supply chain compromise — uses the granted capability to load a crafted nf_tables ruleset exploiting a use-after-free or out-of-bounds write, escaping the container's network namespace boundary and obtaining kernel-level access on the host node.

3. **Patch-gap attacker monitoring the `nf` tree.** An attacker monitors `https://git.kernel.org/pub/scm/linux/kernel/git/netfilter/nf.git/log/` for commits touching `nf_conntrack_expect.c` or `nf_tables_core.c`. When the commit fixing CVE-2026-31414's unsafe helper lookup appears in the tree, the attacker reads the diff, identifies the precise code path that was changed (the expectation creation and helper assignment sequence in `nf_conntrack_expect`), and begins developing a proof-of-concept against unpatched systems. With an approximately eight-week window between the upstream commit and the arrival of patched kernels in major distribution package repositories, the attacker has substantial time to produce a working exploit and deploy it against exposed targets before defenders apply the fix.

4. **Denial of service via conntrack exhaustion.** An attacker able to send network traffic to a target (or able to influence traffic patterns through a compromised adjacent system) crafts packets designed to create large numbers of connection tracking entries or malformed expectations. Without conntrack table size limits, this can fill the entire conntrack table (`nf_conntrack_max`), causing all new connection establishment to fail. On a system using automatic conntrack helper assignment (`nf_conntrack_helper=1`), crafted application-layer traffic can also trigger unexpected helper invocations that interact with the vulnerability class described in CVE-2026-31414.

The blast radius of an nf_tables or conntrack exploit is wide because the netfilter subsystem runs in kernel context with full kernel memory access. A successful local privilege escalation reaches every process, every credential, every secret on the machine. In a Kubernetes environment, a compromised node can be used to exfiltrate secrets from etcd-backed volumes, impersonate the kubelet, or pivot to other cluster nodes via the control plane. Reducing the blast radius requires eliminating the preconditions — unprivileged user namespace creation and automatic conntrack helper assignment — and maintaining a kernel patching cadence fast enough to close the patch-gap window.

## Configuration / Implementation

### Restricting Unprivileged User Namespace Creation

Unprivileged user namespace creation is the primary vector for local privilege escalation via nf_tables. A user who cannot create a new network namespace cannot reach `CAP_NET_ADMIN` without already having elevated privileges. On Debian and Ubuntu, a non-upstream sysctl knob controls this:

```bash
# Disable unprivileged user namespace creation (Debian/Ubuntu)
sysctl -w kernel.unprivileged_userns_clone=0

# Persist across reboots
echo "kernel.unprivileged_userns_clone=0" >> /etc/sysctl.d/99-netfilter-hardening.conf
sysctl -p /etc/sysctl.d/99-netfilter-hardening.conf
```

On RHEL, Fedora, and distributions without the `unprivileged_userns_clone` knob, use the upstream kernel parameter:

```bash
# Disable user namespaces entirely (upstream kernel)
sysctl -w user.max_user_namespaces=0

# Persist
echo "user.max_user_namespaces=0" >> /etc/sysctl.d/99-netfilter-hardening.conf
```

Verify the restriction is effective:

```bash
# Should fail with "unshare: unshare failed: Operation not permitted"
unshare -n ip link
```

The trade-off is real: `kernel.unprivileged_userns_clone=0` breaks Podman rootless containers (which use user namespaces to avoid requiring root for container operations), Chrome and Chromium's process sandbox (which uses a user namespace to isolate renderer processes), and Bubblewrap-based sandboxing tools used by Flatpak. Document this trade-off explicitly before deploying. On servers and production Linux hosts where rootless container tooling is not required, this is the single most effective control against nf_tables local privilege escalation.

### Disabling nf_tables If Not Required

Systems using iptables-legacy as their firewall backend may have nf_tables loaded as a kernel module but unused. Removing the module eliminates the attack surface entirely.

```bash
# Check whether nf_tables is currently in active use
nft list ruleset

# Check which iptables backend is active
iptables-legacy-save | head -5

# If no rules exist in nf_tables and iptables-legacy is in use, unload the module
modprobe -r nf_tables

# Verify unload
lsmod | grep nf_tables
```

If `modprobe -r nf_tables` returns an error because the module is in use, identify what is holding it:

```bash
lsmod | grep -E "^nf_tables|^nft_"
```

To prevent nf_tables from loading on future boots:

```bash
echo "blacklist nf_tables" >> /etc/modprobe.d/blacklist-nftables.conf
update-initramfs -u   # Debian/Ubuntu
# or
dracut --force        # RHEL/Fedora
```

Note: blacklisting nf_tables prevents Docker and Kubernetes from using iptables-nft (the default on RHEL 9 and newer distributions). Verify your container runtime's firewall backend before applying this control in a container hosting environment.

### Conntrack Hardening

Three sysctl settings address the conntrack-specific attack surface, including the helper assignment behaviour directly implicated in CVE-2026-31414-class bugs.

```bash
# Cap the conntrack table to prevent exhaustion DoS
# Default is often unlimited or set based on system RAM; 131072 is reasonable for most servers
sysctl -w net.netfilter.nf_conntrack_max=131072

# Reduce the idle timeout for established TCP connections
# Default is 432000 (5 days); 3600 (1 hour) aggressively reclaims table entries
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=3600

# Disable automatic conntrack helper assignment
# This is the direct mitigation for CVE-2026-31414-class unsafe helper lookup bugs
# Conntrack helpers will no longer be automatically assigned to new connections
sysctl -w net.netfilter.nf_conntrack_helper=0
```

Persist these settings:

```bash
cat >> /etc/sysctl.d/99-netfilter-hardening.conf << 'EOF'
net.netfilter.nf_conntrack_max=131072
net.netfilter.nf_conntrack_tcp_timeout_established=3600
net.netfilter.nf_conntrack_helper=0
EOF
sysctl -p /etc/sysctl.d/99-netfilter-hardening.conf
```

Verify the helper setting took effect:

```bash
cat /proc/sys/net/netfilter/nf_conntrack_helper
# Expected output: 0
```

Monitor current conntrack table utilisation to avoid inadvertently setting `nf_conntrack_max` too low:

```bash
# Current number of conntrack entries
cat /proc/sys/net/netfilter/nf_conntrack_count

# Should be well below nf_conntrack_max; if >80%, increase max
```

The `nf_conntrack_helper=0` setting disables automatic helper assignment globally. If your environment uses NAT traversal for FTP, SIP, or IRC — protocols that require conntrack helpers for ALG (Application Layer Gateway) functionality — you must explicitly configure helpers on a per-connection basis using nft `ct helper` rules rather than relying on automatic assignment. This is covered in the Trade-offs section.

### Restricting Netlink Socket Access via Seccomp

Processes that do not need to configure the firewall should not be able to open `AF_NETLINK` sockets, which are the interface through which userspace communicates with netfilter and nf_tables. A seccomp profile blocking `AF_NETLINK` socket creation for non-firewall workloads eliminates the ability of a compromised process to reach nf_tables at all.

The seccomp rule to block `socket(AF_NETLINK, ...)` — `AF_NETLINK` is address family 16:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "args": [
        {
          "index": 0,
          "value": 16,
          "op": "SCMP_CMP_EQ"
        }
      ]
    }
  ]
}
```

Save this as `/etc/seccomp/block-netlink.json` and apply it to non-network-admin workloads. In Kubernetes, apply it as a pod-level seccomp profile for pods that do not need firewall access:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: block-netlink.json
  containers:
    - name: app
      image: app:latest
```

Store the seccomp profile in the kubelet's seccomp profile directory (typically `/var/lib/kubelet/seccomp/`) and reference it with `localhostProfile: block-netlink.json`.

For systemd services, apply the equivalent restriction using `RestrictAddressFamilies`:

```ini
# In the [Service] section of a systemd unit file
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# Omitting AF_NETLINK prevents the service from opening netlink sockets
```

### Auditing netlink Socket Access

Track which processes attempt to open netlink sockets to identify unexpected access attempts:

```bash
# Add an audit rule to log AF_NETLINK socket creation
auditctl -a always,exit -F arch=b64 -S socket -F a0=16 -k netfilter_socket

# Watch the audit log for hits
ausearch -k netfilter_socket -ts today
```

Audit the currently loaded nf_tables ruleset to detect unexpected rules that may have been loaded by a compromised process:

```bash
# List the full ruleset with handle numbers for auditability
nft list ruleset -a

# Validate a ruleset file before loading it
nft -c -f /etc/nftables.conf
```

### Monitoring the netfilter Tree for Silent Fixes

Establish a local clone of the `nf` tree and run a cron job to detect new commits before they acquire CVE numbers:

```bash
# Initial clone of the netfilter stable fixes tree
git clone https://git.kernel.org/pub/scm/linux/kernel/git/netfilter/nf.git /opt/netfilter-nf --bare

# Weekly cron job: fetch and report new commits touching netfilter source files
cat > /etc/cron.d/netfilter-monitor << 'EOF'
0 8 * * 1 root git -C /opt/netfilter-nf fetch origin 2>/dev/null && git -C /opt/netfilter-nf log --oneline ORIG_HEAD..origin/main -- net/netfilter/ 2>/dev/null | grep -q . && git -C /opt/netfilter-nf log --oneline ORIG_HEAD..origin/main -- net/netfilter/ | mail -s "netfilter nf tree: new commits" security-team@example.com
EOF
```

A more robust daily monitoring script with focused filtering for high-risk paths:

```bash
#!/bin/bash
# /usr/local/sbin/netfilter-monitor.sh
# Run daily; alerts on new commits touching connection tracking or nf_tables core

NF_REPO=/opt/netfilter-nf
ALERT_EMAIL="${NETFILTER_ALERT_EMAIL:-security-team@example.com}"
HIGH_RISK_PATHS="net/netfilter/nf_conntrack net/netfilter/nf_tables"

git -C "$NF_REPO" fetch origin --quiet 2>&1

for path in $HIGH_RISK_PATHS; do
    commits=$(git -C "$NF_REPO" log --oneline ORIG_HEAD..origin/main -- "$path" 2>/dev/null)
    if [ -n "$commits" ]; then
        echo "New commits in $path:"
        echo "$commits"
        echo ""
        echo "Review at: https://git.kernel.org/pub/scm/linux/kernel/git/netfilter/nf.git/log/"
    fi
done | mail -s "[ALERT] netfilter nf tree new commits - $(date +%Y-%m-%d)" "$ALERT_EMAIL"

git -C "$NF_REPO" update-ref refs/previous/main origin/main 2>/dev/null || true
```

Cross-reference alerts with:
- `https://www.openwall.com/lists/oss-security/` — search for "netfilter" threads
- `https://osv.dev/list?ecosystem=Linux` — kernel CVEs with netfilter tags
- `netfilter-devel@vger.kernel.org` mailing list archives

## Expected Behaviour

| Signal | Unpatched / default config | Patched + hardened |
|---|---|---|
| Unprivileged user runs `unshare -n` then loads crafted nf_tables ruleset | Succeeds; attacker reaches `CAP_NET_ADMIN` in new network namespace and submits nf_tables expressions to the kernel expression engine | `unshare -n` fails with "Operation not permitted"; kernel never receives the crafted ruleset |
| Connection to FTP server triggers conntrack helper auto-assignment | `nf_conntrack_ftp` helper assigned automatically; CVE-2026-31414-class unsafe helper lookup reachable | `nf_conntrack_helper=0` prevents automatic assignment; helper lookup path is not reached for untrusted traffic |
| Attacker sends traffic crafted to exhaust conntrack table | Conntrack table fills without bound; all new connections fail; kernel may OOM or become unresponsive | `nf_conntrack_max=131072` caps table size; `nf_conntrack_tcp_timeout_established=3600` reclaims idle entries; table exhaustion is bounded |
| Compromised pod attempts nf_tables UAF exploit via netlink socket | Pod with `CAP_NET_ADMIN` successfully opens `AF_NETLINK` socket and loads crafted rules into the expression engine | Seccomp profile blocks `socket(AF_NETLINK, ...)` for non-network-admin pods; pod receives `EPERM`; audit rule logs the attempt |
| Patch-gap attacker monitors `nf.git` for CVE-2026-31414 fix commit | Fix commit visible in `nf` tree for weeks before distribution kernels are updated; attacker develops exploit against unpatched systems | Automated monitoring detects new commits in `net/netfilter/nf_conntrack*` within 24 hours; alert triggers accelerated kernel patching workflow |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| `kernel.unprivileged_userns_clone=0` | Eliminates the primary unprivileged path to `CAP_NET_ADMIN` and the nf_tables expression engine; closes CVE-2023-32233, CVE-2024-1086, and CVE-2026-31414 class attacks for local unprivileged users | Breaks Podman rootless (user namespaces required for uid mapping), Chrome/Chromium renderer sandbox (uses user namespace for isolation), Flatpak/Bubblewrap sandboxing | Use on servers and production nodes where rootless container tools are not deployed; document the requirement explicitly; use Podman with explicit root or a dedicated socket instead |
| `nf_conntrack_helper=0` | Disables automatic conntrack helper assignment; directly mitigates CVE-2026-31414-class unsafe helper lookup; reduces attack surface in `nf_conntrack_expect.c` | Breaks passive mode FTP, SIP call setup, IRC DCC, and other protocols that rely on ALG helpers for secondary connection authorisation | Configure explicit `ct helper` rules in nft for the specific protocols and ports your environment uses; document which conntrack helpers are intentionally enabled |
| nf_tables module blacklist | Removes the nf_tables expression engine from kernel memory entirely; eliminates the entire CVE class for kernels where nf_tables is unused | Prevents Docker (iptables-nft mode) and Kubernetes kube-proxy from loading iptables rules on RHEL 9+ and newer distributions that default to the nft backend | Switch container runtime and kube-proxy to the legacy iptables backend before blacklisting; verify with `iptables -V` that "legacy" appears in the output |
| AF_NETLINK seccomp restriction | Prevents compromised application processes from opening netlink sockets to interact with netfilter; contains post-exploitation capability | Breaks any tool inside the sandboxed process that legitimately needs netlink (network namespace introspection, CNI plugins, systemd-networkd interactions) | Apply only to well-understood workloads that provably never need netlink; do not apply to CNI plugin containers, network monitoring agents, or kube-proxy |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `nf_conntrack_helper=0` breaks FTP passive mode | FTP clients connect successfully but `PASV` command returns a port that firewalls do not open; file transfers hang or fail with connection refused | Test with `ftp` or `lftp` to a known-good FTP server; `PASV` connection times out; `conntrack -L` shows no expectation entries created for FTP | Add an explicit nft `ct helper` rule: `nft add rule inet filter input ct helper set "ftp-21"`; load the `nf_conntrack_ftp` module; verify expectations appear with `conntrack -L -p tcp --dport 21` |
| nf_tables blacklist prevents Docker iptables from loading | Docker daemon fails to start or reports "Failed to program FORWARD chain"; containers have no network connectivity; `docker network ls` shows networks but `iptables -L` shows no Docker rules | `journalctl -u docker` shows iptables errors; `lsmod | grep nf_tables` returns empty | Switch Docker to legacy iptables: `echo '{"iptables": true}' > /etc/docker/daemon.json` and ensure `update-alternatives --set iptables /usr/sbin/iptables-legacy`; rebuild initramfs without the blacklist if iptables-nft is the only available backend |
| Seccomp AF_NETLINK block breaks CNI plugin | Kubernetes pod networking fails; pods start but immediately enter `CrashLoopBackOff` or cannot reach cluster DNS; CNI plugin logs show socket errors | `kubectl describe pod` shows container started but network setup failed; `strace -e trace=network` on the CNI binary shows `socket(AF_NETLINK, ...) = -1 EPERM`; auditd logs show `netfilter_socket` hits from the CNI process | Remove the seccomp profile from the node's CNI DaemonSet pods; apply the profile only to application pods; maintain a separate, less restrictive profile for network infrastructure pods |
| Conntrack table full causes connection drops | New TCP connections to the host fail with "connection refused" or time out; existing connections are unaffected; SSH to the host from a new source fails | `cat /proc/sys/net/netfilter/nf_conntrack_count` equals `nf_conntrack_max`; `dmesg | grep "nf_conntrack: table full"` shows recent messages; `conntrack -L | wc -l` confirms full table | Immediately: `sysctl -w net.netfilter.nf_conntrack_max=262144` to double the limit; `conntrack -F` to flush stale entries after identifying safe-to-remove entries; reduce `nf_conntrack_tcp_timeout_established` to `1800` to accelerate idle entry reclamation; longer term: investigate which service is generating excessive conntrack entries |

## Related Articles

- [Linux Firewall Hardening with nftables](/articles/linux/nftables/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [Seccomp BPF for Non-Container Workloads](/articles/linux/seccomp-bpf-non-container/)
- [eBPF Verifier Security Hardening](/articles/linux/ebpf-verifier-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
