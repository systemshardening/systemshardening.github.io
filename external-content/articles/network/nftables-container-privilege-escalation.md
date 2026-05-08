---
title: "nf_tables Container Privilege Escalation: Hardening the Kernel's Highest-Risk Subsystem"
description: "nf_tables accounts for 43% of user-namespace-enabled kernel CVEs. When containers gain CAP_NET_ADMIN via user namespaces, they reach nf_tables kernel code — the source of dozens of container escapes. Block netfilter access from containers with seccomp, AppArmor, and namespace restrictions."
slug: nftables-container-privilege-escalation
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - nftables
  - container-escape
  - netfilter
  - seccomp
  - kernel-hardening
personas:
  - platform-engineer
  - security-engineer
article_number: 457
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/nftables-container-privilege-escalation/
---

# nf_tables Container Privilege Escalation: Hardening the Kernel's Highest-Risk Subsystem

## The Problem

nf_tables is the modern Linux packet filtering framework — successor to iptables — implemented as a kernel subsystem with a complex, user-programmable expression language for defining filter rules. Its implementation spans roughly 30,000 lines of kernel C, accepts and processes user-controlled data structures, and sits directly behind the `NETLINK_NETFILTER` socket interface. That combination of size, complexity, and user-controlled input has produced a sustained run of memory corruption vulnerabilities: CVE-2022-32250 (use-after-free in `nft_set_elem_list_deactivate`), CVE-2023-32233 (use-after-free in the handling of anonymous sets), CVE-2024-1086 (use-after-free in `nft_verdict_init`), and multiple CVEs in 2025 and 2026 following the same structural pattern of incorrect object lifetime management across `nft_rule`, `nft_set`, and `nft_chain` APIs.

What makes nf_tables distinctively dangerous in container environments is not that the vulnerabilities exist — large kernel subsystems accumulate bugs — but that an unprivileged process can reach this code without any prior privilege. When a container process calls `unshare(CLONE_NEWUSER | CLONE_NEWNET)` to create a user namespace paired with a network namespace, the kernel grants `CAP_NET_ADMIN` within that new namespace. That capability is enough to open a `NETLINK_NETFILTER` socket and call the full nf_tables API — the same kernel code paths that root uses to manage the host firewall. The memory corruption bugs in that code become exploitable by any process that can create a user namespace, which on a default Linux system means any unprivileged user.

Edera's 2026 analysis of kernel CVEs from 2020 through 2025 confirmed that netfilter and nf_tables account for 43% of user-namespace-enabled kernel CVEs over that period — a higher proportion than io_uring, bpf, or any other individual subsystem. That figure is not an artefact of increased research attention; it reflects genuine structural risk in a subsystem that exposes complex mutable kernel state to user-controlled input. Restricting container access to nf_tables eliminates this entire vulnerability class without requiring a patch for each individual CVE. The mitigations in this article close the access path; kernel updates remain necessary to fix the underlying bugs, but the access restriction prevents exploitation while updates are in transit.

The nf_tables access path has four components: user namespace creation grants `CAP_NET_ADMIN`, `CAP_NET_ADMIN` permits `NETLINK_NETFILTER` socket creation, `NETLINK_NETFILTER` socket creation reaches the `nf_tables` message dispatch loop, and the dispatch loop dereferences attacker-controlled kernel objects. Removing any one of these links breaks the chain. This article covers all four removal points and ranks them by effectiveness.

## Threat Model

- **Container process via user namespace self-grant:** An unprivileged container process calls `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, gaining `CAP_NET_ADMIN` within the new namespace. It then opens a `NETLINK_NETFILTER` socket, crafts a sequence of `NFT_MSG_NEWTABLE`, `NFT_MSG_NEWCHAIN`, and `NFT_MSG_NEWRULE` messages designed to trigger a use-after-free in the nf_tables garbage collection path, and exploits the resulting kernel memory corruption to overwrite a kernel function pointer and redirect execution to shellcode running in the container. The attacker exits to the host network namespace with root effective UID. This is the standard exploit path for CVE-2024-1086 and the majority of nf_tables CVEs since 2022.

- **Pod with explicitly granted `CAP_NET_ADMIN`:** A Kubernetes pod running a network policy controller, a service mesh sidecar init container, or a CNI plugin helper has `CAP_NET_ADMIN` added to its capability set in the pod spec. That pod does not need user namespace creation to reach nf_tables — the capability is directly held in the container's effective set. An attacker who achieves RCE within that pod can immediately send nf_tables netlink messages without any namespace manipulation.

- **LLM-automated exploit enumeration:** An AI agent with code execution inside a container systematically generates and tests exploit payloads for known nf_tables CVEs. Because these exploit patterns are well-documented and the nf_tables kernel interface is stable across kernel versions, an LLM can enumerate the relevant `nft_*` call sequences without manual reverse engineering. Automated exploit development compresses the time from container escape attempt to successful kernel corruption compared with purely manual exploitation.

- **Overlayfs as a secondary vector:** Container processes with user namespace access can mount an overlayfs filesystem with host directories as the lower layer. Historical overlayfs CVEs (CVE-2023-0386 and related) use this to write files outside the container or to execute setuid binaries with unexpected privilege. This is a parallel user-namespace-enabled attack class; the same access restriction that closes the nf_tables path also closes the overlayfs path when applied at the namespace creation layer.

- **Access level:** All primary adversaries require only an unprivileged shell inside a container. The pod-with-capability adversary requires only application-level code execution in a pod that was granted `CAP_NET_ADMIN` for legitimate reasons.

- **Objective:** Escape the container and gain root on the Kubernetes node host, from which lateral movement to the Kubernetes control plane is trivial.

## Hardening Configuration

### 1. seccomp: Block nf_tables-Related Syscalls

The nf_tables kernel API is reached exclusively through `NETLINK_NETFILTER` sockets. Those sockets are created with `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` where `NETLINK_NETFILTER` is socket protocol `12`. A seccomp profile that blocks `socket` calls with `AF_NETLINK` (family `16`) prevents container processes from opening the netlink socket required to reach nf_tables. No `nft_*` kernel function is reachable without this socket.

The targeted seccomp approach blocks only `AF_NETLINK` socket creation, leaving all other socket families available. This is sufficient for the nf_tables threat; a more conservative profile for pods that need no network management at all can additionally block `setsockopt` with `SOL_NETLINK` (`270`), but the `socket` restriction alone is the load-bearing control.

Save this profile at `/var/lib/kubelet/seccomp/profiles/block-netfilter.json` on each node:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_AARCH64"
  ],
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
    },
    {
      "names": ["unshare"],
      "action": "SCMP_ACT_ERRNO",
      "errnoRet": 1,
      "args": [
        {
          "index": 0,
          "value": 268435456,
          "op": "SCMP_CMP_MASKED_EQ",
          "valueTwo": 268435456
        }
      ]
    }
  ]
}
```

The second rule blocks `unshare` calls that include `CLONE_NEWUSER` (`0x10000000`), which removes the ability to self-grant capabilities via namespace creation. Both rules together close the direct and indirect nf_tables access paths.

Reference the profile in a pod spec:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened-app
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/block-netfilter.json
  containers:
    - name: app
      image: myapp:latest
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
```

For systemd-managed services on the node itself, use `RestrictAddressFamilies` to apply the same constraint at the service unit level:

```bash
[Service]
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
```

This drops `AF_NETLINK` from the allowed set for the service without affecting its other network operations.

### 2. AppArmor Profile: Deny Netlink Socket Creation

AppArmor's `network` rule controls which socket families a confined process may create. The `network netlink` denial blocks creation of `AF_NETLINK` sockets, preventing access to nf_tables, rtnetlink, and other netlink-based kernel interfaces. This is distinct from `network inet` or `network inet6` denial, which only blocks TCP and UDP sockets and has no effect on netlink.

An AppArmor profile snippet for a container that should have no netlink access:

```
profile container-app flags=(attach_disconnected, mediate_deleted) {
  file,
  network inet stream,
  network inet6 stream,
  network unix stream,
  network unix dgram,

  deny network netlink raw,
  deny network netlink dgram,

  capability net_bind_service,

  deny capability net_admin,
  deny capability net_raw,
}
```

The `deny network netlink raw` and `deny network netlink dgram` rules block the socket types used for netlink communications. The `deny capability net_admin` rule adds a second layer: even if a process reaches a netlink socket through an unexpected path, it will be denied the capability required to use the nf_tables API.

Apply the profile and set it to enforce mode:

```bash
apparmor_parser -r -W /etc/apparmor.d/container-app
aa-status | grep container-app
```

Profiles loaded in `complain` mode log denials but do not block. Confirm the profile shows `enforce` in the `aa-status` output before relying on it as a security control.

For container runtimes, reference the profile in the container configuration. Under containerd with the CRI plugin, specify the profile in the runtime class or pod annotations:

```yaml
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/app: localhost/container-app
```

### 3. Drop `CAP_NET_ADMIN` Explicitly

For pods that do not need to manage network configuration, `CAP_NET_ADMIN` must be dropped explicitly. The Kubernetes default capability set inherited from the container runtime (Docker or containerd) includes capabilities beyond what typical application containers require. Dropping `ALL` capabilities and adding back only what is needed removes `CAP_NET_ADMIN` along with the rest:

```yaml
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE
```

`CAP_NET_BIND_SERVICE` allows binding to ports below 1024; it does not grant access to the netlink subsystem. If the container needs to bind low ports, this is the correct replacement for `CAP_NET_ADMIN`. If the container does not need low port binding either, omit the `add` section entirely.

For pods that legitimately require network management — CNI plugins, service mesh data planes, network policy controllers — explicitly enumerate which netlink operations they need and scope the capability accordingly. There is no finer-grained capability below `CAP_NET_ADMIN` for netlink access, which means these pods require a compensating control: an AppArmor or SELinux policy that restricts which netlink families they can use, combined with audit logging of their netlink activity.

### 4. Disable Unprivileged User Namespace Creation

Disabling `kernel.unprivileged_userns_clone` removes the ability for any unprivileged process to call `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER)`. This single sysctl closes the self-grant path: without user namespace creation, an unprivileged process cannot obtain `CAP_NET_ADMIN`, and therefore cannot reach the nf_tables API regardless of seccomp or AppArmor configuration. It is the most effective single mitigation because it operates at the access primitive rather than at any particular use of that primitive.

```bash
echo "kernel.unprivileged_userns_clone = 0" | tee /etc/sysctl.d/99-userns-restrict.conf
sysctl -p /etc/sysctl.d/99-userns-restrict.conf
```

On RHEL and Fedora, which do not expose `kernel.unprivileged_userns_clone`, use the equivalent control:

```bash
echo "user.max_user_namespaces = 0" | tee /etc/sysctl.d/99-userns-restrict.conf
sysctl -p /etc/sysctl.d/99-userns-restrict.conf
```

Setting `user.max_user_namespaces = 0` prevents user namespace creation system-wide. Setting it to a low integer (e.g., `128`) restricts the total number of user namespaces that can exist simultaneously, which limits abuse without fully blocking rootless containers.

Disabling unprivileged user namespace creation breaks rootless container runtimes (rootless Podman, rootless Docker, rootless Buildah). On Kubernetes nodes where workloads run as the kubelet-managed container user rather than as rootless containers, this restriction typically has no operational impact. Verify by checking whether any DaemonSet or system pod relies on user namespace creation before applying to production nodes.

The companion article [Linux Unprivileged Namespace Restriction](/articles/linux/linux-unprivileged-namespace-restriction/) covers the full impact analysis and delegation patterns for systems where some workloads legitimately require user namespaces.

### 5. Monitor for Netfilter Rule Manipulation from Containers

A container that attempts to add or modify nf_tables rules is behaving anomalously. Legitimate application containers do not call `nft` — that is the job of the host's firewall management tooling or a dedicated network policy controller. Audit events from container processes touching `NETLINK_NETFILTER` are high-fidelity signals for exploitation attempts.

Configure auditd to watch for netlink socket creation with the NETFILTER protocol:

```bash
cat > /etc/audit/rules.d/99-nftables-container.rules << 'EOF'
-a always,exit -F arch=b64 -S socket -F a0=16 -F a2=12 -k netfilter_socket
-a always,exit -F arch=b64 -S unshare -F a0&268435456 -k userns_create
-a always,exit -F arch=b32 -S socket -F a0=16 -F a2=12 -k netfilter_socket
-a always,exit -F arch=b32 -S unshare -F a0&268435456 -k userns_create
EOF

auditctl -R /etc/audit/rules.d/99-nftables-container.rules
```

The first rule fires on `socket(AF_NETLINK=16, *, NETLINK_NETFILTER=12)`. The second fires on `unshare` calls with the `CLONE_NEWUSER` flag bit set. Both rules use keys (`-k`) that allow fast correlation in `ausearch`:

```bash
ausearch -k netfilter_socket --interpret | grep -v 'comm="nft"'
ausearch -k userns_create --interpret
```

Filter out the host's own `nft` process (which legitimately creates these sockets) and alert on all others, particularly those where the `pid` is inside a container network namespace. To correlate audit events with container processes, cross-reference the PID against `/proc/<pid>/cgroup`:

```bash
ausearch -k netfilter_socket -i | awk '/pid=/ {print $NF}' | while read pid; do
  cat /proc/$pid/cgroup 2>/dev/null | grep -q 'kubepods' && echo "CONTAINER PID: $pid"
done
```

Any hit from a `kubepods`-scoped cgroup is a container process attempting netfilter access and should trigger an immediate alert.

## Expected Behaviour After Hardening

After the seccomp profile is applied, a container process that calls `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` receives `EPERM`. The `nft` binary inside the container will fail:

```
Error: Could not process rule: Operation not permitted
```

A direct syscall attempt from C or Python returns `errno=1` (`EPERM`). The nf_tables kernel dispatch loop is never reached; the attack chain is severed at the socket creation step.

After the AppArmor denial is applied and the profile is in enforce mode, the same call is blocked by the LSM hook before the syscall reaches the network stack. The AppArmor denial appears in the audit log:

```
type=AVC msg=audit(1746316800.000:4601): apparmor="DENIED" operation="create"
  profile="container-app" pid=41200 comm="nft"
  family="netlink" sock_type="raw" protocol=12
```

After `CAP_NET_ADMIN` is dropped from the container spec, a process that successfully creates a user namespace (if that path remains available) cannot use nf_tables APIs because the kernel checks `CAP_NET_ADMIN` in the network namespace before processing any `NETLINK_NETFILTER` message. The attempt results in:

```
Error: Could not process rule: Operation not permitted
```

Verify the active capability set inside a running container to confirm the drop took effect:

```bash
kubectl exec -it <pod> -- grep CapEff /proc/1/status
CapEff: 0000000000000400
```

`0x0400` is `CAP_NET_BIND_SERVICE` alone. The absence of `CAP_NET_ADMIN` (`0x1000`) confirms the drop is active.

After disabling `kernel.unprivileged_userns_clone`, any attempt by an unprivileged process to create a user namespace returns `EPERM`:

```bash
unshare -Ur /bin/bash
unshare: unshare failed: Operation not permitted
```

## Trade-offs and Operational Considerations

Blocking `AF_NETLINK` sockets broadly affects any workload that uses netlink for legitimate purposes. The most common cases in Kubernetes environments:

- **CNI plugins:** All standard Kubernetes CNI plugins (Flannel, Calico, Cilium, Weave) use `AF_NETLINK` — specifically `NETLINK_ROUTE` (protocol `0`) — to configure network interfaces, routes, and addresses during pod setup. These plugins run as DaemonSets with elevated privileges. They must be explicitly excluded from the seccomp restriction that blocks `AF_NETLINK`. Apply the block-netfilter seccomp profile only to application workload pods, not to network infrastructure DaemonSets.

- **Service mesh sidecar containers:** Envoy-based sidecars (Istio, Linkerd2) use `AF_NETLINK` during their init container phase to configure iptables redirect rules. The init container, which runs with `CAP_NET_ADMIN`, must be excluded from the `AF_NETLINK` block. The main sidecar proxy container typically does not need netlink after init and can receive the restriction.

- **eBPF-based monitoring agents:** Falco in kernel module mode and eBPF-based network monitors (Cilium Hubble, Pixie) use `AF_NETLINK` for network event subscription. Verify that monitoring agent pods are excluded from the seccomp restriction before deploying it. Test with `strace -e socket falco` to confirm which socket families the agent uses.

- **Rootless container runtimes on developer nodes:** Setting `kernel.unprivileged_userns_clone=0` breaks rootless Podman and rootless Docker entirely. On developer workstations or CI nodes where rootless containers are in use, this mitigation must either be skipped or implemented through a more targeted delegation mechanism (Ubuntu 23.10+ `userns` AppArmor rules, systemd `DelegateNamespaces=` for specific services).

The seccomp approach is the most surgically precise: it blocks `NETLINK_NETFILTER` specifically (protocol `12`) while permitting `NETLINK_ROUTE` (protocol `0`) and other netlink families. Refine the profile to target only the netfilter protocol if blocking all netlink is too broad:

```json
{
  "names": ["socket"],
  "action": "SCMP_ACT_ERRNO",
  "errnoRet": 1,
  "args": [
    {
      "index": 0,
      "value": 16,
      "op": "SCMP_CMP_EQ"
    },
    {
      "index": 2,
      "value": 12,
      "op": "SCMP_CMP_EQ"
    }
  ]
}
```

This args-filtered rule blocks `socket(AF_NETLINK, *, 12)` while permitting `socket(AF_NETLINK, *, 0)` (route) and other netlink protocols. It is a more targeted version of the full AF_NETLINK block and preserves CNI plugin functionality in containers that receive the profile.

## Failure Modes

**Seccomp applied to application pods but not to DaemonSet pods with network access.** A cluster may have monitoring, logging, or network policy DaemonSets that hold `CAP_NET_ADMIN` and run without a seccomp profile. If those DaemonSets are compromised — via a supply-chain attack on the image or an RCE in the agent — the attacker has direct access to nf_tables without needing user namespace creation. The mitigations here are necessary for DaemonSets too, adapted to exclude only the netlink protocols they legitimately use.

**`CAP_NET_ADMIN` dropped in the container spec but user namespace creation remains available.** If the container spec drops `CAP_NET_ADMIN` but the seccomp profile does not block `unshare(CLONE_NEWUSER)`, the container process can create a new user namespace where it is the initial user and automatically holds a full capability set including `CAP_NET_ADMIN` within that namespace. The capability drop at the container level does not prevent re-acquisition via namespace creation. Both the capability drop and the `unshare` block are required together.

**AppArmor profile applied in complain mode rather than enforce mode.** A profile in `complain` mode generates audit log entries for denied operations but does not block them. This is the default for newly loaded profiles on some distributions. Confirm the mode explicitly:

```bash
aa-status | grep -A1 "container-app"
```

The output must show `enforce`, not `complain`. Switching to enforce mode:

```bash
aa-enforce /etc/apparmor.d/container-app
```

**Auditd rules applied but not reloaded.** Writing rules to `/etc/audit/rules.d/` does not activate them until auditd rereads its configuration. Confirm the rules are active:

```bash
auditctl -l | grep netfilter_socket
```

An empty result means the rules are not loaded, even if the file exists.

**Sysctl set at runtime but not persisted.** `sysctl -w kernel.unprivileged_userns_clone=0` takes effect immediately but does not survive a reboot. The setting must be in a file under `/etc/sysctl.d/` and loaded via `sysctl --system` during boot. Verify after the next scheduled reboot:

```bash
sysctl kernel.unprivileged_userns_clone
```

## Related Articles

- [Linux Unprivileged Namespace Restriction](/articles/linux/linux-unprivileged-namespace-restriction/)
- [nftables](/articles/linux/nftables/)
- [Linux Netfilter Security](/articles/linux/linux-netfilter-security/)
- [Seccomp BPF Without Containers](/articles/linux/seccomp-bpf-non-container/)
- [Kubernetes LLM Escape Hardening](/articles/kubernetes/kubernetes-llm-escape-hardening/)
