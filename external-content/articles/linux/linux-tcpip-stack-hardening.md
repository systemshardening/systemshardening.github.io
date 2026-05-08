---
title: "Linux TCP/IP Stack Hardening via sysctl Parameters"
description: "A defence-in-depth guide to hardening the Linux network stack with sysctl: SYN flood protection, ICMP filtering, reverse path filtering, TCP timestamps, IPv6 RA hardening, and full verified drop-in configuration for production systems."
slug: linux-tcpip-stack-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - sysctl
  - tcp-hardening
  - network-security
  - kernel
  - syn-flood
personas:
  - security-engineer
  - platform-engineer
article_number: 467
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-tcpip-stack-hardening/
---

# Linux TCP/IP Stack Hardening via sysctl Parameters

## The Problem

Your firewall ruleset does not cover everything. `nftables`, `iptables`, and cloud security groups operate on packet decisions: accept, drop, forward. They have limited visibility into how the kernel *processes* the packets it accepts. The kernel's TCP/IP stack itself handles SYN queue management, ICMP error processing, route resolution, and connection keepalive — and its defaults are tuned for compatibility and interoperability, not adversarial environments.

Consider what ships enabled by default on a stock Ubuntu 24.04 or RHEL 9 system:

- The kernel accepts ICMP redirect messages from any router on the local segment, allowing a malicious host to rewrite your routing table without touching your firewall.
- Source-routed packets are processed normally, giving an attacker control over the path packets take through your infrastructure.
- TCP keepalive fires after 7200 seconds (2 hours) of idle time, meaning a NAT entry or firewall state table entry for a dead connection can stay alive — and allow bypassed state checks — for the better part of an afternoon.
- The SYN backlog defaults are tuned for a workstation, not a server under deliberate flood conditions.
- IPv6 router advertisements are accepted unconditionally, letting any host on the same network segment reconfigure your IPv6 default route.

None of these are firewall problems. They are kernel network stack behaviour. Sysctl parameters are the correct tool to address them.

This article covers only network stack parameters. For kernel memory hardening and information disclosure protections, see the companion article on [kernel sysctl hardening](/articles/linux/sysctl-kernel-hardening/).

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, kernel 5.15+.

## Threat Model

- **Adversary:** Network-adjacent attacker (compromised host on the same VPC, untrusted tenant on shared infrastructure, attacker who has gained a foothold in the internal network), and external attackers capable of sending volumetric traffic.
- **Access level:** Network access to one or more interfaces on the target host. No local shell required for most of these attacks.
- **Objective:** Traffic interception via ICMP redirect manipulation, IP spoofing to bypass per-source-IP rate limits or access controls, SYN flood denial of service, network topology reconnaissance via ICMP, stale connection reuse to bypass firewall state tables.
- **Blast radius:** Ranges from denial of service (SYN flood) to traffic redirection (ICMP redirect, source routing) to outright connection hijacking. On Kubernetes nodes, a DoS against the node's TCP stack can starve the kubelet and cause pod eviction cascades.

---

## SYN Flood Protection

A SYN flood sends a high volume of TCP SYN packets with spoofed source IPs. The server allocates a half-open connection entry for each SYN, waiting for the completing ACK that never arrives. When the SYN backlog fills, legitimate connection attempts are dropped.

### How SYN cookies work

When `tcp_syncookies = 1` and the SYN backlog is full, the kernel stops allocating state for new connections and instead encodes the necessary connection parameters (MSS, timestamp, sequence number) as a cryptographic cookie in the SYN-ACK's sequence number field. If the client is real, it will echo the cookie back in the ACK's acknowledgement number. The kernel decodes the cookie and completes the handshake. If the client is spoofed, no ACK ever arrives and no state was ever allocated.

SYN cookies are a fallback mechanism. They have a cost: TCP options negotiated during the handshake (window scaling, SACK) cannot be preserved in the cookie and are lost, slightly reducing throughput for connections that complete under flood conditions. This is acceptable. Running out of SYN backlog and dropping all new connections is not.

Three parameters control SYN flood behaviour:

```ini
# SYN cookies: engage when the SYN backlog is full.
# REQUIRED: do not disable. If disabled, the kernel has no fallback
# when the backlog fills and will simply drop new connection attempts.
net.ipv4.tcp_syncookies = 1

# Maximum number of half-open (SYN_RECV) connections in the SYN queue.
# Default on most distributions: 128 or 256. Increase for high-connection-rate
# servers. The kernel will use the maximum of this and somaxconn.
net.ipv4.tcp_max_syn_backlog = 2048

# How many times to retransmit SYN-ACK before dropping a half-open connection.
# Default: 5 (approximately 180 seconds). Reduce to 2 to reclaim SYN queue
# slots faster during a flood, at the cost of longer RTT paths occasionally
# losing connections.
net.ipv4.tcp_synack_retries = 2
```

**The `tcp_timestamps` dependency:** SYN cookies require TCP timestamps to encode the timestamp field in the cookie. Older hardening guides recommend setting `net.ipv4.tcp_timestamps = 0` to prevent uptime fingerprinting. This is wrong: disabling timestamps disables the MSS encoding in SYN cookies, degrading their effectiveness. The uptime information leaked by TCP timestamps is minimal and obtainable through other means (TLS certificate TTLs, response headers, SNMP). Keep timestamps enabled. The fingerprinting threat model does not justify disabling a core flood protection mechanism.

```ini
# Required for full SYN cookie functionality. Do not disable.
net.ipv4.tcp_timestamps = 1
```

The one legitimate argument for disabling timestamps is a specific class of side-channel attack that can infer the timing of packets at the kernel level by observing timestamp increments. This is a realistic concern on shared-CPU cloud tenants executing cryptographic operations. For most servers, the flood protection value outweighs the side-channel risk.

---

## ICMP Hardening

ICMP serves a legitimate operational role (path MTU discovery, unreachable notifications) but several ICMP message types are attack vectors.

### Broadcast ICMP (Smurf amplification)

An attacker sends ICMP echo requests to a subnet broadcast address with a spoofed source IP (the victim). Every host on the subnet responds to the victim, amplifying traffic by the number of hosts. Setting `icmp_echo_ignore_broadcasts` prevents the kernel from responding to broadcast-destined ICMP echo requests.

```ini
# Ignore ICMP echo requests sent to broadcast or multicast addresses.
# Prevents participation in Smurf amplification attacks.
net.ipv4.icmp_echo_ignore_broadcasts = 1
```

### Bogus ICMP error messages

Some network devices generate malformed ICMP error messages with incorrect checksums or type/code combinations. Without this setting, the kernel logs each one, potentially filling disk with noise or — in crafted scenarios — triggering state machine edge cases.

```ini
# Silently drop malformed ICMP error messages.
net.ipv4.icmp_ignore_bogus_error_responses = 1
```

### ICMP redirects

ICMP redirect messages (type 5) instruct a host to update its routing table: "next time you want to reach X, send to Y instead." On a properly segmented network, your hosts should only accept routing updates from your actual routers, via a routing protocol, not from arbitrary ICMP senders on the local segment.

Accepting ICMP redirects means any host on the same broadcast domain can redirect your traffic through itself — a trivially exploitable man-in-the-middle primitive. `secure_redirects` limits acceptance to gateways in the routing table, which is better than no restriction, but still allows any host that happens to be in your routing table to send redirects. The correct setting for servers is to reject all redirects.

```ini
# Do not accept ICMP redirect messages for IPv4.
# Any setting below accept_redirects=0 leaves a manipulation surface open.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Do not consider "secure" redirects (from a gateway) acceptable either.
# For servers, routing table updates should come from your routing daemon only.
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Do not send ICMP redirects. Servers are not routers.
# Sending redirects leaks your internal routing topology.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
```

---

## Reverse Path Filtering

Reverse path filtering (RPF) answers the question: "if I received this packet on interface X from source address S, would I route a reply back out through interface X?" If the answer is no, the source address is inconsistent with the network topology — it is likely spoofed.

RPF has two modes:

- **Mode 1 (strict):** Drop the packet if the best route back to the source address does not go out the same interface the packet arrived on. Correct for hosts with a single uplink or symmetric routing.
- **Mode 2 (loose):** Drop the packet if there is no route back to the source address at all (any interface). Appropriate for multi-homed hosts with asymmetric routing where legitimate traffic may arrive on a different interface than replies would use.
- **Mode 0:** No filtering. Never use on a production host.

```ini
# Strict reverse path filtering on all interfaces.
# Change to =2 only if this host has asymmetric routing
# (e.g., BGP multi-homed with different uplinks for inbound vs outbound).
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

**Container and Kubernetes caveat:** Container runtimes (containerd, CRI-O) create virtual network interfaces for pod traffic. Traffic from pods to external services may appear on `eth0` but the source address routes back out a virtual interface. In this case, strict RPF (`=1`) can drop legitimate pod traffic. Test with your container networking plugin. Flannel with host-gw mode, Calico in BGP mode, and Cilium with direct routing all require evaluating whether `rp_filter=2` is needed on the node-facing interfaces. The pod-facing interfaces (`cni0`, `flannel.1`, etc.) typically need `rp_filter=0`.

---

## Source Routing Rejection

IP source routing (IPv4 options 131/137, IPv6 type 0 routing header) allows the packet sender to specify the exact path the packet takes through intermediate routers. Legitimate use cases for source routing are essentially non-existent in modern networks. The attack use case — routing traffic through a controlled intermediate host to bypass firewall rules or observe traffic — is well-documented.

```ini
# Reject packets with IPv4 source routing options set.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Reject IPv6 packets with type 0 routing headers.
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
```

---

## TCP Keepalive Tuning

TCP keepalive probes detect dead connections by sending a probe packet on an otherwise idle connection. The default Linux values are:

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `tcp_keepalive_time` | 7200 s | How long to wait after the last data exchange before sending the first probe |
| `tcp_keepalive_intvl` | 75 s | How long between subsequent probes |
| `tcp_keepalive_probes` | 9 | How many consecutive unanswered probes before declaring the connection dead |

With defaults, a dead connection is not declared until 7200 + (9 × 75) = 7875 seconds — over two hours.

This matters for security in two ways:

1. **Firewall state table exhaustion:** Stateful firewalls track established connections. A flood of half-dead connections that the kernel has not yet cleaned up can exhaust state table entries, causing the firewall to drop new legitimate connections or — worse — enter a fail-open mode where stateful inspection is bypassed.

2. **Connection slot starvation:** Applications that maintain per-connection state (databases, reverse proxies) can exhaust their connection limits because dead connections from crashed clients are not cleaned up promptly.

For servers in controlled infrastructure where dead client detection is important, reduce the keepalive time significantly:

```ini
# Time before the first keepalive probe after inactivity.
# 300 seconds (5 minutes) is aggressive; 600 seconds works for most servers.
# Application-level keepalives (e.g., database ping intervals) can use shorter
# intervals without touching these kernel parameters.
net.ipv4.tcp_keepalive_time = 600

# Interval between keepalive probes once the first one is sent.
net.ipv4.tcp_keepalive_intvl = 30

# Number of unanswered probes before the connection is declared dead.
# With intvl=30 and probes=3: dead connection detected 90 seconds after
# first unanswered probe, total dead time: 600 + 90 = 690 seconds.
net.ipv4.tcp_keepalive_probes = 3
```

**Note:** These are TCP-level keepalives, enabled only when `SO_KEEPALIVE` is set on a socket. Applications must opt in. Most database clients, SSH, and long-lived API servers use `SO_KEEPALIVE`. Short-lived HTTP connections are typically unaffected.

---

## IPv6-Specific Parameters

IPv6 introduces its own attack surface through Neighbour Discovery Protocol (NDP) and Router Advertisements (RA).

### Router Advertisements

Router Advertisements (ICMPv6 type 134) allow any host on the local segment to announce itself as a default router and configure addresses via Stateless Address Autoconfiguration (SLAAC). On a server with statically assigned IPv6 addresses, accepting RAs is unnecessary — and dangerous. An attacker who can send ICMPv6 on the local network can redirect IPv6 traffic through themselves by sending a spoofed RA with a higher router preference.

```ini
# Do not accept Router Advertisements on servers with static IPv6 configuration.
# WARNING: If this host uses SLAAC (autoconf) for its IPv6 address assignment,
# setting this to 0 will remove its IPv6 default route. Only set on hosts
# with statically configured IPv6 addresses and routes.
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable RA-based SLAAC address configuration.
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0

# Disable NDP forwarding of router advertisements.
net.ipv6.conf.all.accept_ra_rtr_pref = 0

# Disable ICMP redirects for IPv6 (same reasoning as IPv4).
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
```

**RA Guard as a complementary control:** sysctl settings protect individual hosts. RA Guard is a switch-level control that drops RA packets on ports where no router should be connected. Deploy both: sysctl settings as a host-level defence in depth, RA Guard at the network layer to prevent the RA from propagating at all. On Cisco switches this is `ipv6 nd raguard policy`; on Juniper, `router-advertisement-guard`.

### IPv6 on infrastructure that doesn't use it

If you have IPv6 enabled on interfaces but no IPv6 connectivity is provisioned or required, disable it entirely rather than trying to harden individual RA parameters:

```bash
# Disable IPv6 on a specific interface (here: eth0):
net.ipv6.conf.eth0.disable_ipv6 = 1

# Disable IPv6 globally (affects all interfaces):
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
```

Disabling IPv6 when you do not use it removes the entire IPv6 attack surface rather than trying to harden it piecemeal.

---

## Martian Packet Logging

Log packets with impossible or reserved source addresses. These are almost always either spoofed packets or misconfigured upstream routers. The logs are useful for detecting scanning activity and diagnosing routing misconfigurations.

```ini
# Log packets arriving with source addresses that should not be routable.
# These include loopback addresses on external interfaces, RFC 1918 addresses
# appearing on public-facing interfaces, and multicast sources.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
```

**Rate limiting:** On busy interfaces under a spoofed-source flood, martian logging can produce enough log volume to fill disk or degrade syslog performance. The kernel rate-limits these messages by default (controlled by `net.ipv4.conf.all.mc_forwarding` and the netlink socket backlog), but ensure your syslog pipeline can handle burst log volumes before enabling this in high-traffic environments.

---

## Full Drop-In Configuration

Save this as `/etc/sysctl.d/70-tcpip-hardening.conf`. The `70-` prefix ensures it loads after distribution defaults (typically `10-` to `20-`) but before any application tuning (`90-` or higher).

```ini
# /etc/sysctl.d/70-tcpip-hardening.conf
# TCP/IP stack hardening for production Linux servers.
# Target: Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9, kernel 5.15+
#
# Review CAVEATS section at the bottom before applying.
# Test in staging before production. Apply with: sudo sysctl --system

# ============================================================
# SYN FLOOD PROTECTION
# ============================================================

# Enable SYN cookies. Fallback mechanism when SYN backlog is full.
# MUST remain enabled. Disabling causes connection drops under flood.
net.ipv4.tcp_syncookies = 1

# Timestamps are required for SYN cookie MSS encoding.
# Do NOT disable despite older guides recommending it.
net.ipv4.tcp_timestamps = 1

# Increase SYN backlog size. Default 128/256 is insufficient for
# high-connection-rate servers. 2048 is reasonable for most servers;
# increase to 4096 on load balancers or connection-intensive services.
net.ipv4.tcp_max_syn_backlog = 2048

# Reduce SYN-ACK retransmit count to reclaim SYN queue slots faster
# during flood conditions. Default 5 (~180s). Setting 2 (~24s).
net.ipv4.tcp_synack_retries = 2

# ============================================================
# ICMP HARDENING
# ============================================================

# Ignore broadcast/multicast ICMP echo requests (Smurf attack prevention).
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Silently drop malformed ICMP error responses.
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Do not accept ICMP redirect messages.
# Prevents remote routing table manipulation by LAN-adjacent hosts.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Do not send ICMP redirects. Servers are not routers.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ============================================================
# REVERSE PATH FILTERING (anti-spoofing)
# ============================================================

# Strict mode: drop packets where the best return route does not
# go back out the same interface the packet arrived on.
# Change to =2 if this host has asymmetric routing.
# Set to =0 on CNI bridge/overlay interfaces (cni0, flannel.1, etc.).
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ============================================================
# SOURCE ROUTING REJECTION
# ============================================================

# Reject IPv4 packets with source routing options.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Reject IPv6 packets with type 0 routing headers.
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ============================================================
# TCP KEEPALIVE (stale connection detection)
# ============================================================

# Begin keepalive probing after 600 seconds of inactivity.
# Default is 7200 (2 hours). Reduces time dead connections hold resources.
net.ipv4.tcp_keepalive_time = 600

# Interval between keepalive probes once started.
net.ipv4.tcp_keepalive_intvl = 30

# Declare connection dead after 3 unanswered probes.
# Dead connection detected at: 600 + (3 × 30) = 690 seconds total.
net.ipv4.tcp_keepalive_probes = 3

# ============================================================
# MARTIAN PACKET LOGGING
# ============================================================

# Log packets with impossible source addresses.
# Monitor log volume in high-traffic environments before enabling.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ============================================================
# IPv6 HARDENING
# ============================================================

# Do not accept Router Advertisements.
# CAUTION: Only set to 0 on hosts with static IPv6 configuration.
# If this host uses SLAAC, setting accept_ra=0 removes the default route.
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable SLAAC address autoconfiguration.
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0

# Do not accept ICMPv6 redirect messages.
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
```

Apply immediately without rebooting:

```bash
sudo sysctl --system
```

The `--system` flag reads all files in `/etc/sysctl.d/`, `/run/sysctl.d/`, and `/usr/lib/sysctl.d/` in lexicographic order, then `/etc/sysctl.conf`. Output confirms each file applied:

```
* Applying /etc/sysctl.d/70-tcpip-hardening.conf ...
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
...
```

---

## Verification

### Verify settings are active

Check individual parameters:

```bash
# Read a single parameter's current value:
sysctl net.ipv4.tcp_syncookies
sysctl net.ipv4.conf.all.rp_filter

# Read all network-related parameters at once:
sysctl -a | grep -E '^net\.(ipv4|ipv6)\.(conf|tcp|icmp)'
```

### Verification script

Save as `/usr/local/bin/verify-tcpip-hardening.sh` and run after each system update or configuration change:

```bash
#!/bin/bash
# Verify TCP/IP stack hardening settings are active.
# Exit 0 = all expected. Exit 1 = one or more mismatches.

FAIL=0

check() {
    local key="$1"
    local expected="$2"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null)
    if [ "$actual" != "$expected" ]; then
        printf "FAIL: %-55s = %s (expected %s)\n" "$key" "$actual" "$expected"
        FAIL=1
    else
        printf "OK:   %-55s = %s\n" "$key" "$actual"
    fi
}

check net.ipv4.tcp_syncookies                     1
check net.ipv4.tcp_timestamps                     1
check net.ipv4.tcp_max_syn_backlog                2048
check net.ipv4.tcp_synack_retries                 2
check net.ipv4.icmp_echo_ignore_broadcasts        1
check net.ipv4.icmp_ignore_bogus_error_responses  1
check net.ipv4.conf.all.accept_redirects          0
check net.ipv4.conf.default.accept_redirects      0
check net.ipv4.conf.all.secure_redirects          0
check net.ipv4.conf.default.secure_redirects      0
check net.ipv4.conf.all.send_redirects            0
check net.ipv4.conf.default.send_redirects        0
check net.ipv4.conf.all.rp_filter                 1
check net.ipv4.conf.default.rp_filter             1
check net.ipv4.conf.all.accept_source_route       0
check net.ipv4.conf.default.accept_source_route   0
check net.ipv6.conf.all.accept_source_route       0
check net.ipv6.conf.default.accept_source_route   0
check net.ipv4.tcp_keepalive_time                 600
check net.ipv4.tcp_keepalive_intvl                30
check net.ipv4.tcp_keepalive_probes               3
check net.ipv4.conf.all.log_martians              1
check net.ipv4.conf.default.log_martians          1
check net.ipv6.conf.all.accept_ra                 0
check net.ipv6.conf.default.accept_ra             0
check net.ipv6.conf.all.accept_redirects          0
check net.ipv6.conf.default.accept_redirects      0

exit $FAIL
```

```bash
chmod +x /usr/local/bin/verify-tcpip-hardening.sh
sudo /usr/local/bin/verify-tcpip-hardening.sh
```

### Verify persistence across reboots

Settings in `/etc/sysctl.d/` are loaded by `systemd-sysctl.service` at boot. Verify the unit is enabled:

```bash
systemctl is-enabled systemd-sysctl.service
# Expected: static
# (static means it cannot be disabled; it always runs at boot)
```

To test persistence without a full reboot, reset a parameter to its default and re-apply:

```bash
# Temporarily disable SYN cookies:
sudo sysctl -w net.ipv4.tcp_syncookies=0

# Re-apply all sysctl.d settings:
sudo sysctl --system

# Confirm the value is restored:
sysctl net.ipv4.tcp_syncookies
# Expected: net.ipv4.tcp_syncookies = 1
```

If `--system` does not restore the value, check that the file is being read:

```bash
# List files sysctl --system will read, in order:
sudo sysctl --system --dry-run 2>&1 | grep "Applying"
```

### Verify SYN cookies engage under load

This requires a controlled test. `hping3` can generate a SYN flood on a test system:

```bash
# On a separate test machine — do NOT run on production:
sudo hping3 -S --flood -V -p 80 <target-ip>
```

On the target, watch for SYN cookie engagement:

```bash
watch -n1 'netstat -s | grep -i "syn cookies"'
# Look for: "SYN cookies sent" incrementing
```

---

## What Not to Touch

Several sysctl parameters appear in hardening checklists but should not be changed in production without understanding their costs.

### `net.ipv4.tcp_timestamps = 0`

As covered above: disabling timestamps degrades SYN cookie effectiveness. The uptime information leaked is minimal. Leave at 1.

### `net.ipv4.tcp_rfc1337 = 1`

Enables an obscure mitigation for a TIME_WAIT assassination attack described in RFC 1337. The attack is theoretical and requires very specific timing. Enabling `tcp_rfc1337` causes the kernel to silently discard RST packets received in TIME_WAIT state, which can cause legitimate connection resets to be ignored. Leave at 0 unless you have a specific reason.

### `net.ipv4.conf.all.rp_filter = 1` on multi-homed hosts

Strict RPF breaks asymmetric routing. If this host has multiple uplinks, receives traffic on one interface, and routes replies out another (common with BGP multi-homing, policy routing, or VPN tunnels), strict RPF will drop legitimate traffic. Use mode 2 (loose) on multi-homed hosts, or mode 0 on specific interfaces that carry asymmetric traffic.

### `net.ipv4.ip_forward = 0`

Disabling IP forwarding prevents the kernel from forwarding packets between interfaces. This is correct for end-hosts, but **must not be applied to**:

- Kubernetes nodes (kubelet and kube-proxy require forwarding for pod traffic)
- Container hosts using bridge networking
- VPN servers
- Any host acting as a router or NAT gateway

Setting `ip_forward = 0` on a Kubernetes node silently breaks pod-to-pod networking and service VIP routing.

### `net.ipv6.conf.all.accept_ra = 0` on SLAAC hosts

As noted in the IPv6 section: if the host's IPv6 address or default route is assigned via SLAAC (the default for cloud VMs that provision IPv6 via DHCP6 or NDP), disabling RA acceptance removes the default route and breaks IPv6 connectivity. Verify the host's IPv6 addressing method before changing this.

---

## Integration with Automation

### Ansible

```yaml
# roles/tcpip-hardening/tasks/main.yml
- name: Deploy TCP/IP hardening sysctl configuration
  ansible.builtin.copy:
    src: 70-tcpip-hardening.conf
    dest: /etc/sysctl.d/70-tcpip-hardening.conf
    owner: root
    group: root
    mode: "0644"
  notify: Apply sysctl settings

# roles/tcpip-hardening/handlers/main.yml
- name: Apply sysctl settings
  ansible.builtin.command: sysctl --system
  changed_when: true
```

### Verification in CI

Add the verification script to your infrastructure pipeline. Run it as a post-deployment check:

```bash
# In your CI pipeline (after Ansible applies the configuration):
ssh deploy@target '/usr/local/bin/verify-tcpip-hardening.sh'
# Non-zero exit code fails the pipeline if any setting is wrong.
```

For Kubernetes nodes managed by a node configuration operator (e.g., NTO on OpenShift), sysctl settings can be applied via `TunedProfile` or a `MachineConfig` manifest. Using the OS-level drop-in file as shown here is simpler and more portable.

---

## Relationship to Firewall Rules

These sysctl settings and your firewall ruleset (`nftables`, `iptables`, cloud security groups) are complementary, not redundant. They operate at different points in the packet processing path:

| Layer | Tool | Controls |
|-------|------|---------|
| Packet filtering | nftables / iptables | Accept/drop/forward decisions based on IP, port, protocol, connection state |
| Network stack behaviour | sysctl | How the kernel *processes* accepted packets: SYN queue management, ICMP response policy, routing decisions, keepalive behaviour |
| Link layer | Switch ACLs, RA Guard | Drop frames before they reach the host at all |

A firewall that blocks port 80 does not protect against ICMP redirect manipulation on port 443. A firewall stateful connection tracking entry cannot detect that the remote end of a TCP connection has crashed without keepalive probes. Defence in depth requires both layers.
