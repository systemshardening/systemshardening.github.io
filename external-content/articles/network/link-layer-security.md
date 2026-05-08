---
title: "Link-Layer Security: ARP Spoofing Defence and DHCP Snooping"
description: "Defend against ARP/ND spoofing, DHCP starvation, and rogue gateway attacks using Linux kernel controls, dynamic ARP inspection, and open source tools with active maintenance checks."
slug: link-layer-security
date: 2026-05-02
lastmod: 2026-05-02
category: network
tags: ["arp", "dhcp", "link-layer", "spoofing", "nd-guard", "arptables", "network-security"]
personas: ["systems-engineer", "sre", "security-engineer"]
article_number: 345
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/network/link-layer-security/index.html"
---

# Link-Layer Security: ARP Spoofing Defence and DHCP Snooping

## Problem

The Address Resolution Protocol (ARP) was designed in 1982 for a trusted, cooperative network. Its core mechanic — broadcast a question, accept the first reply — has no authentication and no replay protection. An attacker sharing a network segment can send gratuitous ARP replies at any time, announcing that their MAC address corresponds to the IP of the default gateway. Every host on the segment updates its ARP cache without verification, and all traffic intended for the gateway flows through the attacker instead. The attack requires no special privileges beyond access to the local network and completes in seconds.

DHCP carries a similar structural weakness. When a host sends a `DHCPDISCOVER` broadcast, it accepts the first `DHCPOFFER` it receives. A DHCP starvation attack first exhausts the legitimate server's address pool by flooding the network with `DHCPDISCOVER` messages using forged MAC addresses (tools such as `dhcpstarv` automate this). With the pool exhausted, the attacker's rogue DHCP server responds to new client requests and assigns a gateway IP and DNS server under attacker control. Clients joining the network after the attack are silently routed through the attacker for all traffic.

IPv6 extends these problems rather than solving them. The Neighbor Discovery Protocol (NDP) replaces ARP for address resolution and uses Router Advertisement (RA) messages for default gateway distribution. Any host on the segment can send an unsolicited RA containing an arbitrary default route and recursive DNS server (RDNSS) address. Hosts that accept RAs — which is the default on most Linux systems — reconfigure their routing table immediately. This is the IPv6 equivalent of ARP poisoning combined with rogue DHCP, and it happens at the ICMPv6 level in a single unauthenticated packet.

These attacks persist not because defences are unknown but because they are inconsistently applied. Modern cloud VPC networks and overlay fabrics (VXLAN, Geneve, Wireguard mesh) implement ARP proxy and ND filtering at the hypervisor or data-plane level, making these attacks ineffective in those environments. The exposure surface is bare-metal deployments, co-location environments with shared VLANs, on-premises networks with legacy switch infrastructure, and any deployment where hosts share a Layer 2 domain without managed-switch-level dynamic ARP inspection (DAI). Kubernetes nodes on a bare-metal cluster sharing a flat L2 network are a particularly common unexamined case.

The deeper problem is the state of the open source tooling that defenders rely on to monitor and prevent these attacks. `arpwatch`, the canonical tool for detecting ARP cache changes, has not had an upstream release from `ee.lbl.gov` since 2013. The version shipped in Debian, Ubuntu, and RHEL repositories is nearly a decade old. There is no `SECURITY.md`, no CVE reporting channel, and no evidence of recent security audit. The packet capture path in `arpwatch` parses raw ARP frames from a `pcap` socket — a parsing bug in that code path could allow a crafted malformed ARP frame to crash or exploit the monitoring process, blinding the defender while the actual ARP poisoning proceeds. This has never been publicly audited. A Debian-maintained fork exists at `https://github.com/Debian/arpwatch` and receives occasional patches, but it inherits the same aged codebase.

`arpon` (ARP Protection daemon), which ships DARP (Dynamic ARP Protection), SARP (Static ARP Protection), and HARP (Hybrid ARP Protection) modes, had its last meaningful upstream commit in 2014. Several distributions have dropped it from their package repositories entirely. Neither `arpwatch` nor `arpon` is suitable as a primary defence in a security-conscious deployment. The Linux kernel itself provides the most reliable and actively maintained link-layer defences through sysctl controls, `nftables` ARP family rules, and `ip neigh` static entries — but these controls are poorly documented, scattered across kernel source and man pages, and unknown to many operators.

Kernel patches for ARP and NDP handling are committed regularly but often without CVE assignment. A search of the Linux kernel git log for "net: fix arp" or "ipv6: ndisc" reveals multiple memory handling and race condition fixes per year. These fixes reach production systems via kernel updates, not via a userspace tool with a version number — which means operators who audit their open source dependencies for CVEs may miss this entire category of fix.

Target systems: Linux kernel ≥ 5.15, nftables 1.0+, systemd-networkd 252+ (for IPv6 RA guard).

## Threat Model

1. **On-path ARP poisoning for credential theft.** An attacker with access to the same VLAN sends continuous gratuitous ARP replies claiming the MAC address of the default gateway. All hosts on the segment update their ARP cache. Traffic destined for the gateway is forwarded through the attacker's machine (which forwards it onward to avoid detection). The attacker performs TLS stripping or passive capture of cleartext protocols. The attack requires no authentication bypass — only L2 adjacency.

2. **DHCP starvation followed by rogue server injection.** The attacker floods the DHCP server with `DHCPDISCOVER` messages using randomised source MAC addresses, exhausting the address pool. The attacker then starts a rogue DHCP server responding to new `DHCPDISCOVER` broadcasts. New clients receive a lease with a malicious default gateway and DNS server. DNS responses can be forged; all new traffic is routed through the attacker. Existing leases are unaffected until renewal, meaning the attack impact expands over time as leases expire.

3. **IPv6 Router Advertisement injection.** The attacker broadcasts a forged ICMPv6 RA message with `Router Lifetime > 0` and a high route preference, advertising itself as the default IPv6 gateway. Hosts that have `accept_ra=1` (the kernel default) immediately update their IPv6 routing table. The RA can also include a Recursive DNS Server (RDNSS) option to redirect DNS resolution. Because most operators focus IPv6 hardening on firewall rules rather than RA acceptance, this attack is frequently undetected. A single packet can reconfigure routing on every host in a subnet.

4. **Unmaintained-tool blind-spot attack.** The attacker sends a stream of malformed ARP frames with invalid hardware type fields or truncated payloads targeting the `arpwatch` monitoring process. Because `arpwatch` parses raw ARP frames from a `pcap(3)` socket in a codebase that has not been audited since 2013, a parsing fault can crash the daemon. With ARP monitoring silenced, the attacker proceeds with standard ARP poisoning. The operator's alerting shows no anomaly because the tool that would generate the alert is no longer running.

The blast radius of these attacks scales with network architecture. In a flat /24 with 254 hosts, a single ARP poison affects every host simultaneously. In a segmented environment with per-tenant VLANs, an attacker compromising one tenant host can only attack other hosts in the same VLAN. The defensive controls described below operate independently and should be applied in layers: kernel sysctl settings are always-on with no runtime overhead; static ARP entries eliminate cache poisoning for critical infrastructure; nftables rules enforce MAC-to-IP binding at the packet level; RA guard removes the IPv6 RA injection surface entirely.

## Configuration / Implementation

### Linux Kernel ARP Hardening via sysctl

The kernel provides several sysctl knobs that significantly reduce ARP attack surface. These settings have no dependency on userspace tools and persist across reboots when applied through `/etc/sysctl.d/`.

```
# /etc/sysctl.d/80-arp-hardening.conf

# Do not respond to ARP requests on interfaces that do not own the target IP.
# Prevents an attacker from using an ARP probe to enumerate secondary addresses.
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1

# Only announce the best local address for the outgoing interface.
# Prevents ARP replies from leaking addresses bound to other interfaces.
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2

# Drop unsolicited ARP replies (gratuitous ARP). Linux 5.3+.
# This is the primary control against ARP cache poisoning.
# WARNING: breaks VRRP/HSRP — see Trade-offs section.
net.ipv4.conf.all.drop_gratuitous_arp = 1
net.ipv4.conf.default.drop_gratuitous_arp = 1

# ARP cache sizing. Defaults are often too small for busy networks.
# gc_thresh1: minimum entries before GC runs
# gc_thresh2: soft maximum; GC runs more aggressively above this
# gc_thresh3: hard maximum; entries above this are dropped
net.ipv4.neigh.default.gc_thresh1 = 1024
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh3 = 8192

# IPv6: disable RA acceptance on hosts that are not routers
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
```

Apply immediately and persist:

```bash
sysctl --system
# Verify drop_gratuitous_arp is active (requires kernel >= 5.3)
sysctl net.ipv4.conf.all.drop_gratuitous_arp
```

The `drop_gratuitous_arp` control was added in Linux 5.3 (commit `56022a8fdd874`). Verify kernel version before deploying: `uname -r`. On kernels older than 5.3, this sysctl silently has no effect.

### Static ARP Entries for Critical Hosts

For the default gateway and any critical infrastructure (DNS servers, LDAP, monitoring hosts), a permanent ARP entry eliminates the ability to poison that entry. The kernel does not update permanent entries in response to ARP traffic.

```bash
# Add a permanent ARP entry for the default gateway
ip neigh add 192.168.1.1 lladdr aa:bb:cc:dd:ee:ff dev eth0 nud permanent

# Verify
ip neigh show nud permanent
```

To persist across reboots using systemd-networkd, add a `[Neighbor]` section to the interface's `.network` file:

```ini
# /etc/systemd/network/10-eth0.network

[Match]
Name=eth0

[Network]
Address=192.168.1.50/24
Gateway=192.168.1.1

[Neighbor]
Address=192.168.1.1
LinkLayerAddress=aa:bb:cc:dd:ee:ff
```

Reload with `networkctl reload`. Verify with:

```bash
networkctl status eth0
ip neigh show dev eth0 nud permanent
```

Maintain a version-controlled inventory of gateway MAC addresses. When the gateway hardware is replaced, the permanent entry must be updated before connectivity is restored — see Failure Modes.

### nftables ARP Filtering

nftables supports an `arp` address family that allows filtering on ARP header fields directly, without requiring `arptables`. This is the preferred approach on systems running nftables 1.0+.

```bash
# Create the ARP filter table
nft add table arp filter

# Create the input chain
nft add chain arp filter input '{ type filter hook input priority 0; policy accept; }'

# Allow ARP from the known gateway MAC only (adjust as needed)
# Drop gratuitous ARP replies (operation=reply, sender IP = target IP) from unknown sources
nft add rule arp filter input \
  arp operation reply \
  arp saddr ether != aa:bb:cc:dd:ee:ff \
  arp saddr ip != 0.0.0.0 \
  drop
```

A complete ruleset as a file for `nft -f`:

```
# /etc/nftables.d/20-arp-filter.nft

table arp filter {
    # Set of authorised gateway/server MAC addresses
    set allowed_arpers {
        type ether_addr
        elements = { aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66 }
    }

    chain input {
        type filter hook input priority 0; policy accept;

        # Drop ARP replies from MAC addresses not in the allowed set
        arp operation reply arp saddr ether != @allowed_arpers drop

        # Log and drop gratuitous ARP (sender IP == target IP) from unknown sources
        arp operation reply \
            arp saddr ip == arp daddr ip \
            arp saddr ether != @allowed_arpers \
            log prefix "gratuitous-arp-drop: " drop
    }
}
```

Load with `nft -f /etc/nftables.d/20-arp-filter.nft` and persist by including this file from `/etc/nftables.conf`.

Verify the ruleset is active:

```bash
nft list table arp filter
```

### IPv6 ND/RA Guard with systemd-networkd

For hosts that should never accept IPv6 Router Advertisements (any host that is not itself a router or does not require IPv6 prefix delegation), disable RA acceptance at both the kernel and networkd layers.

Via sysctl (already shown above): `net.ipv6.conf.all.accept_ra = 0`.

Via systemd-networkd `.network` file:

```ini
# /etc/systemd/network/10-eth0.network

[Match]
Name=eth0

[Network]
IPv6AcceptRA=false
```

For hosts that act as IPv6 routers, enabling `net.ipv6.conf.all.forwarding=1` automatically sets `accept_ra` to 0 for forwarding interfaces — the kernel enforces this to prevent routing loops. Verify:

```bash
sysctl net.ipv6.conf.eth0.accept_ra
# Should be 0 when forwarding is enabled on that interface
```

For environments requiring IPv6 prefix delegation to downstream hosts (e.g. home routers or edge nodes), scope RA acceptance to specific trusted interfaces rather than `all`:

```bash
sysctl -w net.ipv6.conf.eth0.accept_ra=0   # upstream interface: no RA
sysctl -w net.ipv6.conf.eth1.accept_ra=1   # downstream interface: accept delegated prefix
```

### DHCP Snooping Alternative with nftables

Managed switches implement DHCP snooping at hardware level by marking ports as trusted or untrusted. On Linux hosts or software bridges without managed switch support, nftables can enforce that DHCP responses (UDP destination port 68, which is the client port) arrive only from the known authoritative DHCP server.

```
# /etc/nftables.d/30-dhcp-snooping.nft

table inet dhcp_guard {
    chain input {
        type filter hook input priority -100; policy accept;

        # Drop DHCP offers/acks from any source other than the authorised server
        # DHCPOFFER and DHCPACK arrive on UDP dst port 68 (client port)
        udp dport 68 ip saddr != 192.168.1.10 drop
        udp dport 68 ip6 saddr != 2001:db8::1 drop
    }
}
```

This rule drops DHCP responses from any IP other than the authorised DHCP server. A rogue DHCP server on the same segment cannot deliver a `DHCPOFFER` to clients protected by this rule. The rule operates on the receiving host — it does not protect hosts that do not have the rule installed. For comprehensive DHCP snooping across a network, the control must be deployed uniformly to all client hosts, or implemented at the Linux bridge level using `ebtables` on a software bridge.

To apply at the bridge level for a Linux software bridge:

```bash
# Allow DHCP only from the known server MAC on the bridge
ebtables -A FORWARD --protocol IPv4 \
  --ip-protocol udp --ip-destination-port 68 \
  ! --source aa:bb:cc:dd:ee:ff --jump DROP
```

### Replacing arpwatch with Kernel-Native Monitoring

Rather than running the unmaintained `arpwatch` binary, use `ip monitor neigh` to stream kernel neighbor table change events and pipe them to a detection script.

```bash
# /usr/local/bin/neigh-monitor.sh
#!/bin/bash
# Stream neighbor table changes and alert on new or changed entries

KNOWN_GATEWAY_MAC="aa:bb:cc:dd:ee:ff"
ALERT_CMD="logger -t neigh-monitor -p security.warning"

ip monitor neigh 2>&1 | while read -r line; do
    # Lines look like: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    if echo "$line" | grep -qE 'lladdr'; then
        ip_addr=$(echo "$line" | awk '{print $1}')
        mac_addr=$(echo "$line" | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}')

        # Alert if the gateway IP appears with an unexpected MAC
        if [ "$ip_addr" = "192.168.1.1" ] && [ "$mac_addr" != "$KNOWN_GATEWAY_MAC" ]; then
            $ALERT_CMD "ARP SPOOFING DETECTED: gateway $ip_addr resolved to $mac_addr (expected $KNOWN_GATEWAY_MAC)"
        fi
    fi
done
```

Run as a systemd service with minimal privileges:

```ini
# /etc/systemd/system/neigh-monitor.service

[Unit]
Description=Kernel neighbor table change monitor
After=network.target

[Service]
ExecStart=/usr/local/bin/neigh-monitor.sh
Restart=always
RestartSec=5

# Privilege restriction — this service needs no privileges beyond reading
# kernel netlink events. CAP_NET_ADMIN is not required for ip monitor.
NoNewPrivileges=yes
CapabilityBoundingSet=
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
User=nobody

[Install]
WantedBy=multi-user.target
```

If `arpwatch` is required for compliance or legacy integration, verify the version and apply a restrictive systemd unit:

```bash
# Check installed version
arpwatch -v 2>&1 | head -1
# Compare against https://github.com/Debian/arpwatch/commits/master
# for last patch date

# Restrict the arpwatch unit
systemctl edit arpwatch.service
```

Add under `[Service]`:

```ini
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_RAW
PrivateTmp=yes
ProtectSystem=strict
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
```

The capability restriction limits the blast radius of a parsing exploit: an attacker who achieves code execution in the `arpwatch` process gains only `CAP_NET_RAW` rather than full root privileges.

## Expected Behaviour

| Signal | Without link-layer controls | With hardening |
|---|---|---|
| Gratuitous ARP reply received | ARP cache updated for all hosts on segment immediately | Kernel drops the frame (`drop_gratuitous_arp=1`); nftables logs and drops if MAC not in allowlist |
| Rogue DHCP server sends DHCPOFFER | Client accepts first response received; may be from rogue server | nftables DHCP guard drops DHCPOFFER not originating from authorised server IP |
| IPv6 RA injection (forged RA packet sent) | Host installs attacker's default route within seconds; routing table silently overwritten | Kernel discards RA (`accept_ra=0`); systemd-networkd honours `IPv6AcceptRA=false`; no route change |
| Malformed ARP frame sent to crash arpwatch | arpwatch daemon crashes silently; ARP monitoring stops; attacker proceeds undetected | `ip monitor neigh` is a kernel syscall path (not a pcap parser); malformed frames do not reach it; monitoring continues |
| ARP cache poisoning detection time | Minutes to hours via manual `ip neigh show` inspection; arpwatch may alert if not crashed | `ip monitor neigh` script alerts within seconds of neighbor table change; permanent entries for critical hosts cannot be poisoned |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Static ARP entries (`nud permanent`) | Gateway MAC cannot be poisoned; zero ongoing kernel ARP traffic for that entry | Manual update required when gateway hardware changes; incorrect entry causes full connectivity loss | Store MAC addresses in version-controlled configuration (systemd-networkd `.network` files, Ansible inventory); automate deployment; test MAC rotation in staging |
| `drop_gratuitous_arp=1` | Eliminates the primary ARP cache poisoning vector with zero userspace overhead | Breaks VRRP and HSRP failover, which rely on gratuitous ARP to force cache updates after gateway failover | Disable on nodes participating in VRRP/HSRP; use per-interface setting (`net.ipv4.conf.eth0.drop_gratuitous_arp=0`) for VRRP interface only; test failover after any kernel upgrade |
| RA guard (`accept_ra=0`) | Eliminates IPv6 rogue gateway injection; no unauthorised route can be installed | Breaks IPv6 prefix delegation workflows (e.g. DHCPv6-PD edge routers); breaks legitimate renumbering via RA if operator uses this mechanism | Apply per-interface rather than globally; allow RA on explicitly trusted upstream interfaces only; test IPv6 connectivity after applying |
| nftables MAC allowlist for ARP/DHCP | Blocks spoofed ARP and rogue DHCP at packet level | Adding a new legitimate DHCP server or gateway requires updating the allowlist before the change; incorrect allowlist causes network disruption | Store allowlist in configuration management; automate `nft` ruleset deployment; include allowlist update in network change runbooks |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| `drop_gratuitous_arp=1` breaks VRRP failover | After a VRRP primary failure, the backup router takes over but hosts do not update their ARP cache; traffic continues going to the dead primary MAC; connectivity loss persists until ARP entries expire (typically 60s–300s depending on `gc_stale_time`) | VRRP failover test in staging shows connectivity loss exceeding expected sub-second failover; `ip neigh show` on client shows stale MAC for gateway IP | Set `net.ipv4.conf.<vrrp-interface>.drop_gratuitous_arp=0` for the specific interface used by the VRRP group; leave `all` and `default` set to 1; redeploy and retest |
| Static ARP entry stale after gateway MAC change | After gateway hardware replacement or NIC swap, permanent ARP entry points to old MAC; all traffic to the gateway is dropped; host appears to have no external connectivity | `ip neigh show nud permanent` reveals the wrong MAC; `arping -I eth0 192.168.1.1` receives no reply from the installed MAC | Update permanent entry: `ip neigh replace 192.168.1.1 lladdr <new-mac> dev eth0 nud permanent`; update systemd-networkd `.network` file and run `networkctl reload`; document MAC change in configuration management |
| nftables DHCP guard rule blocks legitimate DHCP renew | Client's existing lease expires; renewal request is sent; response from an authorised server IP is dropped because the server IP changed (e.g. DHCP server migration) or because the rule references the wrong IP | Client loses IP address after lease expiry; `journalctl -u systemd-networkd` shows DHCP renew failures; `nft list ruleset` reveals the stale allowed IP | Update nftables DHCP guard rule with new server IP; `nft replace` or redeploy the ruleset file; verify with `nft list table inet dhcp_guard` |
| RA guard blocks IPv6 prefix delegation | Edge node running DHCPv6-PD cannot receive delegated prefix via RA; downstream hosts get no IPv6 addresses; IPv6 connectivity silently absent | `ip -6 route show` shows no default IPv6 route; `rdisc6 eth0` returns no response; IPv6 ping to gateway fails | Set per-interface override: `sysctl -w net.ipv6.conf.eth0.accept_ra=1` for the upstream interface; update systemd-networkd with `IPv6AcceptRA=yes` scoped to the upstream interface match; do not set globally |

## Related Articles

- [Network Segmentation Patterns](/articles/network/network-segmentation-patterns/)
- [VXLAN and Geneve Overlay Security](/articles/network/vxlan-geneve-overlay-security/)
- [IPv6 Security in Production](/articles/network/ipv6-security/)
- [Network Flow Analysis](/articles/observability/network-flow-analysis/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
