---
title: "BGP and OSPF Hardening: Routing Protocol Security for Production Networks"
description: "Routing protocol attacks — BGP hijacking, OSPF LSA injection, route table flooding — can silently redirect or blackhole all traffic. Harden BGP and OSPF with MD5/TCP-AO authentication, GTSM, RPKI filtering, prefix-list hygiene, BFD, and passive interface isolation."
slug: bgp-ospf-routing-security
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - bgp
  - ospf
  - routing-security
  - gtsm
  - md5-authentication
personas:
  - security-engineer
  - network-engineer
article_number: 501
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/bgp-ospf-routing-security/
---

# BGP and OSPF Hardening: Routing Protocol Security for Production Networks

## The Problem

Routing protocols are the nervous system of a network. BGP (Border Gateway Protocol, RFC 4271) carries reachability information between autonomous systems across the internet. OSPF (Open Shortest Path First, RFC 2328 / RFC 5340) distributes routes inside a single organisation. Both protocols were designed under the assumption of cooperative, trusted peers. Neither has authentication or path validation built into its core design. The result is a set of attacks that are straightforward to execute and catastrophic in impact.

**BGP hijacking** occurs when an autonomous system announces IP prefixes it does not own. Every router along the propagation path accepts the announcement if it looks more specific or has a shorter AS path than the legitimate route. Traffic that should reach the genuine owner is silently forwarded to the hijacker — where it can be inspected, modified, or blackholed. Real-world incidents:

- **2010 China Telecom route leak:** AS23724 announced ~37,000 prefixes covering US government, military, and commercial networks. Traffic was routed through China Telecom for approximately 18 minutes.
- **2018 Amazon Route 53 hijack:** An AS announced Amazon's DNS resolver prefixes. Attackers intercepted DNS responses to steal ~$150,000 in cryptocurrency.
- **2023 Cloudflare and Google prefix leaks:** Multiple route leaks caused widespread traffic misrouting through unintended carriers.

**BGP route injection** targets the control plane directly. If an attacker can establish a BGP session — or spoof TCP packets into an existing session — they can inject arbitrary route announcements. Without session authentication, TCP reset attacks can tear down BGP peering sessions, causing route withdrawal storms and network instability.

**OSPF LSA spoofing** injects forged Link State Advertisements into an interior routing domain. OSPF uses a flooding algorithm to propagate LSAs across all routers in an area. A spoofed LSA claiming a shorter path through an attacker-controlled router can redirect intra-domain traffic. Cost manipulation attacks set artificially low OSPF costs on attacker-controlled interfaces to attract traffic. Without authentication, any host on a network segment can send OSPF hello packets, establish adjacency with legitimate routers, and inject routing information.

The common thread is that routing protocols accept information from peers before verifying the peer's identity or the information's validity. The hardening measures described below address this at four levels: session authentication (who can speak the protocol), topological constraints (where peering is permitted), route content validation (what routes are acceptable), and failure detection (how fast bad state is detected and recovered).

**Target systems:** FRRouting (FRR) 8.x+, BIRD 2.0.x, Linux kernel routing; BGP and OSPF across both iBGP/eBGP and OSPF areas.

## Threat Model

- **Adversary 1 — BGP session hijack via TCP spoofing:** An on-path attacker forges TCP RST or data packets into an established BGP session (TCP port 179). BGP sessions use a 32-bit sequence number. An attacker who can guess or observe the sequence window can inject route withdrawals or announcements, or tear down the session entirely.
- **Adversary 2 — BGP prefix hijack from a malicious peer:** A BGP peer (legitimate or rogue) announces prefixes it does not own. Without outbound route filters on the receiving router, the hijacked routes are accepted and propagated.
- **Adversary 3 — OSPF adjacency injection:** An attacker on the same L2 segment as a router interface sends OSPF hello packets with matching area ID and hello/dead intervals. The legitimate router forms an adjacency and accepts LSAs from the attacker, which can then inject false routes.
- **Adversary 4 — Route table flooding:** A BGP peer sends an abnormally large number of route announcements (tens of thousands of prefixes). Without max-prefix limits, the receiving router's route table grows without bound, consuming memory and potentially causing the routing process to crash.
- **Adversary 5 — Routing loop creation:** An attacker injects routes with manipulated metrics or path attributes that create forwarding loops between two or more routers. Packets caught in the loop consume bandwidth and CPU until TTL expires.
- **Adversary 6 — RPKI-invalid route acceptance:** Without RPKI Route Origin Validation, a router accepts hijacked route announcements even when a valid ROA exists that would contradict the announcement.
- **Access level:** Adversaries 1 and 3 require on-path or L2 adjacency. Adversaries 2 and 4 require a BGP peering relationship (legitimate or hijacked). Adversaries 5 and 6 require BGP session access or the ability to inject into OSPF.
- **Objective:** Redirect traffic for interception, cause route instability, exhaust router resources, or create forwarding loops.
- **Blast radius:** An undetected BGP prefix hijack can redirect 100% of traffic to a network. An OSPF LSA injection can redirect all intra-domain traffic through an attacker-controlled router. Route table flooding can crash the routing daemon, making the router unreachable.

## Configuration

### Step 1: BGP Session Authentication — MD5 and TCP-AO

BGP sessions run over TCP. Without session authentication, an on-path attacker can inject or reset sessions. The two mechanisms are MD5 (widely deployed, cryptographically weak) and TCP-AO (RFC 5925, the modern replacement).

**MD5 authentication (legacy — still required for compatibility with many peers):**

MD5 authentication signs each TCP segment in the BGP session using a shared key. It prevents casual injection but is vulnerable to offline collision attacks — MD5's compute cost is low enough that a determined attacker with captured session traffic can attempt brute force. Use it where TCP-AO is not supported by both sides; plan migration to TCP-AO.

FRR configuration:

```
# /etc/frr/frr.conf
router bgp 64496
 neighbor 192.0.2.1 remote-as 64497
 neighbor 192.0.2.1 password s3cur3-md5-k3y-here
 neighbor 192.0.2.1 description "upstream-peer-1"
```

BIRD 2.x configuration:

```
# /etc/bird/bird.conf
protocol bgp upstream1 {
  neighbor 192.0.2.1 as 64497;
  password "s3cur3-md5-k3y-here";
  description "upstream-peer-1";
}
```

**TCP-AO (RFC 5925) — the correct long-term solution:**

TCP Authentication Option replaces MD5 with a proper HMAC construction using configurable algorithms (HMAC-SHA-1-96, AES-128-CMAC-96). It supports key rollover without session teardown and uses a Master Key Tuple (MKT) that maps a key ID to an algorithm and key material. Linux kernel support for TCP-AO landed in kernel 6.7 (2024); FRR supports it from version 9.0.

FRR TCP-AO configuration:

```
# /etc/frr/frr.conf
router bgp 64496
 neighbor 192.0.2.1 remote-as 64497
 neighbor 192.0.2.1 ao-key 1 hmac-sha256 "tcp-ao-master-key-here"
 neighbor 192.0.2.1 description "upstream-peer-1-tcp-ao"
```

Key rotation without session teardown (TCP-AO key rollover):

```
# Add new key alongside existing key — both are accepted during rollover.
router bgp 64496
 neighbor 192.0.2.1 ao-key 1 hmac-sha256 "old-key"
 neighbor 192.0.2.1 ao-key 2 hmac-sha256 "new-key"
 neighbor 192.0.2.1 ao-send-id 2    # Start sending with new key.
# After confirming peer accepts new key, remove key ID 1.
```

### Step 2: GTSM — Generalised TTL Security Mechanism (RFC 5082)

GTSM exploits a fundamental property of TCP/IP: the TTL field decrements by one at each hop. A BGP peer that is directly connected (one hop away) sends packets with TTL=255. By the time those packets arrive at the local router, TTL=254. An attacker who is not directly adjacent cannot inject packets with TTL=254 — their packets will have been decremented further across the intervening hops.

GTSM instructs the router to drop any BGP TCP segment whose TTL is below a minimum threshold (255 - expected-hops + 1). For single-hop eBGP peers, the minimum acceptable TTL is 254. This defeats remote attackers even if they know the session's TCP sequence numbers.

FRR GTSM configuration:

```
# /etc/frr/frr.conf
router bgp 64496
 neighbor 192.0.2.1 remote-as 64497
 neighbor 192.0.2.1 ttl-security hops 1
 ! "hops 1" = directly connected peer; min accepted TTL = 254.
 ! For multi-hop eBGP peers: ttl-security hops 2 (min TTL = 253).
```

BIRD 2.x GTSM configuration:

```
protocol bgp upstream1 {
  neighbor 192.0.2.1 as 64497;
  ttl security;    # Enables GTSM; assumes single-hop peer.
}
```

GTSM is a lightweight, zero-overhead defence that eliminates the entire class of remote BGP injection attacks. Enable it on all eBGP peers where the hop count is known and stable. Do not enable it on multi-hop peers where the hop count varies (anycast paths, load-balanced peering fabrics).

Verify GTSM is active at the kernel level:

```bash
# Confirm TTL socket option is set on the BGP TCP socket.
ss -tnp sport = :179 | head -5
# Check that minimum TTL is enforced.
ip tcp_metrics show 192.0.2.1
```

### Step 3: BGP Route Filtering — Prefix Lists and Max-Prefix

Authentication secures the session; filtering secures the routing information exchange. Without outbound route filtering, a misconfigured or malicious peer can announce routes you should never accept. Without inbound filtering, you may accept and re-announce prefixes you should not be propagating.

**Inbound prefix filtering — only accept what you expect:**

```
# /etc/frr/frr.conf

! Define the permitted prefixes for peer AS64497.
ip prefix-list PEER64497_IN seq 10 permit 203.0.113.0/24
ip prefix-list PEER64497_IN seq 20 permit 198.51.100.0/22
ip prefix-list PEER64497_IN seq 30 deny any

router bgp 64496
 neighbor 192.0.2.1 remote-as 64497
 neighbor 192.0.2.1 prefix-list PEER64497_IN in
```

For internet-facing peering where the permitted prefix set is not a small known list, generate prefix lists from the IRR (Internet Routing Registry) using bgpq4:

```bash
# Generate an FRR-format prefix list for peer AS64497.
bgpq4 -4 -f 64497 -l PEER64497_IN AS64497

# Automate weekly refresh (IRR data changes as peers add/remove prefixes).
0 3 * * 0 bgpq4 -4 -f 64497 -l PEER64497_IN AS64497 \
  > /etc/frr/prefix-list-peer64497.conf \
  && vtysh -c "configure terminal" -c "$(cat /etc/frr/prefix-list-peer64497.conf)" \
  && vtysh -c "clear ip bgp 192.0.2.1 soft in"
```

**Max-prefix limits — prevent route table flooding:**

```
# /etc/frr/frr.conf
router bgp 64496
 ! Warn at 80% of limit; tear down session if peer sends more than 500 prefixes.
 neighbor 192.0.2.1 maximum-prefix 500 80
 ! Use "restart 5" to automatically re-establish after 5 minutes.
 neighbor 192.0.2.1 maximum-prefix 500 80 restart 5
```

Set max-prefix based on the expected routing table size from that peer. A transit provider peering session that normally carries 10 routes should have a limit of 50 — not 500,000. This prevents a misconfigured or malicious peer from exhausting the routing process's memory.

**Outbound prefix filtering — only announce your own prefixes:**

```
# /etc/frr/frr.conf

! Never leak routes learned from other peers to this peer (no transit).
ip prefix-list MY_PREFIXES_OUT seq 10 permit 203.0.113.0/24 le 24
ip prefix-list MY_PREFIXES_OUT seq 20 permit 198.51.100.0/22 le 22
ip prefix-list MY_PREFIXES_OUT seq 30 deny any

router bgp 64496
 neighbor 192.0.2.1 prefix-list MY_PREFIXES_OUT out
```

### Step 4: RPKI Route Origin Validation — Filtering INVALID Routes

RPKI Route Origin Authorisation (ROA) records cryptographically associate IP prefixes with the AS authorised to originate them. Route Origin Validation (ROV) checks inbound BGP routes against the RPKI database and classifies them as VALID, NOT FOUND, or INVALID. Routes classified INVALID should be dropped.

This section focuses on the filtering side; for ROA creation and validator deployment see the companion article on [BGP Security and RPKI](/articles/network/bgp-security-rpki/).

**Deploy a local RPKI validator:**

```bash
# Routinator — fetches ROAs from all five RIR repositories.
apt install routinator    # Debian/Ubuntu

# Initialise (accept ARIN RPA on first run).
routinator init --accept-arin-rpa

# Start the RTR server on localhost (routers connect to this).
routinator server --rtr 127.0.0.1:3323 --http 127.0.0.1:9556

# Confirm it is syncing ROAs.
curl -s http://127.0.0.1:9556/api/v1/status | jq '{roas: .valid_roas, last_update: .last_update_elapsed_seconds}'
```

Run two validators (primary and secondary) for redundancy. Routers connect to both; either may be unavailable without losing validation capability.

**FRR RPKI configuration — drop INVALID routes:**

```
# /etc/frr/frr.conf

rpki
 rpki polling-period 3600
 rpki cache 127.0.0.1 3323 preference 1
 rpki cache 192.0.2.200 3323 preference 2
exit

! Route map: reject INVALID, prefer VALID, accept NOT FOUND.
route-map BGP_RPKI_IN permit 10
 match rpki valid
 set local-preference 200
!
route-map BGP_RPKI_IN permit 20
 match rpki notfound
 set local-preference 150
!
route-map BGP_RPKI_IN deny 30
 match rpki invalid
 ! INVALID routes are dropped. No implicit permit here.
!

router bgp 64496
 neighbor 192.0.2.1 route-map BGP_RPKI_IN in
```

**BIRD 2.x RPKI configuration:**

```
# /etc/bird/bird.conf

roa4 table rpki_roas;
roa6 table rpki_roas6;

protocol rpki rtr1 {
  roa4 { table rpki_roas; };
  roa6 { table rpki_roas6; };
  remote "127.0.0.1" port 3323;
  retry keep 90;
  refresh keep 900;
  expire keep 172800;
}

function rpki_check_v4() {
  if roa_check(rpki_roas, net, bgp_path.last) = ROA_INVALID then {
    print "RPKI INVALID: ", net, " origin AS ", bgp_path.last;
    reject;
  }
  accept;
}

protocol bgp upstream1 {
  neighbor 192.0.2.1 as 64497;
  import filter { rpki_check_v4(); };
}
```

Verify ROV is operating:

```bash
# FRR: show RPKI session status.
vtysh -c "show rpki prefix-table"
vtysh -c "show rpki cache-connection"

# Check how many INVALID routes were dropped (look for route-map deny hits).
vtysh -c "show route-map BGP_RPKI_IN" | grep -A2 "deny"

# Validate a specific prefix+origin.
vtysh -c "show bgp 203.0.113.0/24 rpki"
```

### Step 5: OSPF Authentication — MD5 on All Areas and Interfaces

OSPF hellos, LSAs, and database exchange packets should all be authenticated. Without authentication, any host on a segment can join the OSPF topology and inject routes. Use MD5 key chains; OSPF does not yet have wide support for HMAC-SHA in open source implementations, though the capability exists in the RFC (RFC 7166 for OSPFv3).

**FRR OSPF MD5 configuration:**

```
# /etc/frr/frr.conf

! Define a key chain for OSPF.
key chain OSPF_KEYS
 key 1
  key-string ospf-auth-key-here
  cryptographic-algorithm md5
!

interface eth0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 ospf-auth-key-here
!

interface eth1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 ospf-auth-key-here
!

router ospf
 network 10.0.0.0/24 area 0
 network 10.0.1.0/24 area 0
 area 0 authentication message-digest
```

Authentication must be enabled on every interface participating in OSPF. A single unauthenticated interface is sufficient for an attacker to inject LSAs. Audit all interfaces:

```bash
# Verify authentication is active on all OSPF interfaces.
vtysh -c "show ip ospf interface" | grep -E "^(eth|bond|ens|enp)|Authentication"
# Every OSPF-enabled interface should show "Message digest authentication".
```

**Key rotation without adjacency teardown:**

```
# Add new key alongside old key — OSPF will send both during transition.
interface eth0
 ip ospf message-digest-key 1 md5 old-key-here
 ip ospf message-digest-key 2 md5 new-key-here
# After confirming all routers have the new key configured, remove key ID 1.
interface eth0
 no ip ospf message-digest-key 1 md5 old-key-here
```

For OSPFv3 (IPv6), use IPsec for authentication — OSPFv3 removed the built-in authentication field in favour of IPsec AH/ESP:

```
# /etc/frr/frr.conf (OSPFv3 with IPsec AH)
interface eth0
 ipv6 ospf6 authentication ipsec spi 1001 md5 0102030405060708090a0b0c0d0e0f10
```

### Step 6: OSPF Passive Interfaces

OSPF passive mode suppresses hello packets on the specified interface. The interface's address is still redistributed into OSPF (so it is reachable), but no adjacency can be formed on that segment. Use passive mode on every interface that faces end users, servers, or any host that should not participate in routing.

```
# /etc/frr/frr.conf
router ospf
 ! Make all interfaces passive by default; explicitly enable routing on
 ! infrastructure-facing interfaces.
 passive-interface default
 no passive-interface eth0    ! Uplink to core router.
 no passive-interface eth1    ! Peer link between routers.
 ! eth2 (server-facing), eth3 (user-facing) remain passive.
```

The passive-interface-default pattern is safer than explicitly listing passive interfaces — new interfaces added to the router are automatically passive until explicitly activated. This prevents accidentally distributing OSPF hellos onto new network segments.

Verify no OSPF hellos are being sent on passive interfaces:

```bash
# Check passive interface status.
vtysh -c "show ip ospf interface eth2" | grep -i passive
# Expected: "OSPF not enabled on this interface" or "passive interface"

# Confirm no OSPF traffic on the server-facing segment using tcpdump.
tcpdump -i eth2 -n 'ip proto 89' -c 10
# Should capture zero packets within a few seconds.
```

### Step 7: BFD — Bidirectional Forwarding Detection

BGP and OSPF have their own failure detection mechanisms, but they are slow. BGP hold timers default to 90 seconds; an undetected peer failure means 90 seconds of blackholing traffic. OSPF dead intervals default to 40 seconds. BFD (Bidirectional Forwarding Detection, RFC 5880) runs independent liveness probes at sub-second intervals, detecting path failures in milliseconds and triggering routing protocol convergence immediately.

BFD is lightweight (small UDP probe packets) and does not interact with the routing protocol's authentication — it is a separate detection layer. FRR includes a BFD daemon (`bfdd`) that integrates with both BGP and OSPF.

**FRR BFD configuration for BGP:**

```
# /etc/frr/frr.conf

bfd
 peer 192.0.2.1
  receive-interval 300
  transmit-interval 300
  detect-multiplier 3
  ! Failure declared after 3 missed probes = 900ms detection time.
 !
!

router bgp 64496
 neighbor 192.0.2.1 remote-as 64497
 neighbor 192.0.2.1 bfd
```

**FRR BFD configuration for OSPF:**

```
# /etc/frr/frr.conf

interface eth0
 ip ospf bfd

! Optional: configure BFD profile for OSPF.
bfd
 profile ospf-bfd
  receive-interval 300
  transmit-interval 300
  detect-multiplier 3
 !
!
interface eth0
 ip ospf bfd profile ospf-bfd
```

Monitor BFD session state:

```bash
# Show all BFD sessions and their state.
vtysh -c "show bfd peers"

# Show BFD statistics for a specific peer.
vtysh -c "show bfd peer 192.0.2.1"

# Expected output fields: Status (up), Uptime, Rx/Tx intervals, multiplier.
```

BFD timers should be set based on the link type. For direct Ethernet links, 300ms transmit/receive with a multiplier of 3 gives 900ms failure detection. For links crossing a provider network where packet loss is expected, increase the interval to avoid false positives (use 1000ms / multiplier 3 = 3-second detection).

### Step 8: Route Summarisation for Security

Route summarisation (aggregation) reduces the number of specific routes visible to BGP peers and in the OSPF topology. Fewer specific routes mean fewer attack vectors: an attacker cannot inject a more-specific hijack for a sub-prefix that is not advertised externally.

**BGP aggregation in FRR:**

```
# /etc/frr/frr.conf
router bgp 64496
 ! Advertise only the aggregate; suppress more-specifics.
 aggregate-address 203.0.113.0/24 summary-only
 aggregate-address 198.51.100.0/22 summary-only
 ! "summary-only" suppresses the component /25, /26 routes from being
 ! advertised to peers. Internal OSPF still knows the specifics.
```

**OSPF inter-area summarisation:**

```
# /etc/frr/frr.conf
router ospf
 ! Summarise area 1 routes into area 0 at the ABR.
 area 1 range 10.1.0.0/16
 ! This hides the specific /24 and /25 routes from area 0,
 ! limiting LSA flooding and reducing the attack surface.
```

Summarisation also reduces convergence time after a failure — fewer routes to update means faster convergence across the topology.

### Step 9: Hardening the Routing Daemon Process

FRR and BIRD run as long-lived, privileged network processes. Compromise of the routing daemon directly enables route table manipulation. Reduce the privilege surface:

**FRR process hardening:**

```bash
# FRR installs with its own user/group by default.
id frr
# uid=105(frr) gid=110(frr) groups=110(frr),111(frrvty)

# Confirm FRR daemons are not running as root.
ps aux | grep -E '(zebra|bgpd|ospfd|bfdd)' | grep -v grep | awk '{print $1}'
# All should show "frr", not "root".

# Restrict the FRR configuration directory.
ls -la /etc/frr/
# Owner: root:frr, mode: 0750 for directory, 0640 for files.
chown -R root:frr /etc/frr
chmod 750 /etc/frr
chmod 640 /etc/frr/*.conf
```

FRR systemd unit hardening (add to `/etc/systemd/system/frr.service.d/hardening.conf`):

```ini
[Service]
# Restrict filesystem access.
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/frr /var/log/frr /var/run/frr

# Drop capabilities not needed for routing.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_CHROOT CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

# Namespace isolation.
PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
NoNewPrivileges=true
```

**BIRD process hardening:**

```bash
# BIRD runs as root by default; restrict to a dedicated user where possible.
# BIRD 2.x supports the -u (user) and -g (group) flags.
useradd -r -s /sbin/nologin bird
chown -R root:bird /etc/bird
chmod 750 /etc/bird
chmod 640 /etc/bird/*.conf

# /etc/systemd/system/bird.service.d/hardening.conf
```

```ini
[Service]
User=root    # BIRD requires root for raw socket access on Linux.
# Compensate with namespace isolation.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
```

Restrict VTY access (FRR management socket):

```
# /etc/frr/frr.conf
line vty
 access-class MGMT_ONLY
!
! Only allow VTY connections from the management subnet.
access-list MGMT_ONLY permit 192.168.100.0/24
access-list MGMT_ONLY deny any
```

### Step 10: Telemetry

```
bgp_session_state{peer, remote_as}                     gauge (1=established)
bgp_prefixes_received_total{peer, remote_as}           gauge
bgp_prefixes_advertised_total{peer, remote_as}         gauge
bgp_rpki_valid_routes_total                            counter
bgp_rpki_invalid_rejected_total                        counter
bgp_rpki_notfound_routes_total                         counter
bgp_updates_received_total{peer}                       counter
bgp_max_prefix_exceeded_total{peer}                    counter
ospf_adjacency_state{interface, neighbor}              gauge (1=full)
ospf_lsa_updates_total{area}                           counter
ospf_authentication_failures_total{interface}          counter
bfd_session_state{peer}                                gauge (1=up)
bfd_session_flaps_total{peer}                          counter
```

Alert on:

- `bgp_session_state` == 0 for any peer — session down; check peer reachability and logs for TCP RST injection.
- `bgp_max_prefix_exceeded_total` increment — a peer is sending an abnormal volume of routes; possible route table flooding attack.
- `ospf_authentication_failures_total` increment — possible OSPF injection attempt or key misconfiguration.
- `bfd_session_flaps_total` rapid increments — link instability or BFD parameter mismatch; also investigate for routing loop symptoms.
- `bgp_rpki_invalid_rejected_total` sudden spike — a peer is sending routes that contradict published ROAs; investigate the peer.
- `bgp_prefixes_received_total` doubling on a single peer — possible route leak from that peer.

## Expected Behaviour

| Signal | Without hardening | With hardening |
|--------|------------------|----------------|
| Remote TCP injection into BGP session | Session reset or route injection succeeds | GTSM drops packets with low TTL before TCP stack; MD5/TCP-AO rejects unauthenticated segments |
| OSPF adjacency from rogue host | Adjacency formed; rogue LSAs accepted | MD5 authentication rejects unauthenticated hellos; passive-interface blocks adjacency on user-facing segments |
| BGP peer sends 100,000 unexpected prefixes | Route table exhausted; routing process may crash | Max-prefix limit tears down session; alert fires |
| Peer announces prefix with RPKI-invalid origin AS | Route accepted and forwarded to other peers | RPKI route map drops INVALID route at ingress; counter increments |
| BGP peer fails (link down) | Traffic blackholed for up to 90 seconds (hold timer) | BFD detects failure in under 1 second; BGP withdraws routes immediately |
| OSPF cost manipulation via forged LSA | Traffic redirected through attacker router | MD5 authentication prevents forged LSA acceptance |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| MD5 BGP authentication | Prevents unauthenticated session injection; widely supported | MD5 is computationally weak; vulnerable to offline brute force if session traffic is captured | Use TCP-AO where both sides support it; rotate MD5 keys quarterly. |
| TCP-AO | Cryptographically sound; supports key rollover | Requires kernel 6.7+ and FRR 9.0+; not supported by all peers | Deploy where supported; use MD5 as fallback for legacy peers. |
| GTSM | Eliminates all remote BGP injection attacks at zero operational cost | Cannot be used on multi-hop eBGP sessions where TTL varies | Enable on all directly-connected eBGP peers; skip only where hop count genuinely varies. |
| RPKI ROV (drop INVALID) | Blocks hijacked routes with published ROAs | A misconfigured ROA on your own prefixes causes remote peers to drop your routes | Test ROA configuration with RIPE validator API before enabling strict filtering. |
| Max-prefix limits | Prevents route table flooding and memory exhaustion | Overly conservative limits cause session teardown on legitimate route changes | Set limits to 5–10x the expected normal route count from each peer. |
| BFD fast failure detection | Sub-second convergence after link failure | BFD probe traffic adds minor bandwidth and CPU overhead | Use 300ms intervals; disable on high-packet-loss or satellite links. |
| Passive-interface default | New interfaces are safe by default | Easy to forget to un-passive a legitimate routing interface | Pair with interface-up monitoring; OSPF adjacency telemetry alerts when no neighbours form. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| BGP session drops after enabling MD5 | Peering session never comes up; `show bgp neighbor` shows Idle or Active | `bgp_session_state` == 0; FRR logs show "bad MD5 digest" | Verify key matches on both sides; check for leading/trailing whitespace in key configuration. |
| OSPF adjacency lost after enabling authentication | OSPF neighbors go to INIT/EXSTART; routes withdrawn | `ospf_adjacency_state` drops; traffic loss | Verify identical key and key-ID on both ends; check authentication type matches (both must be message-digest). |
| RPKI validator unreachable | FRR falls back to last-known ROA table or permissive mode | `rpki_rtr_session_state` == 0; FRR logs show RTR connection failure | Restore validator; configure secondary RTR source; know whether your router is configured for "permissive on cache miss" or "strict". |
| Max-prefix limit fires on legitimate route change | BGP session tears down during prefix expansion | `bgp_max_prefix_exceeded_total` increments; session state drops | Increase limit temporarily; investigate root cause; re-establish session with `clear ip bgp 192.0.2.1`. |
| BFD false positive causing route flapping | BGP/OSPF routes oscillate; traffic disruption despite link being up | `bfd_session_flaps_total` increments; routing table churn in logs | Increase BFD detect-multiplier or transmit-interval; investigate underlying packet loss. |
| GTSM dropping legitimate multi-hop eBGP | Peering session never establishes for multi-hop peer | BGP session stays in Active state; no MD5 or TCP-AO errors | Disable GTSM (`no neighbor X ttl-security`) for multi-hop peers only; use authentication only. |

## Related Articles

- [BGP Security and RPKI: Route Origin Validation](/articles/network/bgp-security-rpki/)
- [IPsec VPN Hardening](/articles/network/ipsec-vpn-hardening/)
- [Link-Layer Security: ARP Spoofing and DHCP Snooping](/articles/network/link-layer-security/)
- [Suricata IDS/IPS](/articles/network/suricata-ids-ips/)
- [Network Segmentation and Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)
