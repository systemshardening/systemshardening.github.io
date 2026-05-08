---
title: "Anycast-Based DDoS Mitigation Architecture"
description: "Deploy a multi-PoP anycast architecture that absorbs volumetric DDoS floods across geographically distributed scrubbing nodes, combining BGP anycast, ECMP, SYN cookies, and XDP-based SYN proxies to keep origin infrastructure reachable under multi-hundred-Gbps attacks."
slug: anycast-ddos-mitigation
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - anycast
  - ddos-mitigation
  - bgp
  - scrubbing
  - dns-security
personas:
  - security-engineer
  - network-engineer
article_number: 504
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/anycast-ddos-mitigation/
---

# Anycast-Based DDoS Mitigation Architecture

## The Problem

A single-datacenter DDoS mitigation strategy has a hard capacity ceiling: whatever your upstream transit bandwidth is, that is the most traffic you can absorb. A 100 Gbps transit link becomes worthless the moment an attacker directs 120 Gbps of UDP amplification traffic at it. The link is congested, packets are dropped indiscriminately — attack traffic and legitimate traffic alike — and your service is offline. Adding more transit to the same facility merely raises the ceiling; it does not change the fundamental architecture. The attacker always wins the capacity race at any single location, because botnets can trivially exceed any single-point transit capacity.

Anycast changes the game entirely. Instead of funneling all inbound traffic toward one geographic location, anycast distributes it: the same IP prefix is announced from multiple Points of Presence (PoPs), and BGP's best-path selection routes each source to its nearest PoP. A 500 Gbps flood that would saturate a single 100 Gbps link is spread across ten PoPs — each absorbing 50 Gbps, all within capacity. There is no single overload point because there is no single convergence point.

This is not theory. Cloudflare, Google, AWS Route 53, and Akamai all operate anycast networks for exactly this reason. During the 2023 HTTP/2 rapid-reset attacks (generating over 200 million requests per second), Cloudflare absorbed the traffic across its anycast PoP fabric without origin-level impact. The architecture is public, the components are available in open source, and any network operator with BGP transit relationships can build a meaningful subset of it.

This article covers the full stack: BGP anycast fundamentals, scrubbing centre topology, FlowSpec integration, cloud-managed anycast options, ECMP within a PoP, health-check-driven prefix withdrawal, SYN flood mitigation, and per-PoP monitoring. It assumes you operate or have access to at least one autonomous system and one transit relationship with a provider that supports BGP.

**Target systems:** Linux 6.x (kernel, XDP); FRRouting 9.x or BIRD 2.0.x (BGP); ExaBGP 4.x (health-check-driven announcement); GoBGP 3.x (FlowSpec controller); NSD 4.x or BIND 9.x (authoritative DNS); GRE/IPIP kernel tunnels.

## Threat Model

- **Adversary 1 — Volumetric UDP amplification:** A botnet uses spoofed-source UDP to DNS, NTP, or CLDAP amplifiers, generating 200–500 Gbps aimed at a single IP prefix. A single-DC architecture saturates immediately.
- **Adversary 2 — SYN flood at scale:** 50–200 million SYN packets per second exhaust connection-tracking state tables and CPU at any individual node. The kernel's conntrack table fills; new legitimate TCP sessions are rejected.
- **Adversary 3 — DNS amplification targeting authoritative servers:** Attackers query your authoritative DNS servers with spoofed sources and large response payloads. DNS floods have historically overwhelmed even well-provisioned authoritative infrastructure.
- **Adversary 4 — Application-layer DDoS that survives volumetric mitigation:** HTTP/2 rapid-reset or slow-read attacks that pass volumetric filters and arrive at origin. Anycast plus scrubbing is not sufficient alone; origin-layer application-level controls are also required, but outside this article's scope.
- **Adversary 5 — PoP exhaustion:** An attacker concentrates traffic from a single geographic region to overwhelm one PoP rather than distributing the attack. The anycast architecture must detect per-PoP capacity exhaustion and dynamically withdraw the overwhelmed PoP's prefix announcement.
- **Access level:** All adversaries have network reach to public IP space. Adversaries 1 and 3 require access to amplification infrastructure or a large botnet. Adversary 2 requires botnet or spoofing capability.
- **Blast radius without anycast:** Any single-point saturation event takes the entire service offline. With anycast, PoP saturation causes geographic degradation only, and BGP withdrawal routes traffic to adjacent PoPs within convergence time (2–30 seconds depending on session configuration).

## BGP Anycast Fundamentals

Anycast is not a special protocol. It is a routing convention: the same IP prefix is announced to BGP from multiple autonomous system locations simultaneously. Every BGP router receiving those announcements applies standard best-path selection — preferring routes with higher local preference, shorter AS path, lower MED, or nearest IGP next-hop — and installs the "best" route. Since each announcing location has a different AS path length and a different IGP cost from the perspective of each receiving router, different routers select different best-paths. Traffic naturally flows to the nearest PoP.

This is the same mechanism that makes `8.8.8.8` (Google Public DNS) resolve fast from every continent: the same `/32` is announced from Google PoPs worldwide. Your DNS query routes to the nearest one.

For a DDoS mitigation anycast network, the typical structure is:

- Your origin AS (e.g., AS64496) peers with one or more transit providers at each PoP.
- At each PoP, a BGP-speaking router (FRR or BIRD) announces the same prefix — say `203.0.113.0/24` — to the upstream transit.
- Optionally, you also announce from a scrubbing centre via a separate peer relationship.
- Clean traffic is returned to origin via a GRE or IPIP tunnel if the scrubbing function is decoupled from the forwarding path.

The critical design point: BGP announcements from each PoP should use your own ASN (or a dedicated scrubbing ASN), not the transit provider's ASN. This ensures that BGP best-path selection based on AS path length is consistent and that you retain full control over prefix withdrawal.

```
# FRR /etc/frr/frr.conf — PoP 1 (e.g. Frankfurt)
frr version 9.1
frr defaults traditional
hostname frr-pop-fra
log syslog informational
!
router bgp 64496
 bgp router-id 198.51.100.1
 !
 neighbor 198.51.100.254 remote-as 64500   ! transit provider peer
 neighbor 198.51.100.254 description transit-fra-01
 !
 address-family ipv4 unicast
  network 203.0.113.0/24
  neighbor 198.51.100.254 activate
  neighbor 198.51.100.254 send-community both
  ! Prepend AS path to de-prefer this PoP if it is backup-only
  ! neighbor 198.51.100.254 route-map PREPEND-BACKUP out
 exit-address-family
!
ip prefix-list ALLOWED-ANNOUNCE seq 5 permit 203.0.113.0/24
ip prefix-list ALLOWED-ANNOUNCE seq 10 deny any
!
route-map EXPORT-TO-TRANSIT permit 10
 match ip address prefix-list ALLOWED-ANNOUNCE
!
```

Repeat this configuration at each PoP with a different `bgp router-id` and transit peer address. BGP automatically handles routing: traffic from Europe routes to Frankfurt, traffic from North America routes to the North America PoP.

### Automatic Failover

When a PoP loses its transit session — either because the session drops or because ExaBGP withdraws the prefix after a health check failure — the upstream transit withdraws the route from its RIB. Within the BGP hold-timer period (typically 90 seconds on public internet peers, configurable to 30 seconds or less with BFD), routers that previously sent traffic to the failed PoP re-select the next-best path and redirect traffic to the next nearest PoP. Capacity planning must account for this: each PoP should have sufficient headroom to absorb at least one adjacent PoP's traffic load in addition to its own.

## Anycast for Authoritative DNS

DNS amplification is one of the most common DDoS vectors because DNS responses are routinely 30–50x the size of queries: a 40-byte query for a TXT record can return a 3,000-byte response. An attacker with 1 Gbps of spoofed-source UDP query capacity can generate 30–50 Gbps of amplified DNS traffic aimed at the spoofed source addresses — your customers.

Anycast addresses this at two levels. First, by distributing your authoritative DNS servers across PoPs using anycast, any DNS amplification attack aimed at your resolver's IP is absorbed across all PoPs rather than concentrated at one. Second, the anycast distribution means that a flood targeting one region does not affect DNS resolution for other regions: a 100 Gbps attack absorbing your Frankfurt PoP's capacity does not affect DNS resolution for users in Asia Pacific.

The implementation is straightforward: run NSD or BIND behind a BGP-speaking host at each PoP and announce the same DNS server IP from each location.

```bash
# NSD 4.x — /etc/nsd/nsd.conf
server:
    ip-address: 203.0.113.10       # anycast DNS IP, same at every PoP
    port: 53
    verbosity: 1
    log-time-ascii: yes
    tcp-count: 1024
    tcp-query-count: 25
    tcp-timeout: 3
    ipv4-edns-size: 1232           # limit amplification payload
    refuse-any: yes                # block ANY queries — largest amplification vector
    minimal-responses: yes         # suppress additional section to reduce amplification

zone:
    name: "example.com"
    zonefile: "/etc/nsd/zones/example.com.zone"
```

The `refuse-any: yes` and `minimal-responses: yes` directives directly reduce the amplification factor. Combined with anycast distribution, a DNS amplification attack hitting your anycast prefix is spread across PoPs and its individual query load is handled by multiple NSD instances, each of which can process hundreds of thousands of queries per second.

At the BGP layer, the DNS server's anycast IP is announced from each PoP the same way the main service prefix is announced. No special DNS anycast configuration is needed beyond ensuring NSD binds to the anycast IP.

## Scrubbing Centre Architecture

A scrubbing centre sits between the internet and your origin infrastructure. It receives attack-plus-legitimate traffic, strips the attack traffic, and forwards clean traffic to origin. Two topologies exist:

### Inline Scrubbing

Traffic flows: Internet → PoP/Scrubber → Origin. The scrubber is in the forwarding path at all times. Latency is added at all times (typically 5–15ms per PoP hop), but no diversion is required during an attack. This is the Cloudflare Magic Transit and AWS CloudFront model: all traffic always transits the scrubbing infrastructure.

Inline scrubbing is appropriate when:
- You are already using a CDN or reverse proxy for performance (the latency cost is zero marginal cost)
- Your traffic profile means attacks are frequent enough that always-on scrubbing is operationally simpler than divert-on-demand

### Divert-and-Return (Out-of-Path Scrubbing)

Normal traffic flows directly: Internet → Origin. During an attack, BGP is used to divert traffic to the scrubber; clean traffic is returned to origin via GRE or IPIP tunnel.

```
Attack traffic path:
  Internet → Scrubber PoP (BGP redirect via /32 host route or FlowSpec)
             ↓
             Scrubber strips attack traffic
             ↓
             GRE tunnel to origin
             ↓
             Origin receives clean traffic

Normal traffic path (no attack):
  Internet → Origin (direct, lowest latency)
```

GRE tunnel setup for clean-traffic return:

```bash
# On the scrubber node: create GRE tunnel back to origin
ip tunnel add gre-to-origin mode gre \
    local 203.0.113.1 \       # scrubber external IP
    remote 192.0.2.100 \      # origin IP
    ttl 64
ip link set gre-to-origin up
ip route add 192.0.2.0/24 dev gre-to-origin

# On the origin node: create corresponding GRE endpoint
ip tunnel add gre-from-scrubber mode gre \
    local 192.0.2.100 \
    remote 203.0.113.1 \
    ttl 64
ip link set gre-from-scrubber up

# Traffic arriving via gre-from-scrubber is already clean
# Origin responds directly (asymmetric routing — responses do not
# return via the scrubber, which is correct and expected)
ip route add default via 198.51.100.1 dev eth0  # direct return path
```

Divert-and-return is appropriate when:
- Latency from always-on scrubbing is unacceptable (financial trading, real-time gaming)
- You have an existing BGP infrastructure you want to keep as the normal forwarding path
- You are using a carrier-grade scrubbing service (Telia Clean Pipes, Lumen, Zayo) that operates out-of-path by design

The operational risk of divert-and-return is the detection-and-diversion latency: you must detect the attack, trigger the BGP diversion, and wait for convergence before scrubbing begins. This window — typically 2–5 minutes for automated systems, longer for manual — is when attack traffic hits origin directly.

## BGP FlowSpec Integration and RTBH

Anycast distributes attack absorption across PoPs, but it does not eliminate traffic at the source. BGP FlowSpec and Remote Triggered Blackhole (RTBH) are complementary mechanisms that reduce the total volume reaching your anycast fabric. See the companion article on [BGP FlowSpec for DDoS Mitigation](/articles/network/bgp-flowspec-ddos/) for full configuration detail; the key integration points with anycast are:

**RTBH for amplification sources:** When your monitoring identifies a high-volume amplification source (a single IP generating 10+ Gbps of reflected UDP), push an RTBH blackhole advertisement for that source `/32` to your upstream transit peers. This causes the transit provider to drop traffic from that source before it reaches your anycast PoPs, reducing the total load each PoP must absorb.

```bash
# ExaBGP process: announce RTBH for a known amplifier source
# /etc/exabgp/rtbh-announce.py
import sys, time

BLACKHOLE_COMMUNITY = "64496:9999"   # agreed community with transit peer
BLACKHOLE_NEXTHOP   = "192.0.2.1"   # RTBH trigger next-hop

def blackhole(prefix):
    sys.stdout.write(
        f"announce route {prefix} next-hop {BLACKHOLE_NEXTHOP} "
        f"community [{BLACKHOLE_COMMUNITY}]\n"
    )
    sys.stdout.flush()

# Example: blackhole a known NTP amplifier
blackhole("198.51.100.55/32")
time.sleep(300)   # hold for 5 minutes, then withdraw
```

**FlowSpec rate-limiting at PoP edge:** Rather than dropping an entire source, push a FlowSpec rate-limit rule to your PoP edge routers that restricts inbound UDP/53 traffic from any source to a defined rate. This allows legitimate DNS traffic to flow while capping amplification.

```
# FRR FlowSpec rule: rate-limit inbound UDP/53 to 100 Mbit/s per PoP
router bgp 64496
 address-family ipv4 flowspec
  network flowspec destination 203.0.113.0/24 protocol udp destination-port 53 \
    action traffic-rate 100000000
 exit-address-family
```

## Cloud Provider Anycast: When to Use Managed vs Self-Built

Building your own anycast DDoS mitigation infrastructure requires capital (rented transit at multiple PoPs), operational maturity (BGP operations team), and ongoing maintenance. Cloud-managed anycast services offer a different trade-off: higher cost-per-Gbps-absorbed, but no infrastructure management overhead and access to PoP footprints that dwarf what any individual operator can build.

**Cloudflare Magic Transit** announces your IP prefixes from Cloudflare's global anycast network (330+ PoPs as of 2026). Cloudflare's scrubbing is inline: all traffic destined for your prefixes transits Cloudflare's network first. Clean traffic is returned via GRE or CNI. Appropriate when you need terabit-scale absorption capacity without owning infrastructure. The minimum prefix requirement is `/24` for IPv4.

**AWS Shield Advanced + CloudFront anycast:** CloudFront operates as an anycast CDN; Shield Advanced provides volumetric DDoS protection at the CloudFront edge PoPs. Appropriate if your origin is already on AWS and you are already using CloudFront for CDN. Shield Advanced also provides DDoS cost protection (AWS credits any EC2/ELB/CloudFront cost spikes caused by DDoS traffic).

**GCP Cloud Armor with anycast edges:** Cloud Armor sits in front of GCP's global external load balancer (GCLB), which is itself anycast. GCLB distributes traffic across Google's edge PoPs; Cloud Armor applies rate-limiting and WAF rules before traffic reaches your backend. Appropriate for workloads hosted on GCP.

**Decision framework:**
- Self-built anycast: you need IP ownership, custom routing control, non-HTTP protocol protection, or existing transit relationships. Budget: PoP colocation + transit at 3+ sites.
- Cloudflare Magic Transit: you need turnkey anycast absorption for arbitrary IP protocols at scale. Budget: per-Mbps pricing, typically $0.05–0.50/Mbps/month depending on contract.
- AWS Shield / GCP Cloud Armor: your origin is already on that cloud provider. Budget: existing cloud spend + Shield Advanced flat fee (~$3,000/month) or Cloud Armor per-request pricing.

Managed services are not mutually exclusive with self-built anycast. A common architecture uses managed scrubbing (Cloudflare Magic Transit) as the first-layer anycast absorber, with self-operated RTBH and FlowSpec as complementary upstream mitigations pushed to transit providers.

## ECMP Within a PoP

A single anycast PoP must itself distribute load across multiple physical servers, since one server cannot handle the traffic that BGP routes to the PoP. Equal-Cost Multipath (ECMP) is the standard mechanism: the PoP's BGP speaker announces the anycast prefix with multiple next-hops (one per physical scrubbing or service server), and the upstream router load-balances across them using a per-flow hash.

```bash
# Linux kernel ECMP: add multiple next-hops for the anycast prefix
# Each next-hop is a separate scrubbing server in the PoP
ip route add 203.0.113.0/24 \
    nexthop via 10.0.1.1 dev bond0 weight 1 \
    nexthop via 10.0.1.2 dev bond0 weight 1 \
    nexthop via 10.0.1.3 dev bond0 weight 1 \
    nexthop via 10.0.1.4 dev bond0 weight 1

# Verify ECMP is active
ip route show 203.0.113.0/24
# 203.0.113.0/24
#    nexthop via 10.0.1.1 dev bond0 weight 1
#    nexthop via 10.0.1.2 dev bond0 weight 1
#    ...
```

ECMP hashing is per-flow (5-tuple: src IP, dst IP, proto, src port, dst port) by default in the Linux kernel, ensuring that packets from the same TCP connection always reach the same backend. For UDP-based services (DNS), the 5-tuple hash is still appropriate — each UDP query is a distinct flow.

**Consistent hashing for stateful protocols:** For stateful protocols like TCP-based scrubbing proxies (where connection state must persist for the duration of a session), simple ECMP can route retransmits to a different backend after a topology change. Consistent hashing — as used by Maglev (Google's L4 LB) and Katran (Meta's L4 LB) — ensures that adding or removing a backend minimally disrupts existing flows. The `bpf_jhash` function in eBPF XDP programs can implement consistent hashing at the driver level for PoP-internal load balancing.

```c
// Consistent hash selection in XDP (simplified)
// Full Maglev consistent hash requires the lookup table approach
static __always_inline __u32 select_backend(__u32 src_ip, __u32 dst_ip,
                                             __u16 src_port, __u16 dst_port) {
    __u32 hash = bpf_jhash_3words(src_ip, dst_ip,
                                   ((__u32)src_port << 16) | dst_port,
                                   0xdeadbeef);
    return hash % NUM_BACKENDS;   // NUM_BACKENDS defined at compile time
}
```

## Health Checking and Prefix Withdrawal

An anycast architecture is only as good as its ability to withdraw a failing PoP. A PoP that is under attack and approaching capacity, or that has lost its uplink, must stop announcing the anycast prefix immediately — otherwise BGP continues routing traffic to a location that cannot handle it.

ExaBGP is the standard tool for health-check-driven prefix announcement. It runs a configurable process (typically a shell script or Python script) that monitors local health indicators and announces or withdraws the prefix via the ExaBGP API.

```ini
# /etc/exabgp/exabgp.conf
process health-check {
    run /usr/local/bin/pop-health-check.sh;
    encoder text;
}

neighbor 198.51.100.254 {
    router-id 198.51.100.1;
    local-address 198.51.100.1;
    local-as 64496;
    peer-as 64500;

    family {
        ipv4 unicast;
    }
}
```

```bash
#!/usr/bin/env bash
# /usr/local/bin/pop-health-check.sh
# Announces the anycast prefix only when this PoP is healthy.

PREFIX="203.0.113.0/24"
NEXTHOP="self"
THRESHOLD_GBPS=80          # withdraw if inbound > 80 Gbps (near-capacity)
HEALTH_ENDPOINT="http://127.0.0.1:8080/health"

announce() {
    echo "announce route ${PREFIX} next-hop ${NEXTHOP}"
}

withdraw() {
    echo "withdraw route ${PREFIX} next-hop ${NEXTHOP}"
}

while true; do
    # Check application health
    http_status=$(curl -so /dev/null -w "%{http_code}" \
                  --connect-timeout 2 "${HEALTH_ENDPOINT}")

    # Check inbound traffic rate from interface counters
    rx_bytes_now=$(cat /sys/class/net/eth0/statistics/rx_bytes)
    sleep 1
    rx_bytes_next=$(cat /sys/class/net/eth0/statistics/rx_bytes)
    rx_gbps=$(echo "scale=2; (${rx_bytes_next} - ${rx_bytes_now}) * 8 / 1000000000" | bc)

    if [[ "${http_status}" == "200" ]] && \
       (( $(echo "${rx_gbps} < ${THRESHOLD_GBPS}" | bc -l) )); then
        announce
    else
        withdraw
        logger -t pop-health "Withdrawing ${PREFIX}: status=${http_status} rx=${rx_gbps}Gbps"
    fi

    sleep 5
done
```

For faster convergence during failures, configure BFD (Bidirectional Forwarding Detection) alongside BGP. BFD detects link failures in milliseconds rather than waiting for the BGP hold-timer to expire:

```
# FRR: enable BFD on transit peer session
router bgp 64496
 neighbor 198.51.100.254 bfd
!
bfd
 peer 198.51.100.254 interface eth0
  detect-multiplier 3
  receive-interval 300
  transmit-interval 300
 !
```

With the above BFD configuration, a link failure is detected within 900ms (3 × 300ms) rather than the 90-second hold-timer default. BGP prefix withdrawal propagates within the next BGP convergence cycle.

## SYN Flood Mitigation at Scale

SYN floods are particularly damaging to anycast architectures because SYN packets are stateless from the attacker's perspective — no three-way handshake is needed to generate millions of SYN packets per second. Each arriving SYN at your PoP causes the kernel to allocate connection state, which exhausts the `nf_conntrack` table and CPU.

Two complementary mitigations work at anycast scale:

### SYN Cookies

SYN cookies eliminate server-side state for the initial handshake. Instead of allocating a `sk` socket entry on SYN receipt, the kernel encodes connection parameters into the initial sequence number (ISN) of the SYN-ACK. Only when a valid ACK arrives does the kernel allocate full connection state. Enable it system-wide:

```bash
# Enable SYN cookies unconditionally (not just under backlog pressure)
sysctl -w net.ipv4.tcp_syncookies=2

# Increase SYN backlog queues
sysctl -w net.ipv4.tcp_max_syn_backlog=65536
sysctl -w net.core.somaxconn=65536

# Persist in /etc/sysctl.d/99-syn-hardening.conf
cat > /etc/sysctl.d/99-syn-hardening.conf << 'EOF'
net.ipv4.tcp_syncookies = 2
net.ipv4.tcp_max_syn_backlog = 65536
net.core.somaxconn = 65536
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
EOF
sysctl -p /etc/sysctl.d/99-syn-hardening.conf
```

### XDP-Based SYN Proxy at PoP Edge

For SYN floods exceeding ~5 million packets/second, even SYN cookie processing in the kernel is too expensive — the socket lookup path and `sk_buff` allocation overhead still saturates CPU. An XDP SYN proxy terminates the TCP handshake at the driver level before the kernel allocates any socket state. See the companion article on [eBPF-XDP for L4 DDoS Mitigation](/articles/network/ebpf-xdp-ddos/) for the full XDP SYN proxy implementation. The key integration with anycast is that the XDP program runs on each physical server in the PoP, behind the ECMP distribution, so the SYN flood load is spread across all ECMP next-hops and processed in parallel:

```
BGP anycast → PoP edge router → ECMP hash → Server 1 (XDP SYN proxy)
                                          → Server 2 (XDP SYN proxy)
                                          → Server 3 (XDP SYN proxy)
                                          → Server 4 (XDP SYN proxy)
```

Each server handles its 25% share of the flood independently. A 100 Mpps SYN flood becomes 25 Mpps per server, within the capacity of a modern XDP-capable NIC (Intel ice or Mellanox mlx5 can sustain 50–100 Mpps in XDP_DROP mode).

## Monitoring Per-PoP Traffic

An anycast network without per-PoP visibility is operationally blind. The monitoring objectives are:

1. **Detect volume spikes** that indicate a PoP is absorbing an attack and approaching capacity
2. **Detect asymmetric load** across PoPs that indicates BGP routing anomalies or geographically concentrated attacks
3. **Correlate PoP saturation with BGP withdrawal events** to verify that automatic failover is functioning

The standard stack is sFlow (sampled from the PoP's BGP-speaking router) → a collector (pmacct or GoFlow2) → Prometheus → Grafana.

```yaml
# /etc/prometheus/scrape_configs — per-PoP flow metrics
scrape_configs:
  - job_name: 'pop_traffic'
    static_configs:
      - targets:
          - 'pop-fra-01:9090'   # Frankfurt PoP Prometheus exporter
          - 'pop-lax-01:9090'   # Los Angeles PoP
          - 'pop-sin-01:9090'   # Singapore PoP
          - 'pop-nyc-01:9090'   # New York PoP
    relabel_configs:
      - source_labels: [__address__]
        target_label: pop_location
```

```bash
# GoFlow2: collect sFlow from PoP router, export as Prometheus metrics
docker run --rm -d \
    -p 6343:6343/udp \
    -p 8080:8080 \
    cloudflare/goflow2:latest \
    -sflow.addr 0.0.0.0:6343 \
    -metrics.addr 0.0.0.0:8080

# Configure sFlow on FRR edge router
# (sFlow config is typically on the router, not FRR — example for a Linux bridge acting as PoP router)
apt-get install -y hsflowd
cat > /etc/hsflowd.conf << 'EOF'
sflow {
    polling = 30
    sampling = 1000         # 1:1000 sampling rate
    collector { ip=10.0.0.5 udpport=6343 }   # GoFlow2 collector IP
    pcap { dev=eth0 }
}
EOF
systemctl enable --now hsflowd
```

Critical alerts to configure:

```yaml
# Prometheus alert rules — /etc/prometheus/rules/anycast-ddos.yml
groups:
  - name: anycast_ddos
    rules:
      - alert: PoPTrafficNearCapacity
        expr: pop_inbound_gbps > 75   # 75% of PoP capacity
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PoP {{ $labels.pop_location }} approaching capacity"
          description: "Inbound traffic {{ $value }}Gbps. Automatic withdrawal threshold is 80Gbps."

      - alert: PoPPrefixWithdrawn
        expr: pop_bgp_prefix_announced == 0
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: "PoP {{ $labels.pop_location }} has withdrawn anycast prefix"
          description: "BGP prefix withdrawn. Adjacent PoPs are now absorbing diverted traffic."

      - alert: AsymmetricPoPLoad
        expr: stddev(pop_inbound_gbps) / avg(pop_inbound_gbps) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Uneven traffic distribution across PoPs"
          description: "Coefficient of variation > 50%. Possible BGP routing anomaly or geographically concentrated attack."
```

The `AsymmetricPoPLoad` alert is particularly important for detecting PoP exhaustion attacks (Adversary 5 in the threat model): an attacker concentrating traffic from a single region causes that PoP to receive disproportionate load, which appears as high standard deviation across PoP traffic metrics before the PoP's health check triggers withdrawal.

## Operational Checklist

- Each PoP has a transit relationship that supports BGP community-based RTBH (verify before an attack, not during)
- ExaBGP health-check scripts are tested with deliberate health check failures in a maintenance window
- BFD is enabled on all transit BGP sessions; convergence time is measured and documented
- SYN cookies are enabled system-wide on all PoP servers (`net.ipv4.tcp_syncookies=2`)
- XDP SYN proxy is loaded and verified on PoP edge servers before going live
- Per-PoP capacity headroom is sized for at least 1.5× expected normal load (to absorb adjacent-PoP failover)
- Scrubbing GRE tunnels are monitored for MTU issues (GRE adds 24 bytes of overhead; set MTU to 1476 on GRE interfaces to avoid fragmentation)
- FlowSpec peering sessions with transit providers are tested with a non-impacting rate-limit rule before relying on them during an attack
- Prometheus alerts for PoP capacity, prefix withdrawal, and asymmetric load are firing to an on-call channel
- Runbook exists for: manual prefix withdrawal, emergency RTBH push to transit, adding a new PoP under active attack

## Summary

Anycast-based DDoS mitigation replaces a single overload point with a distributed fabric that absorbs attack traffic proportional to its geographic spread. The architecture stacks: BGP anycast distributes load across PoPs; ECMP distributes within each PoP; XDP SYN proxies and SYN cookies handle SYN floods before kernel state is exhausted; FlowSpec and RTBH push drop rules upstream to reduce total absorbed volume; health-check-driven BGP withdrawal routes traffic away from saturated PoPs within seconds; and per-PoP sFlow telemetry provides the visibility needed to detect attacks, trigger mitigations, and verify recovery. For operators who cannot maintain their own PoP infrastructure, Cloudflare Magic Transit, AWS Shield Advanced, and GCP Cloud Armor provide managed anycast absorption at the cost of per-Mbps pricing and loss of direct routing control. Most production deployments combine both: managed scrubbing at the outermost layer, self-operated FlowSpec and RTBH as a complementary upstream mitigation.
