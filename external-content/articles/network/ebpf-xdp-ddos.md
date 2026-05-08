---
title: "eBPF-XDP for L4 DDoS Mitigation: Line-Rate Drop in the Kernel"
description: "XDP runs your filter at the network driver level, before the kernel allocates an sk_buff. Drop attacks at line rate on commodity NICs with a few hundred lines of eBPF."
slug: "ebpf-xdp-ddos"
date: 2026-04-27
lastmod: 2026-04-27
category: "network"
tags: ["ebpf", "xdp", "ddos", "linux", "network-security"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 204
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/network/ebpf-xdp-ddos/index.html"
---

# eBPF-XDP for L4 DDoS Mitigation: Line-Rate Drop in the Kernel

## Problem

Layer-4 floods (SYN flood, UDP amplification, raw packet floods at >1 Mpps) overwhelm a server long before the application gets a chance to respond. The kernel's path from NIC to application — driver receive, sk_buff allocation, conntrack, netfilter, socket lookup, application receive — is hot. At a few million packets/second of attack traffic, the host's CPUs saturate handling kernel-level packet bookkeeping.

XDP (eXpress Data Path) is an eBPF hook in the network driver that runs *before* the kernel allocates an sk_buff. A program at this hook decides:

- `XDP_DROP` — packet discarded immediately. No kernel memory allocated, no further processing. Cost: ~1ns per packet.
- `XDP_TX` — packet bounced back out the same NIC.
- `XDP_REDIRECT` — packet sent to another CPU or another NIC.
- `XDP_PASS` — packet enters normal kernel processing.

For DDoS mitigation, dropping at XDP gives line-rate filter capacity on commodity hardware: a 25 Gbps NIC drops the full attack rate while leaving CPU available for legitimate traffic.

By 2026 the tooling is mature. Cilium uses XDP for its load-balancer fast-path; Katran (Facebook's L4 LB) and Cloudflare's edge use XDP for production DDoS mitigation; tools like `bpf-iptools`, `xdp-filter`, and `xdpctl` provide pre-built XDP filters for common patterns.

The specific gaps in a default Linux server facing DDoS:

- iptables / nftables run in netfilter — long after sk_buff allocation. Drop happens, but the cost of allocating-and-discarding sk_buff per packet still saturates CPU.
- `tcp_syncookies` mitigates SYN flood specifically but doesn't help against UDP amplification or generic flood.
- Cloud-provider DDoS protection (AWS Shield, Cloudflare) handles most volumetric traffic but not internal-east-west floods or smaller-scale attacks below cloud-provider thresholds.
- Self-hosted edges (NGINX, HAProxy, custom load balancers) lack a kernel-level filter; everything reaches userspace.

This article covers writing simple XDP programs for SYN flood, UDP amplification, and rate-limiting; loading via `bpftool` and integration with Cilium; observability via per-action counters; the trade-offs vs. cloud-managed DDoS.

**Target systems:** Linux kernel 5.4+ (XDP native mode); 5.10+ for stable XDP-CPUMAP; NICs with native XDP driver support (Intel ixgbe / i40e / ice, Mellanox mlx5, Broadcom bnxt, virtio-net). Most cloud instances support XDP in generic mode (slower but functional).

## Threat Model

- **Adversary 1 — Volumetric SYN flood:** botnet sends 5-50 million SYN packets/second to exhaust server connection-tracking and CPU.
- **Adversary 2 — UDP amplification:** spoofed-source UDP traffic to a service that responds with larger payloads (DNS, NTP, SSDP).
- **Adversary 3 — Pulse-wave attack:** short bursts of attack traffic followed by gaps; bypasses cloud-DDoS detection thresholds.
- **Adversary 4 — Encrypted L4 flood:** UDP / TCP packets to ports the server expects (HTTPS 443, DNS 53), so the cloud DDoS edge cannot drop based on protocol mismatch.
- **Access level:** all adversaries have network reach to the public IP; some have spoofing capability (BCP38-non-compliant networks).
- **Objective:** Service unavailability via CPU exhaustion, network-stack saturation, or downstream resource exhaustion.
- **Blast radius:** Without XDP-level filtering, a multi-Mpps flood saturates host CPU and triggers TCP-stack-level effects (conntrack overflow, TIME_WAIT exhaustion). With XDP filtering, the host stays available; legitimate traffic is unaffected.

## Configuration

### Step 1: Verify XDP Capabilities

```bash
# Check NIC driver support.
ip link show eth0
# 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ... mode DEFAULT group default

# Native XDP support per driver.
ethtool -i eth0 | grep driver
# driver: ixgbe   (or i40e, ice, mlx5, bnxt — these support native mode)

# Test XDP loading (load an empty program).
sudo ip link set dev eth0 xdpgeneric obj /dev/null sec xdp
# (succeeds = generic mode works; native mode requires the driver flag)
```

For VMs in clouds, native XDP often isn't available; fall back to generic mode (XDP_FLAGS_SKB_MODE), which is slower but still meaningfully better than netfilter.

### Step 2: A Simple SYN Flood Filter

```c
// xdp_synflood.c
// Drop SYN packets from sources exceeding rate limit; pass others.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#define MAX_SOURCES 1000000
#define SYN_RATE_LIMIT 100   /* SYNs per second per source */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);     /* source IP */
    __type(value, __u64);   /* token bucket: 32-bit count + 32-bit window */
    __uint(max_entries, MAX_SOURCES);
} syn_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} stats SEC(".maps");

#define STAT_PASS 0
#define STAT_DROP_RATE 1
#define STAT_DROP_BAD 2
#define STAT_DROP_LIMIT 3

SEC("xdp")
int xdp_syn_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_DROP;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end) return XDP_DROP;

    /* Only rate-limit SYN packets without ACK (initial connection). */
    if (!(tcp->syn) || tcp->ack) return XDP_PASS;

    __u32 src = ip->saddr;
    __u64 *bucket = bpf_map_lookup_elem(&syn_rate_map, &src);
    __u64 now_sec = bpf_ktime_get_ns() / 1000000000ULL;

    if (!bucket) {
        __u64 init_val = (now_sec << 32) | 1;
        bpf_map_update_elem(&syn_rate_map, &src, &init_val, BPF_ANY);
        __u32 k = STAT_PASS;
        __u64 *s = bpf_map_lookup_elem(&stats, &k);
        if (s) (*s)++;
        return XDP_PASS;
    }

    __u32 window = (*bucket) >> 32;
    __u32 count = (*bucket) & 0xFFFFFFFF;
    if (window != now_sec) {
        /* Reset window. */
        __u64 new_val = (now_sec << 32) | 1;
        bpf_map_update_elem(&syn_rate_map, &src, &new_val, BPF_ANY);
        return XDP_PASS;
    }
    count++;
    if (count > SYN_RATE_LIMIT) {
        __u32 k = STAT_DROP_RATE;
        __u64 *s = bpf_map_lookup_elem(&stats, &k);
        if (s) (*s)++;
        return XDP_DROP;
    }
    __u64 new_val = ((__u64)now_sec << 32) | count;
    bpf_map_update_elem(&syn_rate_map, &src, &new_val, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

Compile and load:

```bash
clang -O2 -g -target bpf -c xdp_synflood.c -o xdp_synflood.o
sudo ip link set dev eth0 xdp obj xdp_synflood.o sec xdp
```

Verify:

```bash
sudo bpftool prog list | grep xdp_syn_filter
sudo bpftool map dump name stats
# [
#   { "key": 0, "value": [ /* PASS counts per CPU */ ] },
#   { "key": 1, "value": [ /* DROP_RATE counts */ ] },
# ]
```

A SYN flood from a single source exceeding 100 SYNs/sec is dropped at the NIC. Legitimate connections from the same source pass through.

### Step 3: UDP Amplification Filter (DNS / NTP)

```c
// Drop UDP responses that don't match an outbound query in flight.
// Useful as a UDP amplification reflection drop.
SEC("xdp")
int xdp_udp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    __u16 dport = bpf_ntohs(udp->dest);
    /* Drop unsolicited DNS responses to non-resolver hosts. */
    if (dport == 53 || dport == 123) {  /* DNS or NTP source ports */
        /* On a host that's NOT a DNS or NTP server, drop these. */
        __u32 k = STAT_DROP_BAD;
        __u64 *s = bpf_map_lookup_elem(&stats, &k);
        if (s) (*s)++;
        return XDP_DROP;
    }
    return XDP_PASS;
}
```

This is a coarse filter; a real deployment correlates UDP responses with outbound queries via a connection-tracking map. The principle: at XDP, drop traffic that has no business reaching this host.

### Step 4: IP Allowlist / Blocklist via XDP Maps

Often the simplest mitigation is "drop traffic from known-bad sources." Maintain a `BPF_MAP_TYPE_LPM_TRIE` for CIDR blocklists:

```c
struct cidr_key {
    __u32 prefixlen;   /* CIDR prefix length */
    __u32 addr;        /* IPv4 address */
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct cidr_key);
    __type(value, __u32);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist SEC(".maps");

SEC("xdp")
int xdp_blocklist(struct xdp_md *ctx) {
    /* ... parse to ip header ... */
    struct cidr_key k = {.prefixlen = 32, .addr = ip->saddr};
    if (bpf_map_lookup_elem(&blocklist, &k)) {
        return XDP_DROP;
    }
    return XDP_PASS;
}
```

Userspace pushes blocklist updates to the map at runtime — no XDP program reload needed. Updates take effect within nanoseconds.

```bash
# Add a CIDR.
sudo bpftool map update name blocklist key 24 0 0 0 192 0 2 0 value 0
```

Couple to a threat-intel feed: pull blocked IPs from a service like Spamhaus DROP, AbuseIPDB, your SIEM's hot-list.

### Step 5: Integrating With Cilium

Cilium uses XDP under the hood. For a Cilium cluster, custom XDP programs install as `CiliumLoadBalancerIPPool`-aware filters or via `CiliumNetworkPolicy` extensions. The `cilium-bpfctl` tool inspects active programs.

For per-Pod XDP (rare; usually node-level XDP is sufficient):

```yaml
apiVersion: cilium.io/v2
kind: CiliumLocalRedirectPolicy
metadata:
  name: ddos-filter
spec:
  redirectFrontend:
    addressMatcher:
      ip: 192.0.2.1
      toPorts:
        - port: "443"
  redirectBackend:
    localEndpointSelector:
      matchLabels:
        app: ddos-filter
    toPorts:
      - port: "8443"
```

For a high-traffic edge, treat XDP as part of the host-level setup (independent of Cilium); use Cilium for service-mesh and policy.

### Step 6: Observability

XDP counters via per-CPU array maps. Aggregate to Prometheus:

```bash
# Read stats via bpftool, aggregate per-CPU.
sudo bpftool map dump name stats -j | jq '
  .[] | {
    action: .key,
    total: ([.formatted.value[]] | add)
  }'
```

Wire into Prometheus via a small exporter:

```python
# bpf_xdp_exporter.py
from prometheus_client import start_http_server, Gauge
import json, subprocess, time

ACTIONS = ["pass", "drop_rate", "drop_bad", "drop_limit"]
metric = Gauge("xdp_packets_total", "XDP per-action packet count", ["action"])

while True:
    out = subprocess.check_output(
        ["bpftool", "-j", "map", "dump", "name", "stats"]).decode()
    data = json.loads(out)
    for entry in data:
        action_idx = entry["key"]
        total = sum(entry["formatted"]["value"])
        metric.labels(action=ACTIONS[action_idx]).set(total)
    time.sleep(1)

start_http_server(9100)
```

Alert rules:

- `rate(xdp_packets_total{action="drop_rate"}[1m]) > 100000` — sustained SYN flood.
- `rate(xdp_packets_total{action="pass"}[1m])` drops sharply with `drop_*` rising — active attack.

### Step 7: Failure Recovery

XDP loaded programs persist across NIC restarts but not host reboots. Persist via systemd:

```ini
# /etc/systemd/system/xdp-ddos-filter.service
[Unit]
Description=Load XDP DDoS filter on eth0
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/xdp-loader load -m native eth0 /usr/local/lib/xdp/synflood.o
ExecStop=/usr/local/sbin/xdp-loader unload eth0 --all

[Install]
WantedBy=multi-user.target
```

Always include unload logic; a buggy XDP program loaded with native mode can wedge the NIC, and unload-by-systemd-stop is the recovery path.

## Expected Behaviour

| Signal | Without XDP | With XDP |
|--------|-------------|----------|
| SYN flood at 5 Mpps | Host CPU saturated; legitimate traffic stalls | Floor of CPU usage; floods dropped at NIC; legitimate traffic flows |
| Network-stack memory under flood | sk_buff allocations explode | bounded; flood drops before allocation |
| Latency for legitimate connection | Severely degraded | Unchanged |
| netfilter / iptables overhead | Linear with packet rate | Bypassed at XDP |
| Cloud DDoS provider triggers | At threshold | Below threshold (XDP absorbs) |
| Per-flood reaction time | Reactive (slowdown noticed) | Sub-second (XDP rate-limit) |

Synthetic test (use only against your own infrastructure):

```bash
# Generate 1M SYN/sec from a single source (pktgen).
sudo pktgen-dpdk --vdev=eth_pcap0,iface=eth1 \
  -- -P -m "[1].0" \
  -p 0 --tx-rate 1000000 --tx-burst 100

# On target with XDP loaded:
watch sudo bpftool map dump name stats
# Confirm drop_rate counter rises proportional to over-limit traffic.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Native XDP on hardware NIC | Line-rate drop | Limited to driver-supported NICs | Use generic mode for VMs; functional but slower. |
| Per-source rate limit | Bounds noisy-neighbor floods | Memory for source-tracking map | LRU map sizes well; 1M entries fit in ~80 MB. |
| Programmability | Custom logic for unique attacks | eBPF programming complexity | Use existing libraries (xdp-filter, Katran) for common patterns; write custom only for special cases. |
| In-kernel speed | No userspace context switch | Debugging is harder than userspace code | Use bpftool for inspection; structured logging via per-CPU arrays. |
| Drop-and-forget | No latency from defensive logic | Legitimate traffic from rate-limited source dropped during burst | Tune limits to legitimate-burst tolerances; couple with state-aware logic. |
| Persistence via systemd | Survives NIC restart | Requires unload procedure on reboot | Include unload in systemd ExecStop; idempotent reload. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| XDP program rejected by verifier | Loading fails | `bpftool prog load` error | Verifier errors are detailed; fix the BPF program. Common: too many map lookups in a loop. |
| Native XDP unsupported on NIC | `ip link set xdp` fails | Error: "operation not supported" | Use generic mode (`xdpgeneric`) or upgrade NIC / driver. |
| Map table fills | Some sources unrate-limited | LRU evicts entries; overall function still works | Increase `max_entries`. LRU is forgiving here. |
| XDP wedges NIC | Network unreachable | Cannot reach host | Have an out-of-band recovery path (IPMI, console). Always test new XDP programs in a non-production environment first. |
| Verifier loop limit hit | Program rejected on update | `Loop too complex` | Refactor to avoid bounded loops; use `bpf_loop` helper (5.17+) for explicit iteration. |
| XDP and conntrack interaction | Connections drop unexpectedly | conntrack table grows; legitimate traffic dropped | Don't rate-limit at XDP without considering conntrack state; combine with userspace policy. |
| False-positive drop | Legitimate clients rate-limited | Customer reports of blocked traffic | Lower limits trigger false-positives at scale (CGNAT). Tune; consider TLS-fingerprint-based identification rather than IP. |

## When to Consider a Managed Alternative

Self-hosted XDP DDoS mitigation requires kernel tuning, NIC selection, BPF expertise, and 24/7 ops to tune limits as attacks evolve (10-30 hours/month for an exposed-edge fleet).

- **Cloudflare Magic Transit / Spectrum:** L4 DDoS at the edge; absorbs volumetric traffic before it reaches your origin.
- **AWS Shield Advanced:** L3/L4 protection with custom rate-rules.
- **Google Cloud Armor:** L7 + L4 protection with managed rules.
- **OVH / DDoS-Guard:** dedicated DDoS-mitigation providers for self-hosted edges.

For internal east-west traffic where cloud-edge protection doesn't help, XDP remains the right answer.

## Related Articles

- [HTTP/3 and QUIC Production Hardening](/articles/network/http3-quic-hardening/)
- [HTTP/2 RST and CONTINUATION Flood Mitigation](/articles/network/http2-flood-mitigation/)
- [DDoS Defense at Mega-Scale](/articles/network/ddos-megascale-defence/)
- [eBPF Runtime Security with Tetragon](/articles/observability/ebpf-tetragon/)
- [Linux Firewall Hardening with nftables](/articles/linux/nftables/)
