---
title: "MASQUE and CONNECT-UDP Proxy Hardening: Production Egress Gateways for HTTP/3 Traffic"
description: "MASQUE (RFC 9298) lets HTTP/3 clients tunnel UDP through a proxy — Apple Private Relay, Cloudflare Zero Trust, and enterprise SASE gateways all run on it. The proxy itself sees plaintext QUIC connection IDs, can be abused as an open relay, and concentrates a lot of trust. Hardening guide for operators."
slug: "masque-connect-udp-proxy-hardening"
date: 2026-05-08
lastmod: 2026-05-08
category: "network"
tags: ["masque", "connect-udp", "http3", "quic", "proxy", "egress"]
personas: ["network-engineer", "security-engineer", "platform-engineer"]
article_number: 659
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/network/masque-connect-udp-proxy-hardening/index.html"
---

# MASQUE and CONNECT-UDP Proxy Hardening: Production Egress Gateways for HTTP/3 Traffic

## Problem

MASQUE — Multiplexed Application Substrate over QUIC Encryption — is the IETF's name for a family of HTTP/3 extension methods that let a client tunnel arbitrary IP, UDP, or Ethernet datagrams through an HTTP/3 proxy. The two extensions in production use today are CONNECT-UDP (RFC 9298, June 2022) and CONNECT-IP (RFC 9484, October 2023). What started as the technical backbone of Apple iCloud Private Relay is now table stakes for SASE products, enterprise zero-trust egress gateways, and most major CDNs' WAF egress paths.

For network operators this is a step change. A traditional HTTP CONNECT proxy is a TCP relay: simple to reason about, easy to log, slow to scale. A MASQUE proxy is a UDP-aware HTTP/3 server that maintains state for arbitrarily many tunnelled QUIC connections, each with its own connection ID, datagram flow ID, and capsule stream. The proxy sits in the data path of every packet but cannot decrypt the payload (the inner QUIC handshake is end-to-end), so traditional protocol-aware controls like WAF rule inspection or DLP scanning do not apply to the tunnelled traffic.

That changes the nature of what the proxy must defend. Five concrete problems consistently surface in MASQUE deployments. (1) The proxy is the choke-point for client identity — if its authentication is weak or stateless, anyone on the internet can ride your egress IP allocation. (2) Datagram flow-ID collisions and connection-ID confusion across tunnels have produced two known disclosure-class bugs in 2025. (3) MASQUE concentrates *outbound* traffic policy at a layer above the OS firewall, so misconfiguration silently bypasses egress rules other components depend on. (4) The HTTP/3 control surface (capsules, settings frames, datagram registration) is a larger attack surface than any historical proxy protocol. (5) Operational logging is harder than for a TCP CONNECT proxy because the inner traffic is opaque and the per-connection state churns rapidly.

This article assumes you are running an HTTP/3-capable MASQUE proxy at the edge of an enterprise network or a multi-tenant service: examples include `quiche-server` with its `--listen-quic` mode, NGINX 1.27+ with the experimental QUIC build, the `masque-go` reference server, Envoy 1.32+ with the `udp_proxy` filter, and HAProxy 3.0+. The configuration patterns shown apply to all of them; specific syntax varies.

Target systems: Linux 6.8+ kernel (for `SO_RXQ_OVFL` accounting and `UDP_GRO`), proxy software with HTTP/3 support, eBPF-capable load balancer (Cilium 1.16+, Katran, or vendor equivalent), and a QUIC-aware observability stack (qlog or qvis pipeline).

## Threat Model

1. **Untrusted internet client probing the MASQUE listener** for open-relay behaviour. Goal: discover that the proxy will tunnel UDP to arbitrary hosts without authentication, abuse the egress IP for spam/exfil, or relay reflection-amplification toward third parties.
2. **Authenticated low-privilege tenant** of the proxy whose policy says "may reach corp DNS resolver only." Goal: confuse the proxy's per-tunnel ACL so a `CONNECT-UDP /v1/proxy?h=8.8.8.8&p=53` succeeds or — worse — `CONNECT-IP` for an internal subnet works.
3. **Adversary with capture access** between client and proxy. Goal: correlate plaintext QUIC connection IDs across handshakes to fingerprint a tenant's traffic, even though payloads are encrypted.
4. **Compromised proxy** (RCE in the QUIC stack) used as a pivot to read configuration secrets, attack inner-tunnel TLS sessions, or relay traffic to internal subnets the proxy can reach.
5. **Resource exhaustion attacker** opening many MASQUE tunnels to consume kernel UDP port allocations, conntrack entries, or capsule reassembly buffers.

## Configuration / Implementation

### Step 1 — Constrain the listener and the kernel UDP path

```bash
# /etc/sysctl.d/90-masque.conf
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.optmem_max=131072
net.ipv4.udp_mem='262144 524288 1048576'
net.ipv4.udp_rmem_min=65536
net.ipv4.udp_wmem_min=65536
net.ipv4.ip_local_port_range='10000 60999'
net.netfilter.nf_conntrack_udp_timeout=30
net.netfilter.nf_conntrack_udp_timeout_stream=120
net.core.netdev_max_backlog=65536
```

`udp_timeout` of 30 seconds keeps conntrack entries from accumulating for short-lived MASQUE flows; without this a busy proxy can pin tens of millions of conntrack rows. `ip_local_port_range` sets the source-port pool the proxy uses for outbound tunnels — keep it disjoint from your control-plane ranges.

The MASQUE listener should bind to a dedicated interface and the kernel should drop unauthenticated probes early via XDP:

```c
// xdp_masque_filter.c (loaded with bpftool)
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end) return XDP_DROP;
    if (udp->dest != bpf_htons(443)) return XDP_PASS;
    // Drop QUIC INITIAL packets where SCID length is implausible (>20 octets).
    __u8 *p = (__u8 *)(udp + 1);
    if (p + 6 > (__u8 *)data_end) return XDP_DROP;
    if ((p[0] & 0xC0) == 0xC0 && p[5] > 20) return XDP_DROP;
    return XDP_PASS;
}
```

### Step 2 — Authenticate every tunnel — no anonymous CONNECT-UDP

Stock MASQUE servers will accept any HTTP/3 client that completes TLS. That is a recipe for an open relay. Bind tunnel authorisation to one of:

- **mTLS** with a private CA whose leaf certificates carry tenant identity in a SAN URI like `spiffe://gateway.example.com/tenant/<id>`.
- **OAuth 2.1 access tokens** carried in `Proxy-Authorization: Bearer <jwt>` on the CONNECT-UDP request.
- **HTTP Message Signatures** (RFC 9421) for cases where the JWT itself must not be forwardable.

Example NGINX (with the QUIC patchset) snippet for mTLS-bound MASQUE:

```nginx
server {
    listen 443 quic reuseport;
    listen 443 ssl;
    http3 on;

    ssl_certificate     /etc/nginx/tls/proxy.example.com.crt;
    ssl_certificate_key /etc/nginx/tls/proxy.example.com.key;
    ssl_client_certificate /etc/nginx/tls/clients-ca.pem;
    ssl_verify_client on;
    ssl_verify_depth 2;

    location /v1/proxy {
        if ($ssl_client_verify != "SUCCESS") { return 401; }
        proxy_request_buffering off;
        masque_connect_udp on;
        masque_target_allowlist /etc/nginx/masque-targets.conf;
        masque_per_tenant_quota 200;  # max concurrent tunnels per cert SAN
    }
}
```

`masque_target_allowlist` is non-negotiable: it bounds which `(host, port)` tuples the proxy will tunnel to. Open MASQUE proxies have been observed in the wild abused for DNS amplification and to relay credential-stuffing attacks at billions-of-requests scale.

### Step 3 — Per-tenant target allowlist

The allowlist is the meat of the policy. A reasonable shape is:

```
# /etc/nginx/masque-targets.conf
# tenant SAN URI                         protocol  destination       ports     dscp
spiffe://gw/tenant/finance               udp       8.8.8.8           53,853    af11
spiffe://gw/tenant/finance               udp       1.1.1.1           53,853    af11
spiffe://gw/tenant/sre-tooling           udp       monitoring.corp   8472,4789 cs0
spiffe://gw/tenant/dev                   udp       10.50.0.0/16      *         cs0
```

Two important properties: targets are by FQDN (resolved server-side, with DNSSEC if available, on a short TTL), and `*` wildcards are namespace-scoped, never cluster-wide.

### Step 4 — Defeat connection-ID correlation

A MASQUE proxy sees the *outer* QUIC connection ID for every tunnelled packet. If a misbehaving client picks a static connection ID (some early QUIC stacks did), the proxy can be used as an oracle by a passive observer to link sessions across IP changes. RFC 9000 mandates `NEW_CONNECTION_ID` rotation; enforce it.

```yaml
# masque-go config snippet
quic:
  enforce_active_cid_rotation: true   # NEW_CONNECTION_ID required within 30s
  initial_cid_min_length: 8
  initial_cid_max_length: 20
  per_path_cid_pool: 4
```

Reject clients that fail to advertise a non-zero `active_connection_id_limit` transport parameter — they cannot rotate, so they will leak.

### Step 5 — Datagram flow-ID hygiene

CONNECT-UDP multiplexes inner UDP packets by datagram context ID. Two known classes of bug have appeared in 2025:

1. **Flow-ID reuse across tunnels**: a tenant's `CONNECT-UDP /a` is mapped to context-id 0; when their tunnel closes, the next tenant's `/b` reuses 0, but a stale datagram from `/a` lands in `/b`. Production proxies must hold context IDs in a *quarantine* state for `2 × max_idle_timeout` after tunnel close.
2. **Capsule injection**: a malformed `Capsule` frame on the request stream is accepted by some proxies as a configuration update. Reject any `Capsule-Type` outside the explicit allowlist `(DATAGRAM, ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT)`.

### Step 6 — Per-tunnel rate and resource limits

Apply both rate (packets/s, bytes/s) and quantity (concurrent tunnels per identity) limits. Without rate limits the inner traffic dominates and a single tenant can exhaust the proxy's egress bandwidth.

```yaml
# Envoy 1.32+ udp_proxy filter
- name: envoy.filters.udp.connect_udp
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.udp.connect_udp.v3.ConnectUdpConfig
    stat_prefix: masque
    upstream_idle_timeout: 30s
    per_tenant_pps_limit: 5000
    per_tenant_bps_limit: 50_000_000
    max_concurrent_tunnels_per_tenant: 200
    capsule_allowlist: [DATAGRAM]
```

### Step 7 — qlog-based observability

You cannot meaningfully debug a MASQUE proxy with packet capture alone — the QUIC payloads are encrypted. Enable qlog (RFC IETF QUIC working-group draft) at the proxy, scrubbing inner CIDs from logs that leave the host:

```yaml
qlog:
  enabled: true
  output: /var/log/masque/qlog/
  redact_inner_cid: true
  events:
    - connectivity:connection_started
    - connectivity:connection_closed
    - transport:packet_dropped
    - security:key_updated
    - masque:tunnel_open
    - masque:tunnel_closed
    - masque:capsule_received
```

Pair with `qvis` for replay during incident response. Retain qlog for 30 days minimum, encrypted at rest.

### Step 8 — Egress NAT and source-port exhaustion

Behind the proxy, every outbound tunnel needs a source IP and port. If the proxy NATs all tenants behind a single egress IP, port exhaustion at scale is real. Allocate per-tenant egress IPs where billing or compliance permit:

```bash
# Add tenant-specific egress IP and steer via cgroup-classid.
sudo ip addr add 198.51.100.42/32 dev eth1
sudo iptables -t mangle -A OUTPUT -m cgroup --cgroup 0x110001 \
  -j SNAT --to-source 198.51.100.42
```

This also gives downstream services (and abuse-report recipients) a per-tenant IP to attribute traffic to.

## Expected Behaviour

| Signal | Before hardening | After |
|---|---|---|
| Anonymous client CONNECT-UDP | Accepted, tunnel established | TLS handshake fails (mTLS) or 401 |
| CONNECT-UDP to non-allowlisted target | Tunnel established | 403 |
| Static QUIC connection ID across sessions | Allowed (correlatable) | Connection rejected |
| Capsule with unknown type | Silently accepted | Connection terminated, alert |
| Concurrent tunnels per tenant | Unbounded | Capped, 429 once exceeded |
| Inner UDP egress port range | Default ephemeral | Bounded `10000–60999` per sysctl |
| qlog visibility | None | Per-event records, redacted CIDs |
| Source-IP attribution | Single egress | Per-tenant egress IP |

Verification snippet:

```bash
# Open-relay test from an unauthenticated client.
curl --http3 -X CONNECT -H "Capsule-Protocol: ?1" \
  "https://proxy.example.com/v1/proxy?h=example.com&p=80"
# Expect: HTTP/3 401 (or TLS handshake failure with mTLS)

# Authenticated tunnel to allowed target.
curl --http3 -X CONNECT --cert tenant-finance.pem --key tenant-finance.key \
  -H "Capsule-Protocol: ?1" \
  "https://proxy.example.com/v1/proxy?h=8.8.8.8&p=53"
# Expect: 200 + capsule stream

# Authenticated tunnel to disallowed target.
curl --http3 -X CONNECT --cert tenant-finance.pem --key tenant-finance.key \
  -H "Capsule-Protocol: ?1" \
  "https://proxy.example.com/v1/proxy?h=10.0.0.1&p=22"
# Expect: 403
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| mTLS authentication | Strong per-tenant identity | Cert lifecycle complexity | SPIFFE/SPIRE for automation |
| Target allowlist | Closes open-relay risk | Operational burden adding new targets | Self-service portal with security review for new entries |
| Per-tenant egress IPs | Attribution, abuse handling | IP allocation scaling | IPv6-only egress where downstream allows |
| qlog retention | Forensic capability | Storage cost (~5KB/connection) | Compress, retain 30d, ship to cold storage |
| Capsule allowlist | Reduces protocol surface | Some legitimate extensions blocked | Add types only after review |
| XDP filter | Pre-userspace drops | Loses per-tenant context | Filter only on obviously malformed traffic |
| UDP rate limits | Bandwidth fairness | Bursty workloads see drops | Token-bucket with credit accumulation |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Allowlist FQDN resolves to public IP | Tenant tunnels reach unintended host | DNS resolution log shows unexpected target | DNSSEC-validate; resolve allowlist only against trusted resolvers |
| QUIC retry token leak | Reflection amplification possible | Net flow asymmetry alarm | Rotate retry-token secret; enforce token TTL |
| Conntrack table exhaustion | Tunnels fail intermittently | `nf_conntrack: table full` in dmesg | Raise `nf_conntrack_max`; lower UDP timeouts |
| Capsule reassembly buffer DoS | Memory growth, OOM | `connect_udp.capsule_buffer_bytes` metric | Per-connection capsule cap (4 KiB) |
| Inner connection-ID leak via logs | Tenant correlation possible | Log-scan finds unredacted CIDs | Redact at qlog write; rotate any logs that leaked |
| Egress IP listed as abuse source | Tenant traffic blocked downstream | Reputation feeds | Rotate egress IP; per-tenant egress |
| Source port exhaustion at NAT | New tunnels fail with `EADDRNOTAVAIL` | `udp_send_skb_errors` counter | Larger port range; per-tenant egress IPs |
| Capsule-type confusion | Proxy drops valid client traffic | Client errors paired with allowlist-rejection logs | Audit allowlist; add types after review |

## When to Consider a Managed Alternative

- **Cloudflare WARP / Zero Trust egress** runs MASQUE at scale and handles most of the operational burden if your compliance allows third-party DPI of TLS-clear metadata.
- **Apple iCloud Private Relay** is consumer-only and does not offer enterprise tenancy.
- **Google BeyondCorp Enterprise** uses similar egress patterns over HTTP/2 today; HTTP/3+MASQUE rollout is in beta.

## Related Articles

- [HTTP/3 and QUIC hardening fundamentals](/articles/network/http3-quic-hardening/)
- [Encrypted Client Hello deployment](/articles/network/encrypted-client-hello/)
- [Internal API protection patterns](/articles/network/internal-api-protection/)
- [Zero-trust network access](/articles/network/zero-trust-network-access/)
- [eBPF XDP for DDoS mitigation](/articles/network/ebpf-xdp-ddos/)
