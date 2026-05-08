---
title: "HTTP/2 RST and CONTINUATION Flood Mitigation: CVE-2023-44487, CVE-2024-27316, and Beyond"
description: "Two recent CVE classes weaponize HTTP/2's stream and header model. Mitigation is settings-tweak in NGINX and Envoy, but only if you know which knobs."
slug: "http2-flood-mitigation"
date: 2026-04-27
lastmod: 2026-04-27
category: "network"
tags: ["http2", "ddos", "nginx", "envoy", "rst-flood", "continuation-flood"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 196
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/network/http2-flood-mitigation/index.html"
---

# HTTP/2 RST and CONTINUATION Flood Mitigation: CVE-2023-44487, CVE-2024-27316, and Beyond

## Problem

HTTP/2 multiplexes many streams over a single TCP connection. The protocol's design — streams created and reset cheaply, headers split across `CONTINUATION` frames — was optimized for browser-server performance. The same primitives are weaponized in two recent attack classes:

- **CVE-2023-44487 (HTTP/2 Rapid Reset, "RST flood")** — disclosed October 2023. A client opens a stream and immediately sends `RST_STREAM`. The server allocates request-handling state, then must tear it down. With high concurrency, the cost-asymmetry causes denial of service. Cloudflare, Google, and AWS reported attacks reaching hundreds of millions of requests/second targeting HTTP/2 endpoints.
- **CVE-2024-27316 (HTTP/2 CONTINUATION flood)** — disclosed April 2024. A client opens a stream and sends `HEADERS` followed by an indefinite stream of `CONTINUATION` frames without setting the END_HEADERS flag. The server buffers the headers. Memory exhaustion within a single connection.

Multiple HTTP/2 implementations were affected. Many shipped patches in 2023–2024, but some configurations remain exposed:

- Default Apache HTTP Server, Tomcat, Jetty configurations had vulnerable defaults until late 2024.
- Self-hosted NGINX before 1.25.3 was vulnerable to RST flood; before 1.27.4 was vulnerable to CONTINUATION flood.
- Envoy versions before 1.28.1 / 1.29.0 had partial mitigations only.
- Custom HTTP/2 servers (Go `net/http`, Rust hyper-h2, Python httpx) shipped fixes on different timelines.
- Even patched versions need additional config to fully mitigate when defaults are too permissive.

This article covers mitigation in NGINX, Envoy, Apache, and at the Cloudflare / CloudFront edge; the general HTTP/2 settings (`max_concurrent_streams`, `max_field_size`, etc.) that bound the attack regardless of patches; and the rate-limiting primitives that catch flood-class attacks before they exhaust resources.

**Target systems:** NGINX 1.27+, Envoy 1.30+, Apache HTTP Server 2.4.62+, Cloudflare (managed), AWS CloudFront (managed), Caddy 2.8+, Go `net/http` 1.22+, Rust hyper 1.5+.

## Threat Model

- **Adversary 1 — Volumetric DDoS:** botnet generates RST or CONTINUATION floods at large scale, attempting to exhaust server resources. Wants service unavailability.
- **Adversary 2 — Targeted single-source flood:** smaller-scale attack from a constrained source aiming at a specific endpoint or tenant.
- **Adversary 3 — Layer-7 amplification:** crafted requests that consume disproportionate server resources per byte sent — a slow-response generator hit at high stream count.
- **Adversary 4 — Connection-resource exhaustion of a backend behind a proxy:** the front edge accepts the requests; backends behind it cannot handle the burst.
- **Access level:** All adversaries have network reach to the public HTTPS endpoint. None have credentials or backend access.
- **Objective:** CPU exhaustion, memory exhaustion, connection-table exhaustion, eventual TCP-level connection refusal for legitimate traffic.
- **Blast radius:** Without mitigation, a single high-bandwidth client can saturate a multi-thousand-RPS HTTPS endpoint. With mitigation, per-connection caps and per-source rate limits cap the damage at the connection level; the server continues serving other clients.

## Configuration

### Step 1: Patch the HTTP/2 Implementation

The first step is the obvious one: patches.

```bash
# NGINX: confirm version supports both fixes.
nginx -V 2>&1 | grep -oE 'nginx/[0-9.]+'
# nginx/1.27.4 or higher

# Apache.
httpd -v
# Apache/2.4.62

# Envoy (in your sidecar or gateway).
envoy --version
# 1.30.x+
```

For older versions, upgrading is mandatory. Below covers settings that bound the attack regardless of version.

### Step 2: NGINX Configuration

```nginx
# /etc/nginx/conf.d/http2-hardening.conf

server {
    listen 443 ssl;
    listen 443 quic reuseport;
    http2 on;

    server_name api.example.com;
    ssl_certificate /etc/nginx/certs/api.crt;
    ssl_certificate_key /etc/nginx/certs/api.key;

    # HTTP/2 stream and header limits.
    http2_max_concurrent_streams 32;       # was 128 default
    http2_recv_buffer_size 128k;
    http2_max_field_size 4k;               # max single header field
    http2_max_header_size 16k;             # max combined headers
    http2_idle_timeout 30s;
    http2_max_requests 100;                # max requests per connection

    # Connection-level rate limits.
    limit_conn http2_per_ip 5;             # max 5 simultaneous connections per IP
    limit_req zone=api_burst burst=20 nodelay;
}

# Top of nginx.conf or http {} block.
http {
    limit_conn_zone $binary_remote_addr zone=http2_per_ip:10m;
    limit_req_zone $binary_remote_addr zone=api_burst:10m rate=50r/s;

    # Reset-flood mitigation: count RST_STREAM frames per connection.
    # NGINX 1.25.3+ enforces a maximum.
    http2_recv_timeout 30s;
}
```

Key settings:

- `http2_max_concurrent_streams 32` — default is 128. A real client rarely needs 32; reducing limits the per-connection blast radius of any flood.
- `http2_max_requests 100` — closes the connection after 100 requests. Forces re-establishment, breaking long-lived attack connections.
- `http2_max_field_size 4k` and `http2_max_header_size 16k` — caps total header bytes; prevents CONTINUATION-flood from consuming unbounded memory.
- `limit_conn http2_per_ip 5` — caps concurrent HTTP/2 connections per source IP.
- `limit_req zone=api_burst rate=50r/s` — caps sustained request rate per source.

### Step 3: Envoy Configuration

```yaml
# Envoy listener with HTTP/2 hardening.
http_filters:
  - name: envoy.filters.http.local_ratelimit
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
      stat_prefix: http2_protect
      token_bucket:
        max_tokens: 100
        tokens_per_fill: 100
        fill_interval: 1s

  - name: envoy.filters.http.router

http_protocol_options:
  initial_stream_window_size: 65536
  initial_connection_window_size: 524288
  max_concurrent_streams: 32
  max_outbound_frames: 10000
  max_outbound_control_frames: 1000
  max_consecutive_inbound_frames_with_empty_payload: 1
  max_inbound_priority_frames_per_stream: 100
  max_inbound_window_update_frames_per_data_frame_sent: 10
  override_stream_error_on_invalid_http_message: true
```

The CVE-2023-44487 mitigation is `max_consecutive_inbound_frames_with_empty_payload: 1` and `max_outbound_frames: 10000`. The CVE-2024-27316 mitigation is `max_inbound_priority_frames_per_stream: 100` plus `override_stream_error_on_invalid_http_message: true`.

For Envoy as a sidecar in Istio:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: http2-hardening
  namespace: istio-system
spec:
  configPatches:
    - applyTo: NETWORK_FILTER
      match:
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
      patch:
        operation: MERGE
        value:
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
            http2_protocol_options:
              max_concurrent_streams: 32
              max_outbound_frames: 10000
              max_consecutive_inbound_frames_with_empty_payload: 1
```

### Step 4: Apache HTTP Server

```apache
# /etc/apache2/mods-available/http2.conf
H2MaxSessionStreams 32
H2MaxStreams 32
H2MaxHeaderListSize 16384
H2MaxDataFrameLen 16384
H2MaxWorkerIdleSeconds 30
H2KeepAliveTimeout 30
H2MaxRequestsPerConn 100
H2MinWorkers 4
H2MaxWorkers 64
H2WindowSize 65535
```

Apache 2.4.62+ has the patch baked in; the additional settings above bound resources within the patched runtime.

### Step 5: TCP-Level and Network-Edge Controls

Below the application protocol, harden the TCP listener:

```bash
# /etc/sysctl.d/60-http2-flood.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_synack_retries = 2
```

For nftables-level UDP and TCP rate limits:

```nft
table inet filter {
    set http_floods {
        type ipv4_addr; flags timeout, dynamic; timeout 60s;
    }
    chain input {
        type filter hook input priority 0; policy accept;
        # Cap new TCP connections per source.
        tcp dport 443 ct state new \
          meter conn_per_src { ip saddr limit rate 100/second burst 50 packets } accept
        tcp dport 443 ct state new drop
    }
}
```

### Step 6: Cloudflare and CloudFront Managed Mitigation

For sites behind Cloudflare or CloudFront, the edge handles much of the flood mitigation automatically. Verify it's on:

- Cloudflare: Security → DDoS → "HTTP/2 Rapid Reset" set to "Block."
- AWS CloudFront with Shield Standard: HTTP/2 mitigations apply automatically. Shield Advanced adds custom rate-based rules.

When using a managed edge, the origin's HTTP/2 settings still matter — Cloudflare's edge could be misconfigured to forward to origin without mitigation. Apply the NGINX/Envoy hardening at origin regardless.

### Step 7: Telemetry

Track HTTP/2 frame statistics for early detection:

```
http2_streams_opened_total{source_ip}
http2_rst_stream_total{source_ip}
http2_continuation_frames_total{source_ip}
http2_max_concurrent_reached_total
http2_connections_dropped_oversize_headers_total
http2_connections_per_source_ip{source_ip}        gauge
```

Alert on:

- `http2_rst_stream_total / http2_streams_opened_total > 0.5` — suspicious; legitimate clients rarely reset more than they complete.
- `http2_continuation_frames_total / http2_streams_opened_total > 100` — abnormal CONTINUATION usage.
- `http2_connections_per_source_ip > 5` — possible single-source flood.

## Expected Behaviour

| Signal | Default config | Hardened |
|--------|----------------|----------|
| Max streams per connection | 128 (NGINX), 100 (Envoy default) | 32 |
| Max requests per connection | unlimited or very high | 100 |
| RST_STREAM ratio that triggers protection | None | Implicit via `max_consecutive_inbound_frames_with_empty_payload` |
| Memory exhaustion via CONTINUATION flood | Possible | Bounded by `max_field_size` + `max_header_size` |
| Per-source connection cap | None | 5 (configurable) |
| Per-source request rate | Unlimited | 50 req/s (configurable) |
| Edge-level mitigation (Cloudflare/CloudFront) | Often on but not verified | Verified and origin also hardened |

Synthetic test:

```bash
# RST flood test (use only against your own infrastructure).
nghttp -v -t 30 -m 100 https://api.example.com/ &
# Without protection: server slows or stalls.
# With protection: connection limits trigger; server stays responsive.

# CONTINUATION flood test.
# (Requires a custom client; see CVE-2024-27316 PoC for reference.)
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `max_concurrent_streams: 32` | Bounds per-connection resource use | Some clients (high-throughput proxies) prefer more streams | 32 is plenty for browsers and most internal proxies. Raise selectively for known internal callers. |
| `max_requests: 100` | Forces connection rotation | Slight overhead from re-establishing TLS | Negligible cost; HTTP/2 connection setup is fast. Real clients respect `Connection: close` cleanly. |
| `max_field_size: 4k` | Caps header memory | Long auth tokens may exceed 4k | Most JWT tokens fit in 2-3k; if not, raise to 8k. Cookies should not be that large. |
| Per-IP connection cap | Bounds single-source flood | Behind CGNAT, multiple users share one IP | Use TLS fingerprint or User-Agent + IP for differentiation; or accept some collateral damage on shared IPs. |
| Edge + origin hardening | Defense in depth | Two places to maintain | Always do both: edge hardening doesn't replace origin hardening. |
| Audit / metrics | Detect attacks early | More metrics to ingest | Acceptable; low-cardinality. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Patches missing on origin | Attack succeeds despite edge mitigation | Edge metrics show legitimate traffic, origin metrics show resource exhaustion | Upgrade origin software; reload. The edge protects only its own footprint. |
| `max_concurrent_streams` too low | Legitimate high-volume client slow | Specific high-volume internal caller reports slowdowns | Raise per-host on the specific listener; not as a global default. |
| Per-IP cap blocks legitimate CGNAT users | Customer reports from specific ISPs | Mass complaints traced to a single CIDR | Raise the per-IP cap; pair with rate-limit-by-token (where feasible) for finer control. |
| Connection close on `max_requests` triggers reconnection storms | Spike of TLS handshakes | TLS-handshake latency rises | Raise `max_requests` to 1000+; the goal is bounded, not aggressive. |
| Patch regression in newer version | New CVE class emerges, patches incomplete | Security advisory; vendor announcement | Subscribe to nginx-announce, envoy-announce; have a "fast patch" process. |
| Edge bypass (direct origin access) | Attack hits origin directly | Origin metrics show traffic from non-edge IPs | Lock origin to accept connections only from the edge's IP ranges via NetworkPolicy or firewall. |

## Related Articles

- [HTTP/3 and QUIC Production Hardening](/articles/network/http3-quic-hardening/)
- [DDoS Defense at Mega-Scale](/articles/network/ddos-megascale-defence/)
- [Rate Limiting at the Ingress Layer](/articles/network/rate-limiting-ingress/)
- [TLS 1.3 on NGINX and Envoy: Secure Defaults and Cipher Selection](/articles/network/tls-nginx-envoy/)
- [Beyond TLS: Hardening NGINX for Production Traffic](/articles/network/nginx-hardening-beyond-tls/)
