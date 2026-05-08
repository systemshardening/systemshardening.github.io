---
title: "HTTP/3 and QUIC Production Hardening: UDP Amplification, 0-RTT Replay, and Connection ID Privacy"
description: "QUIC moves TLS into the transport. New attack surface: UDP amplification, 0-RTT replay, connection ID tracking, stream flow-control abuse. Hardening is non-trivial."
slug: "http3-quic-hardening"
date: 2026-04-24
lastmod: 2026-04-24
category: "network"
tags: ["quic", "http3", "tls", "udp", "ddos", "nginx", "envoy"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 168
difficulty: "intermediate"
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/network/http3-quic-hardening/index.html"
---

# HTTP/3 and QUIC Production Hardening: UDP Amplification, 0-RTT Replay, and Connection ID Privacy

## Problem

QUIC (RFC 9000) replaces TCP+TLS+HTTP/2 with an integrated transport that encrypts both the data and most of the transport metadata. HTTP/3 (RFC 9114) is HTTP over QUIC. The combination removes head-of-line blocking, reduces handshake round trips, and enables connection migration across IP changes. It has also changed the attack surface significantly:

- **UDP-based transport.** Firewalls, WAFs, and DDoS scrubbers that terminate TCP often do not inspect UDP. Traditional connection-tracking offload (SYN cookies, TCP stack tuning, conntrack) does not apply.
- **Amplification potential.** The initial QUIC server response is larger than the client's Initial packet unless specific anti-amplification controls are enforced. Servers must limit response size to 3x the received client bytes until the client address is validated.
- **0-RTT data.** QUIC reuses the TLS 1.3 0-RTT mechanism, letting clients send application data in the first flight. This data is replayable by any attacker with passive capture capability.
- **Connection IDs.** QUIC connections survive IP changes via connection IDs in packet headers. A static connection ID is a persistent tracker for any on-path observer. A missed rotation exposes user mobility.
- **Per-stream flow control.** Each QUIC stream has its own flow-control window. Poorly-tuned windows allow client-initiated memory exhaustion.
- **Stateless reset oracles.** QUIC's stateless reset key, if leaked, allows any on-path attacker to terminate any connection.
- **Initial packet decryption key is public.** The first flight is encrypted with a key derived from the connection ID. An attacker who observes the first packet can read and modify it until the handshake completes.

This article covers rate-limiting initial packets, enforcing anti-amplification, restricting 0-RTT, rotating connection IDs, setting flow-control safe defaults, and securing the stateless reset key.

**Target systems:** NGINX 1.25+ with `--with-http_v3_module`, Envoy 1.25+ with quiche codec, Cloudflare (managed), AWS CloudFront with HTTP/3, Caddy 2.6+.

## Threat Model

- **Adversary 1 — Amplification/reflection:** external attacker spoofs the source IP of a target victim and sends small QUIC Initial packets to your server. Without anti-amplification, the server sends a larger response to the victim, burning bandwidth at both ends.
- **Adversary 2 — 0-RTT replay:** passive observer captures a legitimate 0-RTT request (e.g., "POST /transfer $1000") and replays it, causing duplicate processing.
- **Adversary 3 — On-path tracker:** ISP, state actor, or compromised network tap observes unencrypted QUIC headers (connection ID, packet number, retry tokens) to correlate a user across IP addresses and time.
- **Adversary 4 — Memory exhaustion:** remote attacker opens many streams with small amounts of data but holds them open, consuming per-connection and per-stream buffer memory.
- **Adversary 5 — Stateless reset oracle:** attacker who observes enough packet traces can attempt to induce stateless resets to confirm endpoints exist, then flood resets to disrupt legitimate sessions if the reset key is discovered.
- **Blast radius:** amplification floods your outbound bandwidth and damages your IP reputation. 0-RTT replay can cause financial or data-altering operations to execute twice. On-path tracking undermines privacy guarantees users expect from HTTPS. Memory exhaustion crashes the edge server, affecting every user behind it.

## Configuration

### NGINX HTTP/3 Baseline

```nginx
# /etc/nginx/conf.d/http3.conf
# Production QUIC + HTTP/3 for nginx 1.25+.

server {
    listen 443 quic reuseport;
    listen 443 ssl;
    http2 on;

    server_name app.example.com;
    ssl_certificate /etc/nginx/certs/app.crt;
    ssl_certificate_key /etc/nginx/certs/app.key;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768:X25519;

    # Advertise HTTP/3 support.
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    # 0-RTT disabled by default. Enable only for idempotent endpoints.
    ssl_early_data off;

    # QUIC-specific limits.
    quic_gso on;                          # Generic segmentation offload.
    quic_retry on;                        # Enforce retry for amplification control.

    # Connection-level limits.
    http3_stream_buffer_size 64k;
    http3_max_concurrent_streams 128;

    location / {
        proxy_pass http://upstream;
    }

    # Endpoints safe for 0-RTT (idempotent GETs only).
    location /static/ {
        ssl_early_data on;
        root /var/www/static;
    }
}
```

Key settings explained below.

### Anti-Amplification: Enable Retry

`quic_retry on` instructs NGINX to issue a Retry packet for every new connection, requiring the client to prove address ownership before the server commits resources. This closes the amplification vector at the cost of one extra round trip on first connection. For public-facing edges, always on.

```nginx
quic_retry on;
```

Combine with a connection-rate limit at the UDP level via nftables:

```bash
# /etc/nftables.conf
table inet quic_ratelimit {
    chain input {
        type filter hook input priority 0; policy accept;
        udp dport 443 meter quic-rate { ip saddr limit rate 300/second burst 50 packets } accept
        udp dport 443 drop
    }
}
```

This caps Initial-packet floods to 300/second per source IP. Legitimate QUIC clients do not need more than a handful of Initial packets per second to establish connections.

### 0-RTT: Enable Only for Idempotent Endpoints

0-RTT data in QUIC inherits TLS 1.3's replay risk. Any request the server performs based on 0-RTT data could be replayed by a passive observer. The safe rule: enable 0-RTT only for requests the application already treats as idempotent.

In NGINX:

```nginx
# Server-wide default: disabled.
ssl_early_data off;

# Per-location: allow 0-RTT only where safe.
location / {
    # Dynamic, non-idempotent: stays disabled.
}
location /static/ {
    ssl_early_data on;
}
location ~* \.(jpg|png|css|js|woff2)$ {
    ssl_early_data on;
}
```

For endpoints that accept 0-RTT, enforce the HTTP `Early-Data: 1` header check in application code. If the backend processes a 0-RTT request, it must verify that it is idempotent:

```python
# Python backend example.
@app.before_request
def reject_non_idempotent_early_data():
    if request.headers.get("Early-Data") == "1":
        if request.method not in ("GET", "HEAD"):
            abort(425, "Too Early: non-idempotent method")
```

### Connection ID Rotation

QUIC supports connection ID rotation via the `NEW_CONNECTION_ID` frame. The server issues a pool of connection IDs; the client switches to a new one after NAT rebinding, path migration, or periodically for privacy.

NGINX configuration (requires nginx 1.25.3+):

```nginx
# Number of unused connection IDs the server keeps available.
http3_hq off;
http3_max_table_capacity 4096;
```

For Envoy:

```yaml
quic_protocol_options:
  max_concurrent_streams: 100
  initial_stream_window_size: 65536
  initial_connection_window_size: 524288
connection_id_generator_config:
  name: envoy.quic.deterministic_connection_id_generator
```

Default NGINX will issue a modest pool of connection IDs. For stricter client-side unlinkability, the client must rotate aggressively. Server-side, the main hygiene is:

- Do not log connection IDs to any long-term store (they become tracking identifiers).
- Ensure connection ID regeneration key (used for address-validation tokens) rotates per server instance and never ships in a config file.

### Flow-Control Defaults

QUIC flow control has both per-connection and per-stream windows. Oversized windows let a misbehaving client pin a large amount of kernel/userspace memory on the server.

```nginx
# Per-connection and per-stream flow control.
http3_stream_buffer_size 64k;     # Per-stream buffer default.
http3_max_concurrent_streams 128; # Cap on simultaneous streams per connection.

# Connection-level caps.
client_body_buffer_size 128k;
client_max_body_size 10m;
```

For Envoy:

```yaml
quic_protocol_options:
  max_concurrent_streams: 100
  initial_stream_window_size: 65536
  initial_connection_window_size: 524288
```

Rationale: `initial_stream_window_size: 65536` (64 KB) means a new stream can have at most 64 KB in-flight before the server sends a `MAX_STREAM_DATA` to grant more. `initial_connection_window_size: 524288` (512 KB) caps total in-flight across all streams. Together this bounds the per-connection buffer footprint to under 1 MB even with 100 concurrent streams.

### Stateless Reset Key Management

The QUIC stateless reset key derives per-connection reset tokens. Any holder of the key can craft reset packets for any connection. Protect it like a TLS private key.

NGINX does not expose this key directly; it is generated internally per process. The hardening implication: do not share process memory images (core dumps, debug snapshots) externally. Disable core dumps for the NGINX worker:

```nginx
worker_rlimit_core 0;
```

For load-balanced QUIC clusters, the reset key must be consistent across instances (so that resets work across connection migration). Distribute via a secret store, not a config file:

```bash
# systemd drop-in that injects the key as an environment variable.
# /etc/systemd/system/nginx.service.d/quic-reset.conf
[Service]
LoadCredential=quic-reset-key:/run/secrets/nginx-quic-reset-key
```

Rotate the key on a schedule (weekly) and when any operator with access leaves.

### UDP-Layer Mitigations

Firewalls must allow UDP port 443, but that opens the door to every UDP-based attack. Apply source-address validation and rate limiting at the network edge:

```bash
# nftables: drop UDP fragments destined for :443.
nft add rule inet filter input ip frag-off != 0 udp dport 443 drop

# Limit per-source UDP:443 packet rate.
nft add rule inet filter input udp dport 443 \
  meter quic_per_src { ip saddr limit rate 500/second burst 100 packets } accept
nft add rule inet filter input udp dport 443 drop
```

For cloud-hosted edges, use provider-level rate limiting (AWS Shield Advanced, Cloudflare Spectrum, GCP Cloud Armor).

## Expected Behaviour

| Signal | Default | Hardened |
|--------|---------|----------|
| Amplification factor (server response / client Initial) | Up to 10x without Retry | Bounded to 3x via RFC 9000 limits; Retry reduces to 1:1 |
| 0-RTT replay window | All endpoints replayable | Only idempotent endpoints eligible; non-idempotent methods rejected |
| Connection ID pool | Default 3-5 | Rotates on NAT rebinding; no connection ID persisted to logs |
| Per-connection memory ceiling | Unbounded (can reach hundreds of MB) | ~1 MB per connection |
| UDP flood resistance | None | 500 pps/src at network edge; 300 Initials/s via rate meter |
| Reset key exposure | In-memory only | Loaded via systemd credentials, no logs, no core dumps |

Verify behavior with `curl` and `wireshark`:

```bash
# Confirm HTTP/3 works.
curl --http3 -I https://app.example.com
# HTTP/3 200

# Confirm 0-RTT disabled on dynamic endpoints.
curl --http3 --tls-max 1.3 -H "Early-Data: 1" -X POST https://app.example.com/api/transfer
# HTTP/3 425 Too Early

# Confirm Retry is required (extra RTT on first connection).
curl --http3 -v https://app.example.com/ 2>&1 | grep -i retry
```

## Trade-offs

| Control | Security Benefit | Cost | Mitigation |
|---------|------------------|------|------------|
| `quic_retry on` | Prevents reflection amplification | Extra RTT on every new connection (+50-200 ms first-byte for long-distance clients) | Keep Retry on for public endpoints. Disable only for trusted internal clients where spoofing is infeasible. |
| 0-RTT disabled by default | Eliminates replay risk for most endpoints | Lose the performance benefit (no first-request 0-RTT for interactive flows) | Enable per-location for known-idempotent assets. Static content benefits most; dynamic rarely does. |
| Strict flow-control windows | Bounds per-connection memory | Large downloads may see slight throughput reduction (more `MAX_*` frames on the wire) | Raise `initial_stream_window_size` for download-heavy endpoints; keep API endpoints tight. |
| Connection ID rotation | Breaks on-path tracking | Client must track multiple IDs, modest CPU increase | Always enable; the overhead is well under 1%. |
| UDP rate limiting at the firewall | First-line DDoS mitigation | Risk of blocking legitimate clients behind CGNAT (shared IP, high packet rate) | Tune the limits based on your traffic. Start at 500 pps; measure legitimate p95 packet rates per source and adjust. |
| Disable core dumps | Prevents reset-key disclosure via crashes | Debugging harder in production | Enable core dumps only in staging. For production, rely on structured logs + opentelemetry for post-mortem visibility. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Firewall drops UDP fragments | HTTP/3 connections fail on large certificate chains | Browser falls back to HTTP/2; QUIC metrics show low connection success rate | Enable IP fragmentation reassembly on the firewall, or raise the MTU. Consider serving short certificate chains (skip intermediates with AIA). |
| 0-RTT enabled accidentally on POST endpoint | Transaction executes twice on replay | Application logs show duplicate requests within ms; user complaints about double-charges | Disable `ssl_early_data` server-wide; enable per-location only after code review confirms idempotency. |
| Connection ID leak via log ingestion | Privacy-sensitive request flows correlate across sessions | Log analysis reveals the same CID across different client IPs over weeks | Scrub CIDs from all logs. Use request IDs for correlation, not transport-level identifiers. |
| Reset-key compromise | Attacker injects stateless reset packets, dropping connections at will | Anomalous per-second connection terminations; users report abrupt disconnects | Rotate key across all instances. Investigate key-exposure vector (shared filesystem, accidental commit, log redaction gap). |
| Flow-control window too small | Legitimate downloads slow down visibly | Throughput metrics drop for file-download endpoints; user-facing reports of slow large responses | Raise `initial_stream_window_size` for the affected location. Keep API endpoints at the stricter default. |
| NGINX worker OOM from stream explosion | Worker process restarts; connections drop | `nginx: worker process (\d+) exited on signal 9`; kernel OOM killer log | Lower `http3_max_concurrent_streams`. Per-connection memory should stay predictable after this. |
| UDP rate limit drops legitimate traffic | Users behind shared NAT report connection failures | Support tickets from specific ISPs; packet drop counters spike for a particular CIDR | Allowlist known CGNAT ranges; use connection-tracking-based rate limiting rather than per-src-IP. |

## When to Consider a Managed Alternative

Running HTTP/3 on self-hosted edges requires NGINX/Envoy compile options, nftables rules, UDP firewall tuning, DDoS visibility, and ongoing patching of QUIC-layer CVEs (6-12 hours/month for a multi-region deployment).

- **[Cloudflare](https://cloudflare.com):** HTTP/3 and QUIC are on by default. Amplification, reset-key, and rate limiting handled at their global edge. Origin can remain HTTP/1.1 or HTTP/2.
- **[AWS CloudFront](https://aws.amazon.com/cloudfront/):** supports HTTP/3 with Shield Advanced for DDoS. 0-RTT opt-in per behavior.
- **[Fastly](https://fastly.com) and [Google Cloud CDN](https://cloud.google.com/cdn):** similar managed HTTP/3 termination with built-in DDoS controls.

## Related Articles

- [TLS 1.3 on NGINX and Envoy: Secure Defaults and Cipher Selection](/articles/network/tls-nginx-envoy/)
- [Beyond TLS: Hardening NGINX for Production Traffic](/articles/network/nginx-hardening-beyond-tls/)
- [DDoS Defense at Mega-Scale](/articles/network/ddos-megascale-defence/)
- [HTTP Security Headers That Actually Work](/articles/network/http-security-headers/)
- [Rate Limiting at the Ingress Layer](/articles/network/rate-limiting-ingress/)
