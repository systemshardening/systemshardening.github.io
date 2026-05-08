---
title: "MASQUE and CONNECT-UDP Proxy Security Hardening"
description: "Production hardening for MASQUE / CONNECT-UDP (RFC 9298) proxies: authentication, egress policy, abuse detection, and operational pitfalls."
slug: "masque-connect-udp-proxy-security"
date: 2026-05-08
lastmod: 2026-05-08
category: "network"
tags: ["masque", "connect-udp", "http3", "quic", "proxy", "egress"]
personas: ["security-engineer", "network-engineer", "platform-engineer"]
article_number: 651
difficulty: "advanced"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/network/masque-connect-udp-proxy-security/index.html"
---

# MASQUE and CONNECT-UDP Proxy Security Hardening

## Problem

MASQUE (Multiplexed Application Substrate over QUIC Encryption) is the IETF's HTTP/3-native proxy framework. Two RFCs anchor its 2026 deployment: **RFC 9298** (CONNECT-UDP), which lets a client tunnel arbitrary UDP datagrams over an HTTP/3 stream, and **RFC 9484** (CONNECT-IP), which tunnels full IP packets. CONNECT-UDP shipped in Apple Private Relay, Google's One VPN, and Cloudflare's WARP-as-a-service offerings. In 2026 it is appearing in enterprise gateways (Zscaler, Netskope, Cloudflare Gateway) as the recommended replacement for traditional HTTP/HTTPS forward proxies because it carries encrypted DNS (DoH3), QUIC, and UDP-based application protocols cleanly.

The novelty is the security model. A traditional HTTP CONNECT proxy gives the operator a TCP socket to a named host:port — there is exactly one transport, one address tuple, and one policy decision per session. CONNECT-UDP gives the operator a *bidirectional UDP datagram pipe*: every datagram is independent, source IP is the proxy's, and the only HTTP-layer signal is the target host:port that established the tunnel. The proxy cannot inspect the inner protocol (QUIC is encrypted), cannot rate-limit per-flow without explicit hooks, and cannot terminate cleanly on policy violation without breaking the QUIC connection from outside.

This produces several concrete risks that operators repeatedly miss. CONNECT-UDP tunnels turn into anonymising relays unless egress allowlists are enforced at the proxy. Tenant identification has to be done at the HTTP/3 layer (token, mTLS, SCRAM) because the inner UDP flow has no identity. Datagram payload inspection is impossible by design — that is the point — so detection must use shape-of-traffic signals. And the asymmetric receive path means standard NAT/firewall conntrack does not naturally clean up — long-idle CONNECT-UDP capsules can pin state for hours.

In 2025 a class of abuse emerged: CONNECT-UDP proxies operated by SaaS vendors with permissive defaults were used to relay outbound DDoS traffic and to tunnel C2 over what looked from the outside like benign HTTP/3 to the SaaS endpoint. Network forensics teams chasing these flows found themselves with an encrypted blob to a CDN and no inner visibility.

Target systems: nginx ≥ 1.27 (with `http_v3_module` + MASQUE patches), Envoy ≥ 1.32 (native MASQUE filter), HAProxy ≥ 3.1 (MASQUE in experimental), Caddy ≥ 2.9, and Cloudflare's `quiche-server` reference implementation.

## Threat Model

1. **Abusive client using the proxy as an anonymiser.** Goal: relay attack traffic so origin sees the proxy's IP. Surface: missing or coarse egress allowlist; absent per-tenant rate limits.
2. **Compromised internal client tunnelling C2.** Goal: blend with legitimate HTTP/3 to a popular SaaS endpoint. Surface: lack of inner-flow shape analysis; no DNS allowlist on `Host:` header for CONNECT requests.
3. **Resource-exhaustion attacker pinning datagram state.** Goal: open millions of idle CONNECT-UDP tunnels, exhaust server FDs and conntrack. Surface: no per-tenant tunnel cap; no idle-tunnel reaper.
4. **Operator with packet-capture access on the wire.** Goal: extract tenant identity. Surface: HTTP/3 0-RTT bypassing TLS-layer auth; missing TLS 1.3 hybrid PQ key exchange.

Without hardening, a permissively configured MASQUE proxy is a DDoS reflector, a covert channel, and a privacy regression simultaneously. With per-tenant authentication, egress allowlists, datagram-rate limits, and an idle reaper, the same proxy becomes a tractable enterprise egress tool.

## Configuration / Implementation

### Step 1 — Enforce HTTP/3-layer authentication on tunnel establishment

CONNECT-UDP requests look like this:

```
:method = CONNECT
:protocol = connect-udp
:scheme = https
:path = /.well-known/masque/udp/example.com/443/
:authority = proxy.example.net
authorization = Bearer <tenant-token>
```

The proxy MUST require `Authorization` (or mTLS) before accepting `:method=CONNECT :protocol=connect-udp`. Envoy:

```yaml
filter_chains:
- filters:
  - name: envoy.filters.network.http_connection_manager
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
      codec_type: HTTP3
      upgrade_configs:
      - upgrade_type: connect-udp
      http_filters:
      - name: envoy.filters.http.jwt_authn
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
          providers:
            tenant-issuer:
              issuer: https://idp.example.net/
              audiences: ["masque-proxy"]
              remote_jwks:
                http_uri:
                  uri: https://idp.example.net/.well-known/jwks.json
                  cluster: idp
                  timeout: 2s
              forward_payload_header: x-tenant
          rules:
          - match: { connect_matcher: {} }
            requires: { provider_name: tenant-issuer }
      - name: envoy.filters.http.connect_grpc_bridge
      - name: envoy.filters.http.router
```

`forward_payload_header: x-tenant` exposes the tenant identity for downstream policy and logging — without it the rest of the pipeline sees only "the proxy".

### Step 2 — Egress allowlist on the CONNECT target

The `:path` segment after `/.well-known/masque/udp/` is `<host>/<port>/`. Inspect both:

```yaml
route_config:
  virtual_hosts:
  - name: masque
    domains: ["proxy.example.net"]
    routes:
    - match:
        connect_matcher: {}
        path_separated_prefix: "/.well-known/masque/udp/"
      route:
        cluster: udp_egress
        upgrade_configs:
        - upgrade_type: connect-udp
          connect_config: {}
      typed_per_filter_config:
        envoy.filters.http.lua:
          "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.LuaPerRoute
          source_code:
            inline_string: |
              function envoy_on_request(handle)
                local path = handle:headers():get(":path")
                local host, port = path:match("/.well-known/masque/udp/([^/]+)/([0-9]+)/")
                if not host then handle:respond({[":status"] = "400"}, "bad path") end
                if not is_allowed(host, port) then
                  handle:respond({[":status"] = "403"}, "egress denied")
                end
              end
```

Maintain `is_allowed` from a denylist of cloud-metadata IPs (169.254.169.254, fd00:ec2::254), RFC1918 ranges, link-local, and a positive allowlist of FQDNs the tenant has registered in advance. Resolve `host` to IP at the proxy (not at the client) and re-check the resolved address — clients can otherwise bypass FQDN allowlists by pointing DNS at a private IP.

### Step 3 — Per-tenant tunnel and datagram rate limiting

CONNECT-UDP datagrams arrive as HTTP/3 capsules; rate-limit at two levels:

```yaml
# Envoy local rate limiter on capsule count
- name: envoy.filters.http.local_ratelimit
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
    stat_prefix: masque_capsules
    token_bucket:
      max_tokens: 1000
      tokens_per_fill: 1000
      fill_interval: 1s
    descriptors:
    - entries: [{ key: tenant, value: "%REQ(x-tenant)%" }]
      token_bucket: { max_tokens: 50000, tokens_per_fill: 50000, fill_interval: 1s }
```

And cap concurrent tunnels per tenant:

```yaml
- name: envoy.filters.http.connect_grpc_bridge
- name: envoy.filters.http.admission_control
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.admission_control.v3.AdmissionControl
    enabled: { default_value: { numerator: 100 } }
    sampling_window: 60s
    aggression: "1.5"
```

A reasonable default: 50 concurrent tunnels per tenant, 50k datagrams/sec, 100Mbit/s sustained.

### Step 4 — Idle-tunnel reaper

CONNECT-UDP tunnels do not naturally close — they idle. Set an aggressive idle timeout:

```yaml
common_http_protocol_options:
  idle_timeout: 30s
  max_stream_duration: 3600s
```

`idle_timeout: 30s` means tunnels with no datagrams in either direction get closed; the client must re-establish, which forces a fresh authentication and policy re-evaluation. `max_stream_duration` caps any single tunnel at one hour regardless of activity — a forced re-auth that prevents long-running covert channels.

### Step 5 — Wire-level shape detection

You cannot inspect the inner flow, but you can record and alert on shape signals. Stream to a SIEM:

```yaml
access_log:
- name: envoy.access_loggers.file
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
    path: /var/log/envoy/masque.log
    log_format:
      json_format:
        ts: "%START_TIME%"
        tenant: "%REQ(x-tenant)%"
        target: "%REQ(:path)%"
        target_ip: "%UPSTREAM_REMOTE_ADDRESS%"
        capsules_up: "%BYTES_SENT%"
        capsules_down: "%BYTES_RECEIVED%"
        duration_ms: "%DURATION%"
        close_reason: "%RESPONSE_FLAGS%"
```

Detection rules to add to your SIEM:

- Tenant exceeding 10× their 30-day p95 datagram rate.
- Tunnel with downstream:upstream byte ratio > 100 (sign of reflection).
- Tunnel target resolved to a private IP (allowlist bypass attempt).
- Unauthenticated CONNECT-UDP requests > 100/min from a single source IP (token-stuffing).

### Step 6 — Use TLS 1.3 with hybrid PQ key exchange

QUIC's TLS 1.3 handshake is the moment the tenant token is sent. Enable hybrid PQ now:

```nginx
ssl_protocols TLSv1.3;
ssl_conf_command Groups X25519MLKEM768:X25519:P-256;
ssl_early_data off;   # disable 0-RTT to avoid replay of CONNECT
```

`ssl_early_data off` is critical: an attacker who replays a 0-RTT CONNECT-UDP request with a captured token can establish a tunnel without a fresh handshake.

### Step 7 — Disable CONNECT-IP unless explicitly needed

CONNECT-IP (RFC 9484) is significantly more dangerous than CONNECT-UDP — it tunnels full IP packets and can carry source-spoofed traffic. Most enterprise use cases need only CONNECT-UDP:

```yaml
upgrade_configs:
- upgrade_type: connect-udp
# DO NOT add: connect-ip
```

## Expected Behaviour

| Signal | Before hardening | After hardening |
|--------|------------------|-----------------|
| Unauthenticated CONNECT-UDP | 200 + tunnel established | 401 |
| CONNECT-UDP to 169.254.169.254 | Tunnel to metadata service | 403 |
| Tunnel idle 5 minutes | Still open | Closed at 30s idle |
| Tenant datagram burst 100k/s | Accepted | Rate-limited at 50k/s |
| 0-RTT replay of captured CONNECT | New tunnel | Rejected (0-RTT disabled) |
| Audit log of tunnel | Generic HTTP/3 line | JSON with tenant, target, byte counts, duration |

```bash
# Functional test (with masque-cli or a custom curl build).
masque-cli --proxy https://proxy.example.net \
  --token $(cat tenant.jwt) \
  --target example.com:443 \
  -- send-udp "test"
# expect: tunnel established, target reached

# Negative test: metadata IP must fail.
masque-cli --proxy https://proxy.example.net \
  --token $(cat tenant.jwt) --target 169.254.169.254:80 -- send-udp "x"
# expect: 403 egress denied
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| 30s idle timeout | Forces re-auth, prevents covert long sessions | Mobile clients reconnect frequently on flaky links | Tune to 60s for mobile-first deployments; client should support resumption |
| Strict egress allowlist | Eliminates anonymisation abuse | Tenant onboarding burden — every new endpoint needs registration | Self-service portal with security-team review for sensitive destinations |
| Hybrid PQ KEX | Long-term confidentiality of tenant tokens | Larger handshake, ~600 bytes overhead | Negligible for sub-1s sessions; relevant for long tunnels |
| Disabling 0-RTT | Closes replay window | Higher first-byte latency | Most enterprise traffic tolerates ~50ms extra; reserve 0-RTT for non-CONNECT routes only |
| Per-tenant rate caps | Stops single tenant from causing bandwidth contention | Legitimate batch transfer hits limits | Higher cap with rate-limit alert rather than hard cap; bursting credits |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| FQDN allowlist resolves to wrong IP at proxy | Legit tenant blocked, forensic confusion | Tenant-side error rate spike on specific FQDN | Cache resolutions with short TTL; alert on resolution flips |
| JWT validation latency on cold cache | Initial CONNECT slow, tenant retry storm | p99 connect-time alarm | Pre-warm JWKS cache; bump cache TTL to 1h with revocation check |
| Lua filter exception on malformed path | 5xx instead of 4xx; log noise | Envoy stats `lua.errors_total` rising | Add explicit nil-check; fail closed via `respond` not `nil` return |
| Idle reaper too aggressive, breaks WebRTC | Calls drop at exactly 30s | Tenant complaint; correlate with reaper events | Per-tenant idle override for known WebRTC apps; default for others |
| Datagram rate limiter clobbers QUIC ACKs | Mysterious connection stalls | Inner-flow MTR shows ACK loss | Apply rate limit on bytes not packets; or exempt small (<128B) capsules |

## When to Consider a Managed Alternative

- Cloudflare Gateway, Zscaler ZIA, and Netskope offer managed MASQUE egress with built-in tenant policy, allowlisting, and abuse detection — saner than self-hosting if your egress policy is mostly tenant-scoped SaaS access.
- For private-network access, a managed Zero Trust offering (Cloudflare Access, Tailscale, Twingate) typically ships safer defaults than a self-built CONNECT-IP setup.

## Related Articles

- [HTTP/3 and QUIC Hardening](/articles/network/http3-quic-hardening/)
- [Encrypted Client Hello](/articles/network/encrypted-client-hello/)
- [TLS Post-Quantum Hybrid Deployment](/articles/network/tls-post-quantum-hybrid-deployment/)
- [Zero Trust Network Access](/articles/network/zero-trust-network-access/)
- [API Gateway Security](/articles/network/api-gateway-security/)
