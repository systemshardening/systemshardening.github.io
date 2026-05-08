---
title: "HAProxy Production Hardening: Beyond TLS, Request Filtering, ACLs, and Logging Hygiene"
description: "HAProxy's defaults are friendly to misconfiguration. The right knobs make it fast, observable, and resistant to common L7 abuse."
slug: "haproxy-hardening"
date: 2026-04-29
lastmod: 2026-04-29
category: "network"
tags: ["haproxy", "tls", "load-balancer", "acl", "network-security"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 220
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/network/haproxy-hardening/index.html"
---

# HAProxy Production Hardening: Beyond TLS, Request Filtering, ACLs, and Logging Hygiene

## Problem

HAProxy is the workhorse load balancer for many large internet properties — Stack Overflow, Reddit, Airbnb, Vimeo. Its design favors raw performance and predictability, with sane TCP and HTTP behavior. The defaults are reasonable for performance; they aren't security-tight.

A default HAProxy configuration sits between users and your application accepting any request shape, forwarding any header, no rate limit, no body-size cap, no logging redaction. Every problem common to web load balancers — header smuggling, slowloris, request bodies sized to exhaust backend memory, stack-trace leakage, unbounded keepalive — applies.

By 2026 HAProxy 3.0+ is the supported branch; HAProxy 2.8+ in many production deployments. The hardening surface includes:

- TLS configuration (covered in [TLS 1.3 on NGINX and Envoy](/articles/network/tls-nginx-envoy/)).
- Request size limits (`http-request deny if { req.body_size,header gt 1048576 }`).
- Header sanitization (drop spoofed `X-Forwarded-*`).
- ACLs for path / IP / header allowlisting.
- Rate limiting via stick-tables.
- Connection lifecycle controls (timeout, keepalive limits).
- Logging that doesn't capture credentials.

The specific gaps in default HAProxy:

- `default-server` accepts any backend response; no per-backend hardening.
- Inbound `X-Forwarded-For` from clients is propagated; spoofs the client IP at the backend.
- No per-IP request rate limit by default.
- HTTP/2 `max_concurrent_streams` defaults are loose.
- Logs include full request URLs and headers; auth tokens leak.
- Stick tables for tracking unbounded; memory usage scales with attacker patience.

This article covers the configuration block-by-block: TLS, frontend, backend, ACLs, rate limiting via stick tables, log scrubbing, and the operational telemetry. Examples are config snippets you can paste into `haproxy.cfg`.

**Target systems:** HAProxy 2.8+ (long-term), 3.0+ (current), with HAProxy Enterprise providing additional features for compliance-regulated environments.

## Threat Model

- **Adversary 1 — Header smuggler:** crafted requests where HAProxy and the backend disagree on header parsing or boundaries; result is HTTP request smuggling.
- **Adversary 2 — Slow-rate attacker:** sends a request very slowly, holding a connection open and consuming HAProxy worker capacity.
- **Adversary 3 — Spoofed client IP:** sends `X-Forwarded-For: 127.0.0.1` hoping the backend trusts it as internal.
- **Adversary 4 — Body-size attacker:** sends large request bodies to exhaust HAProxy or backend memory.
- **Adversary 5 — Log harvester:** an insider with log-read access reads cleartext credentials passed in URLs or headers.
- **Access level:** Adversaries 1-4 have only HTTP-request capability. Adversary 5 has internal log access.
- **Objective:** Bypass authentication; consume resources; impersonate; harvest secrets from logs.
- **Blast radius:** Without hardening, a single attacker can saturate frontends or smuggle past the backend's authorization check. With hardening, requests are bounded, headers sanitized, IPs honest.

## Configuration

### Step 1: Global and Defaults

```haproxy
global
    log stdout format raw daemon
    maxconn 50000
    nbthread 8
    cpu-map auto:1/1-8 0-7
    user haproxy
    group haproxy
    chroot /var/empty/haproxy
    daemon

    # Modern TLS only.
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
    ssl-default-bind-curves X25519MLKEM768:X25519:secp384r1
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11 no-tlsv12 no-tls-tickets

    # CORS preflight handled at HAProxy.
    tune.bufsize 32768
    tune.h2.max-concurrent-streams 32

defaults
    log global
    mode http
    option httplog
    option dontlognull
    option http-server-close
    option redispatch
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    timeout http-request 10s
    timeout http-keep-alive 5s
    timeout queue 30s
    retries 3
    maxconn 30000

    # Block request bodies > 1MB by default.
    http-request deny if { req.body_size gt 1048576 }
```

Notes:

- `chroot /var/empty/haproxy` runs HAProxy in a chroot; a process compromise reaches a near-empty filesystem.
- `tune.h2.max-concurrent-streams 32` mitigates the HTTP/2 RST flood class (covered in [HTTP/2 RST and CONTINUATION Flood Mitigation](/articles/network/http2-flood-mitigation/)).
- Modern TLS-only: TLS 1.3, ChaCha20 + AES-GCM ciphers, X25519MLKEM768 hybrid post-quantum group.
- 5s `timeout http-request` defeats slowloris; the connection is killed if the request line + headers don't arrive in 5 seconds.

### Step 2: Frontend Configuration

```haproxy
frontend public-https
    bind :443 ssl crt /etc/haproxy/certs/wildcard.example.com.pem alpn h2,http/1.1
    bind :443 quic ssl crt /etc/haproxy/certs/wildcard.example.com.pem alpn h3   # HTTP/3

    # HSTS header.
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"
    http-response set-header Permissions-Policy "interest-cohort=()"

    # Strip incoming X-Forwarded-* (we'll set them ourselves).
    http-request del-header X-Forwarded-For
    http-request del-header X-Forwarded-Proto
    http-request del-header X-Real-IP
    http-request del-header X-Original-URL
    http-request del-header X-Original-Forwarded-For

    # Set our own.
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host %[req.hdr(host)]
    http-request set-header X-Real-IP %[src]

    # ACLs.
    acl is_api path_beg /api/
    acl is_admin path_beg /admin/
    acl bad_user_agent hdr_sub(user-agent) -i nikto sqlmap nessus burp

    # Block bad user agents.
    http-request deny if bad_user_agent

    # Admin panel only from internal CIDRs.
    acl internal src 10.0.0.0/8 192.168.0.0/16
    http-request deny if is_admin !internal

    # Routing.
    use_backend api-backend if is_api
    default_backend web-backend
```

Two critical patterns:

- **Strip then set X-Forwarded-* headers.** A client cannot inject a fake client IP; HAProxy is the authority.
- **ACL-based path routing.** The admin path returns a 403 unless the source is internal. Defense in depth — even if the application's auth is bypassed, the network ACL blocks.

### Step 3: Stick Tables for Rate Limiting

HAProxy's stick tables track per-key state in memory.

```haproxy
backend per-ip-counter
    stick-table type ipv6 size 1m expire 30s store http_req_rate(10s),http_err_rate(10s),conn_cur

frontend public-https
    # ... (as above) ...

    # Track every connection by source IP.
    http-request track-sc0 src table per-ip-counter
    http-request set-var(req.req_rate) sc0_http_req_rate(per-ip-counter)
    http-request set-var(req.err_rate) sc0_http_err_rate(per-ip-counter)

    # 100 req/s per IP triggers 429.
    http-request deny deny_status 429 if { sc0_http_req_rate(per-ip-counter) gt 100 }

    # 30 errors/10s suggests scanning; tarpit.
    http-request tarpit if { sc0_http_err_rate(per-ip-counter) gt 30 }
```

The stick table holds 1 million IPs for 30 seconds. Memory: ~256 MB for 1M entries. Per-IP request rate and error rate are tracked; thresholds trigger 429 (rate-limit) or tarpit (slow response, holds the attacker for a configurable time).

### Step 4: Log Scrubbing

The default `httplog` format includes the request URL with query string. Auth tokens, session IDs, and other secrets show up in logs.

```haproxy
defaults
    log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"

    # Custom log format that strips query strings.
    log-format "%ci:%cp [%tr] %ft %b/%s %ST %B %TR/%Ta \"%[capture.req.method] %[path]\" \"%[capture.req.hdr(0)]\""

    # Capture only specific headers; never Authorization or Cookie.
    capture request header Host len 64
    capture request header User-Agent len 128
    capture request header X-Trace-ID len 64
    # (Authorization, Cookie deliberately not captured.)
```

The log line includes path-only (no query string), host, user-agent, trace ID — never auth headers.

For HTTP request bodies (logged for debugging), apply `http-request set-var` with explicit redaction:

```haproxy
http-request set-var(txn.body_redacted) req.body,regsub('"password":"[^"]*"','"password":"REDACTED"')
http-request set-var(txn.body_redacted) var(txn.body_redacted),regsub('"token":"[^"]*"','"token":"REDACTED"')
# (rare in production logs but useful for auth-failed-with-context cases)
```

### Step 5: Backend Hardening

```haproxy
backend web-backend
    balance roundrobin
    option httpchk GET /healthz
    http-check expect status 200

    # Backends connect with TLS verification.
    default-server ssl verify required ca-file /etc/haproxy/certs/internal-ca.pem inter 5s rise 2 fall 3

    server web1 10.0.1.10:443 check
    server web2 10.0.1.11:443 check
    server web3 10.0.1.12:443 check

    # Reject backend responses that are too large (DoS via backend amplification).
    http-response deny if { res.body_size gt 10485760 }

    # Set Server header to a generic value.
    http-response set-header Server "haproxy"
    http-response del-header X-Powered-By
    http-response del-header X-AspNet-Version
```

Notes:

- `ssl verify required` enforces TLS to the backend with mutual auth via `ca-file`. A compromised network peer cannot impersonate the backend.
- Response size cap (`res.body_size gt 10485760`) prevents a malicious or buggy backend from sending unbounded bytes through the proxy.
- Strip identifying headers (`X-Powered-By`, `X-AspNet-Version`) from responses.

### Step 6: HTTP Request Smuggling Mitigation

The Pearl-Necklace request-smuggling class (CL.TE / TE.CL discrepancies) is mitigated by strict header parsing.

```haproxy
defaults
    option http-buffer-request   # buffer the full request before forwarding
    option http-pretend-keepalive    # avoid edge cases with keepalive
    http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
    http-request deny if { req.hdr_cnt(content-length) gt 1 }
    http-request deny if { req.hdr(transfer-encoding) -m sub chunked }
    http-request deny if { req.hdr(content-length) -m reg "[^0-9]" }
```

Reject requests with multiple `Transfer-Encoding` or `Content-Length` headers; reject malformed `Content-Length`. HAProxy 3.0+ does most of this by default; verify with `haproxy -c -f /etc/haproxy/haproxy.cfg`.

### Step 7: Telemetry

HAProxy exposes Prometheus-format metrics on a stats socket:

```haproxy
frontend stats
    bind 127.0.0.1:8404
    no log
    stats enable
    stats uri /
    stats refresh 10s
    http-request use-service prometheus-exporter if { path /metrics }
```

Key metrics:

```
haproxy_frontend_http_requests_total{frontend, code}
haproxy_frontend_http_responses_total{frontend, code}
haproxy_backend_response_time_seconds{backend}
haproxy_stick_table_size{table, key_type}
haproxy_frontend_denied_req_total{frontend}
haproxy_server_check_failures_total{backend, server}
```

Alert on:
- `frontend_http_responses_total{code=~"5.."}` rising — backend failures.
- `denied_req_total` rising — possibly an attack.
- `server_check_failures_total` non-zero — backend health issue.

## Expected Behaviour

| Signal | Default HAProxy | Hardened |
|--------|------------------|------------|
| 100 MB request body | Buffered; possible OOM | 1MB cap; rejected |
| Spoofed `X-Forwarded-For: 127.0.0.1` | Forwarded to backend | Stripped at frontend |
| Slow-request attacker | Holds frontend connection | 5s timeout closes |
| HTTP/2 RST flood | Frontend saturates | Bounded by `max-concurrent-streams` |
| Auth header in URL | Logged in clear | Path-only logging |
| Backend response > 10 MB | Forwarded | Rejected |
| Bot User-Agent | Forwarded | 403 |

Verify the protections:

```bash
# Body size cap.
dd if=/dev/zero bs=1M count=2 | curl -X POST --data-binary @- https://example.com/api/upload
# 413 Request Entity Too Large

# Slowloris.
slowhttptest -c 1000 -X -r 200 -t HEAD -u https://example.com -p 3
# HAProxy closes connections at 5s; attacker can't accumulate.

# Spoofed header strip.
curl -H "X-Forwarded-For: 1.2.3.4" https://example.com/api/whoami
# Backend sees X-Forwarded-For: <real client IP>, not 1.2.3.4.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Body-size cap | Defeats memory exhaustion | Some upload-heavy endpoints need higher | Per-route cap via ACL: higher cap on `/upload`, default elsewhere. |
| Strip + reset X-Forwarded-* | Prevents IP spoofing | Multi-hop proxies need careful handling | Document the proxy chain; the outermost HAProxy is the authority. |
| Stick-table memory | Effective rate limiting | Memory usage grows with attacker IP diversity | Cap table size; LRU eviction. |
| `chroot` | Process compromise contained | Some plugins / extensions don't work in chroot | Common HAProxy plugins work; verify before deploying chroot. |
| TLS 1.3-only | Modern, fast, secure | Some old clients excluded | Acceptable for most production; offer TLS 1.2 only for explicit legacy paths. |
| Log path-only | Privacy + cleaner logs | Less debug detail | Keep separate higher-detail audit log on a more-restricted index. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Stick-table exhaustion | New IPs not tracked | `stick_table_size` near max | Increase `size`; LRU eviction is automatic but tight. |
| Backend cert chain change | Connections fail with verify error | `server_check_failures_total` rises after backend cert rotation | Update `ca-file`; verify backend chain is complete. |
| Path ACL too restrictive | Legitimate paths blocked | 4xx rate rises for specific path | Refine ACL pattern; test in staging. |
| TLS keypair mismatched | TLS handshake fails | TLS-handshake error metric | Verify `crt` file is the full chain + key concatenated. |
| Log format breaks parser | Centralized log ingest fails | SIEM stops receiving HAProxy logs | Test log-format change in staging; pin parser version. |
| HTTP smuggling rule too strict | Legitimate clients sending CL+TE blocked | Specific client behavior breaks | Some legacy clients send both; investigate; either fix client or whitelist. |
| `chroot` breaks reload | Master process can't restart | `systemctl restart haproxy` fails | Verify chroot-friendly config; test reload before deploy. |

## Related Articles

- [TLS 1.3 on NGINX and Envoy](/articles/network/tls-nginx-envoy/)
- [Beyond TLS: Hardening NGINX for Production Traffic](/articles/network/nginx-hardening-beyond-tls/)
- [HTTP/2 RST and CONTINUATION Flood Mitigation](/articles/network/http2-flood-mitigation/)
- [HTTP/3 and QUIC Production Hardening](/articles/network/http3-quic-hardening/)
- [Rate Limiting at the Ingress Layer](/articles/network/rate-limiting-ingress/)
