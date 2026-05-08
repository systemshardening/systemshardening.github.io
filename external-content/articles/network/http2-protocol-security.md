---
title: "HTTP/2 Protocol Security Hardening: Framing, HPACK, Stream Multiplexing, and Smuggling"
description: "HTTP/2 introduced multiplexing, header compression, and server push — each of which carries attack surface absent in HTTP/1.1. This guide covers protocol-level hardening across Nginx, HAProxy, and Envoy."
slug: http2-protocol-security
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - http2
  - protocol-security
  - hpack
  - stream-multiplexing
  - request-smuggling
personas:
  - security-engineer
  - platform-engineer
article_number: 511
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/http2-protocol-security/
---

# HTTP/2 Protocol Security Hardening: Framing, HPACK, Stream Multiplexing, and Smuggling

## The Problem

HTTP/2 (RFC 7540, succeeded by RFC 9113) solved real HTTP/1.1 bottlenecks: head-of-line blocking, connection overhead, and header verbosity. Multiplexed streams, binary framing, HPACK header compression, and server push collectively reduced page load times on high-latency connections. The same protocol features introduced attack surface that does not exist in HTTP/1.1.

The attack classes are distinct from volumetric DDoS (see [HTTP/2 RST and CONTINUATION Flood Mitigation](/articles/network/http2-flood-mitigation/)) and from gRPC-specific hardening (see [gRPC Security in Production](/articles/network/grpc-security/)). They are about the protocol mechanics themselves:

- **Stream multiplexing abuse**: the cost-asymmetry between opening streams and the server state required to track them.
- **HPACK state attacks**: the dynamic table shared across all streams on a connection that can be poisoned or exploded.
- **HTTP/2-to-HTTP/1.1 desync**: reverse proxies that accept HTTP/2 from clients but speak HTTP/1.1 to backends create request smuggling conditions that do not exist in pure HTTP/1.1 chains.
- **Server push**: deprecated in Chrome 106 (October 2022) and removed from HTTP/3, still enabled by default in many servers, adding attack surface with no practical benefit.

These problems require configuration changes across your ingress stack. This article covers Nginx 1.27+, HAProxy 3.0+, and Envoy 1.30+.

## HTTP/2 Framing: How the Binary Protocol Works

Understanding the attack surface requires understanding the framing layer. HTTP/2 sends everything as binary frames. Each frame carries a type (DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION), a stream identifier, and flags.

A stream lifecycle:
1. Client sends `HEADERS` frame with `END_HEADERS` flag set (or `END_HEADERS` clear, followed by `CONTINUATION` frames).
2. Server sends `HEADERS` (response headers) and `DATA` frames.
3. Either side sends `RST_STREAM` to cancel, or the stream ends with `END_STREAM` flag.

Stream identifiers are client-initiated odd numbers (1, 3, 5, …). The server can push resources using server-initiated even-numbered streams via `PUSH_PROMISE`. All streams share a single TCP connection and a single HPACK compression context.

The **connection preface** must begin with `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` followed by a `SETTINGS` frame. Servers that fail to enforce this allow cleartext HTTP/1.1 or malformed data to be parsed as HTTP/2, a desync vector in itself.

## CVE-2024-27316: CONTINUATION Flood

### How It Works

A `HEADERS` frame can carry the `END_HEADERS` flag indicating all headers fit in one frame. When they do not — or when an attacker deliberately omits the flag — the server must wait for `CONTINUATION` frames to complete the header block.

The CONTINUATION flood (CVE-2024-27316, disclosed April 2024) works as follows:
1. Client opens a stream, sends `HEADERS` with `END_HEADERS` clear.
2. Client sends `CONTINUATION` frames indefinitely, never setting `END_HEADERS`.
3. The server buffers every frame, accumulating the header block in memory.
4. With a single connection and a single stream, the server allocates memory proportional to the number of frames received.
5. With a short timeout or unlimited frame count, one connection can exhaust server memory or CPU.

The CPU exhaustion angle is significant: parsers that incrementally decompress HPACK during CONTINUATION processing pay CPU for every frame, not just at `END_HEADERS`. The attack-to-cost ratio was high in unpatched implementations.

**Affected versions at disclosure:**
- Apache HTTP Server < 2.4.59
- Nginx < 1.27.4 (CONTINUATION handling was patched in 1.27.0 with a limit on continuation frames)
- Node.js (multiple versions, patched April 2024)
- HAProxy < 3.0.2
- Envoy was not affected by the specific CONTINUATION buffering due to its reset-on-protocol-error design, but tuning still applies

**Mitigation at the configuration layer** (beyond patching):

```nginx
# nginx.conf
http {
    # Limit total header size across HEADERS + all CONTINUATION frames
    http2_max_header_size 16k;

    # Limit number of concurrent streams; reduces amplification factor
    http2_max_concurrent_streams 64;

    # Time allowed for a client to send initial request headers
    client_header_timeout 10s;
}
```

```haproxy
# haproxy.cfg
global
    # HPACK dynamic table size — smaller table = less memory per connection
    tune.h2.header-table-size 4096

    # Maximum number of simultaneous streams per HTTP/2 connection
    tune.h2.max-concurrent-streams 64

    # Maximum number of CONTINUATION frames before connection is closed
    # Available in HAProxy 2.9+ with the http2-max-continuation-frames tune
    tune.h2.max-continuation-frames 16
```

## HPACK Bomb: Header Compression State Attacks

### How HPACK Compression Works

HPACK (RFC 7541) uses two mechanisms to compress headers:
- **Static table**: 61 pre-defined header name/value pairs indexed as single bytes (`:method GET` = index 2).
- **Dynamic table**: a per-connection, per-direction table that stores recently sent headers and grows as new headers are added. Both client and server maintain synchronized copies.

A `HEADERS` frame can reference an entry in either table by index, or it can add a new entry to the dynamic table. The dynamic table is bounded by `SETTINGS_HEADER_TABLE_SIZE`, which the receiver sends to the peer to cap memory usage.

### The HPACK Bomb

A client can send a `SETTINGS_HEADER_TABLE_SIZE` of 0 in one direction, causing the server to reset its dynamic table. The client then sends `SETTINGS_HEADER_TABLE_SIZE` of 65536. The server's dynamic table is now 64KB. The client fills it with entries that each reference a very long value — or the client uses Huffman-encoded headers that expand to large values upon decompression.

The canonical HPACK bomb: a single compressed header block referencing dynamic table entries that expand to gigabytes upon decompression. The compression ratio with HPACK can exceed 1000:1 for repetitive headers. A 16KB `HEADERS` frame can decompose to over 16MB of header data.

**Mitigations:**

```nginx
# nginx.conf
http {
    # Cap the size of headers after decompression
    # This is the decompressed header list size limit
    http2_max_header_size 32k;

    # Limit total number of header fields (Nginx 1.25+)
    # Prevents a bomb composed of many small headers
    large_client_header_buffers 4 8k;
}
```

```yaml
# Envoy: HttpConnectionManager via xDS (YAML)
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
  http2_protocol_options:
    # Maximum decompressed size of all headers per request
    max_headers_count: 100
    # Maximum size of the header map (decompressed)
    # Maps to SETTINGS_MAX_HEADER_LIST_SIZE sent to peer
    max_request_headers_kb: 60
    # Limit HPACK dynamic table size sent to clients
    hpack_table_size: 4096
    initial_stream_window_size: 65536
    initial_connection_window_size: 1048576
```

```haproxy
# haproxy.cfg
global
    # Limit HPACK dynamic table to reduce decompression memory
    tune.h2.header-table-size 4096

frontend https_frontend
    bind :443 ssl crt /etc/ssl/certs/server.pem alpn h2,http/1.1

    # Cap the decompressed header size
    option http-buffer-request
    http-request deny if { req.hdrs_len gt 32768 }
```

## HTTP/2-to-HTTP/1.1 Request Smuggling

### H2.CL and H2.TE Desync

HTTP/1.1 uses `Content-Length` and `Transfer-Encoding: chunked` headers to delimit message bodies. Ambiguity between these two headers is the classic request smuggling condition (CL.TE and TE.CL, described in Portswigger research by James Kettle).

HTTP/2 is different: body length is determined by the DATA frame structure. The headers `Content-Length` and `Transfer-Encoding` are not used for HTTP/2 body framing. However, when a reverse proxy accepts HTTP/2 from a client and rewrites to HTTP/1.1 toward a backend — the common case for any proxy that does not support end-to-end HTTP/2 — the proxy must translate HTTP/2 framing into HTTP/1.1 body delimiters.

**H2.CL**: A client sends an HTTP/2 request with an explicit `content-length` header whose value does not match the actual body length. The HTTP/2 frontend uses DATA frame lengths (correct). The HTTP/1.1 backend uses `Content-Length` (incorrect). The backend reads more or fewer bytes than intended from the connection, interpreting the overflow as the start of a second request.

**H2.TE**: A client sends `transfer-encoding: chunked` inside an HTTP/2 request. HTTP/2 forbids `transfer-encoding` headers (RFC 9113 §8.2.2). A proxy that forwards this header verbatim to an HTTP/1.1 backend creates a TE.CL condition at the backend.

These vulnerabilities were documented extensively by Portswigger in 2021 and remain present in misconfigured stacks. Kettle's research showed that the most dangerous deployments are those where:
- The frontend terminates HTTP/2 and the backend only speaks HTTP/1.1.
- The frontend normalizes headers too permissively (allows `transfer-encoding` in HTTP/2).
- The backend's content-length parsing differs slightly from the frontend's.

**Mitigations:**

```nginx
# nginx.conf
# Nginx normalizes HTTP/2 headers to HTTP/1.1 before passing upstream.
# Enforce that it strips TE and rejects malformed content-length.
http {
    # Reject requests where Content-Length and body size mismatch
    # (Nginx rejects these by default in 1.21+, but make it explicit)
    proxy_request_buffering on;

    # Strip hop-by-hop and HTTP/2-forbidden headers before upstream
    proxy_set_header Transfer-Encoding "";
    proxy_set_header Connection "";

    # If your backend speaks HTTP/1.1, ensure keep-alive is managed properly
    proxy_http_version 1.1;
    proxy_set_header Connection "keep-alive";
}
```

```haproxy
# haproxy.cfg
frontend https_frontend
    bind :443 ssl crt /etc/ssl/certs/server.pem alpn h2,http/1.1

    # Reject requests with both content-length and transfer-encoding
    http-request deny if { req.hdr(transfer-encoding) -m found } { req.hdr(content-length) -m found }

    # Normalize transfer-encoding — reject chunked in HTTP/2 context
    # HAProxy 2.6+ enforces RFC 9113 §8.2.2 by default; verify your version
    option h2-invalid-header-reject

backend app_backend
    # When downgrading from HTTP/2 to HTTP/1.1, HAProxy rewrites framing
    # Ensure the backend does not see TE headers
    http-request del-header Transfer-Encoding
```

```yaml
# Envoy xDS: enforce strict HTTP/2 header validation
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
  http2_protocol_options:
    # Reject requests with Transfer-Encoding in HTTP/2 (RFC 9113 §8.2.2)
    allow_chunked_length: false
    # Override protocol options — do not normalize content-length ambiguities
  # For the upstream cluster, use HTTP/1.1 with strict chunked handling
  # in the cluster's upstream_http_protocol_options
```

For end-to-end HTTP/2 (h2c or h2 to the backend), smuggling via header translation is eliminated. If your backend supports HTTP/2, use it:

```nginx
# nginx.conf upstream block
upstream backend_app {
    server 127.0.0.1:8080;
    # Nginx does not support HTTP/2 to upstreams natively (use grpc_pass for gRPC,
    # or Envoy as backend-side proxy for full h2 upstream support)
}
```

In Envoy, end-to-end HTTP/2 is straightforward:

```yaml
clusters:
  - name: backend_service
    type: STRICT_DNS
    http2_protocol_options: {}  # Force HTTP/2 to the upstream
    load_assignment:
      cluster_name: backend_service
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: backend.internal
                    port_value: 443
```

## Stream Concurrency Limits

`SETTINGS_MAX_CONCURRENT_STREAMS` is the HTTP/2 settings parameter that bounds how many open streams a client may maintain simultaneously. The default in many implementations is 100 or higher. A lower limit reduces the attack surface for stream-based resource exhaustion without breaking well-behaved clients.

Browsers open at most a few dozen concurrent streams for page loading; REST API clients typically open one or a few. The only legitimate case for high `MAX_CONCURRENT_STREAMS` is a service that explicitly relies on HTTP/2 multiplexing for high-parallelism workloads (some gRPC streaming APIs).

```nginx
# nginx.conf
http {
    http2_max_concurrent_streams 64;

    # Also limit per-connection requests to prevent connection reuse abuse
    keepalive_requests 100;

    # Idle timeout for HTTP/2 connections (in addition to stream limits)
    http2_idle_timeout 3m;
}
```

```haproxy
# haproxy.cfg
global
    tune.h2.max-concurrent-streams 64

frontend https_frontend
    bind :443 ssl crt /etc/ssl/certs/server.pem alpn h2,http/1.1

    # Per-IP connection limits constrain stream amplification
    stick-table type ip size 1m expire 30s store conn_cur,conn_rate(10s)
    tcp-request connection track-sc0 src
    tcp-request connection reject if { sc_conn_cur(0) gt 20 }
```

```yaml
# Envoy xDS
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
  http2_protocol_options:
    max_concurrent_streams: 64
    # Stream idle timeout — server sends RST_STREAM if idle stream exceeds this
  stream_idle_timeout: 300s
  # Connection-level idle timeout
  drain_timeout: 30s
```

## Disabling HTTP/2 Server Push

HTTP/2 server push (`PUSH_PROMISE` frames) allows the server to proactively send resources (CSS, JS, images) to the client before the client requests them. In practice:

- **Chrome removed server push support in Chrome 106** (October 2022), citing low real-world benefit relative to `<link rel="preload">`.
- **HTTP/3 / QUIC removed server push** entirely from the protocol (RFC 9114 §4.6 is absent).
- Firefox deprioritized it. Safari support was inconsistent.
- Server push can be used for **cross-origin push** attacks where a compromised server pushes unauthorized content into the browser's cache.
- Push responses bypass CSP checks in some historical browser implementations.
- Push adds per-stream state on both client and server for something modern browsers ignore.

Disable it:

```nginx
# nginx.conf — server push is controlled per-location or per-server
server {
    listen 443 ssl;
    http2 on;

    # Explicitly disable server push (Nginx enables it if http2_push is set)
    # Do not configure http2_push directives anywhere
    # If using http2_push_preload, disable it:
    http2_push_preload off;
}
```

```haproxy
# haproxy.cfg
# HAProxy does not implement HTTP/2 server push; it terminates push from origins
# Ensure upstream push promises are stripped when acting as a reverse proxy
frontend https_frontend
    bind :443 ssl crt /etc/ssl/certs/server.pem alpn h2,http/1.1

    # Strip Link: headers with rel=preload to prevent push proxying
    http-response del-header Link
```

```yaml
# Envoy xDS — server push is not implemented in Envoy's HTTP/2 codec
# No configuration required; Envoy rejects PUSH_PROMISE from upstreams by default
# Verify with: envoy --component-log-level http2:debug
```

For application frameworks that generate `Link: <...>; rel=preload` headers, audit whether they trigger push in your proxy layer. In Nginx, `http2_push_preload on` (off by default) translates `Link: rel=preload` into `PUSH_PROMISE` frames. Confirm this directive is absent.

## CVE-2023-44487: Rapid Reset — Verification Checklist

The Rapid Reset attack (disclosed October 2023) was already covered in [HTTP/2 RST and CONTINUATION Flood Mitigation](/articles/network/http2-flood-mitigation/), but as part of protocol hardening, verify your current deployment is patched and configured:

```bash
# Check Nginx version — Rapid Reset patched in 1.25.3
nginx -v 2>&1
# Expected: nginx/1.27.x or higher

# Check HAProxy version — patched in 2.8.3 / 2.6.15
haproxy -v | head -1
# Expected: HAProxy version 3.0.x or 2.8.x >= 2.8.3

# Check Envoy version — Rapid Reset patched in 1.27.2
envoy --version
# Expected: envoy 1.30.x or higher

# Test that your server enforces SETTINGS_MAX_CONCURRENT_STREAMS
# Use h2spec to validate HTTP/2 framing compliance:
h2spec -h your-server.example.com -p 443 -t -k -S http2/6.9
```

Installing `h2spec` for protocol validation:

```bash
# Install h2spec (Go binary for HTTP/2 conformance testing)
curl -fsSL https://github.com/summerwind/h2spec/releases/latest/download/h2spec_linux_amd64.tar.gz \
  | tar -xz -C /usr/local/bin/ h2spec
chmod +x /usr/local/bin/h2spec

# Run full HTTP/2 spec conformance suite
h2spec -h your-server.example.com -p 443 --tls -k

# Test specifically for stream handling
h2spec http2/5.1 -h your-server.example.com -p 443 --tls -k
```

## Full Nginx HTTP/2 Hardening Block

```nginx
# /etc/nginx/conf.d/http2-hardening.conf
http {
    # HTTP/2 stream limits
    http2_max_concurrent_streams 64;

    # Header size limits (decompressed)
    http2_max_header_size 32k;

    # Connection lifecycle
    http2_idle_timeout 3m;
    keepalive_requests 100;
    keepalive_timeout 75s;

    # Do not push — disable entirely
    http2_push_preload off;

    # Client header timeout — limits CONTINUATION stalling
    client_header_timeout 10s;
    client_body_timeout 15s;

    # Large header buffers — cap decompressed header storage
    large_client_header_buffers 4 8k;

    server {
        listen 443 ssl;
        http2 on;
        ssl_certificate /etc/ssl/certs/server.pem;
        ssl_certificate_key /etc/ssl/private/server.key;

        # Upstream proxying: strip HTTP/2-forbidden headers
        location / {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Transfer-Encoding "";
            proxy_request_buffering on;
            proxy_buffering on;
        }
    }
}
```

## Full HAProxy HTTP/2 Hardening Block

```haproxy
# /etc/haproxy/haproxy.cfg
global
    log /dev/log local0
    maxconn 50000

    # HTTP/2 tuning
    tune.h2.header-table-size    4096
    tune.h2.max-concurrent-streams 64
    tune.h2.initial-window-size  65536

defaults
    log     global
    mode    http
    timeout connect  5s
    timeout client   30s
    timeout server   30s

frontend https_frontend
    bind :443 ssl crt /etc/ssl/certs/server.pem alpn h2,http/1.1

    # Reject requests with both CL and TE (smuggling precondition)
    http-request deny if { req.hdr(transfer-encoding) -m found } { req.hdr(content-length) -m found }

    # Strip Link: preload (prevent push proxying to HTTP/1.1 backends that interpret it)
    http-response del-header Link

    # Per-IP connection limit to constrain stream amplification
    stick-table type ip size 1m expire 60s store conn_cur,conn_rate(10s),http_req_rate(10s)
    http-request track-sc0 src
    http-request deny if { sc_http_req_rate(0) gt 200 }

    default_backend app_backend

backend app_backend
    balance roundrobin
    http-request del-header Transfer-Encoding
    server app1 10.0.0.1:8080 check
    server app2 10.0.0.2:8080 check
```

## Full Envoy HTTP/2 Hardening (xDS YAML)

```yaml
# envoy-http2-hardening.yaml
static_resources:
  listeners:
    - name: https_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 443
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates:
                  - certificate_chain:
                      filename: /etc/ssl/certs/server.pem
                    private_key:
                      filename: /etc/ssl/private/server.key
                alpn_protocols:
                  - h2
                  - http/1.1
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_https
                stream_idle_timeout: 300s
                drain_timeout: 30s
                http2_protocol_options:
                  max_concurrent_streams: 64
                  max_headers_count: 100
                  max_request_headers_kb: 32
                  # Reject chunked TE in HTTP/2 context (RFC 9113 §8.2.2)
                  allow_chunked_length: false
                  hpack_table_size: 4096
                  initial_stream_window_size: 65536
                  initial_connection_window_size: 1048576
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

## Summary: What to Configure

| Control | Nginx | HAProxy | Envoy |
|---|---|---|---|
| Max concurrent streams | `http2_max_concurrent_streams 64` | `tune.h2.max-concurrent-streams 64` | `max_concurrent_streams: 64` |
| Max header size (decompressed) | `http2_max_header_size 32k` | `http-request deny if { req.hdrs_len gt 32768 }` | `max_request_headers_kb: 32` |
| HPACK table size | N/A (follow peer SETTINGS) | `tune.h2.header-table-size 4096` | `hpack_table_size: 4096` |
| Strip TE header upstream | `proxy_set_header Transfer-Encoding ""` | `http-request del-header Transfer-Encoding` | `allow_chunked_length: false` |
| Server push | `http2_push_preload off` | N/A (not implemented) | N/A (not implemented) |
| Client header timeout | `client_header_timeout 10s` | `timeout client 30s` | `stream_idle_timeout: 300s` |

The four highest-priority actions for any HTTP/2 deployment:

1. **Patch to current versions** — Nginx 1.27+, HAProxy 3.0+, Envoy 1.30+. CVE-2024-27316 and CVE-2023-44487 are fixed in these versions but older instances persist in container images.
2. **Set `MAX_CONCURRENT_STREAMS` to 64 or lower** — the default 100+ is unnecessarily permissive. Browsers and most API clients never approach this limit.
3. **Cap decompressed header size** — a one-line configuration prevents HPACK bombs.
4. **Disable server push** — it provides no benefit for Chrome 106+, adds per-stream state, and represents unnecessary attack surface.

HTTP/2-to-HTTP/1.1 desync requires ongoing attention: every time a new backend service is added without HTTP/2 support, evaluate whether the proxy layer enforces RFC 9113 header validity before translating to HTTP/1.1.
