---
title: "Preventing HTTP Request Smuggling: Configuration for NGINX, HAProxy, and Envoy"
description: "HTTP request smuggling exploits inconsistencies in how chained HTTP processors (reverse proxies, load balancers, backend servers) parse request..."
slug: "request-smuggling-prevention"
date: 2026-01-20
lastmod: 2026-01-20
category: "network"
tags: ["request-smuggling", "nginx", "haproxy", "envoy", "http-parsing", "reverse-proxy", "security"]
personas: ["security-engineer", "platform-engineer"]
article_number: 43
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Fastly"
    id: 71
    category: "cdn-edge"
premium_pack: "request-smuggling-defence"
published: true
layout: article.njk
permalink: "/articles/network/request-smuggling-prevention/index.html"
---

# Preventing HTTP Request Smuggling: Configuration for [NGINX](https://nginx.org), [HAProxy](https://www.haproxy.org), and [Envoy](https://www.envoyproxy.io)

## Problem

HTTP request smuggling exploits inconsistencies in how chained HTTP processors (reverse proxies, load balancers, backend servers) parse request boundaries. When a front-end proxy and a back-end server disagree on where one request ends and the next begins, an attacker can inject a second request that the front-end never inspects but the back-end processes as legitimate.

The core parsing disagreements:

- **CL/TE (Content-Length vs Transfer-Encoding):** The front-end uses `Content-Length` to determine the request boundary. The back-end uses `Transfer-Encoding: chunked`. The attacker embeds a second request inside the body that only the back-end sees.
- **TE/CL:** The inverse. The front-end uses `Transfer-Encoding`, the back-end uses `Content-Length`.
- **TE/TE (Transfer-Encoding obfuscation):** Both servers support `Transfer-Encoding`, but one fails to parse an obfuscated variant like `Transfer-Encoding: chunked\r\nTransfer-Encoding: x` or `Transfer-Encoding: chunked` with extra whitespace.
- **HTTP/2 downgrade smuggling:** An HTTP/2 front-end translates requests to HTTP/1.1 for the back-end. The translation can introduce `Content-Length` or `Transfer-Encoding` headers that create parsing ambiguity.

A single successful smuggling attack can bypass authentication (the smuggled request inherits another user's session), bypass WAF rules (the WAF inspects the outer request, not the smuggled one), poison web caches, or trigger server-side request forgery.

**Target systems:** Any deployment with two or more HTTP-processing layers: reverse proxy in front of application servers, CDN in front of origin, or load balancer in front of a proxy.

## Threat Model

- **Adversary:** External attacker with HTTP(S) access to any endpoint behind the proxy chain. No authentication required.
- **Access level:** Unauthenticated network access.
- **Objective:** Bypass authentication or authorization by smuggling requests that inherit another user's session context. Bypass WAF rules by hiding payloads inside smuggled requests. Poison shared caches so other users receive attacker-controlled responses.
- **Blast radius:** All users and all services behind the affected proxy chain. Cache poisoning can affect every visitor to the site until the cache expires or is purged.

## Configuration

### NGINX: Eliminating Parsing Ambiguity

The most critical NGINX directive for smuggling prevention forces HTTP/1.1 to upstreams with explicit connection handling:

```nginx
# Place in the http {} block of nginx.conf

# Force HTTP/1.1 to backends. HTTP/1.0 has ambiguous keep-alive
# and chunked encoding behaviour that enables smuggling.
proxy_http_version 1.1;

# Clear the Connection header to prevent hop-by-hop header
# manipulation. This prevents an attacker from injecting
# "Connection: Transfer-Encoding" to strip TE from the
# forwarded request.
proxy_set_header Connection "";

# Reject requests with both Content-Length and Transfer-Encoding.
# NGINX does this by default in 1.21.1+, but verify your version.
# If running an older version, upgrade.
```

Block requests that contain ambiguous headers by adding a request inspection map:

```nginx
# Place in the http {} block

# Detect requests that send both Content-Length and Transfer-Encoding.
# RFC 7230 Section 3.3.3: a server MUST treat such messages as malformed.
map $http_transfer_encoding $smuggling_block {
    default 0;
    "~*chunked.*,.*chunked" 1;     # Duplicate chunked values
    "~*,.*chunked" 1;              # Multiple TE values with chunked
}

# In the server {} block:
server {
    listen 443 ssl;
    server_name example.com;

    if ($smuggling_block) {
        return 400;
    }

    # Reject requests with whitespace-obfuscated Transfer-Encoding.
    # Catches "Transfer-Encoding : chunked" (space before colon).
    if ($http_transfer_encoding ~ "^\s") {
        return 400;
    }

    location / {
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_pass http://backend;
    }
}
```

For NGINX as a [Kubernetes](https://kubernetes.io) ingress controller, apply these settings via ConfigMap:

```yaml
# nginx-ingress ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-configuration
  namespace: ingress-nginx
data:
  # Force HTTP/1.1 to upstreams
  proxy-http-version: "1.1"
  # Use HTTP/2 for client connections (no downgrade smuggling)
  use-http2: "true"
  # Strict header parsing
  enable-strict-validate: "true"
```

### HAProxy: Strict HTTP Parsing Mode

HAProxy has explicit options that control how ambiguous HTTP messages are handled:

```haproxy
# /etc/haproxy/haproxy.cfg

global
    # Enable strict HTTP parsing. This rejects requests with:
    # - Both Content-Length and Transfer-Encoding
    # - Malformed chunked encoding
    # - Duplicate Content-Length with different values
    # - Spaces in header names
    tune.h2.max-concurrent-streams 100

defaults
    mode http
    option http-keep-alive

    # Normalize HTTP messages. HAProxy rewrites ambiguous requests
    # into unambiguous form before forwarding to backends.
    option httpclose

    # Close connection on invalid HTTP message instead of
    # attempting to parse it.
    option http-restrict-req-hdr-names reject

    # Reject requests where Content-Length does not match the
    # actual body length.
    option http-buffer-request

    # Set timeouts to prevent slow-smuggling variants
    timeout http-request 5s
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend http_front
    bind *:443 ssl crt /etc/haproxy/certs/site.pem alpn h2,http/1.1

    # Reject requests with both Content-Length and Transfer-Encoding.
    # HAProxy 2.4+ does this by default in strict mode.
    http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
    http-request deny if { req.hdr_cnt(content-length) gt 1 }

    # Reject obfuscated Transfer-Encoding values.
    http-request deny if { req.hdr(transfer-encoding) -m sub "," }
    http-request deny if { req.hdr(transfer-encoding) -m sub " " }

    # Log denied requests for monitoring
    http-request set-var(txn.smuggle_attempt) bool(true) \
        if { req.hdr_cnt(transfer-encoding) gt 1 } || \
           { req.hdr_cnt(content-length) gt 1 }

    default_backend app_servers

backend app_servers
    # Force HTTP/1.1 to backends
    option httpchk GET /health HTTP/1.1\r\nHost:\ localhost

    server app1 10.0.1.10:8080 check
    server app2 10.0.1.11:8080 check
```

Enable strict HTTP mode in HAProxy 2.6+:

```haproxy
global
    # Strict HTTP compliance mode. Rejects:
    # - Ambiguous Content-Length / Transfer-Encoding combinations
    # - Malformed chunk sizes
    # - Header names with spaces or invalid characters
    httpclient.resolvers.prefer ipv4
    tune.h2.header-table-size 4096
    tune.h2.initial-window-size 65535

defaults
    mode http
    # H1 message normalization
    option h1-case-adjust-bogus-client
```

### Envoy: HTTP Connection Manager Settings

Envoy's HTTP connection manager provides granular control over HTTP parsing:

```yaml
# Envoy configuration (static or via xDS)
static_resources:
  listeners:
    - name: ingress
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8443
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_certificates:
                  - certificate_chain:
                      filename: /etc/envoy/certs/server.crt
                    private_key:
                      filename: /etc/envoy/certs/server.key
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                codec_type: AUTO

                # Reject requests with both Content-Length and
                # Transfer-Encoding headers.
                # This is the primary smuggling prevention control.
                http_protocol_options:
                  allow_chunked_length: false

                # Normalize paths to prevent path confusion attacks
                # that often accompany smuggling.
                normalize_path: true
                merge_slashes: true
                path_with_escaped_slashes_action: REJECT_REQUEST

                # HTTP/2 settings to prevent H2 downgrade smuggling
                http2_protocol_options:
                  max_concurrent_streams: 100
                  initial_stream_window_size: 65536

                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: app_cluster

                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: app_cluster
      connect_timeout: 5s
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      # Force HTTP/1.1 to backends to avoid protocol mismatch
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http_protocol_options:
              allow_chunked_length: false
      load_assignment:
        cluster_name: app_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 10.0.1.10
                      port_value: 8080
```

### End-to-End HTTP/2: The Strongest Prevention

The most effective smuggling prevention is to eliminate HTTP/1.1 entirely from the request path. HTTP/2 uses binary framing with explicit stream lengths, removing the Content-Length and Transfer-Encoding ambiguity that enables smuggling:

```nginx
# NGINX: HTTP/2 to backends (requires NGINX 1.25.1+)
upstream backend_grpc {
    server 10.0.1.10:8443;
}

server {
    listen 443 ssl;
    http2 on;

    location / {
        # Use HTTP/2 to the backend, eliminating H1 parsing ambiguity
        grpc_pass grpcs://backend_grpc;
    }
}
```

If your backends cannot support HTTP/2, the HTTP/1.1 configuration above with strict parsing is the fallback.

### Testing for Smuggling Vulnerabilities

Use `smuggler` or `http-request-smuggling` tools to verify your configuration:

```bash
# Install smuggler (Python tool for smuggling detection)
pip install smuggler

# Test for CL/TE smuggling
python3 -m smuggler -u https://your-domain.com -t CLTE

# Test for TE/CL smuggling
python3 -m smuggler -u https://your-domain.com -t TECL

# Manual test: send ambiguous request with curl
# This should be rejected (400) by a properly configured proxy.
curl -v https://your-domain.com/ \
  -H "Content-Length: 6" \
  -H "Transfer-Encoding: chunked" \
  -d "0\r\n\r\nX"

# Test obfuscated Transfer-Encoding
curl -v https://your-domain.com/ \
  -H "Transfer-Encoding: chunked" \
  -H "Transfer-Encoding: x"
```

### Monitoring for Smuggling Attempts

```nginx
# NGINX: Log requests with Transfer-Encoding for analysis.
# Legitimate clients almost never send chunked requests directly;
# most are generated by proxies.

log_format smuggling_detect escape=json
    '{'
        '"time": "$time_iso8601",'
        '"remote_addr": "$remote_addr",'
        '"request_method": "$request_method",'
        '"request_uri": "$request_uri",'
        '"status": "$status",'
        '"http_transfer_encoding": "$http_transfer_encoding",'
        '"content_length": "$content_length",'
        '"http_user_agent": "$http_user_agent"'
    '}';

access_log /var/log/nginx/smuggling.json smuggling_detect;
```

## Expected Behaviour

After applying the smuggling prevention configuration:

```bash
# Verify ambiguous requests are rejected
curl -s -o /dev/null -w "%{http_code}" https://your-domain.com/ \
  -H "Content-Length: 0" \
  -H "Transfer-Encoding: chunked"
# Expected: 400

# Verify obfuscated TE is rejected
curl -s -o /dev/null -w "%{http_code}" https://your-domain.com/ \
  -H "Transfer-Encoding:  chunked"
# Expected: 400

# Verify normal requests still work
curl -s -o /dev/null -w "%{http_code}" https://your-domain.com/
# Expected: 200

# Verify chunked requests without CL work (legitimate use)
echo -e "4\r\ntest\r\n0\r\n\r\n" | curl -s -o /dev/null -w "%{http_code}" \
  -H "Transfer-Encoding: chunked" -d @- https://your-domain.com/api/data
# Expected: 200 (single, unambiguous TE header is fine)
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| `proxy_http_version 1.1` | Disables HTTP/1.0 to backends | Legacy backends expecting HTTP/1.0 break | Upgrade backends or add explicit HTTP/1.0 upstream for legacy services |
| `proxy_set_header Connection ""` | Strips hop-by-hop Connection header | WebSocket upgrades require explicit Connection handling | Add `proxy_set_header Connection "upgrade"` in WebSocket location blocks |
| Rejecting dual CL/TE requests | Blocks ambiguous requests outright | Some broken clients or proxies send both headers | Monitor 400 logs; legitimate clients almost never send both |
| HAProxy strict HTTP mode | Rejects malformed HTTP messages | Poorly written HTTP client libraries may send slightly malformed requests | Test with all known client types before enabling in production |
| End-to-end HTTP/2 | Eliminates HTTP/1.1 parsing ambiguity entirely | Backend applications must support HTTP/2 | Use HTTP/1.1 with strict parsing as fallback |
| Monitoring TE headers | Adds logging volume for Transfer-Encoding analysis | Slightly increased log storage | Route to a separate log file with shorter retention |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Strict parsing breaks legitimate client | Client receives 400 for valid requests | Spike in 400 responses from specific user agents or client IPs | Identify the malformed header and either fix the client or add an exception for that client |
| WebSocket connections fail after Connection header clearing | WebSocket upgrade returns 400 or hangs | WebSocket health checks fail; application monitoring shows WebSocket connection errors | Add explicit `proxy_set_header Connection "upgrade"` and `proxy_set_header Upgrade $http_upgrade` in WebSocket location blocks |
| HAProxy strict mode rejects health check probes | Health checks return 400; backends marked unhealthy | Load balancer shows all backends down; no healthy servers | Verify health check requests are well-formed HTTP; update health check configuration |
| Backend receives double Content-Length after proxy rewrite | Backend processes wrong body, returns incorrect data | Intermittent data corruption in API responses; mismatched response bodies | Verify proxy is normalizing headers, not adding duplicates; check `proxy_pass_request_headers` |
| Envoy rejects legitimate chunked uploads | File upload endpoints return 400 | Upload failure reports from users; 400 spike on upload paths | Verify `allow_chunked_length: false` only rejects dual CL/TE, not legitimate chunked-only requests |

## When to Consider a Managed Alternative

**Transition point:** When your proxy chain includes three or more layers (CDN, load balancer, reverse proxy, application server) and ensuring consistent HTTP parsing across all layers becomes an ongoing verification burden, or when you lack the tooling to continuously test for smuggling in CI/CD.

**What edge providers handle:**

- **[Cloudflare](https://www.cloudflare.com):** Normalizes all HTTP requests at the edge before forwarding to your origin. Cloudflare's HTTP parser strips ambiguous header combinations and rewrites requests into unambiguous form. This eliminates CL/TE, TE/CL, and TE/TE vectors before traffic reaches your infrastructure. Included in all plans.

- **[Fastly](https://www.fastly.com):** HTTP request normalization at the edge with strict parsing. Fastly's VCL layer provides visibility into request headers for custom detection rules. The edge layer handles HTTP/2 to HTTP/1.1 translation with consistent, non-exploitable header generation.

**What you still control:** Even with edge normalization, your internal proxy chain still needs consistent parsing configuration. If you run NGINX behind Cloudflare, a compromised internal service could still smuggle requests against your NGINX-to-backend chain. Apply the configurations in this article to every proxy layer, not just the internet-facing one.


## Related Articles

- [Hardening WebSocket Connections: Authentication, Rate Limiting, and Origin Validation](/articles/network/websocket-hardening/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [NGINX Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls](/articles/network/nginx-hardening-beyond-tls/)
- [Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared](/articles/network/rate-limiting-ingress/)
- [Load Balancer Security: Health Check Abuse, Connection Draining, and TLS Termination](/articles/network/load-balancer-security/)
