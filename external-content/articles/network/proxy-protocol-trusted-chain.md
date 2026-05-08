---
title: "PROXY Protocol and Trusted Proxy Chain Configuration"
description: "X-Forwarded-For spoofing is one of the oldest tricks in the attacker playbook. Configure your proxy chain correctly — PROXY protocol v2, real_ip directives, and trusted hop counts — or every IP-based security control you have is fiction."
slug: proxy-protocol-trusted-chain
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - proxy-protocol
  - reverse-proxy
  - x-forwarded-for
  - trusted-proxies
  - ip-spoofing
personas:
  - security-engineer
  - platform-engineer
article_number: 500
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/network/proxy-protocol-trusted-chain/
---

# PROXY Protocol and Trusted Proxy Chain Configuration

## The Problem

Most production web traffic flows through at least two intermediaries before reaching application code: a cloud load balancer, a CDN edge node, an Nginx ingress, a service mesh sidecar. At each hop the originating client IP is preserved — or corrupted — depending on how the proxy chain is configured.

The standard mechanism for preserving client IP through HTTP proxies is the `X-Forwarded-For` (XFF) header. A load balancer appends the client's IP to XFF before forwarding the request. The backend reads XFF to learn who made the request. This drives rate limiting, geo-blocking, IP allowlisting, audit logs, fraud detection, and session attribution.

The flaw: `X-Forwarded-For` is just an HTTP header. Any HTTP client can send it.

```bash
# Attacker sends a request with a forged XFF header
curl -H "X-Forwarded-For: 1.2.3.4" https://api.example.com/admin

# If the backend trusts XFF unconditionally, it sees the request as coming from 1.2.3.4
# Actual attacker IP: 198.51.100.77
```

If your application reads `request.headers['X-Forwarded-For']` (or its framework equivalent) without first validating which proxies are trusted, an attacker can:

- **Bypass IP allowlists.** Set XFF to `10.0.0.1` (an internal range) to bypass internal-only API checks.
- **Evade rate limits.** Rotate the forged IP header to appear as thousands of different clients.
- **Corrupt audit logs.** Every authentication event, every API call attributed to a forged IP instead of the real one.
- **Defeat geo-blocking.** Forge an IP in an allowed geographic region.
- **Abuse access control decisions.** Any system that gates on client IP — fail2ban, Cloudflare IP reputation, internal network segments — can be bypassed.

This article covers the complete picture: the XFF trust model, PROXY protocol as a TCP-level alternative, configuration patterns for Nginx, HAProxy, and Envoy, application-level trusted proxy configuration, and the specific misconfigurations that create exploitable holes.

## X-Forwarded-For vs PROXY Protocol

These two mechanisms solve the same problem — conveying the original client IP to a backend — but at different protocol layers with different security properties.

### X-Forwarded-For

XFF is an HTTP header appended (or created) by each proxy in the chain:

```
X-Forwarded-For: <client-ip>, <proxy1-ip>, <proxy2-ip>
```

Each proxy appends its received client IP. A backend that wants the original client IP reads the leftmost entry — but only if it trusts every proxy between itself and the internet.

**Security property:** XFF can be set by any HTTP client. There is no cryptographic authentication. The only way to trust XFF is to trust the proxy that sent it — which means the proxy must have stripped any client-supplied XFF and replaced it with the actual connecting IP.

### PROXY Protocol

PROXY protocol is a TCP-level prefix injected by a load balancer before the first byte of the application-layer stream. The backend receives it before the HTTP request is parsed.

**Version 1 (text):**
```
PROXY TCP4 192.168.1.100 10.0.0.1 56324 443\r\n
```

**Version 2 (binary):** A 12-byte fixed header followed by address bytes and optional TLV (Type-Length-Value) extensions. The signature bytes `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A` identify the protocol unambiguously.

**Key difference from XFF:** PROXY protocol is injected at the TCP layer, before HTTP parsing. A client connecting directly to an HTTP backend cannot inject PROXY protocol data unless the backend is listening for it — in which case the client can inject *anything*, which is its own critical misconfiguration (covered below).

**When to use v2 over v1:**

- **TLV extensions:** v2 supports arbitrary TLV extensions including SSL information (`PP2_TYPE_SSL`), Amazon VPC source info, and health-check markers. This lets the backend learn whether the upstream connection was TLS-terminated, what SNI was used, and what the client certificate CN was — without needing custom HTTP headers.
- **Binary parsing efficiency:** v2 is slightly faster to parse at high throughput.
- **Unambiguous identification:** The v2 signature cannot appear in a legitimate v1 text stream, making protocol detection robust.

Use PROXY protocol v2 for any new infrastructure. Use v1 only when backend software doesn't support v2.

## Threat Model

- **Adversary 1 — XFF spoofer:** HTTP client sends `X-Forwarded-For: 10.0.0.1` hoping the backend trusts it unconditionally. Bypasses IP allowlist for an internal admin API.
- **Adversary 2 — Rate limit evader:** Cycles through `X-Forwarded-For` values per request; each appears as a unique IP to a naive rate limiter.
- **Adversary 3 — PROXY protocol injector:** Connects directly to a backend server that has `accept-proxy` or `proxy_protocol` enabled. Injects a crafted PROXY protocol header claiming to originate from a trusted IP.
- **Adversary 4 — Misconfigured hop count:** Application reads the wrong position in a multi-hop XFF chain, trusting a proxy-appended IP that an earlier client could influence.
- **Access level:** Adversaries 1, 2, and 4 need only HTTP access. Adversary 3 needs direct TCP access to the backend (not the public load balancer).
- **Objective:** IP allowlist bypass, rate limit evasion, audit log corruption, geo-blocking evasion.
- **Blast radius:** Every IP-based security control across the stack fails simultaneously if XFF is trusted without a proper proxy chain model.

## Nginx Trusted Proxy Configuration

Nginx uses the `ngx_http_realip_module` to extract the real client IP from XFF. Without it, `$remote_addr` is the IP of the last connecting proxy — which is the load balancer, not the client.

### Basic Configuration

```nginx
# /etc/nginx/conf.d/realip.conf

# Trust only your known load balancer IPs or CIDR ranges
# Do NOT use 0.0.0.0/0 or trust all RFC1918 ranges blindly
set_real_ip_from 10.0.0.0/8;          # Internal VPC
set_real_ip_from 172.16.0.0/12;       # Secondary VPC range
set_real_ip_from 192.168.0.0/16;      # Management network
set_real_ip_from 203.0.113.10;        # Specific public load balancer IP

# Use the last XFF entry that came from a non-trusted proxy
# real_ip_header X-Forwarded-For;     # Standard header
real_ip_header X-Real-IP;             # Some load balancers use this instead

# Walk the XFF chain from right to left, stopping at the first untrusted IP
real_ip_recursive on;
```

**What `real_ip_recursive on` does:** Without it, Nginx takes the rightmost IP in `X-Forwarded-For`. With it, Nginx walks the list from right to left, skipping each IP that matches a `set_real_ip_from` range, and stops at the first IP that doesn't match a trusted proxy. That IP becomes `$remote_addr`. This is the correct behavior for multi-hop proxy chains.

**Without `real_ip_recursive on`:**

```
X-Forwarded-For: 198.51.100.77, 10.0.0.5, 10.0.0.6
set_real_ip_from 10.0.0.0/8;

# Nginx reads rightmost: 10.0.0.6 — still a trusted proxy, not the client
# $remote_addr = 10.0.0.6  ← WRONG
```

**With `real_ip_recursive on`:**

```
# 10.0.0.6 is trusted → skip
# 10.0.0.5 is trusted → skip
# 198.51.100.77 is NOT trusted → stop
# $remote_addr = 198.51.100.77  ← CORRECT
```

### Strip Client-Supplied XFF Headers

Nginx does not strip incoming XFF by default. An attacker can prepend values to the chain:

```nginx
server {
    listen 443 ssl;

    # Strip any XFF injected by the client before the first trusted proxy
    # Only needed if your upstream load balancer does not do this for you
    # (Most CDNs and cloud LBs strip client XFF before appending their own)
    
    # Confirm your upstream LB strips client XFF, or add this:
    # more_set_input_headers "X-Forwarded-For: $http_x_forwarded_for";
    # (requires ngx_headers_more module)

    location / {
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_pass http://backend;
    }
}
```

### Nginx with PROXY Protocol

If your upstream load balancer (AWS NLB, HAProxy) sends PROXY protocol to Nginx:

```nginx
server {
    # Accept PROXY protocol on the listener
    listen 443 ssl proxy_protocol;

    # Trust the PROXY protocol source — only connections from known LBs
    set_real_ip_from 10.0.0.0/8;
    real_ip_header proxy_protocol;

    # PROXY protocol provides $proxy_protocol_addr directly
    # Use this in logs instead of $remote_addr for full visibility
    log_format with_real_ip '$proxy_protocol_addr - $remote_user [$time_local] '
                            '"$request" $status $body_bytes_sent';
}
```

## HAProxy Trusted Proxy Configuration

HAProxy sends and receives PROXY protocol natively, and handles XFF sanitization through ACLs and header directives.

### Sending PROXY Protocol v2 to Backends

```haproxy
backend app_servers
    balance roundrobin

    # Inject PROXY protocol v2 on all backend connections
    default-server send-proxy-v2

    server app1 10.0.1.10:8080 send-proxy-v2 check
    server app2 10.0.1.11:8080 send-proxy-v2 check
```

### Receiving PROXY Protocol from an Upstream LB

```haproxy
frontend public
    bind *:443 ssl crt /etc/ssl/certs/example.pem accept-proxy

    # accept-proxy tells HAProxy to parse the PROXY protocol header
    # from the connecting client before reading the HTTP request.
    # Only enable this if the upstream component (NLB, external LB)
    # is guaranteed to send PROXY protocol — otherwise any TCP client
    # can spoof their source IP.
```

### XFF Sanitization in HAProxy

```haproxy
frontend public
    bind *:443 ssl crt /etc/ssl/certs/example.pem

    # Option 1: forwardfor with except (do not add XFF for internal ranges)
    option forwardfor except 127.0.0.0/8

    # Option 2: Delete any client-supplied XFF before forwarding
    # This ensures clients cannot pre-populate the XFF chain
    http-request del-header X-Forwarded-For
    http-request del-header X-Real-IP
    http-request del-header X-Forwarded-Host

    # HAProxy then adds XFF with the real client IP (from PROXY protocol
    # or the TCP connection) via option forwardfor
    option forwardfor

    default_backend app_servers
```

### HAProxy Stick-Table Rate Limiting with Real IP

```haproxy
frontend public
    bind *:443 ssl crt /etc/ssl/certs/example.pem accept-proxy

    # Rate limit by the PROXY-protocol-supplied client IP
    # src here refers to $src after PROXY protocol resolution
    stick-table type ip size 200k expire 30s store http_req_rate(10s)
    http-request track-sc0 src
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }
```

## Envoy Trusted Proxy Configuration

Envoy's XFF handling is controlled by two related settings in the `HttpConnectionManager` filter.

### xff_num_trusted_hops

```yaml
# envoy-config.yaml
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8080
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          
          # Number of trusted proxy hops to skip from the right side of XFF
          # If your stack is: Client → CloudFront (1) → NLB (2) → Envoy
          # then xff_num_trusted_hops: 2 skips 2 rightmost entries
          # and uses the next entry as the real client IP
          xff_num_trusted_hops: 2
          
          # use_remote_address: true tells Envoy to trust the direct
          # connecting IP as a proxy hop (appends it to XFF).
          # Set to false if Envoy is not the first proxy.
          use_remote_address: true
```

**Critical distinction:**

- `use_remote_address: true` — Envoy treats itself as an edge proxy. It appends the connecting IP to XFF and sets `x-real-ip`. Correct for edge Envoy instances.
- `use_remote_address: false` — Envoy passes XFF through unchanged. Correct for internal sidecars where a trusted upstream already set XFF.
- `xff_num_trusted_hops: N` — Skip N entries from the right of the XFF list. The (N+1)th from the right is the real client IP.

### Envoy PROXY Protocol Listener Filter

```yaml
listener_filters:
- name: envoy.filters.listener.proxy_protocol
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol
    rules:
    - tlv_type: 0xE0
      on_tlv_present:
        metadata_namespace: envoy.filters.listener.proxy_protocol
        key: "custom_tlv"
    # Allow both v1 and v2
    allow_requests_without_proxy_protocol: false
```

Setting `allow_requests_without_proxy_protocol: false` means Envoy rejects any TCP connection that does not begin with a valid PROXY protocol header. This prevents direct client connections from bypassing the PROXY protocol path — critical for backends where direct access would allow IP spoofing.

## Application-Level Trusted Proxy Configuration

Infrastructure-level proxy configuration is necessary but not sufficient. Application frameworks also need to be told which proxies to trust.

### Python: Flask and Django

**Flask (using Werkzeug's ProxyFix):**

```python
from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# x_for=2: trust 2 XFF hops from the right
# x_proto=1: trust X-Forwarded-Proto from 1 hop
# x_host=0: do NOT trust X-Forwarded-Host (common attack vector)
# x_port=0: do NOT trust X-Forwarded-Port
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=2,      # Matches your actual proxy hop count
    x_proto=1,
    x_host=0,
    x_port=0,
    x_prefix=0,
)

@app.route("/")
def index():
    # request.remote_addr now reflects the real client IP
    real_ip = request.remote_addr
    return f"Your IP: {real_ip}"
```

**Django:**

```python
# settings.py

# List the exact IP addresses or CIDR ranges of your trusted proxies
# Django walks XFF from the right and stops at the first non-trusted IP
TRUSTED_PROXIES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "203.0.113.10",  # Specific load balancer
]

# Since Django 4.0, USE_X_FORWARDED_HOST is deprecated in favor of
# explicit TRUSTED_PROXIES. Set SECURE_PROXY_SSL_HEADER if behind TLS termination.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Avoid: ALLOWED_HOSTS = ["*"] — this bypasses Host header validation
ALLOWED_HOSTS = ["api.example.com"]
```

### Go: net/http/httputil ReverseProxy

Go's standard `httputil.ReverseProxy` does not validate XFF by default. You must implement trusted proxy logic explicitly:

```go
package main

import (
    "net"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
)

var trustedProxyCIDRs = []string{
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
}

func isTrustedProxy(ip string) bool {
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return false
    }
    for _, cidr := range trustedProxyCIDRs {
        _, network, err := net.ParseCIDR(cidr)
        if err != nil {
            continue
        }
        if network.Contains(parsed) {
            return true
        }
    }
    return false
}

// realClientIP walks the XFF chain from right to left,
// skipping trusted proxies, and returns the first untrusted IP.
func realClientIP(r *http.Request) string {
    xff := r.Header.Get("X-Forwarded-For")
    if xff == "" {
        host, _, _ := net.SplitHostPort(r.RemoteAddr)
        return host
    }

    ips := strings.Split(xff, ",")
    // Walk from right to left
    for i := len(ips) - 1; i >= 0; i-- {
        ip := strings.TrimSpace(ips[i])
        if !isTrustedProxy(ip) {
            return ip
        }
    }

    // All IPs in XFF are trusted proxies — use the leftmost
    return strings.TrimSpace(ips[0])
}

func main() {
    target, _ := url.Parse("http://backend:8080")
    proxy := httputil.NewSingleHostReverseProxy(target)

    proxy.Director = func(req *http.Request) {
        // Remove any client-injected XFF before forwarding
        clientIP := realClientIP(req)
        req.Header.Set("X-Forwarded-For", clientIP)
        req.Header.Set("X-Real-IP", clientIP)
        req.URL.Scheme = target.Scheme
        req.URL.Host = target.Host
    }

    http.ListenAndServe(":8080", proxy)
}
```

## Security Risks of Misconfiguration

### Risk 1: Unconditional XFF Trust

```python
# DANGEROUS — never do this
client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
```

This reads the leftmost XFF entry — which an attacker controls entirely.

```bash
curl -H "X-Forwarded-For: 10.0.0.1" https://api.example.com/internal
# Backend sees client_ip = "10.0.0.1" — bypasses internal-only check
```

### Risk 2: Trusting All RFC1918 Ranges

```nginx
# DANGEROUS — do not blanket-trust all private IPs
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

If a client can reach your Nginx directly (not through the load balancer), they send:

```bash
curl -H "X-Forwarded-For: 10.0.0.1" https://nginx-direct:443/
# Nginx sees: XFF chain is [10.0.0.1, <client-ip>]
# client-ip is in 10.0.0.0/8 range? No — but 10.0.0.1 IS in the trusted range
# real_ip_recursive skips it... to nothing, falls back to 10.0.0.1
```

Lock `set_real_ip_from` to the specific IPs or tightly scoped CIDRs of your actual load balancers.

### Risk 3: PROXY Protocol Open to Direct Clients

```haproxy
frontend backend_internal
    # DANGEROUS: listening on a public interface with accept-proxy
    bind 0.0.0.0:8080 accept-proxy
```

Any TCP client that can reach port 8080 can send:

```bash
printf "PROXY TCP4 10.0.0.1 198.51.100.1 12345 8080\r\nGET /admin HTTP/1.0\r\n\r\n" \
    | nc backend.example.com 8080
# Backend sees request from 10.0.0.1 — a trusted internal IP
# Real attacker IP 198.51.100.1 never logged
```

**Fix:** PROXY protocol listeners must only be reachable from trusted upstream components. Use firewall rules or network policies to enforce this:

```bash
# iptables: allow PROXY protocol port only from the load balancer
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.5 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### Risk 4: Wrong Hop Count in Multi-Hop Chains

A three-hop chain: Client → CDN → NLB → Nginx

XFF by the time it reaches Nginx: `198.51.100.77, 203.0.113.5, 10.0.0.5`

- `10.0.0.5` = NLB (trusted)
- `203.0.113.5` = CDN edge (trusted)
- `198.51.100.77` = real client

If Nginx only trusts `10.0.0.0/8` (not the CDN range `203.0.113.5`), `real_ip_recursive` stops at `203.0.113.5` — attributing every request to the CDN's edge IP, not the client.

Audit your actual proxy chain. Enumerate every intermediate IP range that legitimately appears in your XFF.

## Testing Trusted Proxy Configuration

### Verify XFF Stripping at the Edge

```bash
# Send a forged XFF from outside the trusted network
# If your edge properly strips client XFF, the backend should NOT see 1.2.3.4
curl -v -H "X-Forwarded-For: 1.2.3.4" https://api.example.com/debug/ip

# Expected: backend reports your real public IP, not 1.2.3.4
# If it reports 1.2.3.4: the edge is not stripping client XFF
```

### Verify Real IP Extraction in Access Logs

```bash
# Make a request from a known IP, check what appears in the access log
curl https://api.example.com/

# Check Nginx access log
tail -1 /var/log/nginx/access.log
# Expected: your real public IP in the first field
# If you see the load balancer IP: real_ip_header or set_real_ip_from misconfigured
# If you see 127.0.0.1: missing set_real_ip_from for the proxy

# For structured JSON logs with both remote_addr and XFF visible:
# {"remote_addr":"198.51.100.77","x_forwarded_for":"198.51.100.77, 10.0.0.5"}
```

### Test PROXY Protocol Receipt

```bash
# haproxy-test-proxy-protocol.sh
# Manually send a PROXY protocol v1 header to verify the backend parses it

printf "PROXY TCP4 198.51.100.77 10.0.0.1 56324 80\r\nGET / HTTP/1.0\r\nHost: example.com\r\n\r\n" \
    | nc -q1 127.0.0.1 8080

# Backend access log should show 198.51.100.77 as the client IP
# Only run this against a test backend; confirms PROXY protocol parsing works
```

### Application-Level Verification

```python
# Flask endpoint to verify IP extraction
@app.route("/debug/ip")
def debug_ip():
    return {
        "remote_addr": request.remote_addr,       # Should be real client IP
        "x_forwarded_for": request.headers.get("X-Forwarded-For"),
        "x_real_ip": request.headers.get("X-Real-IP"),
    }
```

```bash
curl https://api.example.com/debug/ip
# {"remote_addr":"198.51.100.77","x_forwarded_for":"198.51.100.77, 10.0.0.5","x_real_ip":"198.51.100.77"}
# remote_addr should be the real client IP after ProxyFix processes the chain
```

## Summary: Configuration Checklist

| Layer | Control | Setting |
|---|---|---|
| Edge LB | Strip client XFF before appending | Enabled by default on most CDNs; verify |
| Nginx | `real_ip_recursive` | `on` |
| Nginx | `set_real_ip_from` | Specific LB IPs/CIDRs only |
| HAProxy | `http-request del-header X-Forwarded-For` | On frontend, before `option forwardfor` |
| HAProxy | `accept-proxy` | Firewall-restricted to LB IPs only |
| Envoy | `xff_num_trusted_hops` | Equals number of upstream proxy hops |
| Flask | `ProxyFix(x_for=N)` | N = number of trusted upstream proxies |
| Django | `TRUSTED_PROXIES` | Explicit IP list, no wildcards |
| Go | Manual XFF walk | Skip trusted CIDRs from right |
| Network | PROXY protocol port access | Restricted to LB source IPs via firewall |

The core principle is consistent across every layer: trust flows from right to left in the XFF chain, and only as far as you can verify. Each component in the chain must know exactly how many hops upstream of it are operated by infrastructure you control. Any configuration that trusts more than that — all RFC1918 ranges, any value the client sends, an unconstrained hop count — converts your IP-based security controls into suggestions that any attacker with curl can ignore.
