---
title: "NGINX Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls"
description: "Most NGINX hardening guides stop at TLS configuration, cipher suites, certificate setup, HSTS."
slug: "nginx-hardening-beyond-tls"
date: 2026-04-10
lastmod: 2026-04-10
category: "network"
tags: ["nginx", "hardening", "reverse-proxy", "rate-limiting", "request-filtering", "security-headers"]
personas: ["systems-engineer", "platform-engineer"]
article_number: 39
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Fastly"
    id: 71
    category: "cdn-edge"
  - name: "Bunny.net"
    id: 72
    category: "cdn-edge"
premium_pack: "nginx-hardened-config"
published: true
layout: article.njk
permalink: "/articles/network/nginx-hardening-beyond-tls/index.html"
---

# [NGINX](https://nginx.org) Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls

## Problem

Most NGINX hardening guides stop at TLS configuration, cipher suites, certificate setup, HSTS. In production, the attack surface extends far beyond TLS:

- **Default `server_tokens`** broadcasts your exact NGINX version to every client, giving attackers a precise target for known CVEs.
- **No request size limits** allow attackers to send multi-gigabyte request bodies, exhausting memory and disk.
- **Default timeouts** (60 seconds for headers, 60 seconds for body) enable slow-loris attacks that hold connections open indefinitely, exhausting `worker_connections`.
- **No rate limiting** means a single IP can flood your backend with thousands of requests per second.
- **No method filtering** allows PUT, DELETE, TRACE, and OPTIONS on endpoints that should only accept GET and POST.
- **Default error pages** display NGINX branding that confirms your technology stack.
- **Upstream headers are forwarded:** `X-Powered-By: Express`, `Server: Apache` from backends leak your internal architecture.

A stock `nginx.conf` with only TLS added is an incomplete hardening job that leaves the majority of the HTTP attack surface exposed.

**Target systems:** NGINX 1.24+ (stable), NGINX 1.26+ (mainline), running as a reverse proxy or [Kubernetes](https://kubernetes.io) ingress controller.

## Threat Model

- **Adversary:** External attacker with HTTP(S) access to any endpoint served by NGINX. No authentication required.
- **Access level:** Unauthenticated network access to any published URL.
- **Objective:** Denial of service (resource exhaustion through oversized requests, slow connections, or request flooding), information gathering (server version, backend technology, internal topology), request smuggling (bypass authentication or WAF by exploiting parsing inconsistencies), or payload delivery (send malicious payloads to backend applications through unfiltered requests).
- **Blast radius:** All services behind this NGINX instance. If NGINX is the Kubernetes ingress controller, the blast radius is every exposed service in the cluster.

## Configuration

### Information Disclosure Prevention

```nginx
# Place in the http {} block of nginx.conf

# Remove NGINX version from Server header and error pages.
server_tokens off;

# Remove the Server header entirely (requires headers-more module).
# Install: apt install libnginx-mod-http-headers-more-filter
# If the module is not available, server_tokens off is sufficient.
more_clear_headers 'Server';

# Hide backend technology headers that leak internal architecture.
proxy_hide_header X-Powered-By;
proxy_hide_header X-AspNet-Version;
proxy_hide_header X-AspNetMvc-Version;
proxy_hide_header X-Runtime;
```

Custom error pages that do not reveal the web server identity:

```nginx
# Place in each server {} block

# Custom error pages (create these files with your own content).
error_page 400 /errors/400.html;
error_page 403 /errors/403.html;
error_page 404 /errors/404.html;
error_page 500 502 503 504 /errors/50x.html;

location /errors/ {
    internal;
    root /usr/share/nginx/html;
}
```

### Request Size and Buffer Controls

```nginx
# Place in the http {} block

# Maximum allowed request body size. Default is 1m, which is appropriate
# for most API endpoints. Override per-location for file upload endpoints.
client_max_body_size 1m;

# Buffer for reading client request body. If the body exceeds this size,
# it is written to a temporary file (I/O overhead + disk usage).
# 16k handles most API requests in memory.
client_body_buffer_size 16k;

# Buffer for reading client request headers. 1k is sufficient for
# standard headers. Oversized headers (cookie stuffing, header injection)
# are rejected.
client_header_buffer_size 1k;

# For requests with unusually large headers (e.g., JWT in Authorization),
# allow up to 4 buffers of 8k each (32k total). Requests exceeding this
# return 414 Request-URI Too Large.
large_client_header_buffers 4 8k;

# Proxy buffer settings. Controls how NGINX buffers responses from backends.
# Prevents a slow client from holding a backend connection open.
proxy_buffer_size 4k;
proxy_buffers 8 16k;
proxy_busy_buffers_size 24k;

# Limit the size of temporary files when buffering responses.
# 0 disables temporary files (response must fit in proxy_buffers).
proxy_max_temp_file_size 0;
```

Override `client_max_body_size` for upload endpoints:

```nginx
# In the server {} block, allow larger bodies only where needed.
location /api/upload {
    client_max_body_size 50m;
    proxy_pass http://upload-backend;
}
```

### Connection and Timeout Controls

```nginx
# Place in the http {} block

# --- Timeouts (slow-loris defence) ---

# Time to read the complete client request headers.
# A slow-loris attack sends headers one byte at a time.
# 10 seconds is generous for legitimate clients.
client_header_timeout 10s;

# Time to read the client request body.
# Applied per-read, not total. 10 seconds between reads.
client_body_timeout 10s;

# Time to transmit the response to the client.
# Applied per-write. Slow clients that can't receive data
# within 10 seconds per chunk are disconnected.
send_timeout 10s;

# Keep-alive timeout. How long an idle connection stays open.
# Default is 75s. Reduce to 15s to free connections faster.
# Increase if clients use HTTP/1.1 pipelining heavily.
keepalive_timeout 15s;

# --- Connection limiting ---

# Track connections per client IP address.
# 10m zone stores ~160,000 unique IP addresses.
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;

# Maximum simultaneous connections per IP.
# 20 is generous for browsers (6-8 connections per page load).
# Reduce for APIs where each client should use fewer connections.
limit_conn conn_per_ip 20;

# Return 429 (Too Many Requests) when connection limit is hit.
limit_conn_status 429;
```

### Rate Limiting

```nginx
# Place in the http {} block

# Track request rate per client IP address.
# 10m zone stores ~160,000 unique IPs.
# rate=10r/s = 10 requests per second baseline.
limit_req_zone $binary_remote_addr zone=req_per_ip:10m rate=10r/s;

# Apply rate limiting in server {} or location {} blocks:
```

```nginx
# In the server {} block - general rate limiting
location / {
    # burst=20 allows 20 requests above the rate before rejecting.
    # nodelay processes burst requests immediately (no queuing).
    limit_req zone=req_per_ip burst=20 nodelay;
    limit_req_status 429;

    proxy_pass http://backend;
}

# Stricter rate limiting for authentication endpoints
location /api/login {
    limit_req zone=req_per_ip burst=5 nodelay;
    limit_req_status 429;

    proxy_pass http://auth-backend;
}
```

**Rate limiting caveat:** `$binary_remote_addr` tracks by source IP. If your users are behind a shared NAT (corporate office, mobile carrier), all users share one rate limit. For API endpoints, consider rate limiting by API key instead using `map` and `$http_x_api_key`, but this requires application-level key extraction, not just NGINX configuration.

### HTTP Method and URI Restrictions

```nginx
# In each location {} block, restrict to allowed HTTP methods.

location /api/ {
    # Allow only the methods your API actually uses.
    limit_except GET POST PUT DELETE {
        deny all;
    }
    proxy_pass http://api-backend;
}

location / {
    # Static content or read-only endpoints.
    limit_except GET HEAD {
        deny all;
    }
    proxy_pass http://frontend-backend;
}
```

Block known scanner and attack paths. Return 444 (close connection with no response) to waste minimal resources:

```nginx
# Place in the server {} block

# Block common scanner targets.
location ~ /\.(git|env|svn|htaccess|htpasswd) {
    return 444;
}

location ~ /(wp-admin|wp-login|xmlrpc\.php|wp-content) {
    return 444;
}

location ~ /(phpmyadmin|phpMyAdmin|myadmin|mysql) {
    return 444;
}

location ~ /(admin|administrator|console|manager) {
    # Only block if you do not have a legitimate /admin path.
    # Comment out if your application uses these routes.
    return 444;
}
```

**About HTTP response code 444:** This is an NGINX-specific non-standard code that closes the connection without sending any response headers or body. It is more efficient than returning a 403 because NGINX does not generate or transmit a response. Scanners that expect an HTTP response get nothing.

### Security Headers

```nginx
# Place in the server {} block or http {} block.
# Use 'always' to ensure headers are sent on error responses too.

add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# Content-Security-Policy is application-specific.
# Start with report-only mode and monitor for violations.
# See Article #36 (HTTP Security Headers) for comprehensive CSP guidance.
# add_header Content-Security-Policy "default-src 'self'" always;
```

### Logging for Security Monitoring

```nginx
# Structured JSON access log for security analysis.
# Place in the http {} block.

log_format security_json escape=json
    '{'
        '"time": "$time_iso8601",'
        '"remote_addr": "$remote_addr",'
        '"request_method": "$request_method",'
        '"request_uri": "$request_uri",'
        '"status": "$status",'
        '"body_bytes_sent": "$body_bytes_sent",'
        '"request_time": "$request_time",'
        '"upstream_response_time": "$upstream_response_time",'
        '"http_user_agent": "$http_user_agent",'
        '"http_referer": "$http_referer",'
        '"limit_req_status": "$limit_req_status",'
        '"server_name": "$server_name"'
    '}';

access_log /var/log/nginx/access.json security_json;

# Log rate-limited requests separately for monitoring.
# $limit_req_status is "PASSED", "DELAYED", "REJECTED", or "DELAYED_DRY_RUN".
```

### Complete Hardened nginx.conf

This is a drop-in `/etc/nginx/nginx.conf` with all hardening applied. Every directive is commented with its purpose:

```nginx
# /etc/nginx/nginx.conf
# Hardened configuration for NGINX as a reverse proxy.
# systemshardening.com - Article #39

user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    # --- Basic settings ---
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    # --- Information disclosure prevention ---
    server_tokens off;
    more_clear_headers 'Server';
    proxy_hide_header X-Powered-By;
    proxy_hide_header X-AspNet-Version;

    # --- Timeouts (slow-loris defence) ---
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 10s;
    keepalive_timeout 15s;

    # --- Request size limits ---
    client_max_body_size 1m;
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;

    # --- Proxy buffer limits ---
    proxy_buffer_size 4k;
    proxy_buffers 8 16k;
    proxy_busy_buffers_size 24k;
    proxy_max_temp_file_size 0;

    # --- Connection limiting ---
    limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;
    limit_conn conn_per_ip 20;
    limit_conn_status 429;

    # --- Rate limiting ---
    limit_req_zone $binary_remote_addr zone=req_per_ip:10m rate=10r/s;
    limit_req_status 429;

    # --- Logging ---
    log_format security_json escape=json
        '{'
            '"time": "$time_iso8601",'
            '"remote_addr": "$remote_addr",'
            '"request_method": "$request_method",'
            '"request_uri": "$request_uri",'
            '"status": "$status",'
            '"body_bytes_sent": "$body_bytes_sent",'
            '"request_time": "$request_time",'
            '"upstream_response_time": "$upstream_response_time",'
            '"http_user_agent": "$http_user_agent",'
            '"http_referer": "$http_referer",'
            '"server_name": "$server_name"'
        '}';

    access_log /var/log/nginx/access.json security_json;

    # --- Security headers (applied to all server blocks) ---
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # --- Use HTTP/1.1 for upstream connections ---
    proxy_http_version 1.1;
    proxy_set_header Connection "";

    # --- Include site configurations ---
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

Validate the configuration before reloading:

```bash
# Test configuration syntax
sudo nginx -t
# Expected output:
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful

# Reload without downtime
sudo nginx -s reload
```

## Expected Behaviour

After applying the hardened configuration:

```bash
# Verify server header is hidden
curl -sI https://your-domain.com | grep -i server
# Expected: no output (header removed) or "Server: " with no version

# Verify oversized request is rejected
dd if=/dev/zero bs=1M count=2 | curl -s -o /dev/null -w "%{http_code}" \
  -X POST -d @- https://your-domain.com/api/endpoint
# Expected: 413

# Verify rate limiting
for i in $(seq 1 35); do
  curl -s -o /dev/null -w "%{http_code} " https://your-domain.com/
done
echo ""
# Expected: first ~30 return 200, remaining return 429

# Verify scanner path blocking
curl -s -o /dev/null -w "%{http_code}" https://your-domain.com/.env
# Expected: 000 (connection closed, no response - code 444)

# Verify method restriction
curl -s -o /dev/null -w "%{http_code}" -X DELETE https://your-domain.com/
# Expected: 403
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| `client_max_body_size 1m` | Blocks request bodies >1MB | File upload endpoints return 413 | Override per-location for upload paths (`client_max_body_size 50m`) |
| `keepalive_timeout 15s` | Increased TCP connection churn for long-polling clients | WebSocket and SSE endpoints may disconnect | Set higher timeout in WebSocket/SSE location blocks |
| `limit_req rate=10r/s` | Blocks burst traffic from single IPs | Users behind shared NAT (corporate, mobile) all share one limit | Use API key-based limiting for authenticated endpoints |
| `limit_except GET POST` | Blocks PUT, DELETE, PATCH on restricted paths | API endpoints that need these methods return 403 | Explicitly allow needed methods per location block |
| Scanner path blocking (`.git`, `.env`) | Returns 444 for scanner traffic | May block legitimate paths containing these strings | Review against your actual routes before deploying |
| `more_clear_headers 'Server'` | Requires `headers-more` module | Module not installed by default; `nginx -t` fails if module missing | Fall back to `server_tokens off` if module unavailable |
| JSON structured logging | Slightly larger log files (~2x plain text) | More disk I/O | Log rotation handles this; structured logs are worth the space for security querying |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| `client_max_body_size` too small | File upload endpoints return 413 | Application monitoring shows 413 spike on upload paths | Add `client_max_body_size 50m;` (or appropriate size) in the upload location block |
| Rate limiting too aggressive | Legitimate users behind shared NAT get 429 | Support tickets; monitoring shows elevated 429 rate correlated with specific source CIDRs | Increase `rate` and `burst` values; or switch to API key-based rate limiting for authenticated endpoints |
| `proxy_buffer_size` too small | Large backend responses (big JSON, HTML) truncated; 502 errors | `error.log` shows `upstream sent too big header while reading response header from upstream` | Increase `proxy_buffer_size` to `8k` or `16k` for affected upstreams |
| `limit_except` blocks needed method | API endpoints return 403 for PUT/DELETE/PATCH | Application tests fail; monitoring shows 403 on API mutation endpoints | Add the missing method to `limit_except` in the affected location block |
| `more_clear_headers` module not installed | NGINX fails to start after config change | `nginx -t` returns `unknown directive "more_clear_headers"` | Install `libnginx-mod-http-headers-more-filter` (Debian/Ubuntu) or remove the directive |
| `client_header_timeout 10s` too short | Clients on very slow connections (satellite, congested mobile) time out during header send | Connection reset errors in client; `408 Request Timeout` in NGINX logs | Increase to 30s for endpoints serving very slow clients |

## When to Consider a Managed Alternative

**Transition point:** When managing NGINX configuration across 10+ virtual hosts and 3+ environments consumes more than 4-8 hours per month, or when you need capabilities that NGINX alone cannot provide: managed WAF rules that update automatically, bot management that distinguishes humans from scrapers, or DDoS mitigation that absorbs volumetric attacks before they reach your infrastructure.

**What edge/CDN providers handle:**

- **[Cloudflare](https://www.cloudflare.com):** Free tier includes basic DDoS protection and DNS. Pro ($20/month) adds WAF with managed rules (automatically updated for new attack patterns), bot management, security headers management, and rate limiting. The WAF alone eliminates the need for ModSecurity/Coraza tuning. Edge TLS termination with automatic certificates eliminates [cert-manager](https://cert-manager.io) management.

- **[Fastly](https://www.fastly.com):** Signal Sciences WAF provides real-time application-layer protection with low false positive rates and no rule tuning required. Edge compute (Compute@Edge) enables custom security logic at the CDN layer. Usage-based pricing.

- **[Bunny.net](https://bunny.net):** Simple, low-cost edge security with DDoS protection, edge rules, and token authentication. From $0.01/GB. Good for teams that need basic edge protection without the complexity of a full WAF.

**What you still control:** Backend NGINX configuration for service-to-service routing, application-specific request validation, and internal proxy settings remain your responsibility behind the edge layer. The edge provider handles the internet-facing attack surface; you handle the internal routing.

**Architecture:** Edge provider sits in front of your NGINX, absorbing reconnaissance traffic, DDoS, and known attack patterns before requests reach your infrastructure. Your hardened NGINX handles internal routing, backend-specific buffer tuning, and application-level request filtering.
