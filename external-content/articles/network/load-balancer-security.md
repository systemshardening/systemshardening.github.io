---
title: "Load Balancer Security: Health Check Abuse, Connection Draining, and TLS Termination"
description: "Load balancers sit at the most critical point in your infrastructure: every external request passes through them."
slug: "load-balancer-security"
date: 2026-04-02
lastmod: 2026-04-02
category: "network"
tags: ["load-balancer", "haproxy", "nginx", "tls-termination", "health-checks", "x-forwarded-for", "proxy-protocol"]
personas: ["sre", "platform-engineer"]
article_number: 47
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
published: true
layout: article.njk
permalink: "/articles/network/load-balancer-security/index.html"
---

# Load Balancer Security: Health Check Abuse, Connection Draining, and TLS Termination

## Problem

Load balancers sit at the most critical point in your infrastructure: every external request passes through them. Their security configuration is often treated as a networking concern rather than a security concern, leading to gaps that affect the entire stack:

- **Health check endpoints leak internal state.** A `/health` endpoint that returns `{"database": "connected", "redis": "connected", "queue": "3,421 pending"}` tells an attacker your exact backend architecture and current load.
- **TLS termination at the load balancer creates a plaintext segment.** Traffic is encrypted from the client to the LB, then forwarded in plaintext to backends. Anyone with network access between the LB and backends can sniff all traffic.
- **Source IP is lost after proxying.** Without proper configuration, backend applications see the load balancer's IP as the client IP. All audit logs show the same source address. Rate limiting by IP becomes impossible.
- **`X-Forwarded-For` is trivially spoofable.** Clients can inject arbitrary IP addresses in the `X-Forwarded-For` header before the request reaches the load balancer, bypassing IP-based access controls.
- **Connection draining misconfiguration routes requests to dying instances.** During deployments, requests hit instances that are shutting down, causing errors and timeouts.
- **DDoS amplification through open health checks.** Publicly accessible health check endpoints can be used for HTTP reflection attacks.

**Target systems:** [HAProxy](https://www.haproxy.org), [NGINX](https://nginx.org), cloud load balancers (ALB, NLB, GCP LB), and [Kubernetes](https://kubernetes.io) Ingress controllers.

## Threat Model

- **Adversary:** External attacker performing reconnaissance (health check probing), IP spoofing (X-Forwarded-For manipulation), or denial of service. Internal attacker sniffing plaintext traffic between LB and backends.
- **Access level:** Unauthenticated network access to the load balancer's public IP. Potential network access to the LB-to-backend segment if on the same network.
- **Objective:** Enumerate backend architecture through health check responses. Bypass IP-based rate limiting or access controls by spoofing source IP. Intercept sensitive data on the plaintext LB-to-backend path. Cause service disruption during deployments through draining misconfiguration.
- **Blast radius:** All services behind the load balancer. IP spoofing affects every service that trusts `X-Forwarded-For` for access control or logging.

## Configuration

### Securing Health Check Endpoints

Health checks should be accessible only to the load balancer, not to the public internet. They should reveal minimal information about backend state.

Minimal health check endpoint (return only status code, no body details):

```python
# health.py - Minimal health check for production
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/healthz')
def health():
    # Return 200 if the service can handle requests.
    # Do NOT include dependency status in the response body.
    # Use separate, internal-only endpoints for detailed checks.
    return '', 200

@app.route('/readyz')
def ready():
    # Check only whether this instance can serve traffic.
    # If the database is down, this service cannot serve, so return 503.
    try:
        db.execute('SELECT 1')
        return '', 200
    except Exception:
        return '', 503

# INTERNAL ONLY: detailed health for debugging.
# This endpoint must NOT be routed through the public LB.
@app.route('/internal/health/detail')
def health_detail():
    return jsonify({
        'database': check_db(),
        'redis': check_redis(),
        'queue_depth': get_queue_depth(),
    })
```

NGINX configuration to restrict health check access:

```nginx
# Only allow health check access from the load balancer's IP range
# and the internal monitoring system.

server {
    listen 80;
    server_name _;

    # Public health endpoint: minimal response
    location /healthz {
        # Allow only from LB health checker IPs
        allow 10.0.0.0/8;       # Internal network
        allow 172.16.0.0/12;    # Docker/K8s networks
        deny all;

        proxy_pass http://backend;
    }

    # Detailed health endpoint: internal only
    location /internal/health/detail {
        # Only allow from monitoring namespace
        allow 10.0.50.0/24;     # Monitoring subnet
        deny all;

        proxy_pass http://backend;
    }

    # Block common health check paths that scanners probe
    location ~ ^/(status|server-status|health|info|metrics)$ {
        # If your app does not use these paths, block them.
        # If you do use /metrics, restrict to Prometheus scraper IPs.
        allow 10.0.50.0/24;
        deny all;
    }
}
```

HAProxy health check configuration that does not expose detailed state:

```haproxy
# HAProxy health check configuration
backend app_servers
    mode http
    balance roundrobin

    # Health check: simple HTTP GET, expect 200.
    # Do not use a path that returns detailed health info.
    option httpchk GET /healthz HTTP/1.1\r\nHost:\ localhost

    # Mark server as down after 3 consecutive failures.
    # Mark server as up after 2 consecutive successes.
    default-server inter 5s fall 3 rise 2

    server app1 10.0.1.10:8080 check
    server app2 10.0.1.11:8080 check
    server app3 10.0.1.12:8080 check
```

### Source IP Preservation

The load balancer must correctly convey the original client IP to backends. There are two approaches: `X-Forwarded-For` header manipulation and PROXY protocol.

**X-Forwarded-For: overwrite, do not append.**

The critical mistake is appending to an existing `X-Forwarded-For` header. If the client sends `X-Forwarded-For: 1.2.3.4`, a naive LB appends the real client IP, producing `X-Forwarded-For: 1.2.3.4, 203.0.113.50`. The backend reads `1.2.3.4` (the first entry) as the client IP, which the attacker controls.

HAProxy: set, not add:

```haproxy
frontend http_front
    bind *:443 ssl crt /etc/haproxy/certs/site.pem

    # DELETE any existing X-Forwarded-For from the client.
    # Then set it to the actual client IP.
    http-request del-header X-Forwarded-For
    http-request set-header X-Forwarded-For %[src]

    # Also set X-Real-IP for backends that use it
    http-request del-header X-Real-IP
    http-request set-header X-Real-IP %[src]

    # Set X-Forwarded-Proto so backends know TLS was terminated
    http-request set-header X-Forwarded-Proto https

    default_backend app_servers
```

NGINX: use `proxy_set_header` to overwrite:

```nginx
server {
    listen 443 ssl;

    location / {
        # Overwrite X-Forwarded-For with the actual client IP.
        # Do NOT use $proxy_add_x_forwarded_for, which appends
        # to any existing value (allowing client spoofing).
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        proxy_pass http://backend;
    }
}
```

**PROXY Protocol: source IP at the TCP level.**

PROXY protocol embeds the client IP in the TCP connection itself, which cannot be spoofed by HTTP headers. Use this when you need guaranteed source IP accuracy:

```haproxy
# HAProxy: enable PROXY protocol to backends
backend app_servers
    mode http
    server app1 10.0.1.10:8080 check send-proxy-v2
    server app2 10.0.1.11:8080 check send-proxy-v2
```

```nginx
# NGINX: accept PROXY protocol from the load balancer
server {
    # proxy_protocol tells NGINX to read the PROXY protocol header
    listen 8080 proxy_protocol;

    # Use the PROXY protocol source IP for logging and headers
    set_real_ip_from 10.0.0.0/8;   # Trust PROXY protocol from LB
    real_ip_header proxy_protocol;

    location / {
        proxy_set_header X-Forwarded-For $proxy_protocol_addr;
        proxy_set_header X-Real-IP $proxy_protocol_addr;
        proxy_pass http://app;
    }
}
```

### TLS Termination Security

When the load balancer terminates TLS, the segment between the LB and backends is plaintext unless you re-encrypt.

**Option 1: Re-encryption (TLS to backend)**

```haproxy
# HAProxy: TLS termination at LB + re-encryption to backend
frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/site.pem \
        alpn h2,http/1.1 \
        ssl-min-ver TLSv1.2

    default_backend app_servers_tls

backend app_servers_tls
    mode http

    # Re-encrypt traffic to backends using TLS
    server app1 10.0.1.10:8443 check ssl \
        ca-file /etc/haproxy/certs/internal-ca.crt \
        verify required \
        sni str(app1.internal)
    server app2 10.0.1.11:8443 check ssl \
        ca-file /etc/haproxy/certs/internal-ca.crt \
        verify required \
        sni str(app2.internal)
```

**Option 2: TLS passthrough (no termination at LB)**

```haproxy
# HAProxy: TLS passthrough (LB does not decrypt)
frontend https_passthrough
    bind *:443
    mode tcp

    # Route based on SNI without decrypting
    tcp-request inspect-delay 5s
    tcp-request content accept if { req.ssl_hello_type 1 }

    use_backend app1_passthrough if { req.ssl_sni -i app1.example.com }
    use_backend app2_passthrough if { req.ssl_sni -i app2.example.com }

backend app1_passthrough
    mode tcp
    server app1 10.0.1.10:8443 check
```

**Trade-off summary:**

| Approach | Inspects HTTP? | LB can rate-limit? | Plaintext segment? | Certificate management |
|----------|---------------|--------------------|--------------------|----------------------|
| TLS termination only | Yes | Yes | LB to backend | LB only |
| TLS termination + re-encryption | Yes | Yes | None | LB + backends |
| TLS passthrough | No | No (TCP only) | None | Backends only |

### Connection Draining During Deployments

Proper connection draining prevents requests from being routed to instances that are shutting down:

```haproxy
# HAProxy connection draining configuration
defaults
    mode http
    # Drain timeout: how long to wait for in-flight requests
    # to complete on a server that is being removed.
    timeout server 30s
    timeout queue 10s

backend app_servers
    mode http
    balance roundrobin

    # Use the 'drain' keyword when taking a server offline.
    # HAProxy stops sending new connections but lets existing
    # ones complete.

    # Graceful shutdown: set server to drain state via runtime API
    # echo "set server app_servers/app1 state drain" | \
    #   socat stdio /var/run/haproxy.sock

    # Slow start: gradually increase traffic to newly added servers
    # Prevents a cold instance from receiving full load immediately.
    default-server inter 5s fall 3 rise 2 slowstart 30s

    server app1 10.0.1.10:8080 check
    server app2 10.0.1.11:8080 check
```

Kubernetes: proper pod shutdown with preStop hook:

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 60
      containers:
        - name: app
          lifecycle:
            preStop:
              exec:
                # Give the LB time to stop routing to this pod.
                # The pod remains running but stops accepting new
                # connections from the LB during this window.
                command: ["/bin/sh", "-c", "sleep 15"]
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            periodSeconds: 5
            failureThreshold: 1
```

### DDoS Prevention at the Load Balancer

```haproxy
# HAProxy: connection and rate limiting at the LB layer
frontend http_front
    bind *:443 ssl crt /etc/haproxy/certs/site.pem

    # Track connection rate per source IP
    stick-table type ip size 200k expire 30s \
        store conn_cur,conn_rate(10s),http_req_rate(10s)

    # Reject IPs with more than 100 connections per 10 seconds
    http-request track-sc0 src
    http-request deny deny_status 429 \
        if { sc0_conn_rate gt 100 }

    # Reject IPs with more than 50 HTTP requests per 10 seconds
    http-request deny deny_status 429 \
        if { sc0_http_req_rate gt 50 }

    # Reject IPs with more than 30 concurrent connections
    http-request deny deny_status 429 \
        if { sc0_conn_cur gt 30 }

    # Tarpit: slow down suspicious clients instead of immediately
    # rejecting (wastes attacker resources)
    http-request tarpit deny_status 429 \
        if { sc0_conn_rate gt 200 }

    default_backend app_servers
```

### Logging for Security Analysis

```haproxy
# HAProxy: structured logging with security-relevant fields
global
    log /dev/log local0

defaults
    mode http
    log global
    option httplog

    # Custom log format with client IP, timing, and backend info
    log-format '{"time":"%T","client_ip":"%ci","client_port":"%cp","frontend":"%f","backend":"%b","server":"%s","status":%ST,"bytes_read":%B,"request_time":%Tt,"method":"%HM","uri":"%HU","ssl_version":"%sslv","ssl_cipher":"%sslc"}'
```

## Expected Behaviour

After applying the load balancer security configuration:

```bash
# Verify health check is not publicly accessible
curl -s -o /dev/null -w "%{http_code}" https://your-domain.com/healthz
# Expected: 403 (blocked for non-LB IPs)

# Verify X-Forwarded-For is overwritten, not appended
curl -s -H "X-Forwarded-For: 1.2.3.4" https://your-domain.com/echo-headers
# Expected: X-Forwarded-For shows your real IP, not 1.2.3.4

# Verify rate limiting at the LB
for i in $(seq 1 60); do
  curl -s -o /dev/null -w "%{http_code} " https://your-domain.com/ &
done
wait
echo ""
# Expected: first ~50 return 200, remaining return 429

# Verify TLS is active between LB and backend (if re-encrypting)
# From a pod on the backend network:
tcpdump -i eth0 -A port 8443 2>/dev/null | head -20
# Expected: encrypted traffic (no readable HTTP headers in output)

# Verify connection draining during deployment
# In one terminal, start a long-running request:
curl --max-time 30 https://your-domain.com/slow-endpoint &
# In another, trigger a deployment:
kubectl rollout restart deploy/web-app
# Expected: the in-flight request completes successfully (200)
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Overwrite `X-Forwarded-For` (not append) | Removes information about upstream proxies in multi-LB chains | If you have a CDN in front of the LB, the CDN's IP becomes the "client" IP | Configure the CDN to set a trusted header (e.g., `CF-Connecting-IP`) that the LB preserves separately |
| Restrict health check to internal IPs | External monitoring services cannot check health | Third-party uptime monitors are blocked | Create a separate, minimal public endpoint (`/ping` returning only 200) or whitelist monitor IPs |
| TLS re-encryption to backends | Added latency (1-3ms per request) and CPU overhead on backends | Performance impact under high throughput | Use TLS 1.3 session resumption to minimize handshake overhead; accept the latency as the cost of encryption |
| Connection draining with 15s preStop | Deployments take 15 seconds longer per pod | Slower rollout time | Balance draining time against deployment speed; 15s is typically sufficient for most request durations |
| HAProxy rate limiting at LB | Blocks burst traffic from single IPs | Legitimate users behind shared NAT get rate-limited | Increase thresholds; use API key-based limiting at the application layer for authenticated traffic |
| TLS passthrough | LB cannot inspect HTTP traffic | No HTTP-level rate limiting, header manipulation, or routing at the LB | Only use passthrough when end-to-end encryption is mandatory and HTTP inspection is not needed |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| `X-Forwarded-For` overwrite breaks multi-proxy chain | Backend sees LB IP instead of real client IP when CDN is in front | All audit logs show the CDN's IP range as the client; rate limiting is ineffective | Configure the LB to read the CDN's trusted header (e.g., `CF-Connecting-IP`) and use that as the source |
| Health check restriction blocks the LB itself | LB cannot reach health endpoints; all backends marked unhealthy | No healthy backends; all requests fail with 503 | Add the LB's health check source IP to the allow list; verify with `curl` from the LB host |
| TLS re-encryption certificate expired on backend | LB cannot connect to backends; returns 502 | 502 error rate spikes; backend connection error in LB logs | Renew backend certificate; implement certificate expiry monitoring with alerting at 7 days remaining |
| Connection draining preStop too short | In-flight requests fail during deployment with 502 | Error rate increases during deployments; correlates with pod termination | Increase `terminationGracePeriodSeconds` and preStop sleep duration to exceed the longest expected request |
| Rate limiting too aggressive | Legitimate traffic burst (product launch, marketing campaign) gets blocked | 429 rate spikes during expected traffic events; customer reports of blocked access | Temporarily increase rate limits before known traffic events; implement dynamic rate adjustment |

## When to Consider a Managed Alternative

**Transition point:** When you need DDoS mitigation that can absorb multi-gigabit volumetric attacks, or when managing TLS certificates, health check security, and rate limiting across multiple load balancers in multiple regions exceeds your team's operational capacity.

**What managed providers handle:**

- **[Cloudflare](https://www.cloudflare.com):** DDoS mitigation absorbs volumetric and application-layer attacks before traffic reaches your load balancer. Automatic TLS certificate management eliminates certificate renewal failures. Bot management distinguishes legitimate traffic from automated abuse. IP reputation scoring provides context that a self-managed LB cannot match. Free tier includes basic DDoS protection; Pro ($20/month) adds WAF and advanced rate limiting.

**What you still control:** Internal load balancer configuration for service-to-service routing, connection draining during deployments, and backend health check logic remain your responsibility. The edge provider handles the internet-facing attack surface; your load balancer handles internal traffic distribution and deployment coordination.

**Architecture:** Cloudflare sits in front of your load balancer, absorbing DDoS and filtering malicious requests at the edge. Your HAProxy or NGINX load balancer handles backend routing, health checks, and connection draining. The edge provider sets `CF-Connecting-IP` with the real client IP; your LB uses that header (not `X-Forwarded-For`) for logging and rate limiting.


## Related Articles

- [Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared](/articles/network/rate-limiting-ingress/)
- [Preventing HTTP Request Smuggling: Configuration for NGINX, HAProxy, and Envoy](/articles/network/request-smuggling-prevention/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [HTTP Security Headers in Production: CSP, HSTS, and Permissions-Policy Without Breaking Your App](/articles/network/http-security-headers/)
- [NGINX Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls](/articles/network/nginx-hardening-beyond-tls/)
