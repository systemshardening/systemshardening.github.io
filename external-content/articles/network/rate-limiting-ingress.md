---
title: "Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared"
description: "Rate limiting is the first line of defence against abuse, credential stuffing, API scraping, and denial-of-service attacks."
slug: "rate-limiting-ingress"
date: 2026-04-06
lastmod: 2026-04-06
category: "network"
tags: ["rate-limiting", "nginx", "envoy", "ingress", "load-balancer", "api-security"]
personas: ["platform-engineer", "sre"]
article_number: 37
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Kong"
    id: 86
    category: "api-gateway"
  - name: "APISIX"
    id: 89
    category: "api-gateway"
premium_pack: "rate-limiting-configs"
published: true
layout: article.njk
permalink: "/articles/network/rate-limiting-ingress/index.html"
---

# Rate Limiting at the Ingress Layer: [NGINX](https://nginx.org), [Envoy](https://www.envoyproxy.io), and Cloud Load Balancers Compared

## Problem

Rate limiting is the first line of defence against abuse, credential stuffing, API scraping, and denial-of-service attacks. However, production rate limiting is harder than it appears:

- **NGINX `limit_req` is per-instance.** If you run 3 NGINX replicas behind a load balancer, an attacker gets 3x the intended rate limit because each instance tracks state independently. At 5 replicas, the effective limit is 5x.
- **Per-IP limiting breaks behind NAT and proxies.** Corporate offices, mobile carriers, and VPN providers share a single public IP across thousands of users. A per-IP rate limit of 10 requests per second affects every user behind that IP.
- **Per-API-key limiting outgrows NGINX entirely.** NGINX has no native concept of API keys. Implementing per-key limits requires either Lua scripting, an external rate-limit service, or moving to an API gateway.
- **Connection-level and request-level limiting are confused.** `limit_conn` restricts simultaneous connections. `limit_req` restricts request rate. They protect against different attack patterns and are not interchangeable.
- **Cloud load balancer rate limiting varies wildly.** AWS ALB, GCP Cloud Armor, and Azure Front Door each have different granularity, pricing, and limitations. Choosing the wrong layer wastes budget or leaves gaps.

The result: most teams either skip rate limiting, deploy per-instance limits that provide false confidence, or hard-code aggressive limits that block legitimate traffic.

**Target systems:** NGINX 1.24+, Envoy 1.28+, [Kubernetes](https://kubernetes.io) Ingress controllers, and cloud load balancers (AWS, GCP, Azure).

## Threat Model

- **Adversary:** External attacker or automated bot with unauthenticated or authenticated HTTP access. May use distributed IPs (botnet, cloud VM rotation) to bypass per-IP limits.
- **Access level:** Network access to public-facing endpoints. For API abuse, the attacker may have valid API credentials (scraped, leaked, or from a free tier account).
- **Objective:** Credential stuffing against login endpoints, API scraping to extract bulk data, denial of service through request flooding, or resource exhaustion by triggering expensive backend operations (search queries, report generation).
- **Blast radius:** Without rate limiting, a single attacker can consume all backend capacity, affecting every legitimate user. With per-IP-only limiting, an attacker using distributed IPs bypasses all controls.

## Configuration

### NGINX: Per-IP Rate Limiting with `limit_req`

NGINX uses the leaky bucket algorithm. Requests arrive and fill a bucket at the configured rate. Excess requests are either delayed (queued) or rejected.

```nginx
# /etc/nginx/nginx.conf - http {} block

# Define rate limit zones. Each zone tracks a key (client IP) and
# enforces a rate. 10m = ~160,000 unique IPs tracked.

# General API rate: 10 requests/second per IP.
limit_req_zone $binary_remote_addr zone=api_general:10m rate=10r/s;

# Strict rate for authentication endpoints: 3 requests/second per IP.
limit_req_zone $binary_remote_addr zone=auth_strict:10m rate=3r/s;

# Webhook receiver: 50 requests/second per IP (partner integrations).
limit_req_zone $binary_remote_addr zone=webhook:10m rate=50r/s;

# Return 429 (not the default 503) when rate limit is exceeded.
limit_req_status 429;
```

Apply rate limits per location:

```nginx
# /etc/nginx/conf.d/app.conf - server {} block

# General API endpoints.
location /api/ {
    # burst=20: allow 20 requests above the rate before rejecting.
    # nodelay: process burst requests immediately instead of queuing.
    limit_req zone=api_general burst=20 nodelay;

    proxy_pass http://api-backend;
}

# Authentication endpoints: stricter limits.
location /api/auth/login {
    limit_req zone=auth_strict burst=5 nodelay;

    proxy_pass http://auth-backend;
}

location /api/auth/register {
    limit_req zone=auth_strict burst=3 nodelay;

    proxy_pass http://auth-backend;
}

# Webhook endpoints: higher limits for trusted senders.
location /webhooks/ {
    limit_req zone=webhook burst=100 nodelay;

    proxy_pass http://webhook-backend;
}
```

**Connection limiting (separate from request rate):**

```nginx
# http {} block
limit_conn_zone $binary_remote_addr zone=conn_per_ip:10m;

# server {} block
# Max 20 simultaneous connections per IP.
limit_conn conn_per_ip 20;
limit_conn_status 429;
```

### NGINX: Per-API-Key Rate Limiting

NGINX can rate-limit by API key using `map` to extract the key from a header:

```nginx
# http {} block

# Extract API key from the X-API-Key header.
# If no key is present, fall back to client IP.
map $http_x_api_key $rate_limit_key {
    default $binary_remote_addr;
    "~.+"   $http_x_api_key;
}

# Rate limit zone keyed by API key (or IP if no key).
limit_req_zone $rate_limit_key zone=api_by_key:10m rate=20r/s;
```

```nginx
# server {} block
location /api/ {
    limit_req zone=api_by_key burst=40 nodelay;
    limit_req_status 429;

    proxy_pass http://api-backend;
}
```

**Limitation:** This is still per-instance. With multiple NGINX replicas, each tracks keys independently.

### Envoy: Distributed Rate Limiting with External Service

Envoy delegates rate limiting to an external gRPC service backed by [Redis](https://redis.io). This provides true distributed rate limiting across all Envoy instances.

**Rate limit service configuration (ratelimit service using `envoyproxy/ratelimit`):**

```yaml
# ratelimit-config.yaml
# Configuration for the envoyproxy/ratelimit service.
domain: production
descriptors:
  # Per-IP rate limit: 10 requests/second.
  - key: remote_address
    rate_limit:
      unit: second
      requests_per_unit: 10

  # Per-API-key rate limit: 50 requests/second.
  - key: header_match
    value: api-key
    descriptors:
      - key: api_key
        rate_limit:
          unit: second
          requests_per_unit: 50

  # Strict limit for auth endpoints: 3 requests/second per IP.
  - key: header_match
    value: auth-endpoint
    descriptors:
      - key: remote_address
        rate_limit:
          unit: second
          requests_per_unit: 3
```

**Envoy filter configuration:**

```yaml
# envoy-ratelimit-filter.yaml
http_filters:
  - name: envoy.filters.http.ratelimit
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit
      domain: production
      failure_mode_deny: false
      timeout: 0.05s
      rate_limit_service:
        grpc_service:
          envoy_grpc:
            cluster_name: rate_limit_service
        transport_api_version: V3
```

**Rate limit service deployment (Kubernetes):**

```yaml
# ratelimit-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ratelimit
  namespace: ingress
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ratelimit
  template:
    metadata:
      labels:
        app: ratelimit
    spec:
      containers:
        - name: ratelimit
          image: envoyproxy/ratelimit:v1.4.0
          env:
            - name: RUNTIME_ROOT
              value: /data
            - name: RUNTIME_SUBDIRECTORY
              value: ratelimit
            - name: REDIS_SOCKET_TYPE
              value: tcp
            - name: REDIS_URL
              value: redis.ingress.svc.cluster.local:6379
            - name: USE_STATSD
              value: "false"
          ports:
            - containerPort: 8081
              name: grpc
          volumeMounts:
            - name: config
              mountPath: /data/ratelimit/config
      volumes:
        - name: config
          configMap:
            name: ratelimit-config
---
apiVersion: v1
kind: Service
metadata:
  name: ratelimit
  namespace: ingress
spec:
  selector:
    app: ratelimit
  ports:
    - port: 8081
      targetPort: 8081
      name: grpc
```

### Cloud Load Balancer Comparison

**AWS WAF Rate-Based Rules (on ALB or CloudFront):**

```json
{
  "Name": "RateLimitPerIP",
  "Priority": 1,
  "Action": { "Block": {} },
  "Statement": {
    "RateBasedStatement": {
      "Limit": 2000,
      "AggregateKeyType": "IP"
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "RateLimitPerIP"
  }
}
```

**AWS limitation:** Minimum evaluation window is 5 minutes. The `Limit` value is the maximum requests per 5-minute window, not per second. A limit of 2000 means 2000 requests per 5 minutes, which averages to ~6.7 requests per second but allows bursts within the window.

**GCP Cloud Armor rate limiting:**

```bash
gcloud compute security-policies rules create 1000 \
  --security-policy=my-policy \
  --expression="true" \
  --action=rate-based-ban \
  --rate-limit-threshold-count=100 \
  --rate-limit-threshold-interval-sec=60 \
  --ban-duration-sec=600 \
  --conform-action=allow \
  --exceed-action=deny-429
```

GCP Cloud Armor evaluates per-second rates with configurable ban durations. More granular than AWS, but requires a security policy attached to a backend service.

### Comparison Table

| Feature | NGINX `limit_req` | Envoy + ratelimit | AWS WAF | GCP Cloud Armor |
|---------|-------------------|-------------------|---------|-----------------|
| Distributed | No (per-instance) | Yes (Redis-backed) | Yes (managed) | Yes (managed) |
| Granularity | Per-second | Per-second | Per 5-minute window | Per-second |
| Key types | IP, header, variable | IP, header, path, custom | IP, header, query string | IP, header, region |
| Per-API-key | Via map/Lua | Native | Via custom header | Via custom header |
| Cost | Free (self-managed) | Redis + compute | $1/rule/month + $0.60/million requests | $0.006/rule/month + $0.75/million requests |
| Latency added | Sub-millisecond | 1-5ms (Redis lookup) | None (inline) | None (inline) |

## Expected Behaviour

```bash
# Test NGINX rate limiting (10r/s with burst=20).
# Send 35 requests rapidly from a single IP.
for i in $(seq 1 35); do
  curl -s -o /dev/null -w "%{http_code} " https://your-domain.com/api/test
done
echo ""
# Expected: first 30 return 200 (10 base + 20 burst), remaining 5 return 429.

# Test authentication endpoint (3r/s with burst=5).
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} " -X POST \
    -d '{"user":"test","pass":"test"}' \
    https://your-domain.com/api/auth/login
done
echo ""
# Expected: first 8 return 200 (or 401), remaining return 429.

# Verify rate limit headers are returned (if configured).
curl -sI https://your-domain.com/api/test | grep -i "retry-after"
# Note: NGINX does not send Retry-After by default.
# Envoy and API gateways typically include it.

# Verify connection limiting.
# Open 25 concurrent connections from one IP.
for i in $(seq 1 25); do
  curl -s -o /dev/null -w "%{http_code} " --max-time 5 \
    "https://your-domain.com/api/slow-endpoint" &
done
wait
# Expected: first 20 return 200, remaining 5 return 429.
```

**Monitoring rate limit effectiveness:**

```bash
# Count 429 responses in NGINX access log (last hour).
awk -v date="$(date -d '1 hour ago' '+%d/%b/%Y:%H')" \
  '$4 ~ date && $9 == 429' /var/log/nginx/access.log | wc -l

# If using structured JSON logging:
jq -r 'select(.status == "429") | .remote_addr' \
  /var/log/nginx/access.json | sort | uniq -c | sort -rn | head -20
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Per-IP limiting at 10r/s | Blocks aggressive scrapers and credential stuffing | Users behind shared NAT (corporate, mobile carrier) all share one limit | Use per-API-key limiting for authenticated endpoints; increase limits for known office IP ranges |
| NGINX per-instance limiting | No additional infrastructure required | Effective limit multiplied by replica count; 5 replicas = 5x the intended limit | Use Envoy with external rate limit service for true distributed limiting |
| Envoy + Redis rate limit | True distributed limiting across all instances | Redis becomes a single point of failure; adds 1-5ms latency per request | Deploy Redis in HA mode (Sentinel or Cluster); set `failure_mode_deny: false` so requests pass when Redis is down |
| `nodelay` on burst | Burst requests processed immediately | Backend receives full burst at once | Remove `nodelay` to queue burst requests (adds latency but smooths traffic) |
| AWS WAF 5-minute window | Simple to configure, fully managed | Allows large bursts within the window; 2000/5min allows 2000 requests in the first second | Combine with CloudFront caching or application-level limiting for burst-sensitive endpoints |
| Auth endpoint strict limits | Effective against credential stuffing | Locks out legitimate users who mistype passwords | Implement account lockout at the application layer instead of relying solely on IP-based rate limiting |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Rate limit zone memory exhausted | Oldest entries evicted; some IPs bypass limits | NGINX error log: `limit_req zone "api_general" is full` | Increase zone size (10m to 32m) or reduce the number of tracked keys |
| Redis down (Envoy rate limiting) | If `failure_mode_deny: false`, all requests pass unlimited; if `true`, all requests blocked | Redis health checks fail; rate limit metrics drop to zero | Deploy Redis with Sentinel; configure appropriate failure mode based on risk tolerance |
| Rate limit set too low | Legitimate API consumers receive 429 during normal usage | Support tickets; monitoring shows 429 rate increases during business hours (not attack pattern) | Increase rate and burst values; implement tiered limits per API key |
| Rate limit set too high | Attackers stay under the limit while still causing damage | Backend performance degrades despite rate limiting being active | Lower limits; add per-endpoint limits for expensive operations |
| `$binary_remote_addr` behind proxy | All requests appear from the load balancer IP; entire site rate-limited as one user | All users hit rate limits simultaneously | Use `$http_x_forwarded_for` or `realip_module` to extract the actual client IP; set `set_real_ip_from` for trusted proxies |
| Missing `set_real_ip_from` | NGINX trusts any `X-Forwarded-For` header, allowing attackers to spoof their IP | Attacker bypasses rate limits by sending a fake `X-Forwarded-For` | Configure `set_real_ip_from` to only trust your load balancer's IP range |

**Critical NGINX configuration for environments behind a load balancer:**

```nginx
# http {} block
# Only trust X-Forwarded-For from your load balancer.
# Replace with your actual load balancer CIDR.
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

Without this configuration, all rate limiting by `$binary_remote_addr` is useless because every request appears to come from the load balancer's IP.

## When to Consider a Managed Alternative

**Transition point:** When you need distributed rate limiting across multiple instances and maintaining the Redis-backed rate limit service costs more than a managed solution. Or when you need per-API-key limiting with tiered plans (free tier: 100r/min, paid: 1000r/min) and building this into NGINX is not sustainable.

**What managed providers handle:**

- **[Cloudflare](https://www.cloudflare.com):** Distributed rate limiting at the edge with no origin infrastructure required. Rules can target by IP, path, header, cookie, or ASN. Pricing starts at $0.05 per 10,000 requests evaluated. The edge enforcement means rate-limited traffic never reaches your infrastructure.

- **[Kong](https://konghq.com):** Rate limiting plugin with Redis or database backing for distributed enforcement. Supports per-consumer, per-route, and per-service limits. The rate-limiting-advanced plugin (Enterprise) adds sliding window counters and response header customization.

- **[APISIX](https://apisix.apache.org):** `limit-req`, `limit-conn`, and `limit-count` plugins with Redis backing for distributed enforcement. Supports per-consumer and per-route configuration. Open-source with no enterprise paywall for rate limiting features.

**What you still control:** Rate limit thresholds must be tuned based on your application's traffic patterns. No provider can auto-detect the correct rate for your login endpoint versus your search API. You define the policies; the provider handles distributed enforcement and the infrastructure.


## Related Articles

- [Hardening WebSocket Connections: Authentication, Rate Limiting, and Origin Validation](/articles/network/websocket-hardening/)
- [API Gateway Security: Authentication, Authorization, and Request Validation](/articles/network/api-gateway-security/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [NGINX Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls](/articles/network/nginx-hardening-beyond-tls/)
- [Preventing HTTP Request Smuggling: Configuration for NGINX, HAProxy, and Envoy](/articles/network/request-smuggling-prevention/)
