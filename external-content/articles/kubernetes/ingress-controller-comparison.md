---
title: "Hardening Kubernetes Ingress Controllers: NGINX, Traefik, and Envoy Compared"
description: "The ingress controller is the internet-facing entry point to a Kubernetes cluster."
slug: "ingress-controller-comparison"
date: 2026-01-23
lastmod: 2026-01-23
category: "kubernetes"
tags: ["kubernetes", "ingress", "nginx", "traefik", "envoy", "tls", "waf"]
personas: ["platform-engineer", "sre"]
article_number: 27
difficulty: "intermediate"
estimated_reading_time: 21
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "edge-security"
  - name: "Coraza"
    id: 81
    category: "waf"
  - name: "ModSecurity"
    id: 82
    category: "waf"
published: true
layout: article.njk
permalink: "/articles/kubernetes/ingress-controller-comparison/index.html"
---

# Hardening [Kubernetes](https://kubernetes.io) Ingress Controllers: [NGINX](https://nginx.org), [Traefik](https://traefik.io), and [Envoy](https://www.envoyproxy.io) Compared

## Problem

The ingress controller is the internet-facing entry point to a Kubernetes cluster. Every external HTTP request passes through it before reaching backend services. Despite this critical position, default ingress controller configurations vary widely in their security posture, and most deployments use defaults without additional hardening.

The specific risks across controllers:

- **TLS termination defaults are weak.** Default installations may accept TLS 1.0/1.1, use weak cipher suites, or serve self-signed certificates. NGINX Ingress Controller defaults to TLS 1.2 but allows several weak ciphers. Traefik defaults are better but still require explicit cipher configuration for compliance.
- **Header injection is possible without explicit configuration.** Upstream services trust headers like `X-Forwarded-For`, `X-Real-IP`, and `Host` that clients can forge. Without the ingress controller stripping or overwriting these headers, attackers can spoof source IPs, bypass IP-based access controls, or confuse routing logic.
- **HTTP request smuggling targets proxy chains.** When the ingress controller and the backend disagree on how to parse HTTP requests (Content-Length vs. Transfer-Encoding, chunked encoding handling), attackers can smuggle requests past the ingress controller's security checks directly to the backend.
- **No rate limiting or WAF by default.** None of the major ingress controllers ship with rate limiting or web application firewall rules enabled. Every endpoint is exposed to brute force attacks, credential stuffing, and application-layer exploits out of the box.
- **Server information leaks reveal versions.** Default response headers expose the server software and version (`Server: nginx/1.27.0`, `Server: Traefik`), giving attackers a specific target for known CVEs.

This article compares the security configuration of NGINX Ingress Controller, Traefik, and Envoy (via Envoy Gateway), with hardened configurations for each.

**Target systems:** Kubernetes 1.29+ with NGINX Ingress Controller 1.10+, Traefik 3.0+, or Envoy Gateway 1.0+.

## Threat Model

- **Adversary:** External attacker on the internet, or an internal attacker who has compromised a pod and is targeting the ingress controller from within the cluster.
- **Access level:** Ability to send arbitrary HTTP/HTTPS requests to the ingress controller's external IP or load balancer.
- **Objective:** Exploit weak TLS to intercept traffic (downgrade attacks), inject forged headers to bypass authentication or IP restrictions, smuggle requests past security controls, brute force authentication endpoints, exploit application vulnerabilities via unfiltered payloads, or gather reconnaissance from server information disclosure.
- **Blast radius:** A compromised ingress controller can intercept all traffic entering the cluster, modify responses, redirect users, or proxy attacker traffic to internal services. Header injection can compromise every backend service that trusts ingress-set headers.

## Configuration

### Step 1: Security Comparison Matrix

Before configuring, understand what each controller provides by default and what requires explicit configuration:

| Feature | NGINX Ingress Controller | Traefik 3.x | Envoy Gateway 1.x |
|---------|------------------------|-------------|-------------------|
| Min TLS version default | 1.2 | 1.2 | 1.2 |
| Configurable cipher suites | Yes (ConfigMap) | Yes (TLS options) | Yes (SecurityPolicy) |
| Header overwrite (X-Forwarded-For) | Overwrites by default | Overwrites by default | Overwrites by default |
| Request smuggling protection | Requires `use-http2: true` and strict parsing | Built-in HTTP/1.1 normalization | Strong by default (strict HTTP parsing) |
| Rate limiting | Annotation-based | Middleware-based | SecurityPolicy CRD |
| WAF integration | ModSecurity plugin | Plugin system (limited) | External auth filter |
| Server header suppression | ConfigMap setting | Static config | Bootstrap config |
| HSTS | Annotation-based | Middleware | SecurityPolicy |

### Step 2: Hardened NGINX Ingress Controller Configuration

Apply these settings via the ConfigMap and Ingress annotations:

```yaml
# nginx-ingress-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ingress-nginx-controller
  namespace: ingress-nginx
data:
  # TLS hardening
  ssl-protocols: "TLSv1.2 TLSv1.3"
  ssl-ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
  ssl-prefer-server-ciphers: "true"

  # Header security
  hide-headers: "X-Powered-By,Server"
  server-tokens: "false"
  use-forwarded-headers: "true"
  compute-full-forwarded-for: "true"

  # Request handling
  use-http2: "true"
  proxy-body-size: "10m"
  client-header-buffer-size: "1k"
  large-client-header-buffers: "4 8k"

  # Connection limits
  keep-alive: "75"
  keep-alive-requests: "1000"
  upstream-keepalive-connections: "320"

  # Logging for security monitoring
  log-format-upstream: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_length $request_time [$proxy_upstream_name] [$proxy_alternative_upstream_name] $upstream_addr $upstream_response_length $upstream_response_time $upstream_status $req_id'
```

Per-Ingress security annotations:

```yaml
# hardened-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-app
  namespace: production
  annotations:
    # Security headers
    nginx.ingress.kubernetes.io/configuration-snippet: |
      more_set_headers "X-Frame-Options: DENY";
      more_set_headers "X-Content-Type-Options: nosniff";
      more_set_headers "X-XSS-Protection: 0";
      more_set_headers "Referrer-Policy: strict-origin-when-cross-origin";
      more_set_headers "Permissions-Policy: camera=(), microphone=(), geolocation=()";
    # HSTS
    nginx.ingress.kubernetes.io/server-snippet: |
      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "20"
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "5"
    nginx.ingress.kubernetes.io/limit-connections: "10"
    # SSL redirect
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - app.example.com
      secretName: app-tls-cert
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web-app
                port:
                  number: 8080
```

Enable ModSecurity WAF for NGINX Ingress:

```yaml
# Add to the ConfigMap
data:
  enable-modsecurity: "true"
  enable-owasp-modsecurity-crs: "true"
  modsecurity-snippet: |
    SecRuleEngine On
    SecRequestBodyAccess On
    SecRequestBodyLimit 10485760
    SecAuditEngine RelevantOnly
    SecAuditLogRelevantStatus "^(?:5|4(?!04))"
```

### Step 3: Hardened Traefik Configuration

Configure Traefik via its [Helm](https://helm.sh) values and CRD-based middleware:

```yaml
# traefik-values.yaml (Helm)
globalArguments:
  - "--global.checknewversion=false"
  - "--global.sendanonymoususage=false"

additionalArguments:
  - "--entryPoints.web.address=:8080"
  - "--entryPoints.websecure.address=:8443"
  - "--entryPoints.websecure.http.tls=true"
  - "--entryPoints.web.http.redirections.entryPoint.to=websecure"
  - "--entryPoints.web.http.redirections.entryPoint.scheme=https"

# Disable server header
  - "--entryPoints.websecure.transport.respondingTimeouts.idleTimeout=180"

ports:
  web:
    port: 8080
  websecure:
    port: 8443
```

TLS options via CRD:

```yaml
# traefik-tls-options.yaml
apiVersion: traefik.io/v1alpha1
kind: TLSOption
metadata:
  name: hardened
  namespace: traefik
spec:
  minVersion: VersionTLS12
  maxVersion: VersionTLS13
  cipherSuites:
    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  curvePreferences:
    - CurveP256
    - CurveP384
  sniStrict: true
```

Security headers and rate limiting middleware:

```yaml
# traefik-security-middleware.yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: security-headers
  namespace: production
spec:
  headers:
    frameDeny: true
    contentTypeNosniff: true
    browserXssFilter: false
    referrerPolicy: "strict-origin-when-cross-origin"
    permissionsPolicy: "camera=(), microphone=(), geolocation=()"
    customResponseHeaders:
      Server: ""
      X-Powered-By: ""
    stsSeconds: 31536000
    stsIncludeSubdomains: true
    stsPreload: true
    forceSTSHeader: true
---
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: rate-limit
  namespace: production
spec:
  rateLimit:
    average: 20
    burst: 50
    period: 1s
    sourceCriterion:
      ipStrategy:
        depth: 1
```

Apply middleware to an IngressRoute:

```yaml
# traefik-ingressroute.yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: web-app
  namespace: production
spec:
  entryPoints:
    - websecure
  routes:
    - match: Host(`app.example.com`)
      kind: Rule
      middlewares:
        - name: security-headers
        - name: rate-limit
      services:
        - name: web-app
          port: 8080
  tls:
    secretName: app-tls-cert
    options:
      name: hardened
      namespace: traefik
```

### Step 4: Hardened Envoy Gateway Configuration

Envoy Gateway uses the Gateway API with SecurityPolicy CRDs:

```yaml
# envoy-gateway-class.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: hardened-envoy
spec:
  controllerName: gateway.envoyproxy.io/gatewayclass-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: production-gateway
  namespace: production
spec:
  gatewayClassName: hardened-envoy
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: app-tls-cert
      allowedRoutes:
        namespaces:
          from: Same
```

TLS and security policy:

```yaml
# envoy-security-policy.yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: hardened-tls
  namespace: production
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: production-gateway
  tls:
    minVersion: "1.2"
    cipherSuites:
      - ECDHE-ECDSA-AES128-GCM-SHA256
      - ECDHE-RSA-AES128-GCM-SHA256
      - ECDHE-ECDSA-AES256-GCM-SHA384
      - ECDHE-RSA-AES256-GCM-SHA384
---
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: BackendTrafficPolicy
metadata:
  name: rate-limit
  namespace: production
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: web-app
  rateLimit:
    type: Global
    global:
      rules:
        - clientSelectors:
            - headers: []
          limit:
            requests: 20
            unit: Second
```

HTTPRoute with security headers:

```yaml
# envoy-httproute.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: web-app
  namespace: production
spec:
  parentRefs:
    - name: production-gateway
  hostnames:
    - "app.example.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      filters:
        - type: ResponseHeaderModifier
          responseHeaderModifier:
            set:
              - name: X-Frame-Options
                value: DENY
              - name: X-Content-Type-Options
                value: nosniff
              - name: Referrer-Policy
                value: strict-origin-when-cross-origin
              - name: Strict-Transport-Security
                value: "max-age=31536000; includeSubDomains"
            remove:
              - Server
              - X-Powered-By
      backendRefs:
        - name: web-app
          port: 8080
```

### Step 5: Request Smuggling Mitigations

Each controller handles HTTP parsing differently. Apply these controller-specific protections:

**NGINX:** Enable strict HTTP parsing and HTTP/2 upstream:

```yaml
# Add to ConfigMap
data:
  use-http2: "true"
  proxy-http-version: "1.1"
  # Reject requests with ambiguous Content-Length/Transfer-Encoding
  server-snippet: |
    ignore_invalid_headers off;
```

**Traefik:** Traefik normalizes HTTP/1.1 requests by default. Ensure you are not forwarding raw connections:

```yaml
# traefik additional arguments
additionalArguments:
  - "--entryPoints.websecure.forwardedHeaders.insecure=false"
  - "--entryPoints.websecure.forwardedHeaders.trustedIPs=10.0.0.0/8"
```

**Envoy:** Envoy has the strongest default protections against request smuggling. It uses strict HTTP/1.1 parsing by default and rejects ambiguous requests. No additional configuration is required for basic smuggling protection.

## Expected Behaviour

After applying the hardened configurations:

- TLS connections use only TLS 1.2 or 1.3 with strong cipher suites; TLS 1.0/1.1 connections are rejected
- Response headers include HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy
- Server version headers are suppressed; responses do not reveal software or version information
- Rate limiting enforces per-IP request limits; excessive requests receive 429 (Too Many Requests) responses
- X-Forwarded-For headers are overwritten by the ingress controller, not appended to client-supplied values
- HTTP requests are redirected to HTTPS automatically
- WAF rules (when enabled) block common injection patterns and return 403 responses
- `curl -v --tlsv1.1 https://app.example.com` fails with a TLS handshake error

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| TLS 1.2 minimum | Blocks clients that only support TLS 1.0/1.1 | Very old clients (Internet Explorer 10, Android 4.x) cannot connect | These clients represent less than 0.1% of traffic. Monitor 4xx rates after enabling |
| Strict cipher suites | Only strong ciphers are used | Incompatible with clients that do not support ECDHE or AES-GCM | Test with ssllabs.com or testssl.sh before deploying. Modern browsers all support these ciphers |
| Rate limiting | Protects against brute force and DDoS | Legitimate users behind shared NAT/corporate proxies may be rate limited | Use header-based client identification where possible. Set burst values high enough for legitimate traffic spikes |
| WAF (ModSecurity/Coraza) | Blocks injection attacks and known exploit patterns | False positives block legitimate requests containing special characters or large payloads | Start in detection-only mode (SecRuleEngine DetectionOnly). Tune rules before enforcing. Exclude specific paths if needed |
| Suppressing server headers | Reduces reconnaissance information | Minimal operational impact; some monitoring tools expect the Server header | Update monitoring checks that parse the Server header |
| HSTS with long max-age | Forces HTTPS for all future connections | Misconfigured HTTPS becomes inaccessible until max-age expires | Test HTTPS thoroughly before enabling HSTS. Start with a short max-age (3600) and increase gradually |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| TLS certificate expires | All HTTPS connections fail with certificate error; browsers show security warning | Certificate monitoring alerts; ingress controller logs show TLS handshake failures | Renew the certificate and update the Kubernetes TLS secret. Use [cert-manager](https://cert-manager.io) for automatic renewal |
| Rate limiting too aggressive | Legitimate users receive 429 errors; application appears down for some users | Spike in 429 response codes in access logs; user complaints | Increase rate limit thresholds. Add trusted IP ranges to bypass lists. Review rate limit metrics |
| WAF false positives | Legitimate requests blocked with 403; form submissions or API calls fail | Application error reports from users; 403 spikes in access logs | Switch WAF to detection-only mode. Review blocked requests in the audit log. Add rule exclusions for affected paths |
| Configuration snippet injection | An attacker with Ingress creation privileges injects malicious NGINX configuration via annotations | Unexpected NGINX configuration in `/etc/nginx/nginx.conf`; ingress controller restarts | Disable `allow-snippet-annotations` in the ConfigMap (set to "false"). Use the `--enable-annotation-validation` flag |
| Ingress controller pod crash | All external traffic to the cluster is interrupted | Ingress controller pods in CrashLoopBackOff; external health checks fail | Check ingress controller logs for the crash reason. Common causes: invalid ConfigMap values, malformed annotations, or resource exhaustion. Roll back the most recent configuration change |

## When to Consider a Managed Alternative

**Transition point:** Self-managed ingress controllers require ongoing TLS certificate management, WAF rule tuning, rate limit adjustment, and security patching. When your cluster serves 20+ public endpoints or handles more than 10,000 requests per second, the operational overhead of maintaining a hardened ingress layer grows significantly. If your team spends more than 8 hours per month on ingress security configuration and incident response, edge security providers offload the highest-risk layer.

**Recommended providers:**

- **[Cloudflare](https://www.cloudflare.com):** Terminates TLS at the edge with automatic certificate management, provides built-in WAF with managed rulesets, DDoS protection, rate limiting, and bot management. The ingress controller handles only internal routing, reducing its attack surface to cluster-internal traffic only.
- **[Coraza](https://coraza.io):** Open-source WAF engine compatible with ModSecurity rules. Runs as a sidecar or plugin for ingress controllers that do not have built-in WAF support. Provides OWASP Core Rule Set compatibility without the licensing complexity of ModSecurity.
- **[ModSecurity](https://github.com/owasp-modsecurity/ModSecurity):** The established WAF engine integrated directly into NGINX Ingress Controller. Provides the OWASP Core Rule Set for broad protection against injection, XSS, and common web attacks.

**What you still control:** Backend service security, internal routing policies, per-service rate limits, and application-specific WAF rule exceptions. Edge providers handle TLS termination, global rate limiting, and DDoS absorption, but the ingress controller still controls how traffic is routed to backend services within the cluster.


## Related Articles

- [Kubelet Security Configuration: Authentication, Authorization, and Read-Only Port](/articles/kubernetes/kubelet-security/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes Admission Control: From PodSecurity Standards to Custom OPA/Kyverno Policies](/articles/kubernetes/kubernetes-admission-control/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
