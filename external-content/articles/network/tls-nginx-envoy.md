---
title: "TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling"
description: "TLS misconfiguration remains one of the most common security findings in production infrastructure."
slug: "tls-nginx-envoy"
date: 2026-03-19
lastmod: 2026-03-19
category: "network"
tags: ["tls", "nginx", "envoy", "certificates", "cert-manager", "ocsp"]
personas: ["platform-engineer", "sre"]
article_number: 35
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Fastly"
    id: 71
    category: "cdn-edge"
  - name: "DNSimple"
    id: 77
    category: "dns"
premium_pack: "tls-config-pack"
published: true
layout: article.njk
permalink: "/articles/network/tls-nginx-envoy/index.html"
---

# TLS 1.3 Configuration for [NGINX](https://nginx.org) and [Envoy](https://www.envoyproxy.io): Ciphers, Certificates, and OCSP Stapling

## Problem

TLS misconfiguration remains one of the most common security findings in production infrastructure. Servers running TLS 1.0/1.1 (vulnerable to POODLE, BEAST), weak cipher suites (RC4, 3DES, CBC modes), missing OCSP stapling (clients make slow, privacy-leaking OCSP checks), and manual certificate rotation (certificates expire, services go down) are found in nearly every penetration test report.

Getting TLS right requires balancing three concerns simultaneously: security (only modern ciphers), compatibility (clients that must connect), and operations (automated certificate lifecycle). This article provides tested configurations for NGINX and Envoy that achieve an A+ SSL Labs rating with automated certificate management.

**Target systems:** NGINX 1.24+ (stable) / 1.26+ (mainline), Envoy 1.30+, [cert-manager](https://cert-manager.io) 1.14+ on [Kubernetes](https://kubernetes.io) 1.29+.

## Threat Model

- **Adversary:** Network-position attacker performing passive eavesdropping (recording encrypted traffic for future decryption), active man-in-the-middle (protocol downgrade attacks), or exploiting known protocol vulnerabilities (POODLE, CRIME, BREACH, Lucky13).
- **Access level:** Can observe or modify network traffic between client and server.
- **Objective:** Intercept credentials, session tokens, or sensitive data. Impersonate the server to steal user input. Downgrade the connection to a vulnerable protocol version.
- **Blast radius:** All traffic through the misconfigured TLS endpoint.

## Configuration

### NGINX: TLS 1.3 Only

For environments where all clients support TLS 1.3 (modern browsers, Go/Python/Node clients, mobile apps on iOS 12.2+ and Android 10+):

```nginx
# /etc/nginx/conf.d/tls-hardening.conf
# TLS 1.3 only - maximum security, modern clients only.

ssl_protocols TLSv1.3;

# TLS 1.3 cipher suites are NOT configurable in NGINX - the protocol
# mandates the cipher suite during the handshake. All three TLS 1.3
# cipher suites are secure:
# - TLS_AES_256_GCM_SHA384
# - TLS_CHACHA20_POLY1305_SHA256
# - TLS_AES_128_GCM_SHA256
# You cannot and do not need to set ssl_ciphers for TLS 1.3.

# ssl_prefer_server_ciphers is not needed for TLS 1.3.
# The client and server negotiate the best suite automatically.
ssl_prefer_server_ciphers off;

# Session resumption (reduces handshake latency for returning clients).
ssl_session_cache shared:TLS:10m;
ssl_session_timeout 1h;
ssl_session_tickets off;
# Session tickets are disabled because they bypass forward secrecy
# if the ticket key is compromised. Session cache provides resumption
# without this risk.

# OCSP stapling - server fetches and caches the OCSP response,
# so clients don't need to contact the CA's OCSP responder.
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 9.9.9.9 valid=300s;
resolver_timeout 5s;

# HSTS - tell browsers to always use HTTPS.
# max-age=63072000 = 2 years. includeSubDomains applies to all subdomains.
# preload adds to browser preload list (CANNOT be undone easily).
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### NGINX: TLS 1.2 + 1.3 (Broader Compatibility)

For environments that must support older clients (Android <10, IE 11 on Windows 7, enterprise proxies):

```nginx
# TLS 1.2 and 1.3 - secure with broader compatibility.

ssl_protocols TLSv1.2 TLSv1.3;

# For TLS 1.2, cipher selection matters.
# ECDHE = forward secrecy. AES-GCM = authenticated encryption.
# No RSA key exchange (no forward secrecy).
# No CBC modes (vulnerable to Lucky13, BEAST).
# No 3DES, RC4, or NULL ciphers.
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;

ssl_session_cache shared:TLS:10m;
ssl_session_timeout 1h;
ssl_session_tickets off;

ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 9.9.9.9 valid=300s;
resolver_timeout 5s;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### Envoy: TLS 1.3 Configuration

```yaml
# envoy-tls-listener.yaml
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
                tls_params:
                  tls_minimum_protocol_version: TLSv1_3
                  tls_maximum_protocol_version: TLSv1_3
                tls_certificates:
                  - certificate_chain:
                      filename: /etc/envoy/certs/tls.crt
                    private_key:
                      filename: /etc/envoy/certs/tls.key
                alpn_protocols:
                  - h2
                  - http/1.1
              ocsp_staple_policy: MUST_STAPLE
```

### cert-manager: Automated Certificate Lifecycle

```yaml
# cluster-issuer.yaml
# Let's Encrypt issuer using HTTP-01 challenge.
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-production
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: security@example.com
    privateKeySecretRef:
      name: letsencrypt-production-key
    solvers:
      - http01:
          ingress:
            ingressClassName: nginx
```

```yaml
# certificate.yaml
# Certificate for your domain, auto-renewed 30 days before expiry.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com-tls
  namespace: production
spec:
  secretName: example-com-tls-secret
  issuerRef:
    name: letsencrypt-production
    kind: ClusterIssuer
  dnsNames:
    - example.com
    - www.example.com
  renewBefore: 720h  # Renew 30 days before expiry
```

```bash
# Verify certificate is issued:
kubectl get certificate -n production
# Expected: READY=True

# Check certificate details:
kubectl describe certificate example-com-tls -n production

# Verify the secret contains the certificate:
kubectl get secret example-com-tls-secret -n production -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -dates
# Expected: notAfter shows ~90 days from now
```

### Performance Benchmarks

Test TLS handshake latency:

```bash
# TLS 1.3 handshake (0-RTT not measured - requires session resumption):
openssl s_client -connect example.com:443 -tls1_3 < /dev/null 2>&1 | grep "Handshake"
# Typical: 50-80ms (depends on network latency to client)

# Compare TLS 1.2 handshake:
openssl s_client -connect example.com:443 -tls1_2 < /dev/null 2>&1 | grep "Handshake"
# Typical: 60-100ms (one additional round trip for key exchange)

# TLS 1.3 saves one round trip vs TLS 1.2 (1-RTT vs 2-RTT handshake).
# On a 30ms latency connection, this saves ~30ms per new connection.
```

## Expected Behaviour

- SSL Labs test returns A+ grade
- `openssl s_client -connect example.com:443` shows TLS 1.3, correct cipher, valid chain
- OCSP stapling present: `openssl s_client -connect example.com:443 -status` shows OCSP Response Status: successful
- cert-manager renews certificates automatically 30 days before expiry
- Zero-downtime certificate rotation (NGINX reloads; Envoy hot-restarts)
- HSTS header present on all responses

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| TLS 1.3 only | Best security; 1 fewer round trip; eliminates downgrade attacks | Breaks Android <10, IE 11, very old curl (pre-7.52) | Use TLS 1.2+1.3 config if you must support old clients. Monitor TLS version distribution. |
| `ssl_session_tickets off` | No ticket-based resumption | Slightly higher CPU for returning clients (must do full handshake) | Session cache (`shared:TLS:10m`) provides resumption without the ticket key compromise risk. |
| OCSP must-staple | Guarantees OCSP freshness | If OCSP responder is unreachable and NGINX can't refresh the staple, clients may fail hard | Monitor OCSP staple freshness. Use `ssl_stapling_verify on` and check resolver connectivity. |
| HSTS with preload | Permanent HTTPS enforcement in browsers | Cannot undo preload easily. takes months to remove from browser lists | Only enable preload after confirming HTTPS works for all resources, subdomains, and legacy paths. |
| cert-manager HTTP-01 | Simple setup, works behind most load balancers | Doesn't support wildcard certificates | Use DNS-01 solver for wildcards (requires DNS provider API access). |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| cert-manager fails to renew | Certificate expires; all HTTPS connections fail with certificate error | cert-manager [Prometheus](https://prometheus.io) metrics: `certmanager_certificate_expiration_timestamp_seconds` < 7 days; cert READY=False | Check cert-manager logs. Common causes: DNS resolution, HTTP-01 challenge path blocked by ingress, rate limits. Fix and trigger manual renewal: `kubectl delete certificate && kubectl apply -f certificate.yaml`. |
| OCSP stapling fails | Clients fall back to direct OCSP check (adds 100-300ms) or fail hard (must-staple) | `openssl s_client -status` shows no OCSP response; client latency increases | Check resolver configuration (`resolver 1.1.1.1`). Verify NGINX can reach the OCSP responder. Check firewall rules for port 80/443 egress from NGINX. |
| TLS 1.3-only breaks old clients | Specific client segment can't connect | 5xx error rate increases for specific user agents; SSL handshake failure in NGINX error log | Switch to TLS 1.2+1.3 config. Monitor TLS version distribution to decide when to drop 1.2. |
| HSTS preload applied prematurely | Non-HTTPS resources (images, APIs, subdomains) fail | Browser console shows mixed content errors; users report broken pages | Fix all resources to use HTTPS. Remove preload (takes months from browser lists). As an immediate workaround: there is none. this is why preload should be added last, after thorough testing. |

## When to Consider a Managed Alternative

**Transition point:** Certificate management across 10+ domains and 3+ environments generates more than 4 hours of operational toil per month. When you need wildcard certificates across many subdomains, or when managing OCSP stapling failures and cert-manager issues becomes routine firefighting.

- **[Cloudflare](https://www.cloudflare.com):** Edge TLS termination with automatic certificates. Zero-config universal SSL. Managed OCSP. Free tier handles most use cases. This eliminates certificate management entirely for internet-facing traffic.
- **[Fastly](https://www.fastly.com):** Managed TLS at the edge. Custom certificate support. Edge compute for TLS policy.
- **[DNSimple](https://dnsimple.com):** Let's Encrypt integration with automatic DNSSEC. Simplifies DNS-01 challenge configuration for cert-manager wildcards.

**What you still control:** TLS configuration for internal service-to-service communication (mTLS, see [mTLS for Service-to-Service Communication: Istio, Linkerd, and DIY with cert-manager](/articles/network/mtls-service-mesh/)(/articles/network/mtls-service-mesh/)). Backend TLS between the edge provider and your origin. cert-manager for internal certificates not exposed to the internet.

**Premium content pack:** TLS configuration templates for NGINX and Envoy (TLS 1.3-only and TLS 1.2+1.3 variants), cert-manager ClusterIssuer configurations for Let's Encrypt, ZeroSSL, and Buypass, and Prometheus alert rules for certificate expiry monitoring.


## Related Articles

- [Preventing HTTP Request Smuggling: Configuration for NGINX, HAProxy, and Envoy](/articles/network/request-smuggling-prevention/)
- [Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared](/articles/network/rate-limiting-ingress/)
- [Hardening WebSocket Connections: Authentication, Rate Limiting, and Origin Validation](/articles/network/websocket-hardening/)
- [HTTP Security Headers in Production: CSP, HSTS, and Permissions-Policy Without Breaking Your App](/articles/network/http-security-headers/)
- [NGINX Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls](/articles/network/nginx-hardening-beyond-tls/)
