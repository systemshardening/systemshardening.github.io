---
title: "Post-Quantum TLS 1.3 in Production: Deploying X25519+ML-KEM-768 with OpenSSL 3.5, NGINX, and HAProxy"
description: "OpenSSL 3.5 (April 2025) ships ML-KEM as a built-in provider — the first production-ready release for PQC TLS without patching. This guide deploys hybrid X25519+ML-KEM-768 key exchange on NGINX and HAProxy, validates PQC negotiation with clients, and provides a rollout strategy that maintains compatibility with non-PQC clients."
slug: tls-post-quantum-hybrid-deployment
date: 2026-05-08
lastmod: 2026-05-08
category: network
tags:
  - post-quantum
  - tls-1-3
  - openssl
  - ml-kem
  - hybrid-key-exchange
personas:
  - security-engineer
  - platform-engineer
article_number: 635
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/network/tls-post-quantum-hybrid-deployment/
---

# Post-Quantum TLS 1.3 in Production: Deploying X25519+ML-KEM-768 with OpenSSL 3.5, NGINX, and HAProxy

## The Problem with Classical Key Exchange

TLS 1.3 fixed most of the negotiation complexity that plagued TLS 1.2. It removed weak cipher suites, deprecated RSA key exchange, and made forward secrecy mandatory. But it left one fundamental vulnerability intact: the key exchange itself still relies on the hardness of the elliptic curve discrete logarithm problem. X25519 and P-256 — the two default groups — are computationally infeasible to break today. Against a cryptographically relevant quantum computer (CRQC) running Shor's algorithm, neither would survive.

The threat is not abstract and it is not far-future. The practical danger is "harvest now, decrypt later" (HNDL): a nation-state adversary records TLS sessions today, stores the ciphertext, and waits for a CRQC to become available. The session key in TLS 1.3 is derived from the key exchange — once a CRQC can compute the shared secret from the public keys exchanged in the handshake, every recorded session can be decrypted retroactively. The certificate, the cipher suite, and the symmetric encryption layer are all irrelevant at that point. The key exchange is the single point of failure.

TLS 1.3 session keys are not independently archived anywhere — but the handshake messages containing key exchange parameters are transmitted in plaintext and are trivially captured at any point in the network path. Passive recording costs almost nothing at scale. The adversary does not need to break a specific target today; they can record everything and process it later when quantum hardware is available.

This changes the deployment calculus. Migrating from TLS 1.2 to 1.3 was urgent because of active vulnerabilities. Migrating to post-quantum key exchange is urgent because of the HNDL window: the data exchanged today under classical key exchange is already at risk of future decryption. Organisations handling government data, financial records, health information, or any data with a sensitivity horizon extending years into the future have a concrete obligation to act now.

## Threat Model

Three adversary scenarios drive the requirement for PQC TLS:

**Nation-state bulk collection.** Documented SIGINT programmes operate at internet exchange points and backbone interconnects, recording traffic at scale for later analysis. The target is not any specific organisation — it is the bulk corpus. Classified or sensitive HTTPS traffic intercepted today represents an investment in future intelligence collection as quantum hardware matures.

**Cloud provider internal interception.** HTTPS traffic between microservices in a cloud environment transits provider-controlled network fabric. TLS terminates and re-originates at load balancers, sidecars, and gateways. A motivated adversary with access to cloud infrastructure at the physical or hypervisor layer can record wire traffic including TLS handshake parameters. This is not a hypothetical: cloud provider insider threat programmes and nation-state pressure on cloud operators are both documented risk factors.

**CA compromise combined with future quantum capability.** If a certificate authority is compromised and the adversary has recorded TLS sessions from the affected certificate's lifetime, they can impersonate the server retroactively using the compromised CA's historical records. Combining a past CA compromise with a future CRQC allows reconstructing the session from archived data even if the private key was never directly exposed during the session.

In all three cases, the mitigation is identical: ensure the key exchange produces a shared secret that cannot be derived from the public handshake parameters, even by a CRQC.

## The Hybrid Approach: X25519+ML-KEM-768

ML-KEM (FIPS 203, previously called Kyber) is NIST's standardised post-quantum key encapsulation mechanism. It replaces the Diffie-Hellman-style key exchange with a lattice-based construction that is resistant to known quantum algorithms including Shor's.

Using ML-KEM alone in TLS 1.3 is technically possible but not the IETF-recommended approach during the transition period. The reason is confidence: ML-KEM is a new algorithm with a shorter cryptanalytic history than X25519. The hybrid approach — X25519MLKEM768 — combines both mechanisms so that the session key is derived from both exchanges. If either algorithm is broken (classical attack on ML-KEM, or a CRQC applied to X25519), the session remains secure because the other exchange is still sound. This is the construction specified in IETF draft-ietf-tls-hybrid-design.

The IANA-assigned codepoint for X25519MLKEM768 is 0x11ec. P256MLKEM768 is also available (codepoint 0x11eb) for environments requiring P-256 for FIPS compliance reasons, but X25519MLKEM768 is the preferred choice for most deployments due to X25519's stronger security properties and better performance.

## OpenSSL 3.5 and Built-in ML-KEM Support

Prior to OpenSSL 3.5, deploying PQC TLS required either the Open Quantum Safe (OQS) provider — a third-party library not suitable for production use in regulated environments — or waiting for a distribution to backport patches. OpenSSL 3.5, released in April 2025, is the first upstream release where ML-KEM (FIPS 203) is a built-in provider requiring no external dependencies or patches.

This changes the deployment model. OpenSSL 3.5 is a long-term support release and is shipping in current versions of major Linux distributions. NGINX and HAProxy built against OpenSSL 3.5 gain PQC TLS capability with no changes to the build toolchain beyond the OpenSSL version.

Verify your OpenSSL version and PQC support:

```bash
# Confirm OpenSSL 3.5 or later
openssl version

# List available KEM algorithms — should show ML-KEM-512, ML-KEM-768, ML-KEM-1024
openssl list -kem-algorithms | grep -i mlkem

# List available TLS groups including hybrid PQC groups
openssl list -groups | grep -i mlkem
# Expected output includes: X25519MLKEM768, P256MLKEM768
```

If the `list -groups` output does not include hybrid groups, the OpenSSL build does not have PQC provider support compiled in. This will be the case for OpenSSL 3.4 and earlier on all platforms.

### Choosing the Right ML-KEM Level

ML-KEM is available at three security levels:

| Variant | NIST Level | Classical Equivalent | Public Key Size | Ciphertext Size |
|---------|------------|---------------------|----------------|----------------|
| ML-KEM-512 | 1 | AES-128 | 800 bytes | 768 bytes |
| ML-KEM-768 | 3 | AES-192 | 1184 bytes | 1088 bytes |
| ML-KEM-1024 | 5 | AES-256 | 1568 bytes | 1568 bytes |

X25519MLKEM768 (ML-KEM-768 hybridised with X25519) is the browser-deployed default and the IETF working group recommendation for general TLS use. It provides NIST security level 3 post-quantum security combined with classical X25519 security.

## Installing OpenSSL 3.5

On Debian/Ubuntu systems where OpenSSL 3.5 packages are available:

```bash
apt-get update && apt-get install -y openssl libssl-dev libssl3
openssl version
# OpenSSL 3.5.x ...
```

For distributions still shipping OpenSSL 3.4, build from source:

```bash
wget https://www.openssl.org/source/openssl-3.5.0.tar.gz
tar xzf openssl-3.5.0.tar.gz
cd openssl-3.5.0
./Configure --prefix=/usr/local/openssl35 --openssldir=/usr/local/openssl35/ssl \
  enable-fips linux-x86_64
make -j$(nproc)
make install
/usr/local/openssl35/bin/openssl version
```

When building NGINX or HAProxy against a custom OpenSSL installation, pass the OpenSSL prefix to the configure step.

## NGINX Configuration with PQC Groups

### Building NGINX with OpenSSL 3.5

Most distributions package NGINX dynamically linked against the system OpenSSL. If the system ships OpenSSL 3.5, no rebuild is required. If not, rebuild NGINX against the custom OpenSSL installation:

```bash
./configure \
  --with-http_ssl_module \
  --with-openssl=/path/to/openssl-3.5.0-source \
  --with-openssl-opt="enable-fips" \
  --prefix=/etc/nginx \
  --sbin-path=/usr/sbin/nginx
make -j$(nproc)
make install
```

Verify the resulting binary links against OpenSSL 3.5:

```bash
nginx -V 2>&1 | grep OpenSSL
# built with OpenSSL 3.5.x
```

### NGINX TLS Configuration

The `ssl_ecdh_curve` directive (retained for compatibility despite the name) controls the TLS group preference list in NGINX. The hybrid PQC group should be listed first so that PQC-capable clients negotiate it. Classical groups follow for fallback compatibility.

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;

    # TLS 1.3 only — PQC key exchange is only available in TLS 1.3
    ssl_protocols TLSv1.3;

    # Hybrid PQC group first, classical fallbacks for non-PQC clients
    # X25519MLKEM768: hybrid X25519 + ML-KEM-768 (NIST level 3 PQC)
    # P256MLKEM768: hybrid P-256 + ML-KEM-768 (for FIPS P-curve environments)
    # X25519: classical fallback for clients without PQC support
    # P-256: classical fallback of last resort
    ssl_ecdh_curve X25519MLKEM768:P256MLKEM768:X25519:P-256;

    # TLS 1.3 cipher suites (NGINX has no negotiation leverage here — browser selects)
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;

    # Session resumption (does not affect key exchange security)
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://backend;
    }
}
```

The key directive is `ssl_ecdh_curve`. The order matters: the server advertises its preference, but in TLS 1.3 the client sends a `key_share` extension containing one or more precomputed key exchange values. If the client includes a key share for the first matching group, the handshake completes in one round-trip. If not, the server sends a `HelloRetryRequest` and the client computes a key share for the server's preferred group. This is transparent to applications but adds one round-trip latency for non-PQC clients that include X25519 key shares but not X25519MLKEM768.

To avoid the retry round-trip for non-PQC clients, list both the PQC hybrid and X25519 early in the preference list:

```nginx
# Avoids HelloRetryRequest for most clients: Chrome sends both X25519MLKEM768
# and X25519 key shares by default, so this always completes in one round-trip
ssl_ecdh_curve X25519MLKEM768:X25519:P256MLKEM768:P-256;
```

### Logging the Negotiated TLS Group

Add the negotiated TLS group to your access log to monitor PQC adoption:

```nginx
http {
    log_format tls_detailed '$remote_addr - $remote_user [$time_local] '
                             '"$request" $status $body_bytes_sent '
                             '"$http_referer" "$http_user_agent" '
                             'tls=$ssl_protocol cipher=$ssl_cipher '
                             'curve=$ssl_curve';

    access_log /var/log/nginx/access.log tls_detailed;
}
```

The `$ssl_curve` variable (available in NGINX 1.21+) contains the name of the negotiated group, such as `X25519MLKEM768`.

## HAProxy Configuration with PQC Groups

HAProxy 3.x supports OpenSSL 3.5 PQC groups through standard TLS curve configuration. The terminology differs slightly but the mechanism is the same.

### Global Section

Set the default PQC group preference in the `global` section. This applies to all frontends and backends unless overridden:

```
global
    # Set default TLS curve/group preference for all bind directives
    ssl-default-bind-curves X25519MLKEM768:X25519:P256MLKEM768:P-256
    ssl-default-bind-ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.3 no-tls-tickets

    # Backend (HAProxy to origin) also benefits from PQC if origins support it
    ssl-default-server-curves X25519MLKEM768:X25519:P256MLKEM768:P-256
    ssl-default-server-options ssl-min-ver TLSv1.3

    tune.ssl.default-dh-param 2048
```

### Frontend Configuration

```
frontend https_frontend
    bind *:443 ssl crt /etc/haproxy/certs/example.com.pem alpn h2,http/1.1

    # Per-frontend override — remove PQC groups for legacy device segments
    # ssl-default-bind-curves X25519:P-256

    http-request set-header X-Forwarded-Proto https
    default_backend web_servers

frontend api_frontend
    bind *:8443 ssl crt /etc/haproxy/certs/api.example.com.pem alpn h2,http/1.1
    # Inherits global PQC group preference
    default_backend api_servers
```

### HAProxy Stats for TLS Group Monitoring

HAProxy exposes TLS session statistics through the stats socket. Query the negotiated TLS group distribution:

```bash
# Via stats socket
echo "show info" | socat stdio /var/run/haproxy/admin.sock | grep -i ssl

# Query SSL statistics
echo "show stat" | socat stdio /var/run/haproxy/admin.sock | \
  cut -d',' -f1,2,57,58 | grep -v "^#"
```

For richer per-connection TLS metadata, configure HAProxy to log the TLS group via a log-format directive:

```
defaults
    log-format "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq ssl_version=%sslv ssl_cipher=%sslc"
```

HAProxy does not expose the negotiated group name in standard log variables in all versions — check your HAProxy release notes for `%[ssl_fc_curves]` fetch method availability.

## Envoy and BoringSSL

Envoy uses BoringSSL rather than OpenSSL, which has its own PQC implementation path. BoringSSL has shipped Kyber768 (the pre-standardisation name for ML-KEM-768) support since 2023, and X25519Kyber768Draft00 is the group name used internally. As the IETF standardisation completed and IANA codepoints were finalised, BoringSSL updated to use the standard X25519MLKEM768 group name and codepoint.

Configure PQC group preference in Envoy's `DownstreamTlsContext`:

```yaml
name: envoy.transport_sockets.tls
typed_config:
  "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
  common_tls_context:
    tls_params:
      tls_minimum_protocol_version: TLSv1_3
      tls_maximum_protocol_version: TLSv1_3
      # BoringSSL group names — check your Envoy/BoringSSL version for exact names
      ecdh_curves:
        - X25519MLKEM768
        - X25519
        - P-256
    tls_certificates:
      - certificate_chain:
          filename: /etc/envoy/certs/fullchain.pem
        private_key:
          filename: /etc/envoy/certs/privkey.pem
```

Note that BoringSSL group names and OpenSSL group names may differ between versions. If Envoy rejects a group name, check the Envoy changelog for the exact string required for your version.

## Verifying PQC Negotiation

### Using openssl s_client

```bash
# Test PQC negotiation — client offers X25519MLKEM768 as preferred group
openssl s_client -connect example.com:443 \
  -groups X25519MLKEM768:X25519:P-256 \
  -tls1_3 2>&1 | grep -E "Server Temp Key|SSL-Session|Protocol"

# Successful PQC output:
# Protocol  : TLSv1.3
# Server Temp Key: X25519MLKEM768, 1216 bits

# Test fallback behaviour — client offers only classical groups
openssl s_client -connect example.com:443 \
  -groups X25519:P-256 \
  -tls1_3 2>&1 | grep "Server Temp Key"
# Server Temp Key: X25519, 253 bits
```

The key indicator is `Server Temp Key: X25519MLKEM768, 1216 bits`. The 1216-bit figure reflects the combined key material from the ML-KEM-768 and X25519 components.

### Using curl

```bash
# curl 8.9+ with OpenSSL 3.5 backend supports PQC groups
curl -v --curves X25519MLKEM768:X25519 https://example.com 2>&1 | \
  grep -i "SSL connection\|curve\|key exchange"
```

### Using nmap/testssl.sh

```bash
# testssl.sh 3.2+ includes PQC group testing
./testssl.sh --curves example.com:443
```

## Client Compatibility Matrix

| Client | PQC Support | Hybrid Group | Default Behaviour |
|--------|-------------|--------------|-------------------|
| Chrome 124+ | Yes | X25519MLKEM768 | Offers by default, falls back to X25519 |
| Firefox 132+ | Yes | X25519MLKEM768 | Offers by default, falls back to X25519 |
| Safari 18+ (macOS 15) | Partial | X25519MLKEM768 | Enabled in recent releases |
| curl 8.9+ (OpenSSL 3.5) | Yes | X25519MLKEM768 | Requires `--curves` flag or config |
| Go 1.23+ stdlib | Yes | X25519MLKEM768 | Offered by default in TLS client |
| Java 21+ (JDK) | No | — | Falls back to X25519 |
| Python 3.12 + OpenSSL 3.5 | Depends on build | X25519MLKEM768 | Inherits OpenSSL group config |
| OpenSSL 3.5 s_client | Yes | X25519MLKEM768 | Requires `-groups` flag |
| OpenSSL 3.4 and earlier | No | — | Falls back to X25519 |
| Legacy TLS inspection appliances | No | — | May fail — see Failure Modes |

The fallback behaviour for non-PQC clients is seamless: the server advertises PQC hybrid groups but also includes X25519 and P-256 in its list. Clients that do not support X25519MLKEM768 negotiate X25519 or P-256 as they always have. No configuration change is required on the client side for fallback to work correctly.

## Expected Negotiation Outcomes

| Client Type | Negotiated Group | Key Exchange Size | PQC Security Level |
|-------------|-----------------|-------------------|-------------------|
| Chrome 124+ / Firefox 132+ | X25519MLKEM768 | 1216 bits | NIST Level 3 (post-quantum) |
| Go 1.23+ application | X25519MLKEM768 | 1216 bits | NIST Level 3 (post-quantum) |
| curl 8.9+ with `--curves` | X25519MLKEM768 | 1216 bits | NIST Level 3 (post-quantum) |
| Java 21 client | X25519 | 253 bits | Classical only |
| OpenSSL 3.4 s_client | X25519 | 253 bits | Classical only |
| Legacy HTTPS client | P-256 or X25519 | 256/521 bits | Classical only |
| TLS inspection appliance (incompatible) | Handshake failure | — | See Failure Modes |

## Rollout Strategy

The rollout is designed to be zero-disruption. Non-PQC clients continue to negotiate classical groups throughout all phases.

### Phase 1: Add PQC Groups Without Priority Change

Add X25519MLKEM768 to the group list but keep X25519 first. This allows you to verify that the configuration is accepted by your load balancer and that PQC-capable clients can negotiate it without forcing them to use it:

```nginx
# Phase 1: PQC available but not preferred
ssl_ecdh_curve X25519:X25519MLKEM768:P-256;
```

Verify that NGINX starts without errors and that a PQC-capable client can negotiate X25519MLKEM768 when explicitly requesting it:

```bash
openssl s_client -connect example.com:443 -groups X25519MLKEM768 -tls1_3 2>&1 | \
  grep "Server Temp Key"
```

### Phase 2: Move PQC Hybrid to First Preference

Once Phase 1 is verified stable, move X25519MLKEM768 to first position. PQC-capable clients (Chrome, Firefox, Go applications) will now negotiate it by default. Non-PQC clients fall back transparently:

```nginx
# Phase 2: PQC preferred
ssl_ecdh_curve X25519MLKEM768:X25519:P256MLKEM768:P-256;
```

Deploy to a canary or staging environment first. Monitor error rates and TLS handshake failures in your load balancer metrics for 24-48 hours before promoting to production.

### Phase 3: Monitor and Iterate

Track the fraction of connections negotiating PQC groups in your access logs. No action is required for non-PQC clients — they will continue to negotiate classical groups indefinitely. The goal is maximising PQC coverage, not enforcing it.

```bash
# Extract negotiated TLS group distribution from NGINX access logs
grep -o 'curve=[^ ]*' /var/log/nginx/access.log | sort | uniq -c | sort -rn
# curve=X25519MLKEM768   847392
# curve=X25519            52847
# curve=P-256              3291
```

A Prometheus metric using the NGINX log exporter or Prometheus NGINX VTS module:

```yaml
# nginx-prometheus-exporter or custom log parsing
# Metric: tls_group_negotiations_total{group="X25519MLKEM768"}
# Alert if classical-only group fraction spikes — may indicate middlebox interference
```

## Trade-offs and Performance

**ClientHello size increase.** A TLS 1.3 ClientHello with X25519MLKEM768 includes an ML-KEM-768 public key of 1184 bytes in addition to the 32-byte X25519 public key. This increases the ClientHello from roughly 300-500 bytes to approximately 1300-1500 bytes. For most connections this is invisible — it still fits in a single TCP segment. High-volume HTTP/2 or HTTP/3 connections with persistent keep-alive are entirely unaffected since the TLS handshake occurs once per connection. The only meaningful impact is on high-frequency short-lived TLS connections where handshake overhead is already a concern.

**CPU overhead.** ML-KEM-768 key generation and encapsulation are lattice operations. They are significantly faster than RSA but slightly slower than X25519. On modern x86_64 hardware with AVX2 instructions, ML-KEM-768 encapsulation takes roughly 50-80 microseconds, comparable to X25519. The hybrid adds both operations, but X25519 is the dominant cost and the combined overhead is well within acceptable bounds for production TLS termination.

**Distribution availability.** OpenSSL 3.5 is shipping in Fedora 42, Ubuntu 25.04, and Debian unstable as of mid-2025. RHEL 10 and Ubuntu 24.04 LTS users may need to wait for backports or build OpenSSL from source. Check your distribution's OpenSSL version before planning a deployment timeline.

## Failure Modes

**TLS inspection appliances.** Enterprise middleboxes that perform TLS inspection (next-generation firewalls, DLP proxies, SSL offloaders) may not recognise the X25519MLKEM768 group codepoint. Some implementations reject ClientHellos containing unknown group IDs rather than ignoring them. Symptoms: TLS handshake failures logged as `unknown group` or `unsupported extension` errors; connections to the inspection appliance succeed with classical groups but fail with PQC groups in the preference list. Mitigation: identify affected traffic paths and configure a separate listener with a classical-only group list for those network segments. Alternatively, move the TLS termination endpoint behind the inspection appliance so the inspected segment uses classical TLS while the origin-to-LB segment uses PQC.

**NGINX build compatibility.** NGINX compiled against a system OpenSSL older than 3.5 will silently ignore group names it does not recognise in `ssl_ecdh_curve`. The configuration will appear to load without errors but PQC groups will not be offered. Always verify with `openssl s_client` that X25519MLKEM768 actually appears in the server's supported groups extension. Use `openssl s_client -connect host:443 -tlsextdebug -tls1_3 2>&1 | grep -A5 "supported_groups"` to inspect what the server advertises.

**HAProxy version mismatches.** HAProxy 2.x may not support all OpenSSL 3.5 TLS group names. The `ssl-default-bind-curves` directive accepts curve names resolved at startup — an unrecognised name causes a startup error with a message such as `error setting certificate verify locations`. Test the configuration in a non-production environment before deploying.

**Key share mismatch causing HelloRetryRequest latency.** If the server's first preferred group is X25519MLKEM768 but the client's default key share is only X25519, the server issues a HelloRetryRequest and the handshake takes an additional round-trip. Chrome and Firefox pre-compute key shares for both X25519MLKEM768 and X25519 to avoid this, but some TLS clients do not. Monitor P99 TLS handshake latency after enabling PQC preference to detect this pattern.

## Summary

OpenSSL 3.5 removes the last significant barrier to production PQC TLS: the dependency on external libraries or custom patches. The hybrid X25519+ML-KEM-768 deployment pattern is safe, backward-compatible with all non-PQC clients, and incrementally deployable without a flag day. The HNDL threat is real and the data being transmitted today is the data at risk — deploying PQC key exchange now protects traffic that would otherwise be retroactively vulnerable when quantum hardware matures. The configuration changes are minimal: a single directive in NGINX, a single global setting in HAProxy. The compatibility risk is negligible. The security value is permanent.

Add X25519MLKEM768 to your group preference list today. Move it to first position once you have verified it works. Log the negotiated group. The rest follows naturally.
