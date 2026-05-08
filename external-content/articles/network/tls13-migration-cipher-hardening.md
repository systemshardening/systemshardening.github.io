---
title: "Migrating to TLS 1.3 and Hardening Cipher Suite Selection Across Web Servers and Load Balancers"
description: "A practical guide to eliminating weak TLS configurations across Nginx, HAProxy, Apache, and Envoy: dropping legacy cipher suites, enforcing TLS 1.3, managing dual-cert deployments, and automating cipher testing in CI."
slug: tls13-migration-cipher-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - tls-1-3
  - cipher-suites
  - crypto-agility
  - nginx
  - certificate-management
personas:
  - security-engineer
  - platform-engineer
article_number: 493
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/tls13-migration-cipher-hardening/
---

# Migrating to TLS 1.3 and Hardening Cipher Suite Selection Across Web Servers and Load Balancers

## The Problem

TLS 1.2 is not broken the way RC4 is broken, but it remains a persistent source of audit findings and real-world exploits. The underlying issue is that TLS 1.2 permits a large negotiation surface: dozens of cipher suites, multiple key exchange mechanisms, and optional features that were retrofitted for backward compatibility and left residual vulnerabilities behind.

The attack history is long. **BEAST** (2011) exploited CBC mode's predictable IV chaining in TLS 1.0 and earlier, but the CBC family of cipher suites lived on in TLS 1.2. **Lucky13** (2013) demonstrated a timing side-channel against CBC-mode record decryption that allowed plaintext recovery when the attacker could generate many oracle queries — a practical threat on shared-tenant infrastructure. **POODLE** (2014) used padding oracle attacks against SSLv3's CBC implementation, and variants were later adapted to TLS 1.2 implementations that had sloppy padding validation. **RC4** cipher suites were deprecated by RFC 7465 (2015) but many servers accepted them well into the 2020s. **3DES** (SWEET32, 2016) demonstrated birthday attacks against 64-bit block ciphers after roughly 785 GB of traffic on a single session key — achievable over a long-lived HTTPS connection. **EXPORT cipher suites** (FREAK, Logjam) allowed forced downgrade to deliberately weakened 512-bit RSA and 512-bit DH keys that could be broken in hours on commodity hardware.

Beyond specific cipher weaknesses, TLS 1.2 permits RSA key exchange — the server's long-term RSA private key directly decrypts the session premaster secret. There is no forward secrecy: a single private key compromise retrospectively decrypts all recorded traffic. This is not a theoretical concern. Nation-state adversaries, and some commercial entities, have been recording TLS traffic at scale for years.

TLS 1.3, standardized in RFC 8446 (2018), eliminates this entire class of problems by design.

---

## What TLS 1.3 Actually Changes

TLS 1.3 is not a patch on TLS 1.2. It is a redesign of the handshake and record layer with backward compatibility as a secondary concern.

**Mandatory forward secrecy.** RSA key exchange is gone. The only permitted key exchange mechanisms are ECDHE (X25519 and P-256 mandated) and finite-field DHE with groups of at least 2048 bits. Every session derives its own ephemeral key material. Historical traffic cannot be decrypted even with the server's current private key.

**Removed negotiation surface.** The cipher suite in TLS 1.3 specifies only the AEAD algorithm and the hash for HKDF — it no longer bundles the key exchange or authentication algorithm. The full TLS 1.3 cipher suite list is five entries: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`. CBC mode is entirely absent. No padding oracles, no Lucky13 variants, no BEAST.

**Reduced handshake latency.** The TLS 1.3 handshake completes in 1 round-trip (1-RTT) rather than TLS 1.2's 2 round-trips. For connections to distant endpoints this is a meaningful latency reduction. The server sends its `Certificate`, `CertificateVerify`, and `Finished` in the first flight, encrypted. The client can send application data in its first flight after receiving the server's `ServerHello`.

**Encrypted handshake.** In TLS 1.2 the certificate, `ServerHello`, and `ClientHello` extensions are transmitted in plaintext, leaking server identity and protocol negotiation details to passive observers. In TLS 1.3 everything after the `ServerHello` is encrypted — the certificate, supported extensions, and ALPN negotiation are all opaque to a network observer.

### 0-RTT Early Data: The One Footgun

TLS 1.3 introduced 0-RTT resumption (RFC 8446 §2.3) to allow clients with a prior session ticket to send application data before receiving any server response. For read-heavy APIs and content delivery this eliminates a full round trip on resumed connections.

The security cost is real: **0-RTT data is not protected against replay.** An attacker who captures a TLS session ticket and the associated early data can replay that data to a server within the ticket's validity window. For GET requests to read-only endpoints this is generally acceptable. For POST, PUT, DELETE, or any state-mutating endpoint, 0-RTT replay is equivalent to request forgery.

Mitigation options:

1. **Disable 0-RTT entirely.** The operationally safe default for most application servers. Performance difference versus 1-RTT resumption is small.
2. **Use 0-RTT only for idempotent requests.** Requires the application layer to enforce that 0-RTT requests carry a header like `Early-Data: 1` (RFC 8470) and that the application explicitly rejects non-idempotent methods in that path.
3. **Limit ticket lifetime.** A shorter session ticket validity window (`ssl_session_timeout 2h` in Nginx) reduces the replay window even if 0-RTT is enabled.

For most backend applications: disable 0-RTT. The latency gain does not justify the application-layer controls required to use it safely.

---

## Nginx Configuration

Nginx uses OpenSSL's TLS stack. OpenSSL 1.1.1+ supports TLS 1.3; OpenSSL 3.x is preferred for current deployments.

```nginx
# /etc/nginx/conf.d/tls.conf

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    # Certificates — dual-cert configuration (see below)
    ssl_certificate     /etc/nginx/ssl/example.com.ecdsa.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.ecdsa.key;
    ssl_certificate     /etc/nginx/ssl/example.com.rsa.crt;
    ssl_certificate_key /etc/nginx/ssl/example.com.rsa.key;

    # Protocol versions
    ssl_protocols TLSv1.2 TLSv1.3;

    # TLS 1.3 cipher suites are controlled by OpenSSL independently.
    # The ssl_ciphers directive applies only to TLS 1.2.
    # Modern TLS 1.2 fallback: ECDHE with AESGCM or ChaCha20; no CBC, no RSA key exchange.
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;

    # Prefer server cipher order for TLS 1.2 (AESGCM before ChaCha20 on AES-NI hardware).
    # For TLS 1.3 this directive has no effect — client preference is honoured.
    ssl_prefer_server_ciphers on;

    # ECDH curve selection
    ssl_ecdh_curve X25519:prime256v1:secp384r1;

    # Session tickets and cache
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 4h;
    ssl_session_tickets off;   # Disable to avoid ticket key rotation complexity; use cache only.

    # 0-RTT: disabled. Nginx does not expose a native 0-RTT control;
    # OpenSSL 3.x disables it by default. Confirm with `openssl s_client -early_data`.

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/nginx/ssl/example.com.chain.crt;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

Key points:

- `ssl_ciphers` controls only TLS 1.2 cipher negotiation. TLS 1.3 suites are determined by OpenSSL at compile time and can be adjusted with `ssl_conf_command Ciphersuites` if needed.
- Listing both ECDSA and RSA certificate/key pairs enables dual-cert serving. Nginx 1.11+ selects the certificate type based on the client's `signature_algorithms` extension: modern clients get ECDSA, legacy clients fall back to RSA.
- `ssl_session_tickets off` removes ticket-based resumption. Combined with `ssl_session_cache`, clients resume via session IDs stored server-side. This avoids the ticket key rotation problem while preserving resumption.

---

## HAProxy Configuration

HAProxy uses its own TLS abstraction over OpenSSL or WolfSSL. The `bind` directive controls both protocol versions and cipher suites.

```
# /etc/haproxy/haproxy.cfg

global
    ssl-default-bind-options   ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-bind-ciphers   ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-server-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-server-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256

frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/ ssl-min-ver TLSv1.2 alpn h2,http/1.1
    # Per-bind overrides take precedence over global defaults.
    # Use 'crt-list' for dual-cert (ECDSA + RSA) or SNI-based cert selection.

    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

    default_backend app_backend

backend app_backend
    option ssl-hello-chk
    server app1 10.0.0.10:8443 ssl verify required ca-file /etc/haproxy/ca.crt ssl-min-ver TLSv1.2
```

HAProxy distinguishes between `ciphers` (TLS 1.2 and earlier) and `ciphersuites` (TLS 1.3) in both global defaults and per-bind overrides. This separation is important: setting `ciphers` does not affect TLS 1.3 negotiation. Both directives must be explicitly set.

For dual-cert deployments, HAProxy 2.2+ supports `crt-list` files that map certificates to SNI patterns and can specify per-certificate ECDSA/RSA preferences:

```
# /etc/haproxy/crt-list.txt
/etc/haproxy/certs/example.com.ecdsa.pem [ecdhe+aesgcm] example.com
/etc/haproxy/certs/example.com.rsa.pem   []              example.com
```

---

## Apache httpd Configuration

```apache
# /etc/apache2/sites-available/example.com-ssl.conf

<VirtualHost *:443>
    ServerName example.com

    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/example.com.ecdsa.crt
    SSLCertificateKeyFile /etc/ssl/private/example.com.ecdsa.key

    # Protocol: drop SSLv3, TLS 1.0, TLS 1.1
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    # Cipher suite for TLS 1.2 fallback
    SSLCipherSuite TLSv1.2 ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305

    # TLS 1.3 cipher suites (mod_ssl passes these to OpenSSL)
    SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

    # Honour server cipher preference for TLS 1.2 (no effect on TLS 1.3)
    SSLHonorCipherOrder on

    # OCSP stapling
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off

    # HSTS
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
</VirtualHost>

# Required for SSLUseStapling — must be outside VirtualHost
SSLStaplingCache shmcb:/var/run/ocsp(128000)
```

Apache requires `mod_ssl` compiled against OpenSSL 1.1.1+ for TLS 1.3 support. Verify with:

```bash
apache2ctl -M 2>/dev/null | grep ssl
openssl version
```

---

## Envoy Proxy Configuration

Envoy exposes TLS configuration through `DownstreamTlsContext` for listener (inbound) configuration and `UpstreamTlsContext` for cluster (outbound) configuration. Both reference `TlsParameters` for protocol version and cipher suite control.

```yaml
# envoy-tls-listener.yaml (snippet)
static_resources:
  listeners:
  - name: https_listener
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
            tls_params:
              tls_minimum_protocol_version: TLSv1_2
              tls_maximum_protocol_version: TLSv1_3
              # cipher_suites applies to TLS 1.2 only.
              # TLS 1.3 suites are negotiated by BoringSSL and cannot be restricted here.
              cipher_suites:
                - ECDHE-ECDSA-AES128-GCM-SHA256
                - ECDHE-RSA-AES128-GCM-SHA256
                - ECDHE-ECDSA-AES256-GCM-SHA384
                - ECDHE-RSA-AES256-GCM-SHA384
                - ECDHE-ECDSA-CHACHA20-POLY1305
                - ECDHE-RSA-CHACHA20-POLY1305
              ecdh_curves:
                - X25519
                - P-256
            tls_certificates:
            - certificate_chain:
                filename: /etc/envoy/certs/example.com.ecdsa.crt
              private_key:
                filename: /etc/envoy/certs/example.com.ecdsa.key
            - certificate_chain:
                filename: /etc/envoy/certs/example.com.rsa.crt
              private_key:
                filename: /etc/envoy/certs/example.com.rsa.key
          require_client_certificate: false
```

Envoy uses BoringSSL, Google's TLS library forked from OpenSSL. BoringSSL's TLS 1.3 implementation does not expose cipher suite configuration to the application layer — all five standard TLS 1.3 suites are available and BoringSSL selects based on hardware capability. The `cipher_suites` field in `TlsParameters` applies only to TLS 1.2.

---

## ECDSA vs RSA: Dual-Certificate Deployment

RSA certificates with 2048-bit keys remain the baseline for compatibility. ECDSA certificates with P-256 keys offer equivalent security with smaller key sizes, faster handshakes, and lower CPU utilization — particularly at scale on edge nodes handling millions of TLS handshakes per day.

Modern clients (all current browsers, curl, recent OpenSSL) advertise ECDSA support via the `signature_algorithms` and `signature_algorithms_cert` extensions in the `ClientHello`. Servers that hold both certificate types can select the ECDSA certificate for these clients and fall back to RSA for legacy clients (older Android WebViews, embedded devices, Java before 7u6).

Generate both certificate types and configure them as shown in the Nginx and Envoy examples above. Each server presents only one certificate per handshake; the selection logic is handled by the TLS library.

Certificate issuance via ACME (Let's Encrypt, ZeroSSL):

```bash
# Using acme.sh with dual-cert support
acme.sh --issue -d example.com --keylength 2048 -w /var/www/acme \
    --cert-file      /etc/nginx/ssl/example.com.rsa.crt \
    --key-file       /etc/nginx/ssl/example.com.rsa.key \
    --fullchain-file /etc/nginx/ssl/example.com.rsa.chain.crt

acme.sh --issue -d example.com --keylength ec-256 -w /var/www/acme \
    --cert-file      /etc/nginx/ssl/example.com.ecdsa.crt \
    --key-file       /etc/nginx/ssl/example.com.ecdsa.key \
    --fullchain-file /etc/nginx/ssl/example.com.ecdsa.chain.crt
```

For Kubernetes environments with cert-manager, two `Certificate` resources targeting the same ACME `ClusterIssuer` with different `privateKey.algorithm` fields achieve the same result:

```yaml
# cert-manager dual-cert example
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com-ecdsa
spec:
  secretName: example-com-ecdsa-tls
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - example.com
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-com-rsa
spec:
  secretName: example-com-rsa-tls
  privateKey:
    algorithm: RSA
    size: 2048
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - example.com
```

---

## HSTS and Certificate Pinning

**HTTP Strict Transport Security** instructs browsers to refuse HTTP connections and refuse to connect over TLS with certificate errors for the specified duration.

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

- `max-age=63072000`: two years, the minimum required for preload list inclusion.
- `includeSubDomains`: all subdomains must also be HTTPS-capable before enabling this.
- `preload`: signals intent to be included in browsers' hardcoded HSTS preload lists. Submit at [hstspreload.org](https://hstspreload.org). Once submitted, **removal is slow and painful** — browsers ship a new release without the entry, and users on older browsers remain pinned. Do not add `preload` until you are confident the domain and all its subdomains will be HTTPS-only indefinitely.

For a staged rollout:

1. Start with `max-age=300` (five minutes). Monitor for HTTP breakage on subdomains.
2. Increase to `max-age=86400`, then `max-age=2592000`.
3. Add `includeSubDomains` only after all subdomains serve valid HTTPS.
4. Set `max-age=63072000` and submit for preload.

**Certificate pinning** (`Expect-CT`, Public Key Pinning via `HPKP`) is largely deprecated for web applications. `HPKP` was removed from Chrome in 2017 and Firefox in 2018 due to the operational risk of bricking a site permanently if the pinned key is lost. `Expect-CT` was deprecated in Chrome 100 (2022) as Certificate Transparency is now enforced at the CA level without client-side pinning.

For internal services (mTLS between microservices, internal APIs), application-level certificate pinning via pinned CA certificates in the trust store remains appropriate and is implemented at the TLS library level rather than via HTTP headers.

---

## Testing and CI Integration

### Manual Testing

**sslyze** (Python, installable via pip):

```bash
pip install sslyze
python -m sslyze example.com:443 \
    --tlsv1_2 --tlsv1_3 \
    --certinfo --robot --heartbleed \
    --openssl_ccs_injection \
    --json_out /tmp/sslyze-result.json
```

sslyze produces structured JSON output suitable for parsing in CI. Check `accepted_cipher_suites` under each `TlsResumptionSupport` and `CipherSuitesScanResult` key for any accepted CBC-mode or non-ECDHE cipher suites.

**testssl.sh** (bash, no dependencies beyond OpenSSL):

```bash
./testssl.sh --parallel --json /tmp/testssl-result.json \
    --severity MEDIUM \
    example.com:443
```

testssl.sh classifies findings by severity. A clean hardened configuration should produce zero MEDIUM or HIGH severity findings. The `--cipher-per-proto` flag lists accepted cipher suites per protocol version.

**SSL Labs API** for automated scanning:

```bash
#!/usr/bin/env bash
# ci-tls-check.sh — integrates with CI pipelines
HOST="${1:?usage: $0 <hostname>}"
API="https://api.ssllabs.com/api/v3"

# Trigger scan
curl -sf "${API}/analyze?host=${HOST}&startNew=on&all=done" > /dev/null

# Poll until complete (max 10 minutes)
for i in $(seq 1 60); do
    STATUS=$(curl -sf "${API}/analyze?host=${HOST}" | jq -r '.status')
    [[ "${STATUS}" == "READY" ]] && break
    [[ "${STATUS}" == "ERROR" ]] && { echo "SSL Labs scan error"; exit 1; }
    sleep 10
done

# Extract grade
GRADE=$(curl -sf "${API}/analyze?host=${HOST}" | jq -r '.endpoints[0].grade')
echo "SSL Labs grade for ${HOST}: ${GRADE}"

# Fail CI if grade is below A
case "${GRADE}" in
    A|A+) echo "PASS"; exit 0 ;;
    *)    echo "FAIL: grade ${GRADE} does not meet minimum A"; exit 1 ;;
esac
```

SSL Labs scans are rate-limited and require network access to the Qualys scanning infrastructure. For internal services or air-gapped environments, use sslyze or testssl.sh against internal endpoints.

### Automated Cipher Regression in CI

For a Nginx-based deployment, a lightweight regression test using openssl:

```bash
#!/usr/bin/env bash
# check-no-cbc.sh — assert no CBC cipher suites are accepted on TLS 1.2

HOST="${1:?usage: $0 <hostname>}"
PORT="${2:-443}"

CBC_CIPHERS="ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA"

RESULT=$(echo Q | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -tls1_2 \
    -cipher "${CBC_CIPHERS}" \
    2>&1)

if echo "${RESULT}" | grep -q "^Cipher is"; then
    ACCEPTED=$(echo "${RESULT}" | grep "^Cipher is")
    echo "FAIL: CBC cipher suite accepted on ${HOST}: ${ACCEPTED}"
    exit 1
else
    echo "PASS: No CBC cipher suites accepted on ${HOST}"
fi
```

Run this script as a post-deployment gate in your CI/CD pipeline. It fails the pipeline if the server accepts any CBC-mode cipher under TLS 1.2, catching configuration regressions before they reach production.

---

## Migration Checklist

Before cutting over to TLS 1.3-preferred configuration:

```bash
# 1. Verify OpenSSL version supports TLS 1.3
openssl version  # Must be 1.1.1 or later

# 2. Check current Nginx TLS configuration
nginx -T 2>/dev/null | grep -E 'ssl_protocols|ssl_ciphers|ssl_prefer'

# 3. Scan current cipher suite acceptance (no install required)
openssl s_client -connect example.com:443 -tls1_2 2>&1 | grep "Cipher is"
openssl s_client -connect example.com:443 -tls1_3 2>&1 | grep "Cipher is"

# 4. Check if TLS 1.0/1.1 are currently accepted (should not be)
openssl s_client -connect example.com:443 -tls1 2>&1 | grep -E "alert|Cipher"
openssl s_client -connect example.com:443 -tls1_1 2>&1 | grep -E "alert|Cipher"

# 5. Validate OCSP stapling is functioning
openssl s_client -connect example.com:443 -status 2>&1 | grep -A 10 "OCSP Response"

# 6. Confirm HSTS header is present
curl -sI https://example.com | grep -i strict-transport
```

The primary compatibility risk when dropping TLS 1.0 and 1.1 is legacy clients: Android 4.x, IE 10 and below on Windows Vista, Java 6/7 without explicit TLS 1.2 configuration. Analytics data on your current client distribution should drive the timeline. For most B2B and developer-facing services, TLS 1.0/1.1 traffic is under 0.1% of sessions by 2026 and dropping it is low-risk.

The primary risk when dropping CBC-mode TLS 1.2 cipher suites is Java clients using the default `SSLContext`. Java 8 before update 261 does not enable TLS 1.2 GCM suites by default. Java applications that control their own `SSLContext` configuration may need to be updated alongside server-side changes.

---

## Summary

Migrating to TLS 1.3 with hardened TLS 1.2 fallback eliminates an entire attack surface that has accumulated two decades of exploits: CBC padding oracles, RSA key exchange without forward secrecy, downgrade attacks to export-grade cipher suites, and passive decryption of recorded traffic. The configuration changes are mechanical — a handful of directives across Nginx, HAProxy, Apache, and Envoy — but the operational discipline matters: track what you change, test with sslyze or testssl.sh before and after, and integrate cipher suite checks into your CD pipeline so configuration drift is caught automatically.

The dual-cert deployment pattern (ECDSA for modern clients, RSA for legacy fallback) is the correct long-term architecture. ECDSA certificates are smaller, faster, and will remain the preferred type as RSA key sizes continue to grow. Treat the RSA certificate as a temporary compatibility layer with an end-of-life plan tied to your client analytics.

HSTS preload list submission is a one-way door. Set a short `max-age` first, monitor, extend gradually, and only submit for preload when you are confident the domain will be HTTPS-only for its lifetime.
