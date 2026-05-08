---
title: "Encrypted Client Hello (ECH) Deployment on NGINX, Cloudflare, and Internal Edges"
description: "TLS 1.3 still leaks the destination hostname via SNI. ECH closes that gap. Browser support is now wide enough to deploy in production."
slug: "encrypted-client-hello"
date: 2026-04-27
lastmod: 2026-04-27
category: "network"
tags: ["ech", "tls", "nginx", "cloudflare", "sni", "privacy"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 175
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/network/encrypted-client-hello/index.html"
---

# Encrypted Client Hello (ECH) Deployment on NGINX, Cloudflare, and Internal Edges

## Problem

TLS 1.3 encrypts everything in the handshake except one critical field: the Server Name Indication (SNI). The SNI is sent in the client's first handshake message — `ClientHello` — in cleartext, telling the server which virtual host to serve. Anyone observing the network sees which website the user is connecting to, even though the rest of the connection is encrypted.

This single cleartext field is the basis for:

- **Network-level censorship** by ISPs and state actors that block traffic by hostname.
- **Workplace and school filtering** that allows or denies categories of sites.
- **Surveillance correlation** by observers who cannot read the data but can build profiles of who connects to which services.
- **Targeted attacks** — an on-path observer who sees a handshake to a specific service can choose to interfere only with that connection.

Encrypted Client Hello (ECH) was specified in RFC 9230 (DNS) and standardized through TLS-WG drafts that consolidated in 2024–2025. ECH wraps the entire `ClientHello` (including the SNI) inside an outer `ClientHello` that uses a "public" cleartext SNI shared by many origins. An observer sees the public SNI; only the server with the ECH key can decrypt the inner SNI and route to the actual virtual host.

Browser support arrived in production:

- **Chrome 117+** (September 2023) — gated by the `kEncryptedClientHello` flag, default-on by Chrome 122 (February 2024) for users in regions where ECH-supported endpoints exist.
- **Firefox 119+** (October 2023) — default-on for users with DNS-over-HTTPS enabled.
- **Safari 17+** (September 2024 on iOS 17.4 / macOS 14.4) — default-on with DoH or DoT.

Cloudflare has supported ECH for origin connections since 2023; Fastly and Akamai followed in 2024. Self-hosted edges with current OpenSSL (3.5+) or BoringSSL builds gained native support through 2025.

The specific gaps in a 2026 production deployment:

- Public-facing TLS endpoints continue to expose SNI in cleartext, undermining the privacy claim of HTTPS.
- DNS records (`HTTPS` / `SVCB` resource records) carrying ECH configuration are not published, so even ECH-capable clients fall back to cleartext SNI.
- ECH key rotation is manual or absent, leaving long-lived public keys that erode the privacy-by-rotation property.
- Internal mTLS endpoints leak workload-to-workload routing information to anyone with network access (a passive insider, a compromised network appliance).

This article covers ECH key generation, NGINX configuration, DNS HTTPS-record publication, key rotation, and the Cloudflare-style "outer SNI" topology for self-hosted edges.

**Target systems:** NGINX 1.27+ with OpenSSL 3.5+ ECH support, Cloudflare (managed, ECH on by default), Apache Traffic Server 10+, Caddy 2.8+ (via xcaddy with the ECH plugin), Envoy 1.32+ via BoringSSL.

## Threat Model

- **Adversary 1 — Network-level passive observer:** ISP, transit provider, public Wi-Fi operator, or state-level traffic capture. Wants to enumerate which services a user connects to.
- **Adversary 2 — Selective interference:** active attacker that observes SNI and decides whether to RST the connection, inject content, or redirect — often used for censorship or targeted disruption.
- **Adversary 3 — Insider on the internal network:** employee with TAP access, compromised IDS/IPS appliance, or malicious traffic-mirroring service that profiles east-west traffic between workloads.
- **Access level:** All adversaries have on-path passive or active capability. None have access to TLS private keys or to the data inside encrypted streams.
- **Objective:** Identify which services a client is contacting; correlate connections over time; selectively block or interfere with connections based on hostname.
- **Blast radius:** Without ECH, the entire population of connections through a network point is enumerable by hostname. With ECH plus DoH, the only metadata visible is the IP address (often shared across many sites behind a CDN or load balancer) and the public outer SNI.

## Configuration

### Step 1: Generate ECH Keys

ECH keys are HPKE-style asymmetric keys. The public key is published in a DNS `HTTPS` resource record; the private key sits at the edge.

```bash
# OpenSSL 3.5+ has native ECH key generation.
openssl ech -keygen \
  -hpke-algid-kem 0x0020 \
  -hpke-algid-kdf 0x0001 \
  -hpke-algid-aead 0x0001 \
  -public-name public.example.com \
  -out /etc/nginx/ech/key1.ech.pem

# View the corresponding ECHConfig (for the DNS record).
openssl ech -display \
  -in /etc/nginx/ech/key1.ech.pem
# ECHConfig (base64): AEX+DQBBMwAg...
```

`-public-name` is the SNI that observers will see — typically a generic hostname not associated with any specific tenant. For a multi-tenant edge, this is `cloudflare-ech.com`, `public-example.com`, or similar.

Generate a second key for rotation overlap:

```bash
openssl ech -keygen \
  -public-name public.example.com \
  -out /etc/nginx/ech/key2.ech.pem
```

ECH keys are intentionally short-lived. A rotation interval of 30-90 days strikes a balance between operational overhead and limiting the window where a leaked key can decrypt past traffic.

### Step 2: Configure NGINX for ECH

```nginx
# /etc/nginx/conf.d/ech.conf
# ECH-enabled NGINX listener. Requires OpenSSL 3.5+ and nginx 1.27+
# built with --with-http_v3_module --with-openssl=...

server {
    listen 443 ssl;
    listen 443 quic reuseport;
    http2 on;

    server_name app.example.com api.example.com web.example.com;

    ssl_certificate /etc/nginx/certs/wildcard.example.com.crt;
    ssl_certificate_key /etc/nginx/certs/wildcard.example.com.key;
    ssl_protocols TLSv1.3;

    # ECH key files. Multiple files allow rotation overlap.
    ssl_ech_keys /etc/nginx/ech/key1.ech.pem;
    ssl_ech_keys /etc/nginx/ech/key2.ech.pem;

    # Public outer SNI accepted alongside the real names.
    server_name public.example.com;

    location / {
        proxy_pass http://upstream;
    }
}

# Default server for the public SNI — serves a static page when ECH is
# absent or fails.
server {
    listen 443 ssl default_server;
    server_name public.example.com;

    ssl_certificate /etc/nginx/certs/public.example.com.crt;
    ssl_certificate_key /etc/nginx/certs/public.example.com.key;
    ssl_protocols TLSv1.3;
    ssl_ech_keys /etc/nginx/ech/key1.ech.pem;
    ssl_ech_keys /etc/nginx/ech/key2.ech.pem;

    return 200 "Public ECH endpoint\n";
}
```

Validate the configuration:

```bash
nginx -t
sudo systemctl reload nginx

# Confirm ECH is offered.
openssl s_client -connect app.example.com:443 \
  -ech_pn public.example.com \
  -ech_config_list "$(openssl ech -display -in /etc/nginx/ech/key1.ech.pem | awk '/ECHConfig/{getline; print}')"
# ...
# Server ECH: succeeded
```

### Step 3: Publish ECH in DNS HTTPS Records

Browsers learn ECH configuration from DNS `HTTPS` records. Without the record, clients fall back to cleartext SNI even when the server supports ECH.

```bash
# Encode the ECHConfigList into the HTTPS record.
ECHCONFIG=$(openssl ech -display -in /etc/nginx/ech/key1.ech.pem | \
            grep "ECHConfig" | awk '{print $NF}')

# Cloudflare API example (adapt for your DNS provider).
curl -sX POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "HTTPS",
    "name": "app.example.com",
    "content": "1 . alpn=\"h3,h2\" ipv4hint=\"203.0.113.10\" ech=\"'"$ECHCONFIG"'\"",
    "ttl": 300
  }'
```

For BIND zone files:

```
app.example.com. 300 IN HTTPS 1 . alpn="h3,h2" ipv4hint=203.0.113.10 ech="AEX+DQBBMwAg..."
```

`alpn` advertises HTTP/2 and HTTP/3 support; `ipv4hint` shortcuts a separate A query; `ech` is the base64 ECHConfigList. Browsers query for `HTTPS` records before connecting; if the record carries an `ech` parameter, the client uses ECH.

Verify the DNS record:

```bash
dig +short app.example.com type65 @1.1.1.1
# 1 . alpn="h3,h2" ipv4hint=203.0.113.10 ech="AEX+DQBBMwAg..."

# Confirm the browser sees ECH.
curl --ech true \
     --resolve app.example.com:443:203.0.113.10 \
     -v https://app.example.com 2>&1 | grep -i ech
# * ECH: yes
```

### Step 4: Rotate ECH Keys

Schedule rotation via cron or systemd timer. The pattern: generate a new key, add it to the active set, publish it in DNS, then remove the old key after the DNS TTL has expired.

```bash
#!/bin/bash
# /usr/local/bin/rotate-ech-key
# Add a new key, publish in DNS, retire the oldest.

set -euo pipefail
KEYDIR=/etc/nginx/ech
NEW_KEY="$KEYDIR/key-$(date +%Y%m%d).pem"

openssl ech -keygen \
  -public-name public.example.com \
  -out "$NEW_KEY"

# Update DNS with both old and new ECHConfig values.
NEW_ECH=$(openssl ech -display -in "$NEW_KEY" | grep ECHConfig | awk '{print $NF}')
OLDEST_KEY=$(ls -1t "$KEYDIR"/key-*.pem | tail -n 1)
OLDEST_ECH=$(openssl ech -display -in "$OLDEST_KEY" | grep ECHConfig | awk '{print $NF}')

# Combine into ECHConfigList containing both for overlap.
COMBINED=$(openssl ech -concat \
  -in "$NEW_KEY" \
  -in "$OLDEST_KEY" \
  -display | grep ECHConfigList | awk '{print $NF}')

curl -sX PATCH "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -d "{\"content\": \"1 . alpn=\\\"h3,h2\\\" ech=\\\"$COMBINED\\\"\"}"

systemctl reload nginx

# Retire keys older than 90 days.
find "$KEYDIR" -name "key-*.pem" -mtime +90 -delete
systemctl reload nginx
```

```ini
# /etc/systemd/system/rotate-ech-key.timer
[Unit]
Description=Monthly ECH key rotation

[Timer]
OnCalendar=*-*-01 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

### Step 5: Internal Edges (East-West)

Internal services benefit from ECH too — workload-to-workload connections leak SNI to network observers. The same configuration applies to internal edges, with one nuance: the public outer SNI can be a per-cluster generic name (e.g., `internal.cluster-a`) rather than a public hostname.

For Envoy:

```yaml
listener:
  filter_chains:
    - filter_chain_match:
        server_names: ["internal.cluster-a"]
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_params:
              tls_minimum_protocol_version: TLSv1_3
            ech_config:
              keys:
                - key_pem: /etc/envoy/ech/key1.pem
              public_name: internal.cluster-a
```

Service mesh control planes (Istio 1.22+, Linkerd 2.16+) integrate ECH key distribution as part of their certificate-rotation workflow.

## Expected Behaviour

| Signal | Without ECH | With ECH |
|--------|-------------|----------|
| `wireshark` view of a TLS handshake | SNI visible: `app.example.com` | SNI visible: `public.example.com`; inner SNI encrypted |
| DNS query for HTTPS record | A/AAAA only | A/AAAA + HTTPS record with `ech` parameter |
| Connection from non-ECH client | Cleartext SNI as before | Cleartext SNI to public name; falls back gracefully |
| Connection from Chrome 122+ with DoH | Cleartext SNI | Encrypted SNI |
| Connection time overhead | Baseline | +5-15 ms first connection (DNS HTTPS lookup), negligible after |
| Operator visibility into traffic by hostname | Full | Reduced to public outer SNI |

Verify the privacy improvement by capturing a handshake:

```bash
# tcpdump from a host outside the edge, replaying a fresh connection.
sudo tcpdump -i any -w /tmp/ech-test.pcap port 443 &
curl --ech true https://app.example.com >/dev/null
kill %1
tshark -r /tmp/ech-test.pcap -Y "tls.handshake.extension.type == 65037" -V | \
  grep "Encrypted Hello"
# Encrypted Client Hello extension found.
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Privacy of inner SNI | Hostname-level traffic analysis blocked | Browsers must opt in or have DoH enabled | Wait for default-on adoption (already common in Chrome/Firefox); for ECH-incapable clients, behavior is identical to TLS 1.3 today. |
| HTTPS DNS record | Standard delivery channel for ECHConfig | DNS must be DNSSEC-signed for full integrity guarantee | Sign the zone with DNSSEC; without it, an attacker who manipulates DNS can downgrade clients to cleartext SNI. |
| Multiple keys for rotation | Smooth rotation, no client errors | More key files to manage | Automate via systemd timer; align rotation with DNS TTL. |
| Outer SNI uniqueness | Forces operator to choose a public name | Selecting a public name reveals general infrastructure provider | Use a name that does not identify your organization (e.g., a CDN-shared name); for self-hosted, a generic per-region public name. |
| Operational visibility | Network observers cannot enumerate hostnames | Internal monitoring that depended on SNI also breaks | Monitor at the application layer (HTTP virtual host header) rather than at the network layer. |
| Backward compatibility | Pre-ECH clients work unchanged | Privacy benefit only for ECH-capable clients | Acceptable; the deployment causes no harm to legacy clients. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| ECH key compromise | Past-recorded ECH-encrypted SNI becomes decryptable for sessions during compromise window | Detection of key exfiltration via standard incident response | Rotate immediately. The window of exposure is limited to ECH-protected sessions during the compromise. Public-key cryptography means past sessions before the rotation are still confidential per session via TLS 1.3. |
| DNS HTTPS record missing or stale | Browsers fall back to cleartext SNI silently | DNS query returns no `ech` parameter; `curl --ech true` does not negotiate ECH | Publish or refresh the DNS record. Monitor with a synthetic check that confirms the `ech` parameter is present. |
| Key rotation gap | Old key removed before old DNS TTL expired | Browsers using cached DNS attempt ECH with an unknown key; server falls back to public-name handshake | Keep both keys active for 2-3x the DNS TTL. Use the systemd timer pattern with a delay before removal. |
| Mismatched ECHConfig and server | Browser presents an ECH that the server cannot decrypt | Server falls back to public-name; logs show ECH negotiation failure | Verify that the published `ech` parameter matches a key currently loaded by the server. |
| GREASE bug | Server rejects ECH-GREASE handshake from clients without real ECH | Connection failures from older browsers | Ensure OpenSSL/BoringSSL build supports GREASE responses. Most modern builds handle this correctly. |
| Network appliance breaks ECH | Corporate proxy or IDS interferes with the handshake | Specific network paths show ECH failures while others succeed | Identify the appliance; either configure it to permit TLS 1.3 / ECH or accept that some networks will fall back to cleartext SNI. |
| DNSSEC validation failure | Resolver rejects HTTPS record; client never learns ECHConfig | Authoritative-zone DNSSEC errors; clients see no ECH | Verify zone signing; `dig +dnssec` confirms validation. |

## Related Articles

- [TLS 1.3 on NGINX and Envoy: Secure Defaults and Cipher Selection](/articles/network/tls-nginx-envoy/)
- [HTTP/3 and QUIC Production Hardening](/articles/network/http3-quic-hardening/)
- [DNS Security with DNSSEC and CAA Records](/articles/network/dns-security-dnssec-caa/)
- [Beyond TLS: Hardening NGINX for Production Traffic](/articles/network/nginx-hardening-beyond-tls/)
- [Post-Quantum Crypto Migration Plan](/articles/cross-cutting/post-quantum-migration/)
