---
title: "OpenVPN Security Hardening: PKI, Cipher Suites, tls-crypt-v2, and Privilege Separation"
description: "OpenVPN's flexibility is also its attack surface. This guide covers PKI hardening with EC keys and OCSP, the tls-auth/tls-crypt/tls-crypt-v2 ladder, data-channel cipher configuration for OpenVPN 2.6, privilege drop, management interface protection, and per-client access control."
slug: openvpn-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - openvpn
  - vpn
  - tls
  - certificate-management
  - access-control
personas:
  - security-engineer
  - network-engineer
article_number: 497
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/openvpn-hardening/
---

# OpenVPN Security Hardening: PKI, Cipher Suites, tls-crypt-v2, and Privilege Separation

## The Problem

OpenVPN has been deployed in millions of networks for over two decades. That longevity means it carries years of default configurations, compatibility shims, and legacy cipher choices. A default `openvpn --genconfig` in 2015 would have produced a server trusting BF-CBC as the data cipher, operating as root through the entire session, exposing the management interface on an unprotected port, and using a static tls-auth key shared by every client in the deployment. A significant portion of production OpenVPN servers still run that configuration today.

OpenVPN 2.6 changed the cipher defaults, deprecated BF-CBC, and introduced Data Channel Offload (DCO) — but none of that helps deployments that were configured years ago and never revisited.

The concrete failure modes:

- **Static tls-auth keys shared by all clients.** If any client is compromised, the attacker can forge TLS-layer pre-authentication packets from any other client identity, exhausting server resources or bypassing access controls.
- **BF-CBC and CBC modes in the data channel.** OpenVPN pre-2.5 defaults to BF-CBC (Blowfish in CBC mode). Blowfish has a 64-bit block size, making it vulnerable to SWEET32 birthday attacks on long-lived sessions. CBC modes in general lack authenticated encryption, requiring a separate HMAC.
- **Root-owned process post-startup.** Many deployments skip the `user`/`group` privilege drop directives. A successful exploit of an OpenVPN vulnerability (or a plugin vulnerability) runs as root.
- **Unauthenticated management interface.** The management socket, if bound to `0.0.0.0` or left without a password, allows any local process to dynamically reconfigure the VPN, inject commands, or read connection logs including credentials.
- **No CRL or OCSP checking.** Certificates issued to devices that were lost, stolen, or decommissioned continue to authenticate unless revocation is actively checked.
- **Weak DH parameters.** Legacy deployments may include `dh dh1024.pem` — 1024-bit DH is considered broken since the Logjam attack.

**Target systems:** OpenVPN 2.5+ and 2.6+ (Linux server); Easy-RSA 3; clients on Linux, macOS, Windows, iOS, Android.

## Threat Model

- **Adversary 1 — Compromised client with shared tls-auth key:** An attacker extracts the static HMAC key from a compromised laptop. They use it to replay or forge pre-authentication packets against the server, completing TLS handshakes as phantom clients or consuming server threads in a DoS.
- **Adversary 2 — Credential theft via rogue access point:** An attacker performs a man-in-the-middle between a connecting client and the server. Without a verified server certificate chain and TLS cipher enforcement, the client connects to the attacker's OpenVPN server, revealing username/password or session keys.
- **Adversary 3 — Weak cipher downgrade:** A client configured with `cipher AES-256-CBC` but permitting fallback to `BF-CBC` is downgraded by the server during negotiation. A long-lived session accumulates enough data for a SWEET32 birthday attack.
- **Adversary 4 — Revoked certificate reuse:** An employee departs; their VPN client certificate is not revoked. Six months later, they or someone who obtained their device reconnects with the still-valid certificate.
- **Adversary 5 — Management interface abuse:** A malicious local process (compromised application, container breakout) connects to the OpenVPN management socket on localhost and issues `kill` or `client-kill` commands, or reads the client list and connection details.
- **Access level:** Adversary 1 has physical/logical access to any enrolled device. Adversary 2 is on-path. Adversaries 3 and 4 have a client device. Adversary 5 has local process execution on the VPN server.
- **Objective:** Decrypt VPN traffic, impersonate clients, gain network access to protected segments, disrupt VPN availability.
- **Blast radius:** A compromised VPN server grants network-layer access to every subnet in the push route list for every connected client.

## Configuration

### Step 1: PKI Hardening with Easy-RSA 3 and Elliptic Curve Keys

Elliptic curve keys (P-384) provide equivalent security to RSA-7680 at a fraction of the key size and handshake cost. Easy-RSA 3 supports EC natively.

```bash
# Install Easy-RSA 3.
apt-get install easy-rsa   # Debian/Ubuntu
# or: download from https://github.com/OpenVPN/easy-rsa/releases

# Initialize the PKI directory.
make-cadir /etc/openvpn/pki
cd /etc/openvpn/pki

# Configure for EC keys with P-384.
cat > vars <<'EOF'
set_var EASYRSA_ALGO         ec
set_var EASYRSA_CURVE        secp384r1
set_var EASYRSA_DIGEST       sha384
set_var EASYRSA_CA_EXPIRE    1825    # CA valid 5 years.
set_var EASYRSA_CERT_EXPIRE  365     # End-entity certs valid 1 year.
set_var EASYRSA_CRL_DAYS     30      # CRL valid 30 days; refresh before expiry.
set_var EASYRSA_KEY_SIZE     384     # Not used for EC but explicit for clarity.
EOF

# Build the CA.
./easyrsa init-pki
./easyrsa build-ca nopass   # Use a passphrase in production; store offline.

# Issue the server certificate with correct extended key usage.
./easyrsa gen-req server-vpn nopass
./easyrsa sign-req server server-vpn

# Issue per-client certificates.
./easyrsa gen-req client-alice nopass
./easyrsa sign-req client client-alice

# Generate a CRL (must be refreshed before EASYRSA_CRL_DAYS expires).
./easyrsa gen-crl
cp pki/crl.pem /etc/openvpn/server/crl.pem
chmod 640 /etc/openvpn/server/crl.pem
```

Key files to deploy to the server:

```
/etc/openvpn/server/ca.crt           # CA certificate (public)
/etc/openvpn/server/server-vpn.crt   # Server certificate
/etc/openvpn/server/server-vpn.key   # Server private key (600 permissions)
/etc/openvpn/server/crl.pem          # Certificate Revocation List
```

For OCSP, embed the OCSP URI in issued certificates:

```bash
# Add to Easy-RSA's openssl-easyrsa.cnf, under [server] and [client] extensions:
# authorityInfoAccess = OCSP;URI:http://ocsp.vpn.internal.example.com

# Validate an individual certificate against OCSP.
openssl ocsp \
  -issuer /etc/openvpn/pki/ca.crt \
  -cert /etc/openvpn/pki/issued/client-alice.crt \
  -url http://ocsp.vpn.internal.example.com \
  -text
```

Track issued certificate serial numbers in a register (a simple CSV is sufficient). When a certificate is revoked, cross-reference the serial to confirm the correct certificate was invalidated. OpenVPN logs the serial on each connection; correlate against the register in your SIEM.

### Step 2: TLS Control Channel Cipher Hardening

OpenVPN has two separate cipher layers: the **TLS control channel** (used for authentication, key exchange, and control messages) and the **data channel** (used for the actual tunnelled traffic). They are configured independently.

```conf
# /etc/openvpn/server/server.conf — TLS control channel hardening.

# Require TLS 1.2 or higher for the control channel.
tls-version-min 1.2

# Restrict control channel cipher suite to ECDHE-ECDSA with AES-256-GCM.
# This requires the server certificate to be an EC cert (Step 1).
tls-cipher ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# For OpenVPN 2.6+: the data channel cipher list (replaces the old --cipher directive).
# AES-256-GCM is AEAD; no separate --auth needed for the data channel when using GCM.
# CHACHA20-POLY1305 as a fallback for mobile clients with hardware-accelerated ChaCha.
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305

# Explicitly disable BF-CBC (Blowfish — 64-bit block, SWEET32 vulnerable).
# In OpenVPN 2.6, BF-CBC is disabled by default; make it explicit.
data-ciphers-fallback AES-256-GCM

# The auth directive sets the HMAC algorithm for the control channel's packet authentication.
# Only relevant when NOT using AEAD (GCM). With GCM data ciphers, this applies to
# control-channel packets not covered by the TLS record layer.
auth SHA256
```

Verify what the server negotiated after a client connects:

```bash
# Server log shows negotiated ciphers on connection.
journalctl -u [email protected] | grep -E 'cipher|DATA'
# Expected:
# Data Channel: using negotiated cipher 'AES-256-GCM'
# Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384

# List cipher support in the installed OpenSSL.
openssl ciphers -v 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
```

### Step 3: tls-auth, tls-crypt, and tls-crypt-v2

This is the most consequential security control many deployments skip. These directives add a cryptographic HMAC layer *before* the TLS handshake begins, preventing unauthenticated clients from consuming TLS processing resources.

**`tls-auth`** — A static HMAC key shared by all clients and the server. Any packet without a valid HMAC signature is dropped before TLS processing. Drawback: the same key is shared by every client. If one client is compromised, all clients' keys must be rotated.

**`tls-crypt`** — Combines HMAC authentication with encryption of the TLS control channel. Control messages (including the client's certificate identity during the handshake) are encrypted at this layer, not just authenticated. Still a single shared key across all clients.

**`tls-crypt-v2`** — Per-client unique HMAC + encryption keys, derived from a server master key at enrollment time. Each client holds a key unique to them. Compromise of one client's key does not affect any other client and does not require server-wide key rotation. This is the current best practice.

```bash
# Generate the tls-crypt-v2 server key (done once; keep offline backup).
openvpn --genkey tls-crypt-v2-server /etc/openvpn/server/tc2-server.key

# For each client, generate a per-client tls-crypt-v2 key.
# This produces a client key file that embeds the server key's cryptographic binding.
openvpn --tls-crypt-v2 /etc/openvpn/server/tc2-server.key \
        --genkey tls-crypt-v2-client /etc/openvpn/client/tc2-alice.key

# The client key file is included in the client's .ovpn profile (inline or as a path).
```

Server configuration:

```conf
# /etc/openvpn/server/server.conf

# Use tls-crypt-v2 with per-client keys.
# The server key is used to verify per-client keys.
tls-crypt-v2 /etc/openvpn/server/tc2-server.key

# If migrating from tls-auth or tls-crypt and cannot update all clients at once,
# tls-crypt-v2-verify allows a script to verify or reject clients during the
# pre-authentication phase (before TLS, before certificate validation).
# tls-crypt-v2-verify /etc/openvpn/server/verify-tc2.sh
```

Client configuration:

```conf
# /etc/openvpn/client/alice.ovpn (relevant snippet)
tls-crypt-v2 /etc/openvpn/client/tc2-alice.key
# Or inline:
# <tls-crypt-v2>
# [contents of tc2-alice.key]
# </tls-crypt-v2>
```

Without tls-auth/tls-crypt/tls-crypt-v2, anyone on the Internet who can reach UDP port 1194 can initiate a TLS handshake against the server. With tls-crypt-v2, the server silently drops every packet that doesn't carry a valid client-specific HMAC tag — the server doesn't even begin a TLS handshake.

### Step 4: Privilege Drop and Process Isolation

OpenVPN starts as root (to create the tun interface and modify routing tables), but it can and should drop privileges immediately after:

```conf
# /etc/openvpn/server/server.conf

# Drop to unprivileged user/group after initialization.
user nobody
group nobody

# Retain the ability to re-read the CRL after a SIGUSR2 (soft restart).
# Without persist-key, privilege drop prevents re-reading the key file on restart.
persist-key
persist-tun
```

For deeper isolation, use a chroot environment. OpenVPN will chroot into the specified directory after startup — all subsequent file access is relative to that root:

```bash
# Create a minimal chroot jail for OpenVPN.
mkdir -p /var/lib/openvpn/chroot/{tmp,dev,etc}
mknod /var/lib/openvpn/chroot/dev/null c 1 3
chmod 666 /var/lib/openvpn/chroot/dev/null

# Copy the CRL into the chroot (OpenVPN must be able to read it after chroot).
cp /etc/openvpn/server/crl.pem /var/lib/openvpn/chroot/crl.pem
```

```conf
# /etc/openvpn/server/server.conf

# chroot into the jail after startup.
chroot /var/lib/openvpn/chroot

# After chroot, CRL path is relative to the new root.
crl-verify /crl.pem
```

Combine with systemd hardening for defence-in-depth:

```ini
# /etc/systemd/system/[email protected]
[Service]
# Additional capabilities restriction — OpenVPN only needs NET_ADMIN and NET_RAW.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
```

### Step 5: Management Interface Security

The OpenVPN management interface provides a TCP socket for runtime control: listing clients, killing connections, loading new configurations. It is a high-value target for any local attacker.

```conf
# /etc/openvpn/server/server.conf

# Bind management interface to loopback ONLY.
# Never bind to 0.0.0.0 or any public interface.
management 127.0.0.1 7505

# Require a password for management interface access.
# File contains a single line: the password.
management-client-auth
# Or use a password file:
# management-hold
# management-query-passwords
```

Set the management password in a file readable only by the openvpn process:

```bash
echo "$(openssl rand -base64 32)" > /etc/openvpn/server/management-pw
chmod 600 /etc/openvpn/server/management-pw
chown root:root /etc/openvpn/server/management-pw
```

```conf
# Reference the password file.
management-hold
# When using management-hold, the server waits for the management client to send
# the password before processing any connections.
management-up-down
```

If the management interface is not actively used for runtime operations, disable it entirely:

```conf
# Comment out or omit the management directive.
# management 127.0.0.1 7505
# With no management directive, no socket is opened.
```

To interact with the management interface for diagnostics:

```bash
# Connect manually for one-off commands.
nc 127.0.0.1 7505
# > status          — show connected clients
# > kill alice      — disconnect a client by common name
# > crl-verify      — reload CRL
# > quit
```

### Step 6: Per-Client Access Control with client-config-dir

OpenVPN's `client-config-dir` (CCD) mechanism allows per-client IP assignment, per-client route pushing, and per-client access restriction:

```conf
# /etc/openvpn/server/server.conf

# Enable per-client configuration files.
client-config-dir /etc/openvpn/ccd

# Disable client-to-client routing (clients cannot reach each other by default).
# Only enable if explicitly required and documented.
;client-to-client

# If push routes are needed, push only what each client requires.
# Global push routes (in server.conf) go to ALL clients.
# Per-client routes in CCD files go only to that client.
```

Per-client CCD files are named after the client's certificate Common Name:

```bash
# /etc/openvpn/ccd/alice
# Fixed IP assignment for alice (use addresses from the server's --ifconfig-pool range).
ifconfig-push 10.8.0.10 10.8.0.11

# Push only the specific routes alice needs — not the entire internal network.
push "route 10.20.0.0 255.255.255.0"   # Permit alice to reach only the dev subnet.
```

```bash
# /etc/openvpn/ccd/svc-deploy-agent
ifconfig-push 10.8.0.20 10.8.0.21

# Service accounts get very narrow route access.
push "route 10.30.1.100 255.255.255.255"  # Single host only.
```

For clients that should be blocked from connecting (suspended, not yet fully onboarded), use the `--client-deny` mechanism:

```bash
# In the CCD file for a client that should be blocked:
# (This requires --client-config-dir and the file to contain a `disable` directive.)
disable
```

### Step 7: Logging and Monitoring

OpenVPN's verbosity scale runs from 0 (silent) to 11 (debug). For production:

```conf
# /etc/openvpn/server/server.conf

# verb 3: log connection events, authentication outcomes, route pushes.
# verb 4: adds TLS cipher negotiation details.
# verb 6+: protocol-level debugging; too noisy for production.
verb 3

# Append logs (do not truncate on restart).
log-append /var/log/openvpn/server.log

# Log connection status to a machine-readable status file every 60 seconds.
status /var/run/openvpn/status.log 60
```

Parse authentication failures for alerting:

```bash
# Count failed TLS authentications in the last 5 minutes.
journalctl -u [email protected] --since "5 minutes ago" \
  | grep -cE 'TLS Error|AUTH_FAILED|certificate verify failed'

# Watch for new client connections.
tail -F /var/log/openvpn/server.log \
  | grep --line-buffered 'MULTI: Learn' \
  | while read -r line; do
      logger -p daemon.info -t openvpn-monitor "New client connected: $line"
    done

# Parse the status file to list all connected clients.
awk -F',' '/^CLIENT_LIST/{print $2, $3, $4, $8}' /var/run/openvpn/status.log
# Output: common_name, real_address, virtual_address, connected_since
```

Key events to ship to the SIEM:

| Log pattern | Meaning | Response |
|---|---|---|
| `TLS Error: TLS handshake failed` | Client has wrong cert, expired cert, or wrong tls-crypt key | Check client cert validity; check tls-crypt-v2 key distribution |
| `AUTH_FAILED` | Certificate validation failed or username/password rejected | Alert on rate: >3 in 60s from same IP = possible brute-force |
| `certificate verify failed` | Client certificate cannot be verified against the CA | May indicate a rogue certificate or misconfigured client |
| `CRL check failed` | Client cert serial is in the CRL | Alert immediately; investigate which device is using the revoked cert |
| `Peer Connection Initiated` | New connection established | Baseline for anomaly detection: new source IP, unusual hours |
| `Connection reset, restarting` | Client disconnected unexpectedly | May indicate network issue or active TCP reset injection |

### Step 8: OpenVPN 2.6 Specifics — DCO and Cipher Defaults

OpenVPN 2.6 introduced **Data Channel Offload (DCO)**, which moves the encryption/decryption of the data channel into the kernel (`ovpn-dco` kernel module on Linux, or `wintun` on Windows). DCO improves throughput by avoiding the user-kernel copy overhead on every packet.

Security implications of DCO:

```conf
# /etc/openvpn/server/server.conf

# DCO is enabled by default in 2.6 when the kernel module is available.
# DCO only supports AEAD ciphers: AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305.
# If your data-ciphers list includes non-AEAD ciphers, OpenVPN 2.6 may fall back
# to userspace for those clients. Force AEAD-only to ensure DCO is used consistently.
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305

# Verify DCO is active after startup.
# dco-enabled appears in the log when the kernel module is loaded.
```

```bash
# Check if the ovpn-dco kernel module is loaded.
lsmod | grep ovpn_dco

# OpenVPN 2.6 log output confirms DCO when active:
# ovpn-dco: Data channel offload enabled
# If not seen, the kernel module is absent and userspace processing is used.

# Install the DCO kernel module (Debian/Ubuntu).
apt-get install openvpn-dco-dkms

# After installing, reload the OpenVPN service.
systemctl restart [email protected]
```

OpenVPN 2.6 also changed cipher defaults: BF-CBC is no longer in the default `data-ciphers` list. Any client older than 2.5 that negotiated BF-CBC will now fail to connect unless the server explicitly adds it back — which it should not. Clients that cannot be upgraded to 2.5+ should be considered end-of-life.

### Step 9: Full Hardened Server Configuration

A consolidated reference configuration:

```conf
# /etc/openvpn/server/server.conf
# OpenVPN 2.6 hardened server configuration.

# Network.
port 1194
proto udp
dev tun

# Certificates and keys.
ca   /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server-vpn.crt
key  /etc/openvpn/server/server-vpn.key

# DH parameters — only used for servers that need to support non-ECDHE clients.
# For EC-only deployments (tls-cipher with ECDHE-ECDSA), this file is not used.
# If needed: use at least dh2048.pem, never dh1024.pem.
# dh /etc/openvpn/server/dh2048.pem

# For EC cipher suites: disable static DH and rely on ECDHE.
dh none

# CRL — revocation list.
crl-verify /crl.pem   # Path relative to chroot.

# TLS hardening.
tls-version-min 1.2
tls-cipher ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
auth SHA256

# Pre-authentication HMAC (prevents unauthenticated TLS handshakes).
tls-crypt-v2 /etc/openvpn/server/tc2-server.key

# Client IP pool.
server 10.8.0.0 255.255.0.0

# Per-client configuration.
client-config-dir /etc/openvpn/ccd

# Disable client-to-client routing.
# client-to-client   # Commented out — clients cannot reach each other.

# Route push — push ONLY what clients need. Review this list regularly.
push "route 10.20.0.0 255.255.0.0"
push "dhcp-option DNS 10.20.0.53"
push "block-outside-dns"

# Keepalive.
keepalive 10 60

# Privilege separation.
user nobody
group nobody
persist-key
persist-tun
chroot /var/lib/openvpn/chroot

# Logging.
verb 3
log-append /var/log/openvpn/server.log
status /var/run/openvpn/status.log 60

# Management interface — loopback only; disable if not actively used.
; management 127.0.0.1 7505

# Explicitly request client certificates (do not accept anonymous connections).
verify-client-cert require

# Reject clients with duplicate common names (one session per certificate).
duplicate-cn   # Comment this out — below is the hardened setting.
; duplicate-cn  # Do NOT use: allows multiple concurrent sessions per cert.
# Use the negation: if duplicate-cn is absent, only one session per CN is allowed.
```

### Step 10: Telemetry

```
openvpn_connected_clients{server}                       gauge
openvpn_auth_failures_total{server, reason}             counter
openvpn_tls_errors_total{server}                        counter
openvpn_crl_check_failed_total{server, common_name}     counter
openvpn_bytes_received_total{server, common_name}       counter
openvpn_bytes_sent_total{server, common_name}           counter
openvpn_connection_duration_seconds{server, common_name} histogram
openvpn_new_connection_total{server, common_name, src_ip} counter
```

Alert on:

- `openvpn_auth_failures_total` rate > 5/min — possible credential brute-force or mass certificate misconfiguration after a botched update.
- `openvpn_crl_check_failed_total` > 0 — a revoked certificate was used; investigate which client and from which IP immediately.
- `openvpn_tls_errors_total` spike — may indicate tls-crypt-v2 key distribution failure after a new client rollout.
- `openvpn_connected_clients` drops to 0 unexpectedly — server outage or network partition.
- `openvpn_bytes_sent_total` anomalous spike for a single `common_name` — possible data exfiltration over the VPN.
- `openvpn_new_connection_total` from unexpected `src_ip` for a known `common_name` — certificate used from an unexpected location.

Export from the OpenVPN status file using an exporter such as `openvpn_exporter` (GitHub: kumina/openvpn-exporter) or parse the status file directly:

```bash
# Prometheus-compatible scrape of the status file via a simple parser.
python3 - <<'EOF'
import re, time
status_file = "/var/run/openvpn/status.log"
with open(status_file) as f:
    for line in f:
        if line.startswith("CLIENT_LIST"):
            parts = line.strip().split(",")
            cn, real, virtual, since = parts[1], parts[2], parts[3], parts[7]
            print(f'openvpn_client_connected{{cn="{cn}",src="{real}",vip="{virtual}"}} 1')
EOF
```

## Expected Behaviour

| Signal | Default / unpatched config | Hardened config |
|---|---|---|
| Unauthenticated port scan on UDP 1194 | Server begins TLS handshake, consuming a thread | tls-crypt-v2 HMAC check fails; packet silently dropped |
| Client with BF-CBC cipher | Session established with 64-bit block cipher | `data-ciphers` list excludes BF-CBC; connection refused |
| Revoked certificate reconnects | Connection accepted (no CRL check) | CRL check fails; connection rejected; alert fired |
| Compromised tls-auth key (shared) | All clients must rotate | tls-crypt-v2: only the affected client's key is revoked |
| Management interface probed from localhost | Anonymous connection accepted | Password required; or interface not listening |
| OpenVPN process exploited | Root shell on server | Process running as nobody; chroot limits filesystem access |
| Client-to-client lateral movement | Any two clients can reach each other | `client-to-client` absent; inter-client traffic dropped |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| tls-crypt-v2 over tls-auth | Per-client key revocation without server-wide rotation | Client .ovpn profiles must include the per-client key | Automate profile generation; bundle key inline in .ovpn |
| EC keys (secp384r1) | Smaller keys, faster handshakes, strong security | Older clients (pre-2.4) or some embedded devices may not support EC | Audit client base before migrating; add ECDHE-RSA fallback in tls-cipher |
| `crl-verify` in chroot | CRL checked at every connection | CRL file must be kept fresh inside the chroot (cron copy) | Cron: `cp /etc/openvpn/server/crl.pem /var/lib/openvpn/chroot/crl.pem && systemctl kill -s SIGUSR2 [email protected]` |
| `dh none` (ECDHE only) | Eliminates static DH parameter file; forward secrecy from ECDHE | Incompatible with clients that don't support ECDHE | OpenVPN 2.4+ supports ECDHE; older clients need `dh dh2048.pem` |
| `duplicate-cn` disabled | Prevents certificate sharing between users | One device per certificate; re-enrollment needed for new devices | Issue one certificate per device, not per user |
| DCO (OpenVPN 2.6) | Kernel-level crypto; higher throughput | Only AEAD ciphers supported; plugins that inspect data channel packets break | Ensure all plugins are DCO-compatible; test on staging before enabling |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| CRL expires without renewal | Clients with otherwise valid certs are rejected (or accepted if `crl-verify` is soft) | Monitor CRL `nextUpdate` field; alert 7 days before expiry | `./easyrsa gen-crl && cp pki/crl.pem /var/lib/openvpn/chroot/crl.pem && systemctl kill -s SIGUSR2` |
| tls-crypt-v2 key not distributed to new client | Client connection fails at pre-authentication (before TLS) | Log shows `TLS Error` before certificate validation step | Re-generate and distribute the per-client key; include inline in .ovpn |
| Certificate CN contains path characters | CCD file lookup fails; client gets default server config | Log shows no CCD match for CN | Enforce CN naming policy in Easy-RSA; alphanumeric + hyphen only |
| `nobody` user cannot read key after privilege drop with `persist-key` absent | Server fails to reload keys on SIGUSR2 | systemd unit shows restart failures after soft reload | Always pair `user nobody` with `persist-key persist-tun` |
| DCO module absent on new kernel | Data channel falls back to userspace silently | Log does not contain `ovpn-dco` confirmation line | Install `openvpn-dco-dkms`; rebuild DKMS after kernel updates |
| Management interface password file world-readable | Local processes can authenticate to the management socket | File permission audit | `chmod 600` and `chown root:root` on the password file |

## Related Articles

- [IPsec VPN Hardening](/articles/network/ipsec-vpn-hardening/)
- [WireGuard Mesh Networking](/articles/network/wireguard-mesh/)
- [TLS Hardening for nginx and Envoy](/articles/network/tls-nginx-envoy/)
- [TLS Certificate Transparency Monitoring](/articles/network/tls-certificate-transparency/)
- [SSH Bastion Hardening](/articles/network/ssh-bastion-hardening/)
- [mTLS Service Mesh](/articles/network/mtls-service-mesh/)
