---
title: "Network Time Security: Authenticated NTP for Infrastructure"
description: "Unauthenticated NTP lets any on-path attacker shift system clocks, invalidating TLS certificates, JWT tokens, and Kerberos tickets. NTS (RFC 8915) adds TLS-based authentication to NTP without sacrificing accuracy."
slug: "network-time-security-nts"
date: 2026-04-30
lastmod: 2026-04-30
category: "network"
tags: ["ntp", "nts", "time-security", "chrony", "infrastructure"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 273
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/network/network-time-security-nts/index.html"
---

# Network Time Security: Authenticated NTP for Infrastructure

## Problem

Network Time Protocol (NTP) synchronises system clocks across a network. Without authentication, any on-path attacker can forge NTP responses and shift a system's clock — forward or backward — by hours or days. This is not theoretical: the Roughtime project at Google was motivated by demonstrated NTP manipulation attacks.

Why clock manipulation matters for security:

- **TLS certificates:** Certificate validity is time-bounded. Shifting a client's clock backward makes expired attacker certificates appear valid; shifting it forward makes the victim's own certificates appear expired, disrupting HTTPS.
- **JWT and OIDC tokens:** JWTs are validated against `exp` (expiry) and `nbf` (not-before) claims using system time. Clock manipulation can make expired tokens appear valid or current tokens appear expired.
- **Kerberos tickets:** Kerberos requires clocks to be within 5 minutes of each other. A 6-minute clock shift causes authentication failure across the entire infrastructure.
- **Security audit logs:** A clock that drifts by hours makes log correlation across systems impossible. Incident timelines become unreliable.
- **Certificate revocation:** CRL and OCSP responses contain `thisUpdate` and `nextUpdate` fields. Clock manipulation makes stale revocation information appear current.

NTS (Network Time Security, RFC 8915, published 2020) adds authenticated encryption to NTP using TLS-derived keys. The NTS-KE (Key Establishment) phase uses TLS to authenticate the NTP server and exchange keys; subsequent NTP packets are authenticated using those keys. An on-path attacker cannot forge authenticated NTP responses without the server's private key.

**Target systems:** chrony 4.0+ (NTS client and server); ntpd 4.2.8p15+ (NTS client); systemd-timesyncd 247+ (NTS-KE client); NTS-capable public servers: `time.cloudflare.com`, `virginia.time.system.cloudflare.com`; ntppool.org NTS servers.

## Threat Model

- **Adversary 1 — On-path NTP manipulation:** An attacker on the network path between a server and its NTP source sends forged NTP responses. The server accepts them and shifts its clock. TLS certificate validation is affected; JWT tokens are manipulated.
- **Adversary 2 — NTP reflection/amplification DDoS:** An attacker uses unauthenticated NTP monlist requests to amplify traffic against a target (historical attack pattern pre-2014). Modern configurations disable monlist, but unauthenticated NTP servers remain DDoS vectors.
- **Adversary 3 — False ticker attack:** An attacker compromises one of multiple NTP peers and reports a false time. Without authentication, a compromised peer can influence the cluster's consensus time.
- **Adversary 4 — BGP hijacking of NTP servers:** An attacker hijacks the BGP route to a major NTP pool server's IP prefix and redirects all clients to their own server, which serves malicious time values. This is harder with NTS because the client validates the server's TLS certificate against its expected hostname/CA.
- **Access level:** Adversaries 1 and 3 have network MITM capability or have compromised a peer. Adversary 4 has BGP route injection capability.
- **Objective:** Manipulate system clocks to bypass time-dependent security controls, cause authentication failures, or corrupt audit logs.
- **Blast radius:** Successful clock manipulation on all cluster nodes simultaneously makes certificate and JWT validation unreliable across the entire infrastructure. A 30-minute shift forward causes all active TLS sessions to fail if certificates are near expiry.

## Configuration

### Step 1: Configure chrony with NTS Client

chrony is the recommended NTP implementation for Linux. Version 4.0+ supports NTS:

```
# /etc/chrony.conf

# Use NTS-authenticated NTP servers.
# Cloudflare offers free NTS.
server time.cloudflare.com iburst nts
server virginia.time.system.cloudflare.com iburst nts

# Use multiple NTS sources for redundancy and false-ticker protection.
# At least 4 sources for robust minsources selection.
server time.apple.com iburst nts       # Apple's NTS-capable servers.
server ntppool1.time.nl iburst nts     # NTP Pool NTS servers (when available).

# NTS key exchange: trust the system CA bundle.
# The server's TLS certificate is validated against this.
ntstrustedcerts /etc/ssl/certs/ca-certificates.crt

# Or specify a specific CA for your internal NTS server.
# ntstrustedcerts /etc/ssl/certs/internal-ca.crt

# Require at least 3 NTS-authenticated sources to be reachable.
# With 4 sources configured, 1 can be unavailable.
minsources 3

# Allow no more than 1 second of initial adjustment (step).
# Prevents large clock jumps that could disrupt running services.
makestep 1.0 3

# Drift file to remember clock drift across reboots.
driftfile /var/lib/chrony/drift

# Log statistics for monitoring.
logdir /var/log/chrony
log tracking measurements statistics

# Security: refuse to serve time to external clients (chrony as client only).
# Remove if running an internal NTS server.
deny all

# Enable NTS memory protection.
ntsdumpdir /var/lib/chrony
```

```bash
# Restart chrony and verify NTS authentication.
systemctl restart chronyd

# Check NTS status.
chronyc authdata
# Expected output shows authenticated sources:
# Name/IP Address            Mode KeyID Type KLen Last Atmp  NAK Cook CLen
# ==============================================================================
# time.cloudflare.com        NTS      1   15  256    2    0    0    8  100
# virginia.time.system.cl.   NTS      1   15  256    3    0    0    8  100

# Verify sources are authenticated.
chronyc sources -v
# * = selected source (synced); ^ = server; + = combined
# ^ time.cloudflare.com         2   6   377  246  -12us[  -4us] +/-  651us
```

### Step 2: Run an Internal NTS Server for Fleet Synchronisation

For large fleets, run an internal NTS server that synchronises to public NTS servers and serves authenticated time internally. This reduces external NTP traffic and adds a layer of control:

```
# /etc/chrony.conf for the internal NTS SERVER.

# Upstream: authenticate to public NTS servers.
server time.cloudflare.com iburst nts
server virginia.time.system.cloudflare.com iburst nts
ntstrustedcerts /etc/ssl/certs/ca-certificates.crt

# NTS server configuration.
ntsserverkey /etc/chrony/nts-server.key
ntsservercert /etc/chrony/nts-server.crt
# Port 4460 is the NTS-KE port (RFC 8915).
ntsport 4460

# Allow internal clients to query (unauthenticated NTP on port 123).
allow 10.0.0.0/8
allow 172.16.0.0/12

# Allow internal clients to use NTS.
# NTS is always allowed to any host that can reach port 4460.

driftfile /var/lib/chrony/drift
logdir /var/log/chrony
log tracking measurements statistics
minsources 2
makestep 1.0 3
```

Generate an internal TLS certificate for the NTS server:

```bash
# Generate with an internal CA (or use Let's Encrypt if the server has a public hostname).
openssl req -newkey rsa:2048 -nodes \
  -keyout /etc/chrony/nts-server.key \
  -out /etc/chrony/nts-server.csr \
  -subj "/CN=nts.internal.example.com"

# Sign with internal CA.
openssl x509 -req \
  -in /etc/chrony/nts-server.csr \
  -CA /etc/ssl/certs/internal-ca.crt \
  -CAkey /etc/ssl/private/internal-ca.key \
  -days 365 -CAcreateserial \
  -out /etc/chrony/nts-server.crt

chmod 600 /etc/chrony/nts-server.key
chown chrony: /etc/chrony/nts-server.key /etc/chrony/nts-server.crt
```

Internal client configuration:

```
# /etc/chrony.conf on internal clients.
server nts.internal.example.com iburst nts
ntstrustedcerts /etc/ssl/certs/internal-ca.crt
minsources 1
makestep 1.0 3
driftfile /var/lib/chrony/drift
```

### Step 3: Firewall Rules for NTS

NTS-KE runs on TCP port 4460 (distinct from NTP's UDP port 123):

```bash
# Allow NTP (UDP 123) and NTS-KE (TCP 4460) outbound to trusted NTS servers.
nft add rule inet filter output \
  ip daddr { 162.159.200.1, 162.159.200.123 } \  # Cloudflare NTS IPs.
  udp dport 123 accept

nft add rule inet filter output \
  ip daddr { 162.159.200.1, 162.159.200.123 } \
  tcp dport 4460 accept

# For internal clients: allow to internal NTS server only.
nft add rule inet filter output \
  ip daddr 10.0.1.100 \   # Internal NTS server IP.
  udp dport 123 accept

nft add rule inet filter output \
  ip daddr 10.0.1.100 \
  tcp dport 4460 accept

# Block NTP to all other external hosts (prevent using unauthenticated servers).
nft add rule inet filter output \
  udp dport 123 drop
```

### Step 4: Verify and Monitor Time Synchronisation

```bash
# Comprehensive time sync status.
chronyc tracking
# Output:
# Reference ID    : A29FC801 (time.cloudflare.com)
# Stratum         : 4
# System time     : 0.000031412 seconds fast of NTP time
# Last offset     : +0.000018459 seconds
# RMS offset      : 0.000128773 seconds
# Frequency       : 1.234 ppm fast
# Residual freq   : +0.002 ppm
# Skew            : 0.123 ppm
# Root delay      : 0.016842 seconds
# Root dispersion : 0.001234 seconds

# Check NTS cookie status (should not be empty).
chronyc ntsdatastats
# Shows cookie count; empty indicates NTS-KE failed.

# Verify time offset is within acceptable bounds.
OFFSET=$(chronyc tracking | grep "System time" | awk '{print $4}')
echo "Clock offset: ${OFFSET} seconds"
# Alert if |offset| > 0.1 seconds.
```

Prometheus monitoring via chrony's built-in metrics (or node_exporter chrony collector):

```yaml
# prometheus/node_exporter config
- job_name: 'node'
  static_configs:
    - targets: ['localhost:9100']
  params:
    collect[]:
      - 'time'           # Enables time/chrony metrics.
```

Key metrics:

```
node_timex_offset_seconds              — current offset from reference
node_timex_sync_status                 — 1 = in sync, 0 = not
node_timex_root_delay_seconds          — network delay to reference
chrony_nts_ke_session_success_total    — successful NTS-KE authentications
chrony_nts_ke_session_failure_total    — failed NTS-KE (cert errors, network)
```

### Step 5: Detect Unauthenticated Fallback

Alert if chrony falls back to unauthenticated NTP:

```bash
# Check if any source is unauthenticated.
chronyc authdata | grep -v "NTS" | grep -v "Name/IP"
# Any output here means an unauthenticated source is in use.

# Script for monitoring.
#!/bin/bash
UNAUTH=$(chronyc authdata | grep -v "NTS" | grep -v "^Name" | grep -v "^==")
if [ -n "$UNAUTH" ]; then
  echo "ALERT: Unauthenticated NTP sources in use:"
  echo "$UNAUTH"
  exit 1
fi
echo "All NTP sources authenticated."
```

### Step 6: Kubernetes Time Synchronisation

Kubernetes nodes inherit time from the host OS. No per-pod NTP configuration is needed. Verify all nodes are synchronised:

```bash
# Check time offset across all nodes.
kubectl get nodes -o wide -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | \
  xargs -I{} kubectl debug node/{} -it --image=busybox -- \
    chronyc tracking 2>/dev/null | grep "System time"
```

For cloud-managed Kubernetes, the cloud provider's hypervisor handles host time sync (AWS uses VMware VMtools / KVM hardware clock + chronyd; GCP uses the gVNIC time sync). Verify these are still NTS-authenticated:

```bash
# On EKS/GKE nodes:
# Check if the host uses chrony with NTS or falls back to unauthenticated pool.
ssh node1 "chronyc authdata"
```

### Step 7: Telemetry

```
chrony_offset_seconds{host}                        gauge
chrony_sync_status{host}                           gauge (1=synced)
chrony_nts_ke_success_total{host, server}          counter
chrony_nts_ke_failure_total{host, server, reason}  counter
chrony_unauthenticated_sources{host}               gauge (0 = good)
ntp_stratum{host}                                  gauge
```

Alert on:

- `chrony_sync_status` == 0 — host is not time-synchronised; TLS and JWT operations may fail.
- `chrony_offset_seconds` > 0.5 — significant clock offset; Kerberos tickets may be rejected.
- `chrony_unauthenticated_sources` > 0 — a host is using unauthenticated NTP; NTS has failed or fallen back.
- `chrony_nts_ke_failure_total` non-zero — NTS-KE is failing; check TLS certificate validity on the NTS server.

## Expected Behaviour

| Signal | Unauthenticated NTP | NTS-authenticated NTP |
|--------|--------------------|-----------------------|
| On-path time manipulation | Forged NTP packets shift clock | Forged packets rejected (no valid authentication) |
| Server TLS certificate verification | None — any server accepted | TLS cert verified against CA before trusting time |
| Clock accuracy | Typically ±10ms | Typically ±1ms (NTS adds negligible overhead) |
| Audit log reliability | Potentially manipulated | Authentic; cross-system log correlation works |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| NTS over unauthenticated NTP | Authentication; no clock manipulation | NTS-KE requires TCP 4460 outbound; slightly more complex | Straightforward firewall rule; one-time setup. |
| Internal NTS server | Reduces external dependency; adds control layer | One more service to operate; TLS certificate management | cert-manager or Let's Encrypt for certificate automation. |
| `minsources 3` | False-ticker protection (3 of 4 must agree) | One server unavailable = degraded; if 2 fail, no sync | Run 4+ NTS servers in configuration; Cloudflare + Apple + internal = 3 authenticated sources. |
| Blocking unauthenticated NTP egress | Prevents fallback to insecure servers | Breaks workloads using hardcoded NTP servers | Audit for hardcoded NTP references; redirect or update. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| NTS-KE TLS cert expired | `chronyc authdata` shows no NTS; fallback to unauthenticated | `chrony_nts_ke_failure_total` alert; authdata output | Renew the NTS server certificate; chrony retries automatically. |
| All NTS servers unreachable | `chrony_sync_status = 0`; clock drifts | `chrony_sync_status` alert | Check network connectivity; ensure firewall allows TCP 4460 and UDP 123 to NTS servers. |
| Clock jump at startup | Services fail after boot due to sudden time adjustment | `makestep` log entry in chrony logs | Tune `makestep` threshold; allow larger initial adjustment. |
| Kerberos rejects tickets due to clock skew | Authentication failures across services | `kinit` fails with "Clock skew too great" | Restore time sync immediately; chrony will correct drift without a large step if within tolerance. |
| Chrony daemon crash | No time synchronisation; clock drifts at hardware rate | `chrony_sync_status = 0`; systemd unit failed | Restart chronyd; investigate crash via coredump. |

## Related Articles

- [DNS Security: DNSSEC and CAA Records](/articles/network/dns-security-dnssec-caa/)
- [Linux Time Synchronisation Security](/articles/linux/time-sync-security/)
- [TLS Hardening for nginx and Envoy](/articles/network/tls-nginx-envoy/)
- [OAuth 2.0 and OIDC Implementation Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
- [cert-manager PKI Hardening](/articles/kubernetes/cert-manager-pki-hardening/)
