---
title: "IPsec VPN Hardening: IKEv2, StrongSwan, and Certificate-Based Authentication"
description: "IPsec with IKEv2 provides strong network-layer encryption for site-to-site and remote access VPNs. Hardening requires certificate-based authentication over PSKs, strong cipher suites, dead peer detection, and revocation checking to prevent credential replay and MITM attacks."
slug: "ipsec-vpn-hardening"
date: 2026-05-01
lastmod: 2026-05-01
category: "network"
tags: ["ipsec", "ikev2", "strongswan", "vpn", "certificate", "network-security"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 289
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/network/ipsec-vpn-hardening/index.html"
---

# IPsec VPN Hardening: IKEv2, StrongSwan, and Certificate-Based Authentication

## Problem

IPsec is the standard for encrypted, authenticated network tunnels. It operates at Layer 3, providing transparent encryption for all traffic between endpoints — site-to-site between data centres, or road-warrior access for remote employees. WireGuard is the modern alternative for many use cases, but IPsec remains the standard for interoperability with hardware VPN appliances, carrier networks, and regulatory compliance frameworks that require FIPS-validated cryptography.

Common IPsec deployment weaknesses:

- **Pre-shared key (PSK) authentication.** PSK authentication relies on a shared secret distributed to all peers. A compromised peer reveals the PSK for the entire deployment. PSKs are also often weak (manually chosen, not rotated), and PSK-based IKE is vulnerable to offline dictionary attacks if the IKE handshake is captured.
- **IKEv1 instead of IKEv2.** IKEv1 has known weaknesses (aggressive mode credential leakage, no built-in EAP support, more complex negotiation). Many deployments default to IKEv1 for compatibility with legacy hardware. IKEv2 should be enforced.
- **Weak cipher suite negotiation.** Allowing DES, 3DES, MD5, or DH groups below 2048-bit in the proposal set means a downgrade attack can force negotiation to weak algorithms.
- **No dead peer detection (DPD).** Without DPD, a failed tunnel is not detected until traffic attempts to flow through it. An attacker can exploit the stale SA window.
- **No certificate revocation checking.** A device with a revoked certificate (lost, compromised, decommissioned) can still authenticate if OCSP or CRL checking is not enforced.
- **Overly permissive traffic selectors.** A site-to-site tunnel with traffic selectors `0.0.0.0/0 ↔ 0.0.0.0/0` allows the remote site to route any traffic through the VPN, potentially bypassing network security controls.

**Target systems:** StrongSwan 5.9+ (charon daemon, swanctl); Linux kernel IPsec (xfrm); VPN interoperability with Cisco ASA, Palo Alto, Juniper SRX; FIPS 140-2 compliant cipher suites.

## Threat Model

- **Adversary 1 — PSK credential compromise:** An attacker compromises a VPN peer (remote office firewall, laptop) and extracts the pre-shared key. They use the PSK to authenticate as any peer in the VPN mesh, man-in-the-middle VPN sessions, or establish new tunnels.
- **Adversary 2 — IKE aggressive mode credential capture:** In IKEv1 aggressive mode, the responder sends its identity and hash before the initiator authenticates. An attacker who captures the handshake can perform an offline dictionary attack against the PSK.
- **Adversary 3 — Downgrade to weak cipher:** An attacker performs a man-in-the-middle during IKE negotiation, injecting modified proposals to force both peers to negotiate DES or 3DES. Encrypted traffic is then decryptable.
- **Adversary 4 — Stale SA replay:** A VPN session terminates abnormally. The attacker replays packets within the old SA's replay window before the SA expires. Without sequence number anti-replay, forged packets are accepted.
- **Adversary 5 — Revoked certificate still accepted:** A device whose certificate has been revoked (reported lost, employee terminated, device compromised) attempts to reconnect. Without OCSP checking, the connection is accepted.
- **Access level:** Adversaries 1 and 5 have physical or logical access to a VPN peer. Adversaries 2 and 3 are on-path. Adversary 4 is on-path post-session termination.
- **Objective:** Decrypt VPN traffic, impersonate VPN peers, gain network access to protected segments.
- **Blast radius:** A compromised site-to-site VPN effectively merges two network security zones — an attacker in one site has direct layer-3 access to the other.

## Configuration

### Step 1: Certificate Infrastructure

Use certificate-based authentication exclusively. Never use PSK for production:

```bash
# Generate a CA for VPN authentication using the internal PKI.
# (Or use your existing corporate CA — create a dedicated VPN sub-CA.)

# Generate VPN CA.
openssl genrsa -out vpn-ca.key 4096
openssl req -new -x509 -days 3650 \
  -key vpn-ca.key \
  -out vpn-ca.crt \
  -subj "/CN=VPN CA/O=Example Corp/OU=Security"

# Issue a certificate for each VPN peer.
# gateway-ny.example.com
openssl genrsa -out gateway-ny.key 2048
openssl req -new \
  -key gateway-ny.key \
  -out gateway-ny.csr \
  -subj "/CN=gateway-ny.example.com/O=Example Corp"

openssl x509 -req -days 365 \
  -in gateway-ny.csr \
  -CA vpn-ca.crt -CAkey vpn-ca.key -CAcreateserial \
  -extensions v3_req \
  -extfile <(printf "[v3_req]\nsubjectAltName=DNS:gateway-ny.example.com\nextendedKeyUsage=1.3.6.1.5.5.8.2.2") \
  -out gateway-ny.crt

# Install on the gateway.
cp vpn-ca.crt /etc/swanctl/x509ca/vpn-ca.crt
cp gateway-ny.crt /etc/swanctl/x509/gateway-ny.crt
cp gateway-ny.key /etc/swanctl/private/gateway-ny.key
chmod 600 /etc/swanctl/private/gateway-ny.key
```

### Step 2: StrongSwan swanctl Configuration

IKEv2 site-to-site with certificate authentication:

```hcl
# /etc/swanctl/swanctl.conf — New York to London site-to-site.

connections {
  ny-to-london {
    # IKEv2 only. Never IKEv1.
    version = 2

    # Local endpoint.
    local_addrs  = 203.0.113.1   # NY gateway public IP.
    remote_addrs = 203.0.113.2   # London gateway public IP.

    # IKE SA proposal — strong algorithms only.
    proposals = aes256gcm128-prfsha384-ecp384,aes256-sha384-ecp384

    # Require certificate authentication (no PSK).
    local {
      auth = pubkey
      certs = gateway-ny.crt
      id = "gateway-ny.example.com"
    }

    remote {
      auth = pubkey
      cacerts = vpn-ca.crt
      id = "gateway-london.example.com"
    }

    # Child SA (ESP tunnel).
    children {
      ny-london-tunnel {
        # ESP proposal — authenticated encryption only (AEAD).
        esp_proposals = aes256gcm128-ecp384,aes256gcm256

        # Traffic selectors — restrict to specific subnets, not 0.0.0.0/0.
        local_ts  = 10.1.0.0/16   # NY internal network.
        remote_ts = 10.2.0.0/16   # London internal network.

        # Start tunnel automatically and restart on failure.
        start_action = start
        close_action = restart
        dpd_action = restart

        # Anti-replay window.
        replay_window = 32

        # Rekey before expiry.
        life_time = 3600s
        rekey_time = 3000s
        rand_time = 300s
      }
    }

    # Dead peer detection — detect failed peers in 30s.
    dpd_delay = 30s
    dpd_timeout = 120s

    # Rekey IKE SA.
    rekey_time = 86400s   # 24 hours.

    # Enforce certificate revocation.
    revocation = strict   # Reject if OCSP/CRL check fails.

    # Fragmentation for large IKE packets.
    fragmentation = yes
  }
}

# Include secrets (certificates loaded from /etc/swanctl/x509/).
# No PSKs.
```

### Step 3: Cipher Suite Hardening

Only allow FIPS-compliant, forward-secret cipher suites:

```hcl
# Approved IKEv2 proposals (IKE SA).
# Format: encryption-integrity/prf-dhgroup
#
# Approved:
#   aes256gcm128   — AES-256 GCM (AEAD, no separate integrity algo needed)
#   aes256-sha384  — AES-256 CBC with SHA-384 HMAC
#   prfsha384      — PRF SHA-384
#   ecp384         — ECDH P-384 (DH group 20) — Perfect Forward Secrecy
#   modp4096       — DH modp-4096 (DH group 16) — fallback if ECP not supported
#
# Rejected (never use):
#   des/3des       — Weak; export-grade
#   md5/sha1       — Broken; collision attacks
#   modp768/1024   — Small DH groups; broken by Logjam
#   modp2048       — Acceptable minimum; prefer ECP384 or modp4096

proposals = aes256gcm128-prfsha384-ecp384,aes256-sha384-prfsha384-ecp384

# Approved ESP proposals (tunnel encryption).
# AEAD modes preferred (GCM provides both confidentiality and integrity).
esp_proposals = aes256gcm128-ecp384,aes256gcm256-ecp384
```

Verify negotiated algorithms after connection:

```bash
# Check active IKE SA parameters.
swanctl --list-sas --ike

# Output shows negotiated algorithms:
# ny-to-london: #1, ESTABLISHED, IKEv2, ...
#   local  '203.0.113.1' ... AES_CBC-256/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_384
#   remote '203.0.113.2' ...

# Verify ESP (child SA) algorithms.
swanctl --list-sas --child
# Expected: AES_GCM_16-256/ECP_384
```

### Step 4: Certificate Revocation with OCSP

```hcl
# /etc/swanctl/swanctl.conf — OCSP configuration.

connections {
  ny-to-london {
    # Enforce strict revocation checking.
    revocation = strict
    # strict: reject if OCSP/CRL check fails or is unavailable.
    # ifuri: only check if OCSP URI is present in cert.
    # never: no revocation checking (do not use).
  }
}
```

```bash
# Configure OCSP responder in the VPN CA.
# When issuing certificates, include the OCSP URI.
openssl x509 -req -days 365 \
  -in gateway-new.csr \
  -CA vpn-ca.crt -CAkey vpn-ca.key -CAcreateserial \
  -extfile <(printf "[ext]\nauthorityInfoAccess=OCSP;URI:http://ocsp.internal.example.com\n") \
  -extensions ext \
  -out gateway-new.crt
```

```bash
# Run an OCSP responder (using OpenSSL, or a dedicated service like EJBCA).
openssl ocsp \
  -index /etc/pki/CA/index.txt \
  -CA vpn-ca.crt \
  -rsigner vpn-ca.crt \
  -rkey vpn-ca.key \
  -port 8080 \
  -text \
  -out /var/log/ocsp.log &

# Revoke a certificate (stolen gateway, terminated employee).
openssl ca -revoke gateway-compromised.crt -config /etc/pki/CA/openssl.cnf
# OCSP responder will now return "revoked" for this certificate.
# StrongSwan with revocation = strict will reject the peer on next IKE negotiation.
```

### Step 5: Road Warrior Remote Access (EAP-TLS)

For remote users, use EAP-TLS with per-user certificates:

```hcl
# /etc/swanctl/swanctl.conf — road warrior configuration.

connections {
  remote-access {
    version = 2
    local_addrs = 0.0.0.0   # Listen on all interfaces.

    # Server authenticates with certificate.
    local {
      auth = pubkey
      certs = vpn-server.crt
      id = "vpn.example.com"
    }

    # Client authenticates with EAP-TLS (certificate-based EAP).
    remote {
      auth = eap-tls
      id = "%any"
    }

    # Virtual IP pool for clients.
    pools = remote-pool

    children {
      remote-access-tunnel {
        # Split tunneling: only route corporate subnets over VPN.
        # Full tunneling risks making the VPN a point of failure for all traffic.
        remote_ts = 10.0.0.0/8,172.16.0.0/12
        esp_proposals = aes256gcm128-ecp384
      }
    }

    # Client certificate validation.
    revocation = strict
  }
}

pools {
  remote-pool {
    addrs = 10.100.0.0/24
    dns = 10.0.0.53
  }
}
```

### Step 6: Firewall Rules for IPsec

```bash
# nftables rules for IPsec — IKE and ESP/AH.

nft add rule inet filter input \
  ip saddr 203.0.113.2 udp dport 500 accept    # IKE (London gateway).

nft add rule inet filter input \
  ip saddr 203.0.113.2 udp dport 4500 accept   # NAT-T (IKE over NAT).

nft add rule inet filter input \
  ip saddr 203.0.113.2 meta l4proto esp accept  # ESP (encrypted tunnel).

# Allow forwarding through the VPN tunnel.
nft add rule inet filter forward \
  ipsec in reqid 1 accept          # Accept traffic from established IPsec SA.

nft add rule inet filter forward \
  ipsec out reqid 1 accept         # Accept traffic going into established IPsec SA.

# Block unencrypted traffic on VPN-protected interfaces.
# Traffic between VPN subnets must go through the IPsec tunnel.
nft add rule inet filter forward \
  ip saddr 10.1.0.0/16 ip daddr 10.2.0.0/16 \
  ipsec in missing drop            # Drop traffic claiming to be from VPN subnet but not in SA.
```

### Step 7: Monitoring and Alerting

```bash
# StrongSwan exposes statistics via the VICI interface.
# swanctl commands for monitoring:

# List active SAs.
swanctl --list-sas

# List active connections (loaded configs).
swanctl --list-conns

# Statistics.
swanctl --stats

# Script to check all expected tunnels are up.
#!/bin/bash
EXPECTED_TUNNELS=("ny-to-london" "ny-to-sf" "ny-to-tokyo")
for tunnel in "${EXPECTED_TUNNELS[@]}"; do
  STATUS=$(swanctl --list-sas --ike | grep -c "^${tunnel}.*ESTABLISHED" || true)
  if [ "$STATUS" -eq 0 ]; then
    logger -p daemon.alert -t ipsec-monitor "ALERT: VPN tunnel $tunnel is DOWN"
  fi
done
```

### Step 8: Telemetry

```
ipsec_ike_sa_established_total{connection}               counter
ipsec_ike_sa_failed_total{connection, reason}            counter
ipsec_child_sa_established_total{connection}             counter
ipsec_child_sa_rekeyed_total{connection}                 counter
ipsec_bytes_encrypted{connection, direction}             counter
ipsec_packets_replayed_total{connection}                 counter
ipsec_revocation_check_failed_total{connection, peer}    counter
ipsec_tunnel_uptime_seconds{connection}                  gauge
```

Alert on:

- `ipsec_ike_sa_failed_total{reason="auth_failed"}` — authentication failure; potential compromised credential or certificate mismatch.
- `ipsec_tunnel_uptime_seconds` drops to 0 — a required tunnel is down; network connectivity between sites is broken.
- `ipsec_packets_replayed_total` non-zero — replay attack detected; investigate traffic source.
- `ipsec_revocation_check_failed_total` — a peer presented a revoked certificate; connection rejected as expected, but investigate which peer is attempting to connect with a revoked cert.
- `ipsec_ike_sa_failed_total{reason="proposal_mismatch"}` — peer is proposing cipher suites not in the approved list; check peer configuration.

## Expected Behaviour

| Signal | PSK / IKEv1 config | Hardened IKEv2 / cert config |
|--------|-------------------|------------------------------|
| PSK compromise | All peers can impersonate any other | Certificate compromise affects only that peer |
| Weak cipher negotiation | Attacker downgrades to DES/3DES | Proposal set rejects weak algorithms; negotiation fails |
| Revoked device reconnects | Connection accepted (no revocation check) | OCSP check rejects revoked certificate; connection denied |
| Peer fails without DPD | Stale SA persists; traffic blackholed | DPD detects dead peer in 30s; tunnel restarted |
| Overly broad traffic selectors | Remote site routes all traffic over VPN | Traffic selectors restrict to specific subnets |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Certificate auth over PSK | Per-peer credentials; revocable | Certificate lifecycle management overhead | Use cert-manager or EJBCA for automation; annual renewal |
| `revocation = strict` | Revoked certs immediately rejected | OCSP responder becomes a dependency; outage blocks VPN | Run HA OCSP responder; cache responses; set short OCSP grace period |
| ECP384 (P-384) DH group | Strong PFS; FIPS-compliant | Slightly slower key exchange (~5ms) than DH modp | Negligible overhead for VPN use; prefer over weaker groups |
| Split tunneling | Only corporate traffic over VPN | Client can be on hostile network while accessing corporate resources | Apply DNS-based monitoring; require EDR on client regardless of tunnel mode |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Certificate expiry | IKE auth fails; tunnel does not establish | `ipsec_ike_sa_failed_total{reason="auth_failed"}` | Renew certificate; restart StrongSwan after install |
| OCSP responder unreachable | With `revocation=strict`: all new tunnels fail | Certificate monitoring alert; tunnel down alert | Restore OCSP service; or temporarily switch to `revocation=ifuri` during outage |
| DH group mismatch with peer | IKE negotiation fails | `proposal_mismatch` in logs | Add peer's DH group to proposals list; investigate peer config |
| Replay window overflow | Legitimate packets dropped under high throughput | `ipsec_packets_replayed_total` with no attack pattern | Increase `replay_window`; tune per link bandwidth |
| NAT traversal breakage | Tunnel fails to establish through NAT | IKE on UDP 500 works but ESP blocked | Enable NAT-T (UDP 4500); configure firewall to pass UDP 4500 |

## Related Articles

- [WireGuard Mesh Networking](/articles/network/wireguard-mesh/)
- [mTLS Service Mesh](/articles/network/mtls-service-mesh/)
- [TLS Hardening for nginx and Envoy](/articles/network/tls-nginx-envoy/)
- [cert-manager PKI Hardening](/articles/kubernetes/cert-manager-pki-hardening/)
- [Network Time Security (NTS)](/articles/network/network-time-security-nts/)
