---
title: "802.1X Network Access Control: Wired and Wireless Authentication with RADIUS and EAP-TLS"
description: "MAC-based access control is trivially bypassed. 802.1X with EAP-TLS enforces cryptographic device identity at the port level, dynamically assigns VLANs by identity, and eliminates rogue device connection on both wired and wireless networks."
slug: dot1x-network-access-control
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - 802.1x
  - radius
  - eap
  - network-access-control
  - wpa-enterprise
personas:
  - security-engineer
  - network-engineer
article_number: 492
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/dot1x-network-access-control/
---

# 802.1X Network Access Control: Wired and Wireless Authentication with RADIUS and EAP-TLS

## The Problem

Most enterprise networks grant access based on physical port membership or VLAN tag — a device plugs into a switch port, and the switch assumes it belongs there. Networks that have progressed beyond this often rely on MAC address filtering: only pre-registered MAC addresses are allowed on certain VLANs. Both controls fail against a low-skill attacker.

MAC spoofing is a two-command operation on Linux:

```bash
# Discover an allowed MAC by listening passively
tcpdump -i eth0 -e -c 20 2>/dev/null | awk '{print $2}' | grep -E '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' | head -5

# Assume that MAC address
ip link set eth0 down
ip link set eth0 address aa:bb:cc:dd:ee:ff
ip link set eth0 up
```

The attacker then connects their device — a laptop, a Raspberry Pi, a rogue AP — and is indistinguishable from the legitimate device at Layer 2. Guest VLAN bypass is equally straightforward: many switches drop unauthenticated devices into a guest VLAN rather than blocking them, so an attacker on the guest VLAN can probe for misconfigurations between segments.

The concrete gaps in MAC-based environments:

- No cryptographic proof of device identity — any device can claim any MAC.
- Rogue AP deployment: an attacker bridges a wireless AP to a wired port. The AP's MAC is registered; every wireless client is now on the wired network without authenticating.
- No per-user identity tied to the port — security logs show MAC addresses, not user or device names.
- Guest VLAN bypass: fail-open policies put unauthenticated devices somewhere on the network, not off it.
- No dynamic VLAN assignment — a contractor laptop in a conference room gets the same VLAN as a production server.

**Target systems:** Cisco IOS 15.2+, Cisco IOS-XE, Aruba, Juniper EX/QFX series, open-source switch alternatives; FreeRADIUS 3.2+; Windows, Linux, and macOS supplicants; WPA3-Enterprise wireless.

## Threat Model

- **Adversary 1 — Rogue device on wired network:** An attacker plugs a device into an active Ethernet port (conference room, empty office, unlocked wiring closet). Without 802.1X, the port is live. With 802.1X fail-closed, the port stays unauthorised until valid credentials are presented.
- **Adversary 2 — MAC spoofing:** An attacker observes a legitimate MAC and clones it. MAC filtering accepts the spoofed address. EAP-TLS requires a valid device certificate in addition to MAC; cloning a MAC does not grant access.
- **Adversary 3 — Credential theft and lateral movement:** On WPA-Personal or PSK networks, capturing the handshake and cracking the key gives full network access. WPA3-Enterprise with EAP-TLS requires the attacker to steal both the private key and the certificate from the device, then bypass the RADIUS TLS mutual authentication.
- **Adversary 4 — RADIUS impersonation:** An attacker sets up a rogue RADIUS server and attempts to harvest credentials from supplicants. EAP-TLS mutual authentication prevents this: the supplicant validates the RADIUS server certificate before sending any identity material.
- **Adversary 5 — VLAN hopping:** An attacker on an access VLAN attempts to reach other VLANs via double-tagging. 802.1X alone does not prevent this — compensating controls (disabling DTP, non-negotiating trunk ports, native VLAN tagging) are required alongside 802.1X.
- **Access level:** Adversaries 1–3 have physical Layer 1 access. Adversary 4 is a wireless MITM. Adversary 5 is post-authentication.
- **Objective:** Gain unauthorised access to internal network segments, intercept traffic, or pivot to higher-value systems.
- **Blast radius:** A single compromised wired port or wireless association without 802.1X is a direct entry point to the target VLAN. With 802.1X enforced, unauthenticated devices are isolated to a restricted VLAN or dropped entirely.

## 802.1X Architecture

802.1X defines three roles:

**Supplicant** — the client device requesting network access. On Linux this is `wpa_supplicant`; on Windows, the native 802.1X client; on macOS, the built-in network preferences. The supplicant holds the credentials (certificate or password) and executes the EAP exchange.

**Authenticator** — the network device enforcing access. For wired networks this is the switch; for wireless it is the access point or wireless LAN controller. The authenticator does not evaluate credentials itself — it proxies the EAP exchange between supplicant and authentication server via RADIUS. Before authentication completes, the port is in an unauthorised state: only EAPOL (EAP over LAN) frames are passed.

**Authentication server** — the RADIUS server that evaluates credentials and returns an accept or reject. On accept it can return RADIUS attributes that instruct the authenticator to assign a specific VLAN, apply an ACL, or set a session timeout.

The exchange sequence:

1. Device connects. Authenticator sends EAP-Request/Identity.
2. Supplicant responds with EAP-Response/Identity (often just a realm, not a real username, to avoid identity exposure).
3. Authenticator encapsulates EAP in RADIUS Access-Request and forwards to RADIUS server.
4. RADIUS server negotiates the EAP method (TLS tunnel, certificate exchange, etc.).
5. RADIUS returns Access-Accept or Access-Reject.
6. Authenticator moves the port to authorised state and applies VLAN/ACL attributes from the RADIUS response.

## EAP Method Selection

Choosing the wrong EAP method is the most consequential decision in an 802.1X deployment. The options differ significantly in security properties.

| Method | Authentication | Server cert validation | Susceptible to offline attack |
|---|---|---|---|
| EAP-TLS | Mutual certificate | Yes (required) | No |
| PEAP/MSCHAPv2 | Password (tunnelled) | Yes (should be enforced) | Yes (captured handshake) |
| EAP-TTLS/PAP | Password (tunnelled) | Yes (should be enforced) | Yes |
| EAP-FAST | Password or cert | Optional (weak if disabled) | Yes (PAC provisioning) |
| LEAP | Password | No | Yes (very weak, deprecated) |

**EAP-TLS** is the correct choice for environments managing device certificates. Both the server and the client authenticate with X.509 certificates, making it immune to password attacks and MITM. The private key never leaves the device — on modern endpoints it is stored in the TPM or Secure Enclave, making exfiltration significantly harder. The tradeoff is PKI operational overhead: every device needs a certificate, and revocation checking must work.

**PEAP/MSCHAPv2** is widely deployed because it integrates with Active Directory and requires no client certificates. The device only needs to present a username and password inside the PEAP tunnel. The critical requirement is enforcing server certificate validation on the supplicant — without it, an attacker can stand up a rogue RADIUS server, intercept the MSCHAPv2 exchange, and crack the NT hash offline. MSCHAPv2 hashes are crackable; a captured handshake combined with cloud GPU resources can recover common passwords in hours.

**Recommendation:** Use EAP-TLS for all managed devices. Use PEAP/MSCHAPv2 only where certificate deployment is not feasible, and enforce server certificate validation and certificate pinning on every supplicant.

## FreeRADIUS Configuration for EAP-TLS

Install FreeRADIUS 3.2+ on a dedicated server or VM. It should not run other services.

```bash
apt install freeradius freeradius-utils freeradius-config
```

The core EAP configuration lives in `/etc/freeradius/3.0/mods-enabled/eap`:

```conf
# /etc/freeradius/3.0/mods-enabled/eap

eap {
    default_eap_type = tls

    tls-config tls-common {
        private_key_password = ${ENV:RADIUS_KEY_PASS}
        private_key_file     = /etc/freeradius/3.0/certs/server.key
        certificate_file     = /etc/freeradius/3.0/certs/server.crt
        ca_file              = /etc/freeradius/3.0/certs/ca-chain.crt
        ca_path              = /etc/freeradius/3.0/certs/
        dh_file              = /etc/freeradius/3.0/certs/dh
        cipher_list          = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
        tls_min_version      = "1.2"
        tls_max_version      = "1.3"

        # Verify client certificates against the CA
        verify_client_cert   = yes

        # Check revocation via OCSP
        ocsp {
            enable      = yes
            override_cert_url = yes
            url         = "http://ocsp.internal.example.com/"
            use_nonce   = yes
            timeout     = 5
            softfail    = no   # hard-fail if OCSP is unreachable
        }
    }

    tls {
        tls = tls-common
    }

    peap {
        tls        = tls-common
        default_eap_type = mschapv2
        # Enforce server cert validation hint in client config
        # (supplicant-side enforcement is separate)
    }
}
```

Configure clients (authenticators) in `/etc/freeradius/3.0/clients.conf`:

```conf
# /etc/freeradius/3.0/clients.conf

client core-switch-01 {
    ipaddr          = 10.0.1.10
    secret          = "use-a-long-random-secret-min-32-chars"
    shortname       = core-sw-01
    nas_type        = cisco
    require_message_authenticator = yes
}

client wlc-01 {
    ipaddr          = 10.0.1.20
    secret          = "different-secret-per-device-no-shared-secrets"
    shortname       = wlc-01
    nas_type        = other
    require_message_authenticator = yes
}
```

Add dynamic VLAN assignment in `/etc/freeradius/3.0/users` or in your SQL/LDAP backend. The RADIUS reply attributes instruct the switch which VLAN to assign:

```conf
# /etc/freeradius/3.0/users
# Match on certificate CN or OU attribute

DEFAULT Cert-CN =~ "^corp-.*", Auth-Type := EAP
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = "10"

DEFAULT Cert-CN =~ "^iot-.*", Auth-Type := EAP
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = "50"

DEFAULT Cert-CN =~ "^server-.*", Auth-Type := EAP
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = "100"
```

For LDAP-backed user lookups (PEAP deployments), configure the LDAP module:

```conf
# /etc/freeradius/3.0/mods-enabled/ldap

ldap {
    server      = "ldaps://dc01.internal.example.com"
    port        = 636
    identity    = "cn=radius-bind,ou=service-accounts,dc=example,dc=com"
    password    = "${ENV:LDAP_BIND_PASS}"
    base_dn     = "ou=users,dc=example,dc=com"
    tls {
        start_tls    = no
        require_cert = "demand"
        ca_file      = /etc/ssl/certs/internal-ca.crt
    }
}
```

Test the RADIUS configuration before touching switches:

```bash
# Test EAP-TLS authentication with a client cert
eapol_test -c /etc/eapol_test/eap-tls.conf -s shared-secret -a 127.0.0.1

# Verify RADIUS is accepting the test
radtest testuser wrongpassword 127.0.0.1 0 testing123
```

## Switch Configuration: Cisco IOS

Enable 802.1X globally and on access ports. The following applies to Cisco IOS 15.2+ and IOS-XE:

```ios
! Global AAA configuration
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius
aaa accounting dot1x default start-stop group radius

! RADIUS server definition
radius server FREERADIUS-01
 address ipv4 10.0.1.30 auth-port 1812 acct-port 1813
 key 7 <encrypted-key>
 timeout 5
 retransmit 3

! Enable 802.1X globally
dot1x system-auth-control

! Access port configuration template
interface GigabitEthernet1/0/1
 description Workstation Port
 switchport mode access
 switchport access vlan 999          ! Unauthenticated VLAN (restricted/no-access)
 switchport nonegotiate              ! Disable DTP to prevent VLAN hopping
 spanning-tree portfast
 spanning-tree bpduguard enable

 ! Enable 802.1X on the port
 authentication port-control auto
 dot1x pae authenticator

 ! Timeout and retry tuning
 dot1x timeout tx-period 10
 dot1x max-req 3
 dot1x timeout supp-timeout 30

 ! On auth failure: restrict to limited VLAN, do not grant full access
 authentication event fail action authorize vlan 998
 authentication event no-response action authorize vlan 998

 ! On successful auth: RADIUS will push VLAN via Tunnel attributes
 authentication order dot1x mab      ! Try 802.1X first, fall back to MAB
 authentication priority dot1x mab

 ! Log authentication events
 authentication logging verbose
```

VLAN 999 should route to nothing — it exists only to satisfy the port state machine. VLAN 998 is the restricted VLAN for failed or non-802.1X devices: it may have limited internet access but no access to internal resources.

Verify authentication state per-port:

```ios
show authentication sessions interface GigabitEthernet1/0/1
show dot1x interface GigabitEthernet1/0/1
show radius statistics
```

## WPA3-Enterprise for Wireless

WPA3-Enterprise replaces WPA2-Enterprise on all new wireless deployments. The key differences:

- **Protected Management Frames (PMF) is mandatory** — management frames are authenticated, preventing deauthentication attacks used to force clients to re-associate with rogue APs.
- **192-bit security suite (Suite-B)** for sensitive environments — requires EAP-TLS with RSA-3072 or ECDSA-384 certificates, AES-256-GCMP encryption, and HMAC-SHA384.
- **SAE (Simultaneous Authentication of Equals)** is used in WPA3-Personal but not WPA3-Enterprise — Enterprise still uses EAP.

Configure the SSID on an Aruba controller (similar on Cisco WLC):

```bash
# Aruba OS-CX (pseudo-CLI, adapt to your controller)
wlan ssid-profile CORP-ENTERPRISE
  essid "Corp-Network"
  opmode wpa3-aes-ccm-128        # WPA3-Enterprise with CCMP-128
  # Or for Suite-B: opmode wpa3-cnsa (192-bit)
  auth-server FREERADIUS-01
  pmf-required                   # Mandatory PMF
  anon-id "anonymous@example.com"  # Phase 1 identity (hides real identity)
  termination                    # Terminate TLS at controller, not AP

wlan virtual-ap CORP-VAP
  ssid-profile CORP-ENTERPRISE
  vlan 10                        # Default VLAN, overridden by RADIUS
  dynamic-vlan                   # Accept VLAN from RADIUS attributes
```

Supplicant configuration matters as much as server configuration. A client that does not validate the RADIUS server certificate is vulnerable to MITM regardless of EAP method. For Linux with `wpa_supplicant`:

```conf
# /etc/wpa_supplicant/corp-enterprise.conf

network={
    ssid="Corp-Network"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="device@example.com"
    ca_cert="/etc/ssl/certs/internal-ca.crt"
    client_cert="/etc/ssl/certs/device-cert.crt"
    private_key="/etc/ssl/private/device-key.pem"
    private_key_passwd=""          # Key in TPM: use engine instead
    phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1"
    # Validate server identity — critical, do not omit
    subject_match="radius01.internal.example.com"
    # Or use altsubject_match for SAN validation
    altsubject_match="DNS:radius01.internal.example.com"
}
```

For PEAP/MSCHAPv2, enforce server certificate validation:

```conf
network={
    ssid="Corp-Network"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="user@example.com"
    password="password"
    ca_cert="/etc/ssl/certs/internal-ca.crt"
    phase2="auth=MSCHAPV2"
    # Without these two lines, a rogue RADIUS server can capture credentials
    subject_match="radius01.internal.example.com"
    phase1="peaplabel=0"
}
```

## PKI for EAP-TLS: Device Certificate Issuance

EAP-TLS requires every device to hold a valid certificate. At scale, manual certificate issuance is not operationally feasible. Automate using SCEP (Simple Certificate Enrollment Protocol) or EST (Enrollment over Secure Transport, RFC 7030).

For Linux endpoints, use `est-client` or a custom SCEP client. For Windows domain-joined devices, Group Policy auto-enrolment via AD CS handles this automatically. For non-domain Linux devices, use EJBCA, Dogtag, or HashiCorp Vault PKI:

```bash
# Enrol a device certificate via EST (RFC 7030)
# Requires an existing identity cert for mTLS to the EST server

curl --cert /etc/ssl/certs/bootstrap.crt \
     --key  /etc/ssl/private/bootstrap.key \
     --cacert /etc/ssl/certs/internal-ca.crt \
     -X POST \
     -H "Content-Type: application/pkcs10" \
     --data-binary @device-csr.p10 \
     "https://est.internal.example.com/.well-known/est/simpleenroll" \
     -o device-cert.p7

# Convert PKCS#7 response to PEM
openssl pkcs7 -in device-cert.p7 -inform DER -print_certs -out device-cert.crt
```

Generate the CSR with a CN that matches your RADIUS policy patterns:

```bash
openssl req -new -newkey rsa:2048 -nodes \
    -keyout device-key.pem \
    -out device-csr.p10 \
    -subj "/CN=corp-hostname-01/O=ExampleCorp/OU=Workstations"
```

Certificate renewal should be automated and triggered before expiry. A device with an expired certificate cannot authenticate and is denied network access — silent expiry is an outage cause. Set certificate lifetime to 1 year; automate renewal at 80% of lifetime:

```bash
# Check cert expiry (run from monitoring or via cron)
openssl x509 -in /etc/ssl/certs/device-cert.crt -noout -enddate

# Renew if expiring within 73 days (80% of 365-day cert)
EXPIRY=$(openssl x509 -in /etc/ssl/certs/device-cert.crt -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

if [ $DAYS_LEFT -lt 73 ]; then
    /usr/local/sbin/est-renew.sh
fi
```

## MAC Authentication Bypass (MAB)

Printers, IP phones, IoT sensors, and older industrial equipment often do not support 802.1X supplicants. For these devices, MAC Authentication Bypass (MAB) is the fallback: the switch sends the device's MAC address to RADIUS as both the username and password. RADIUS looks up the MAC in a database and returns an accept or reject.

MAB is weaker than 802.1X — it is susceptible to MAC spoofing — but it is better than unconditional access. Compensating controls for MAB devices:

- **Dedicated IoT VLANs with strict egress ACLs.** A printer should reach the print server and nothing else. Enforce this via the VLAN assignment returned by RADIUS and ACLs on the default gateway.
- **DHCP fingerprinting alongside MAB.** Correlate the DHCP Option 55 (Parameter Request List) and User-Agent strings against a known-good fingerprint database for the device model. Alert on mismatches.
- **Network behaviour analysis.** A printer initiating outbound SSH connections is anomalous. Use NetFlow or eBPF-based monitoring to alert on unexpected flows from MAB-authenticated ports.
- **Physical security.** Isolate MAB device ports to segments where physical tampering is detected or controlled.

Configure MAB in FreeRADIUS:

```conf
# /etc/freeradius/3.0/users
# MAB entries — MAC address as username (lower-case, colon-separated)

aa:bb:cc:dd:ee:ff Auth-Type := Accept
    Tunnel-Type = VLAN,
    Tunnel-Medium-Type = IEEE-802,
    Tunnel-Private-Group-Id = "50",
    Session-Timeout = 3600,
    Reply-Message = "MAB: Printer-Floor3"
```

Consider using SQL for MAB entries at scale:

```sql
-- FreeRADIUS radcheck table for MAB
INSERT INTO radcheck (username, attribute, op, value)
VALUES ('aa:bb:cc:dd:ee:ff', 'Auth-Type', ':=', 'Accept');

-- VLAN assignment in radreply
INSERT INTO radreply (username, attribute, op, value)
VALUES ('aa:bb:cc:dd:ee:ff', 'Tunnel-Type', '=', 'VLAN'),
       ('aa:bb:cc:dd:ee:ff', 'Tunnel-Medium-Type', '=', 'IEEE-802'),
       ('aa:bb:cc:dd:ee:ff', 'Tunnel-Private-Group-Id', '=', '50');
```

## Failure Modes and Hardening

**RADIUS server downtime.** If the RADIUS server is unreachable, the authenticator must make a decision: fail-open (allow access) or fail-closed (deny access). The choice depends on your threat model.

- **Fail-closed (default recommendation):** Unauthenticated devices get no access. This is the correct default for all ports except those supporting critical infrastructure (OOB management, fire suppression systems).
- **Fail-open:** Devices are admitted to a restricted VLAN. Only acceptable if the restricted VLAN provides no access to sensitive resources and RADIUS availability monitoring is in place.

Mitigate RADIUS downtime by running two RADIUS servers (primary and secondary) and configuring the authenticator to fail over:

```ios
radius server FREERADIUS-01
 address ipv4 10.0.1.30 auth-port 1812 acct-port 1813
 key 7 <key>
 timeout 3
 retransmit 2

radius server FREERADIUS-02
 address ipv4 10.0.1.31 auth-port 1812 acct-port 1813
 key 7 <key>
 timeout 3
 retransmit 2

aaa group server radius RADIUS-GROUP
 server name FREERADIUS-01
 server name FREERADIUS-02
 load-balance method least-outstanding

aaa authentication dot1x default group RADIUS-GROUP
```

**VLAN hopping.** 802.1X authenticates at Layer 2 but does not prevent VLAN hopping attacks. An attacker on an authenticated port can send double-tagged 802.1Q frames to reach the native VLAN of a trunk. Mitigate:

```ios
! Disable DTP on all ports (access and trunk)
interface range GigabitEthernet1/0/1 - 48
 switchport nonegotiate

! Set native VLAN on trunks to an unused VLAN (never VLAN 1)
interface GigabitEthernet1/0/49
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,50,100

! Tag native VLAN on trunk (vendor-specific, Cisco)
vlan dot1q tag native
```

**EAP re-authentication.** By default, 802.1X sessions persist until the port goes down. An attacker who disconnects the legitimate device, waits for the timeout, and reconnects their own device may inherit the authenticated session window. Enforce periodic re-authentication:

```ios
interface GigabitEthernet1/0/1
 authentication timer reauthenticate 3600    ! Re-auth every hour
 dot1x timeout reauth-period 3600
```

**Monitoring and alerting.** Log all RADIUS authentication events to a SIEM. Key events to alert on:

- Authentication failures exceeding threshold per port (potential brute force or misconfigured supplicant).
- MAB authentication for a MAC address that was previously 802.1X authenticated (device replacement or spoofing).
- RADIUS server failover events (indicates primary RADIUS degradation).
- Certificate expiry within 14 days (pre-empt outages).
- Unexpected VLAN assignment (RADIUS policy drift).

```bash
# Parse FreeRADIUS logs for failed auths
grep "Auth: \(0\)" /var/log/freeradius/radius.log | \
  awk '{print $1, $2, $NF}' | \
  sort | uniq -c | sort -rn | head -20
```

## Verification and Testing

Before rolling out to production ports, verify the end-to-end flow in a lab:

```bash
# Test EAP-TLS from a Linux supplicant
wpa_supplicant -c /etc/wpa_supplicant/corp-enterprise.conf \
               -i eth0 -d 2>&1 | grep -E "EAP|RADIUS|CTRL"

# Verify dynamic VLAN assignment was applied
ip link show eth0
bridge vlan show dev eth0

# Confirm RADIUS returned the expected VLAN via accounting
tail -f /var/log/freeradius/radacct/*/detail | \
  grep -A5 "Tunnel-Private-Group-Id"
```

Test failure paths explicitly:

```bash
# Test with a revoked certificate
openssl ca -revoke /etc/ssl/certs/test-device.crt -config /etc/ssl/openssl.cnf
# Refresh CRL / OCSP responder cache
systemctl restart freeradius

# Attempt authentication with revoked cert — should fail
eapol_test -c /etc/eapol_test/eap-tls-revoked.conf -s shared-secret -a 10.0.1.30
# Expected: Access-Reject
```

## Summary

MAC-based access control provides no meaningful security against an attacker with a laptop and a cable. 802.1X with EAP-TLS raises the bar substantially: every device must present a cryptographically valid certificate issued by your PKI before the switch port opens. RADIUS-driven dynamic VLAN assignment means the network segment a device lands on is determined by identity, not physical port location.

The deployment sequence that works in practice:

1. Stand up FreeRADIUS with EAP-TLS, test with a single switch port.
2. Build the PKI and automate device certificate enrolment via SCEP/EST.
3. Roll out 802.1X in monitor mode (log failures, do not block) to discover non-compliant devices.
4. Enrol non-802.1X devices into MAB with restricted VLAN assignments.
5. Switch to enforcement mode. Set VLAN 999/998 to no-access and restricted-access respectively.
6. Enable WPA3-Enterprise with PMF mandatory on all wireless SSIDs.
7. Run quarterly reviews of MAB device lists — decommissioned devices accumulate.

The residual risk after a full deployment is physical access to a port combined with a stolen device certificate and private key. Store private keys in TPMs and treat certificate-bearing devices as credentials — loss of a device should trigger certificate revocation within the same response window as a password reset.
