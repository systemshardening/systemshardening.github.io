---
title: "OT Non-Person Entity Identity: PKI and Zero Trust for PLCs and RTUs"
description: "CISA's OT Zero Trust guidance highlights device identity as the hardest pillar in OT. Build a PKI for OT non-person entities, separate AD forests for OT, and implement SPIFFE/SPIRE where devices support it — with compensating controls for legacy PLCs."
slug: ot-npe-identity-pki
date: 2026-05-03
lastmod: 2026-05-03
category: cross-cutting
tags:
  - ot-security
  - pki
  - identity
  - spiffe
  - ics
personas:
  - security-engineer
  - platform-engineer
article_number: 405
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/ot-npe-identity-pki/
---

# OT Non-Person Entity Identity: PKI and Zero Trust for PLCs and RTUs

## The Problem

In most OT networks, device identity is implicit: a SCADA server trusts Modbus data from IP address 192.168.10.5 because that is the PLC's static IP. There is no cryptographic proof that the device at that IP is the expected PLC — an attacker on the OT segment can ARP-spoof that IP and inject malicious register values. CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" identifies non-person entity (NPE) identity as the hardest Zero Trust pillar to implement in OT environments. Modern PLCs and RTUs were designed before PKI was affordable. Many have no capability to store or present certificates. Those that do often shipped with fixed 3-year certificate lifetimes, predating short-lived credential practices. Sensors, HMIs, and data historians add further variety: some run embedded Linux and are capable of SPIFFE/SPIRE integration; others are firmware-only devices with a serial-to-Ethernet converter as their sole network interface.

CISA's recommended approach is layered identity enforcement rather than a single control. The network layer — static IP assignment combined with MAC address binding and private VLANs — provides the first layer of identity signal. An OT PKI layer issues device certificates to the devices capable of using them: modern PLCs, Linux HMIs, OT gateways, and SCADA servers. SPIFFE/SPIRE provides a workload identity layer for Linux-capable OT edge devices where the certificate provisioning model is too heavy. Compensating controls — Dynamic ARP Inspection, port security, physical access controls, and anomaly detection — cover legacy PLCs and sensors that cannot participate in any modern identity framework.

A prerequisite that CISA addresses explicitly is Active Directory forest isolation. Many OT networks are compromised not through OT-specific vulnerabilities but through the shared corporate AD forest: an IT admin account, or a compromised corporate account, authenticates into OT systems via a forest trust relationship that was established for operational convenience and never reviewed. Eliminating that trust relationship is the first structural change; everything else in device identity builds on it.

This article covers all four layers: AD forest separation, OT PKI hierarchy, SPIFFE/SPIRE for Linux-capable OT edge devices, and MAC-layer compensating controls for legacy PLCs. Each section provides concrete configuration — not theory.

## Threat Model

- **IP spoofing and ARP poisoning within an OT subnet** — an attacker with a foothold on the OT segment sends gratuitous ARP replies advertising their MAC address as the IP of a trusted PLC. The SCADA server sends Modbus read/write requests to the attacker's host instead of the PLC. The attacker injects false sensor readings or writes malicious setpoint values. The operational impact ranges from process disruption to equipment damage if the attacker targets a safety-critical control loop.

- **Compromised vendor remote access account with no device binding** — a vendor's VPN credentials are phished or exfiltrated. The attacker connects from an arbitrary host and reaches OT systems because authentication is based solely on the credential, not on the device presenting it. Without device certificates or hardware attestation, the SCADA server cannot distinguish a legitimate vendor workstation from an attacker's machine using stolen credentials.

- **Corporate AD compromise giving IT admin access to OT systems via shared forest trust** — a compromised IT domain admin account is valid across a corporate-to-OT forest trust. The attacker logs into OT engineering workstations, historian servers, or SCADA consoles using IT credentials. CISA's April 2026 guidance cites this as a primary escalation path: attackers who compromise IT first pivot to OT through AD trusts established for operational convenience.

- **Expired or self-signed certificates on OT web interfaces** — historian REST APIs, SCADA web consoles, and HMI web interfaces that use self-signed or expired certificates cannot be verified by SCADA clients. Operators click through certificate warnings; MITM attacks on the OT LAN intercept data collection or inject false historian records during outage response.

- **SCADA server trusting any device on the OT VLAN** — without allowlisting specific device identities, any device plugged into an OT switch port can send Modbus, DNP3, or OPC-UA traffic to the SCADA server and have it accepted as legitimate telemetry. A rogue laptop inserted by a contractor or an insider threat goes undetected until data anomalies surface at the process level.

## Hardening Configuration

### 1. Separate OT Active Directory Forest

Create a new AD forest for OT with no trust relationship to the corporate forest. Separate DNS namespace, separate Domain Controllers, separate OT-scoped group policies.

The key requirement is `no trust`: not a one-way trust, not a selective authentication trust — no trust at all. The corporate forest and the OT forest are invisible to each other at the AD protocol level. OT engineers must have two separate accounts: their corporate account for email and IT systems, and an OT account that is provisioned with least-privilege access to specific OT systems.

```powershell
# On the designated OT Domain Controller (physical server, not shared with corporate).
# Run from an elevated PowerShell session on the new DC.

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote to the root of a new forest.
# Use a separate internal DNS domain that has no routing relationship to corp DNS.
Install-ADDSForest `
  -DomainName "ot.example.internal" `
  -DomainNetBiosName "OTDOMAIN" `
  -ForestMode "WinThreshold" `
  -DomainMode "WinThreshold" `
  -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "..." -AsPlainText -Force) `
  -Force

# After forest creation: verify no trust relationships exist.
# Run this on both the corporate DC and the OT DC.
Get-ADTrust -Filter * | Select-Object Name, TrustType, TrustDirection
# Expected output: no objects returned on the OT DC.
# If any trust appears, remove it:
# Remove-ADTrust -Identity <trust-name> -Confirm:$false
```

Configure DNS so the OT domain is not resolvable from the corporate network. OT DNS servers should not have forwarders pointing to corporate DNS — configure root hints or a dedicated external resolver for any internet lookups the OT DMZ requires.

OT engineer accounts in the OT forest should be separate from their corporate accounts. Document the credential management policy: OT accounts are stored in a dedicated vault (e.g., a Vault instance in the OT DMZ or a password manager accessible only from OT engineering workstations) and are not synchronised with corporate identity providers.

### 2. OT PKI Hierarchy

Build a two-tier PKI: an offline Root CA (air-gapped) and an online Issuing CA deployed in the OT DMZ. The Root CA signs only the Issuing CA certificate and the CRL; it is otherwise offline and physically secured (locked cabinet, safe, or offline workstation with encrypted storage). The Issuing CA handles day-to-day certificate issuance for OT devices.

Issue certificates to: OT servers (historian, SCADA, engineering workstation), HMIs, modern PLCs that support a certificate store, and OT gateways. Certificate lifetime: 1 year for device certificates, 5 years for the Issuing CA certificate, 20 years for the Root CA certificate. These lifetimes are shorter than the CISA-criticised 3-year device certificate standard; 1-year lifetimes are achievable with automation (see Step 5) and materially reduce the impact of a stolen certificate.

```bash
# Build the Root CA (run on an air-gapped workstation).
# The Root CA key never leaves this machine.

mkdir -p /root/ot-pki/{root-ca,issuing-ca}/{certs,crl,newcerts,private}
chmod 700 /root/ot-pki/root-ca/private

# Root CA configuration.
cat > /root/ot-pki/root-ca/openssl.cnf << 'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /root/ot-pki/root-ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand
private_key       = $dir/private/root-ca.key
certificate       = $dir/certs/root-ca.crt
crl               = $dir/crl/root-ca.crl
default_md        = sha384
default_days      = 7300
default_crl_days  = 180
policy            = policy_strict

[ policy_strict ]
countryName             = match
organizationName        = match
commonName              = supplied

[ req ]
default_bits        = 4096
default_md          = sha384
distinguished_name  = req_distinguished_name
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName             = Country Name (2 letter code)
organizationName        = Organization Name
commonName              = Common Name

[ v3_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer
basicConstraints        = critical,CA:true,pathlen:1
keyUsage                = critical,keyCertSign,cRLSign
EOF

touch /root/ot-pki/root-ca/index.txt
echo 1000 > /root/ot-pki/root-ca/serial

# Generate Root CA key and self-signed certificate.
openssl genrsa -aes256 -out /root/ot-pki/root-ca/private/root-ca.key 4096
chmod 400 /root/ot-pki/root-ca/private/root-ca.key

openssl req -config /root/ot-pki/root-ca/openssl.cnf \
  -key /root/ot-pki/root-ca/private/root-ca.key \
  -new -x509 -days 7300 -extensions v3_ca \
  -out /root/ot-pki/root-ca/certs/root-ca.crt \
  -subj "/C=US/O=Example Corp OT/CN=OT Root CA"

# Generate Issuing CA key and CSR (run on the OT DMZ Issuing CA server, then transfer CSR to air-gapped Root CA).
openssl genrsa -aes256 -out /root/ot-pki/issuing-ca/private/issuing-ca.key 4096

openssl req -new \
  -key /root/ot-pki/issuing-ca/private/issuing-ca.key \
  -out /root/ot-pki/issuing-ca/issuing-ca.csr \
  -subj "/C=US/O=Example Corp OT/CN=OT Issuing CA"

# Sign Issuing CA CSR with Root CA (on the air-gapped Root CA workstation).
openssl ca -config /root/ot-pki/root-ca/openssl.cnf \
  -extensions v3_ca \
  -days 1825 \
  -notext \
  -md sha384 \
  -in /root/ot-pki/issuing-ca/issuing-ca.csr \
  -out /root/ot-pki/issuing-ca/certs/issuing-ca.crt
```

Deploy the Issuing CA on a dedicated server in the OT DMZ (not shared with corporate infrastructure). Distribute the Root CA certificate to all OT devices and OT engineering workstations as a trusted root. Any OT device that presents a certificate signed by the Issuing CA will be trusted by OT systems that have the Root CA in their trust store; any device that presents a corporate IT certificate, or no certificate, will not be.

Issue device certificates to capable devices:

```bash
# Generate a device key and CSR for a historian server.
# Run on the historian server.
openssl genrsa -out /etc/ot-pki/historian.key 4096
chmod 400 /etc/ot-pki/historian.key

openssl req -new \
  -key /etc/ot-pki/historian.key \
  -out /etc/ot-pki/historian.csr \
  -subj "/C=US/O=Example Corp OT/CN=historian.ot.example.internal" \
  -addext "subjectAltName=DNS:historian.ot.example.internal,IP:192.168.10.20"

# Sign on the Issuing CA (1-year lifetime).
openssl ca -config /root/ot-pki/issuing-ca/openssl.cnf \
  -extensions server_cert \
  -days 365 \
  -notext \
  -md sha256 \
  -in /etc/ot-pki/historian.csr \
  -out /etc/ot-pki/historian.crt
```

### 3. SPIFFE/SPIRE for Linux OT Edge Devices

For Linux-capable OT edge devices — OT gateways running Linux, Raspberry Pi-based sensor aggregators, Linux HMIs, and containerised SCADA components — deploy SPIFFE/SPIRE to issue short-lived SVIDs. The SPIRE server runs in the OT DMZ. SPIRE agents run on each Linux OT device.

Node attestation uses TPM 2.0 where the device has one; for devices without TPM, use SPIRE's join token attestation with compensating network controls (the join token is a one-time credential; after registration, the node's identity is bound to the TPM-measured boot state or, in the join-token case, to the agent's private key stored on device).

SVID TTL: 4 hours. This is shorter than typical enterprise SPIRE deployments (1 hour is common in Kubernetes environments) but longer than feasible for embedded devices that may have intermittent OT DMZ connectivity. Four hours balances credential freshness with the reality that OT networks have higher latency and connectivity constraints than cloud environments.

```hcl
# spire-server.conf — deployed in OT DMZ
server {
  bind_address = "0.0.0.0"
  bind_port    = "8081"
  trust_domain = "ot.example.internal"
  data_dir     = "/var/lib/spire/server"
  log_level    = "INFO"

  ca_subject = {
    country      = ["US"],
    organization = ["Example Corp OT"],
    common_name  = "OT SPIRE Server CA"
  }

  default_x509_svid_ttl = "4h"
  default_jwt_svid_ttl  = "30m"
  ca_ttl                = "168h"
  ca_key_type           = "ec-p256"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type     = "sqlite3"
      connection_string = "/var/lib/spire/server/datastore.sqlite3"
    }
  }

  KeyManager "disk" {
    plugin_data {
      keys_path = "/var/lib/spire/server/keys.json"
    }
  }

  NodeAttestor "tpm_devid" {
    plugin_data {
      devid_cert_path = "/var/lib/spire/server/tpm-devid-root.crt"
    }
  }

  NodeAttestor "join_token" {}
}
```

Register an OT gateway device using TPM attestation:

```bash
# On the SPIRE server host in the OT DMZ.

# Register a Linux OT gateway using its TPM DevID certificate.
spire-server entry create \
  -spiffeID spiffe://ot.example.internal/gateway/line-a \
  -parentID spiffe://ot.example.internal/spire/agent/tpm_devid/gateway-line-a \
  -selector tpm_devid:subject:cn:gateway-line-a.ot.example.internal \
  -ttl 14400

# For a device without TPM: issue a one-time join token and register the node.
JOIN_TOKEN=$(spire-server token generate -spiffeID spiffe://ot.example.internal/agent/sensor-node-7 | awk '{print $2}')

# Transfer the join token to the sensor node via an authenticated OOB channel
# (not via OT network — use a management port or USB configuration stick).
# The join token is consumed on first agent startup and cannot be reused.

# On the sensor node:
spire-agent run \
  -config /etc/spire/agent.conf \
  -joinToken "${JOIN_TOKEN}"
```

SPIRE agent configuration for a Linux OT edge device:

```hcl
# /etc/spire/agent.conf — deployed on Linux OT edge devices
agent {
  data_dir      = "/var/lib/spire/agent"
  log_level     = "INFO"
  server_address = "spire-server.ot-dmz.example.internal"
  server_port   = "8081"
  socket_path   = "/run/spire/agent.sock"
  trust_bundle_path = "/etc/spire/bundle.crt"
  trust_domain  = "ot.example.internal"
}

plugins {
  NodeAttestor "tpm_devid" {
    plugin_data {
      devid_cert_path    = "/var/lib/tpm/devid.crt"
      devid_priv_path    = "/var/lib/tpm/devid.key"
      devid_intermediate_path = "/var/lib/tpm/devid-chain.crt"
    }
  }

  KeyManager "disk" {
    plugin_data {
      directory = "/var/lib/spire/agent/keys"
    }
  }

  WorkloadAttestor "unix" {
    plugin_data {
      discover_workload_path = true
    }
  }
}
```

Applications on Linux OT edge devices fetch their SVID from the agent socket. A Modbus-to-MQTT bridge, for example, can present its SPIFFE SVID when connecting to the MQTT broker in the OT DMZ, and the broker can enforce that only devices with a valid `spiffe://ot.example.internal/gateway/*` identity are permitted to publish sensor data.

### 4. MAC Address Binding and DAI for Legacy PLCs

For PLCs and RTUs that cannot hold certificates, the identity control moves entirely to the network layer. Three controls in combination:

**Static ARP entries on the SCADA server** — the SCADA server maintains a static ARP binding for each PLC's IP-to-MAC mapping. A gratuitous ARP from an attacker cannot override a static ARP entry.

```bash
# On the SCADA server (Linux). Add a static ARP entry for each PLC.
# This must be re-applied at boot; use a systemd oneshot unit or /etc/rc.local equivalent.
arp -s 192.168.10.5 aa:bb:cc:dd:ee:01
arp -s 192.168.10.6 aa:bb:cc:dd:ee:02
arp -s 192.168.10.7 aa:bb:cc:dd:ee:03

# Verify static entries are present.
arp -n | grep PERM
```

**Dynamic ARP Inspection (DAI) on managed OT switches** — DAI validates ARP packets against a DHCP snooping binding table or a static ARP ACL. For OT environments where PLCs use static IPs (common), build the binding table via static ARP ACL entries rather than DHCP snooping.

```conf
# Cisco IOS switch configuration for OT segment.
# Build the ARP ACL with known PLC IP/MAC bindings.
arp access-list OT-PLC-ARP-ACL
 permit ip host 192.168.10.5 mac host aabb.ccdd.ee01
 permit ip host 192.168.10.6 mac host aabb.ccdd.ee02
 permit ip host 192.168.10.7 mac host aabb.ccdd.ee03

# Apply DAI to the OT VLAN using the static ARP ACL.
ip arp inspection vlan 10
ip arp inspection filter OT-PLC-ARP-ACL vlan 10

# Trust the uplink port (to the OT DMZ firewall); do not trust PLC-facing access ports.
interface GigabitEthernet0/1
 ip arp inspection trust

# Enable port security on PLC-facing switch ports.
interface range GigabitEthernet0/2 - 8
 switchport mode access
 switchport access vlan 10
 switchport port-security maximum 1
 switchport port-security mac-address sticky
 switchport port-security violation restrict
 spanning-tree portfast
```

**Private VLAN (PVLAN) to block PLC-to-PLC communication** — PLCs on the OT segment have no legitimate reason to communicate with each other; all Modbus and DNP3 traffic flows between PLCs and the SCADA server. PVLAN isolates each PLC port so that even within the same VLAN, intra-host communication is blocked at the switch level. An attacker who has compromised one PLC cannot use it to probe or spoof another PLC.

```conf
# Private VLAN configuration.
# VLAN 10 is the primary VLAN; VLAN 100 is an isolated secondary VLAN.
vlan 10
 private-vlan primary
vlan 100
 private-vlan isolated

vlan 10
 private-vlan association 100

# PLC-facing ports: isolated (cannot communicate with each other).
interface range GigabitEthernet0/2 - 8
 switchport mode private-vlan host
 switchport private-vlan host-association 10 100

# SCADA server uplink: promiscuous (can communicate with all isolated ports).
interface GigabitEthernet0/9
 switchport mode private-vlan promiscuous
 switchport private-vlan mapping 10 100
```

### 5. Certificate Lifecycle Automation

Manual certificate renewal for OT device certificates fails in practice: certificates expire during a change freeze, the renewal is deferred, and the historian API goes HTTPS-unavailable during an incident. Automate renewal for all Linux-based OT systems using HashiCorp Vault PKI or Step CA with the ACME protocol.

```bash
# Deploy Vault PKI engine in the OT DMZ.
# Vault itself is in the OT DMZ — not the corporate Vault instance.

vault secrets enable -path=ot-pki pki
vault secrets tune -max-lease-ttl=43800h ot-pki

# Import the OT Issuing CA into Vault PKI.
vault write ot-pki/config/ca \
  pem_bundle="$(cat issuing-ca.crt issuing-ca.key)"

# Configure the CRL distribution point.
vault write ot-pki/config/urls \
  issuing_certificates="https://vault.ot-dmz.example.internal:8200/v1/ot-pki/ca" \
  crl_distribution_points="https://vault.ot-dmz.example.internal:8200/v1/ot-pki/crl"

# Create a role for OT server certificates (1-year max TTL).
vault write ot-pki/roles/ot-servers \
  allowed_domains="ot.example.internal" \
  allow_subdomains=true \
  max_ttl="8760h" \
  key_type="rsa" \
  key_bits=4096 \
  require_cn=true

# On an OT server (historian, SCADA): use Vault agent or certbot with the Vault ACME endpoint
# to automate certificate renewal.
# Enable ACME on the Vault PKI engine (Vault 1.14+).
vault write ot-pki/config/acme enabled=true

# On the historian server: use certbot with ACME against the OT Vault instance.
certbot certonly \
  --server https://vault.ot-dmz.example.internal:8200/v1/ot-pki/acme/directory \
  --standalone \
  -d historian.ot.example.internal \
  --agree-tos \
  --email ot-pki-admin@example.com

# Configure a systemd timer for automated renewal check (runs twice daily).
systemctl enable --now certbot.timer
```

Configure a 30-day pre-expiry alert so the operations team knows about impending renewals before automation failures matter:

```bash
# Cron job to alert on certificates expiring within 30 days.
# Runs on the OT PKI management server daily.
openssl x509 -in /etc/ot-pki/historian.crt -noout -checkend 2592000
if [ $? -ne 0 ]; then
  echo "ALERT: OT certificate at /etc/ot-pki/historian.crt expires within 30 days" \
    | mail -s "OT PKI Expiry Warning" ot-security@example.com
fi
```

### 6. Compensating Controls for Uncertifiable Legacy PLCs

Some PLCs in production OT environments cannot be updated, replaced, or reconfigured. They have no certificate storage, no TLS stack, and no mechanism to participate in any identity framework. The compensating control set for these devices covers network, monitoring, and physical layers.

**Network controls:** strict firewall rules on the OT DMZ firewall that allowlist only the specific source IP, destination IP, port, and Modbus/DNP3 function code for each PLC-to-SCADA communication pair. No traffic between PLC addresses and anything other than the SCADA server is permitted through the firewall.

**Monitoring with Zeek** — deploy Zeek on a passive tap on the OT switch uplink. Alert on any new MAC address observed on the OT segment:

```bash
# Zeek script: alert on new MAC addresses on the OT segment.
# Place in /usr/share/zeek/site/ot-mac-monitor.zeek

@load base/frameworks/notice

module OTMACMonitor;

export {
  redef enum Notice::Type += { New_OT_MAC };
  const known_macs: set[string] = {
    "aa:bb:cc:dd:ee:01",
    "aa:bb:cc:dd:ee:02",
    "aa:bb:cc:dd:ee:03"
  } &redef;
}

event new_connection(c: connection) {
  local src_mac = c$id$orig_h;
}

event Pcap::file_done(path: string) {}

event arp_request(mac_src: string, mac_dst: string,
                  SPA: addr, SHA: string, TPA: addr, THA: string) {
  if (SHA !in known_macs) {
    NOTICE([$note=New_OT_MAC,
            $msg=fmt("Unknown MAC address on OT segment: %s at IP %s", SHA, SPA),
            $identifier=SHA]);
  }
}
```

**Physical controls:** OT switch ports must terminate at lockable patch panels. Unused switch ports are disabled in configuration and physically blanked. Cabinet doors are locked; access requires a written work order. Port-security sticky MAC is configured on all access ports so any cable change triggers a violation alert.

## Expected Behaviour After Hardening

After AD forest separation: an IT administrator's domain account has no authentication path to any OT system. Kerberos tickets issued by the corporate forest are not trusted by OT domain controllers. An attempt to mount a share, log into an OT workstation, or authenticate to an OT application with a corporate account fails at the domain authentication layer, not at the application layer.

After OT PKI deployment: the historian HTTPS interface serves a TLS certificate issued by the OT Issuing CA. A SCADA client that has imported the OT Root CA certificate validates the historian TLS session without errors. A client that has not imported the OT Root CA — including any corporate IT browser or tool — receives a certificate validation failure and cannot establish a session. Self-signed certificate warnings on OT web interfaces disappear.

After DAI enablement: an attempt to ARP-spoof a PLC address on the OT switch generates a DAI violation log entry and the spoofed ARP reply is dropped. The SCADA server's ARP table retains the legitimate PLC MAC binding. The SCADA server continues polling the correct PLC; the attacker's host does not receive any SCADA traffic intended for the PLC.

After PVLAN deployment: a device plugged into one PLC port cannot send Ethernet frames directly to another PLC port. All traffic from isolated ports is forwarded only to the promiscuous port (the SCADA server uplink). Intra-OT-subnet scanning and lateral movement from a compromised PLC port are blocked at layer 2.

## Trade-offs and Operational Considerations

Separate AD forest means OT engineers maintain two credentials: their corporate account and their OT account. Document the credential management policy: OT accounts are stored in a vault accessible only from OT engineering workstations (e.g., a CyberArk or Vault instance deployed in the OT DMZ, not the corporate secrets manager). Password complexity and MFA requirements for OT accounts must be at least as strong as corporate policy and ideally stronger, since OT accounts have access to safety-critical systems.

SPIRE requires TPM 2.0 for the strongest node attestation model. Many older Linux OT gateways lack a TPM. Use join token attestation for TPM-less devices, with the following compensating controls: one-time join tokens are delivered out-of-band (not over the OT network), the device's network position is constrained by PVLAN and firewall rules, and the SPIRE server logs all agent attestation events to the OT SIEM. Join tokens are never reused; re-attestation after a node rebuild requires a new token generated and delivered out-of-band.

One-year certificate lifetimes for OT device certificates require renewal automation to be reliable. Test the renewal workflow — the certbot ACME renewal or the Vault agent renewal — in a staging OT environment before deploying to production. A failed renewal on the historian certificate will make the SCADA client unable to connect to the historian until the certificate is manually renewed; test that the pre-expiry alert and the renewal automation both work, and document the manual fallback procedure.

Private VLAN isolation requires managed switches. Legacy unmanaged switches in OT environments cannot support PVLAN or DAI. For segments with unmanaged switches, the compensating control is to replace the unmanaged switch with a managed equivalent at the next maintenance window, or to insert a managed Layer 2 switch upstream of the unmanaged switch that applies the PVLAN and DAI at the port connecting to the unmanaged segment. Document this gap formally in the risk register if immediate replacement is not feasible.

OT PKI CRL distribution points must be reachable from all OT devices that perform certificate validation. The CRL endpoint (the Vault PKI CRL or a standalone OCSP responder) should be deployed in the OT DMZ with high availability; a CRL that is unreachable will cause certificate validation failures on SCADA clients and OT servers depending on how clients are configured to handle CRL fetch failures. Configure OCSP Must-Staple where supported to avoid CRL availability becoming a dependency on every TLS handshake.

## Failure Modes

A new OT AD forest is created but the old trust relationship with the corporate forest is not explicitly removed. If a trust was in place before the new forest was built, or if forest migration scripts re-create it, the implicit trust persists. Verify with `Get-ADTrust -Filter *` on both the corporate and OT domain controllers after any forest change and after any domain controller rebuild.

The OT PKI Issuing CA is deployed on a virtual machine that shares physical hardware with corporate infrastructure. The air gap between OT PKI and corporate IT is violated at the hypervisor level: a compromised corporate hypervisor host can access the OT Issuing CA VM's disk, extract the private key, and sign arbitrary OT device certificates. The Issuing CA must run on dedicated hardware in the OT DMZ. If virtualisation is unavoidable, the hypervisor host itself must be physically in the OT environment and managed exclusively through OT access controls.

SPIRE is deployed with join token node attestation, but join tokens are never rotated after initial registration. A join token that was used once and then stored in a configuration file — rather than consumed and discarded — becomes a persistent credential. SPIRE join tokens are intended to be one-time-use; verify that no join tokens remain in configuration files or deployment scripts after initial use. Audit with `spire-server token list` and revoke any tokens that were not consumed.

DAI is enabled on the OT switch but the static ARP ACL does not include all PLCs on the segment. PLCs with static IPs that are not listed in the ARP ACL will have their ARP traffic classified as untrusted and dropped by DAI, blocking legitimate PLC-to-SCADA communication. Before enabling DAI, enumerate every device on the OT segment and confirm its IP-to-MAC binding is in the ARP ACL. Test DAI in log-only mode (`ip arp inspection validate` without the `drop` action) for one polling cycle before enabling enforcement.

Zeek is deployed for OT segment monitoring but the `known_macs` set in the OT MAC monitor script is not updated when new PLCs are added during maintenance windows. Every OT device addition or replacement must include a step to update the Zeek MAC allowlist and the static ARP ACL on the SCADA server. Document this in the OT change management process; a new device that triggers a Zeek `New_OT_MAC` notice during a planned maintenance window should generate a low-severity alert rather than a high-severity incident — but the MAC must be added to the allowlist before the maintenance window closes.

## Related Articles

- [SPIFFE SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
- [HSM Key Management](/articles/cross-cutting/hsm-key-management/)
- [OT Network Segmentation Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)
- [Go x509 PKI Security](/articles/cross-cutting/go-x509-pki-security/)
- [OAuth2 OIDC Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
