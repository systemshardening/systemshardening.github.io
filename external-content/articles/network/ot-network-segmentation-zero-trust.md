---
title: "OT Network Segmentation: Zero Trust with ISA/IEC 62443 Zones and Conduits"
description: "CISA's OT Zero Trust guidance replaces the Purdue Model with ISA/IEC 62443 zones and conduits for granular segmentation. Learn how to define security zones, enforce conduit rules, design DMZs, and monitor IT/OT boundaries."
slug: ot-network-segmentation-zero-trust
date: 2026-05-03
lastmod: 2026-05-03
category: network
tags:
  - ot-security
  - network-segmentation
  - ics
  - zero-trust
  - iec-62443
personas:
  - platform-engineer
  - security-engineer
article_number: 401
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/ot-network-segmentation-zero-trust/
---

# OT Network Segmentation: Zero Trust with ISA/IEC 62443 Zones and Conduits

## The Problem

The Purdue Model (ISA-95 levels 0–5) has been the default OT network architecture for 30 years. It provides layer-based separation but not identity-aware access control: anything at Level 3 (site operations) can freely communicate with Level 2 (supervisory control) without per-session authentication. CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" identifies this as the primary attack path for Volt Typhoon: compromise a Level 3 historian or data aggregator, then reach Level 2 SCADA servers and Level 1 PLCs via implicit trust. The dwell time on compromised OT infrastructure measured in years — not weeks — because IT security teams have no visibility into lateral movement once traffic stays within the OT layer.

ISA/IEC 62443 zones-and-conduits addresses this directly. Each Security Zone contains assets that share the same security level (SL) requirement, defined by IEC 62443-3-3 on a scale of SL 1 (protection against casual violations) to SL 4 (protection against state-level adversaries with sophisticated means). Each Conduit is a defined communication path between zones: it enumerates allowed protocols, directions, and authentication requirements. Nothing crosses a zone boundary unless a conduit explicitly permits it.

This is fundamentally different from the Purdue Model in one critical way: zones are defined by security requirement, not by physical location or network layer. A remote engineering workstation in a corporate office can be placed in the same zone as the SCADA server if — and only if — the conduit between them carries explicit controls: session authentication, protocol allowlisting, and full logging. The Purdue Model would treat the workstation as Level 3 and the SCADA server as Level 2 and permit any traffic that crosses the layer boundary through a simple VLAN ACL. ISA/IEC 62443 requires that you prove the communication path is necessary and enforce it precisely.

CISA explicitly recommends the ISA/IEC 62443 zones-and-conduits model as more granular than the Purdue Model for implementing Zero Trust controls. The guidance documents Volt Typhoon's specific method: use the IT→OT implicit trust path to gain initial access to the OT environment via a compromised IT host, then exploit the flat Level 3 network to pivot from a historian to an engineering workstation to PLCs without encountering any additional authentication challenges. This article implements the countermeasures CISA recommends.

## Threat Model

- **Volt Typhoon IT→OT implicit trust exploitation.** Nation-state actors with 5-year dwell times use the trust relationship between IT Active Directory and OT hosts to pivot from a compromised IT endpoint into the OT environment. The IT admin credential has no business in the OT environment, but no enforcement mechanism exists to stop it.
- **Flat Level 3 lateral movement.** Historian servers, data aggregators, and engineering workstations share a flat Level 3 network. An attacker who compromises the historian can reach the engineering workstation via SMB and from there push malicious logic to PLCs via vendor engineering software without crossing any firewall.
- **Remote access paths that bypass segmentation.** Vendor VPN connections and corporate remote-access VPNs frequently terminate directly inside the OT zone — often because the VPN concentrator is placed at Level 3 with routing into Level 2. The vendor technician's laptop, connected over the internet, has the same network adjacency as a local HMI.
- **Active Directory trust relationships granting OT access.** When OT systems join the same AD forest as IT systems, IT domain admins have implicit administrative rights on OT Windows hosts. A compromised IT DA account gives full OT access with no additional authentication step.
- **HMI pivot to PLC.** A Windows or Linux HMI workstation running vendor SCADA software sits on the same VLAN as the PLCs it manages. A compromised HMI can query PLC registers, modify setpoints, and issue control commands using the engineering protocol (Modbus, DNP3, OPC-UA) because no firewall exists between the HMI and PLC within the same level.
- **Access level:** Adversaries start with either a compromised IT endpoint (external initial access) or a compromised remote-access credential (vendor phishing, credential stuffing). Post-compromise lateral movement exploits implicit trust paths.
- **Objective:** Long-term persistence in OT infrastructure, positioning for disruption of industrial processes.
- **Blast radius:** On a Purdue-model network with no conduit enforcement, a single compromised IT endpoint can reach PLCs in under 3 hops with no authentication challenges after the initial IT compromise.

## Hardening Configuration

### Step 1: Define Security Zones

The first task is asset discovery and zone assignment. Every OT asset must be enumerated and assigned to a zone before conduits can be defined. The zone assignment is based on security requirement, not physical location.

The following zone model follows IEC 62443-3-3 security level ratings:

| Zone | Name | Example Assets | Security Level | VLAN |
|------|------|---------------|---------------|------|
| Zone 0 | Field Devices | PLCs, RTUs, sensors, actuators | SL 3 | VLAN 10 |
| Zone 1 | Control | DCS controllers, SCADA servers | SL 3 | VLAN 20 |
| Zone 2 | Supervisory | HMIs, engineering workstations | SL 2 | VLAN 30 |
| Zone 3 | Site Operations | Historians, OPC gateways, data aggregators | SL 2 | VLAN 40 |
| DMZ | IT/OT Boundary | Data historian replica, jump host, vendor access gateway | SL 2 | VLAN 50 |
| Zone 4 | Corporate IT | IT workstations, AD, corporate servers | SL 1 | VLAN 100 |

Security Level is assigned per IEC 62443-3-3. Zone 0 and Zone 1 carry SL 3 because they directly affect physical process control — attacks against these assets can cause physical damage or safety incidents. Zone 3 carries SL 2 because compromise enables reconnaissance and is the staging point for lateral movement into higher zones.

Document zone membership in a configuration file that becomes the authoritative source for firewall rule generation:

```conf
# /etc/ot-zones/zone-registry.conf
# Format: ASSET_IP  HOSTNAME  ZONE  FUNCTION  VENDOR_PROTOCOL

10.10.10.1   plc-boiler-1       zone0   boiler-controller     modbus-tcp/502
10.10.10.2   plc-boiler-2       zone0   boiler-controller     modbus-tcp/502
10.10.10.3   rtu-substation-1   zone0   substation-rtu        dnp3/20000

10.10.20.1   scada-server-1     zone1   scada-primary         opc-ua/4840
10.10.20.2   scada-server-2     zone1   scada-secondary       opc-ua/4840
10.10.20.3   dcs-controller-1   zone1   dcs                   modbus-tcp/502

10.10.30.1   hmi-ops-1          zone2   operator-hmi          opc-ua/4840
10.10.30.2   eng-ws-1           zone2   engineering-ws        modbus-tcp/502,opc-ua/4840
10.10.30.3   eng-ws-2           zone2   engineering-ws        modbus-tcp/502,opc-ua/4840

10.10.40.1   historian-primary  zone3   data-historian        opc-da/135
10.10.40.2   opc-gateway-1      zone3   protocol-gateway      opc-ua/4840

10.10.50.1   historian-replica  dmz     it-facing-historian   opc-da/135
10.10.50.2   jump-host-1        dmz     ot-jump-host          ssh/22
10.10.50.3   vendor-gw-1        dmz     vendor-access-gw      rdp/3389

10.10.100.0/24  corporate-it   zone4   it-network            varied
```

### Step 2: Design Conduits

A Conduit is the formal description of a permitted communication path between two zones. Every conduit must specify source zone, destination zone, allowed protocol and port, direction, and authentication requirement. Communication not described by a conduit is implicitly denied.

| Conduit ID | Source | Destination | Protocol | Port | Direction | Auth Required |
|-----------|--------|-------------|----------|------|-----------|---------------|
| C-01 | Zone 0 | Zone 1 | Modbus TCP | 502 | Bidirectional | None (field bus) |
| C-02 | Zone 0 | Zone 1 | DNP3 | 20000 | Bidirectional | None (field bus) |
| C-03 | Zone 1 | Zone 2 | OPC-UA | 4840 | Zone1→Zone2 | OPC-UA session cert |
| C-04 | Zone 2 | Zone 1 | OPC-UA | 4840 | Zone2→Zone1 | OPC-UA session cert |
| C-05 | Zone 2 | Zone 0 | Modbus TCP | 502 | Zone2→Zone0 | Source IP allowlist |
| C-06 | Zone 3 | Zone 2 | OPC-UA | 4840 | Zone3→Zone2 | OPC-UA session cert |
| C-07 | Zone 3 | DMZ | OPC-DA | 135,dynamic | Zone3→DMZ | Unidirectional gateway |
| C-08 | DMZ | Zone 3 | None | — | No return path | Data diode enforced |
| C-09 | DMZ | Zone 4 | HTTPS | 443 | DMZ→Zone4 | TLS mutual auth |
| C-10 | Zone 4 | DMZ | HTTPS | 443 | Zone4→DMZ | TLS mutual auth |
| C-11 | DMZ | Zone 2 | RDP/SSH | 3389, 22 | DMZ→Zone2 | MFA + session recording |

Conduits C-07 and C-08 implement the critical IT/OT data flow: the historian in Zone 3 sends data to its replica in the DMZ, but the DMZ host cannot send anything back to Zone 3. A data diode or unidirectional security gateway (Waterfall, Owl Cyber Defense, Hirschmann Eagle) enforces this physically — no TCP session can be established in the return direction because the hardware does not support it.

There is no conduit from Zone 4 (Corporate IT) directly to Zone 1, Zone 2, or Zone 0. This is the explicit implementation of Volt Typhoon's primary attack path removal.

### Step 3: Implement the IT/OT DMZ

The DMZ zone is the controlled boundary between IT and OT. It hosts three categories of assets, each with a distinct trust model.

**Data historian replica** receives one-way data from the Zone 3 historian via a unidirectional gateway. IT systems read from the replica; they have no path to the source historian. A data diode ensures this: even if the IT network is fully compromised, no traffic can traverse the diode from IT to OT.

**Jump host** is the only path by which OT engineers access Zone 2 systems. Engineers authenticate to the jump host with MFA, and the jump host proxies their RDP or SSH session into Zone 2. The jump host records all sessions (keyboard, screen, commands). Engineers do not have direct network access to Zone 2 from their corporate workstations.

**Vendor access gateway** provides time-limited, session-scoped access for OT vendor technicians. The gateway issues short-lived credentials, records all session activity, and terminates access automatically after the maintenance window. Vendor traffic enters the DMZ from the internet and does not cross to Zone 2 until a local OT engineer grants explicit session approval.

```conf
# /etc/nftables.d/dmz-interfaces.conf
# DMZ firewall — three interfaces:
#   eth0: IT-facing (Zone 4 / Corporate IT)
#   eth1: OT-facing (Zone 3 / Site Operations)
#   eth2: Management

table inet dmz_filter {

  chain input {
    type filter hook input priority 0; policy drop;

    ct state established,related accept
    iifname "lo" accept

    iifname "eth0" tcp dport 443 ct state new accept
    iifname "eth0" tcp dport 3389 ip saddr 10.10.100.0/24 ct state new accept

    iifname "eth1" tcp sport 135 ct state new accept
    iifname "eth1" tcp sport 4840 ct state new accept

    iifname "eth2" tcp dport 22 ip saddr 10.10.200.0/24 accept

    log prefix "dmz-input-drop: " flags all drop
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept

    iifname "eth1" oifname "eth0" accept
    iifname "eth0" oifname "eth1" drop

    iifname "eth0" oifname "eth2" drop
    iifname "eth2" oifname "eth0" drop

    log prefix "dmz-forward-drop: " flags all drop
  }

  chain output {
    type filter hook output priority 0; policy drop;

    ct state established,related accept
    iifname "lo" accept

    oifname "eth0" tcp dport 443 accept
    oifname "eth1" tcp dport 135 accept
    oifname "eth1" tcp dport 4840 accept
    oifname "eth2" tcp dport 514 accept

    log prefix "dmz-output-drop: " flags all drop
  }
}
```

### Step 4: Enforce Conduit Rules at the Zone Boundary Firewall

Each conduit maps directly to a firewall rule set. The zone boundary firewall (an industrial firewall such as a Cisco IE3400, Fortinet FortiGate Rugged, or a hardened Linux host running nftables) enforces conduit definitions at the network level.

The following ruleset implements conduits for the Zone 1/Zone 2 boundary:

```conf
# /etc/nftables.d/zone1-zone2-boundary.conf
# Enforces Conduits C-03, C-04, C-05 between Zone 1 and Zone 2.
# Zone 1 (VLAN 20): 10.10.20.0/24   scada-server-1, scada-server-2, dcs-controller-1
# Zone 2 (VLAN 30): 10.10.30.0/24   hmi-ops-1, eng-ws-1, eng-ws-2

table inet zone_boundary {

  set zone1_hosts {
    type ipv4_addr; flags interval;
    elements = { 10.10.20.1, 10.10.20.2, 10.10.20.3 }
  }

  set zone2_hosts {
    type ipv4_addr; flags interval;
    elements = { 10.10.30.1, 10.10.30.2, 10.10.30.3 }
  }

  set zone2_eng_ws {
    type ipv4_addr; flags interval;
    elements = { 10.10.30.2, 10.10.30.3 }
  }

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept

    ip saddr @zone1_hosts ip daddr @zone2_hosts tcp dport 4840 ct state new \
      log prefix "conduit-C03: " accept

    ip saddr @zone2_hosts ip daddr @zone1_hosts tcp dport 4840 ct state new \
      log prefix "conduit-C04: " accept

    ip saddr @zone2_eng_ws ip daddr 10.10.10.0/24 tcp dport 502 ct state new \
      log prefix "conduit-C05: " accept

    log prefix "zone12-boundary-drop: " flags all drop
  }
}
```

The Zone 2/Zone 3 boundary enforces conduit C-06:

```conf
# /etc/nftables.d/zone2-zone3-boundary.conf
# Enforces Conduit C-06: Zone 3 historian reads from Zone 2 SCADA via OPC-UA.

table inet zone23_boundary {

  chain forward {
    type filter hook forward priority 0; policy drop;

    ct state established,related accept

    ip saddr 10.10.40.1 ip daddr @zone2_hosts tcp dport 4840 ct state new \
      log prefix "conduit-C06: " accept

    log prefix "zone23-boundary-drop: " flags all drop
  }
}
```

Every conduit log line carries the conduit ID. This allows SIEM correlation rules to fire on any traffic that does not match a named conduit — by definition, unexpected traffic.

### Step 5: Eliminate Implicit IT→OT Trust

Removing the implicit trust path requires changes at three layers: routing, DNS, and directory services.

**Routing isolation.** Corporate IT and OT networks must not have routable paths between them except through the DMZ.

```bash
ip route del 10.10.0.0/16 via 10.10.100.1 table main

ip route add unreachable 10.10.10.0/24
ip route add unreachable 10.10.20.0/24
ip route add unreachable 10.10.30.0/24
ip route add unreachable 10.10.40.0/24
```

Validate the isolation. From any corporate IT host, the following must all time out:

```bash
ping -c 3 -W 2 10.10.20.1
ping -c 3 -W 2 10.10.30.2
ping -c 3 -W 2 10.10.10.1
```

**DNS separation.** OT systems must resolve names using an OT-internal DNS resolver, not the corporate DNS infrastructure. If OT systems use corporate DNS, an attacker who compromises the corporate DNS server can redirect OT engineering software to attacker-controlled hosts.

```conf
# /etc/bind/named.conf.local — OT-internal resolver (runs in Zone 3)
# Does NOT forward to corporate DNS.

zone "ot.internal" {
    type master;
    file "/etc/bind/db.ot.internal";
    allow-query { 10.10.0.0/16; };
    allow-transfer { none; };
};

options {
    recursion yes;
    allow-recursion { 10.10.0.0/16; };
    forwarders { };
    forward only;
    dnssec-validation auto;
};
```

**Active Directory forest separation.** OT Windows hosts must not join the corporate AD forest. A separate, isolated AD forest for OT provides authentication for OT Windows endpoints (HMIs, engineering workstations) without any trust relationship to corporate IT.

```conf
# /etc/sssd/sssd.conf — OT Windows host joined to OT-only domain
# NOT joined to corp.example.com — joined to ot.example.internal only.

[sssd]
domains = ot.example.internal

[domain/ot.example.internal]
id_provider = ad
auth_provider = ad
ad_domain = ot.example.internal
krb5_realm = OT.EXAMPLE.INTERNAL
realmd_tags = manages-system joined-with-adcli

access_provider = ad
ad_gpo_access_control = enforcing
```

OT engineers require a separate set of OT-domain credentials. IT admins have no OT-domain accounts. This breaks single sign-on but eliminates the attack path where a compromised IT DA account gives silent OT access.

### Step 6: Monitor Zone Boundaries

Passive monitoring at each conduit point provides detection without disrupting OT traffic. Deploy a network tap or SPAN port at every zone boundary firewall and feed the mirrored traffic to a passive sensor running Zeek with OT protocol dissectors.

```bash
ip link set eth1 promisc on

zeek -i eth1 \
  /opt/zeek/share/zeek/site/local.zeek \
  /opt/zeek/share/zeek/policy/protocols/modbus/main.zeek \
  /opt/zeek/share/zeek/policy/protocols/dnp3/main.zeek \
  /opt/zeek/share/zeek/policy/protocols/opcua-binary/main.zeek \
  -e 'redef Log::default_rotation_interval = 1hr;' \
  LogAscii::use_json=T
```

Zeek's Modbus and DNP3 analyzers log every function code, register read, and coil write. Any write to a PLC register that does not originate from an authorized engineering workstation IP is a high-confidence alert.

```bash
grep -E '"fc":(5|6|15|16)' /var/log/zeek/current/modbus.log | \
  jq -r 'select(.orig_h | inside("10.10.30.2","10.10.30.3") | not) |
    "\(.ts) UNAUTHORIZED MODBUS WRITE from \(.orig_h) to \(.resp_h) fc=\(.fc)"'
```

Modbus function codes 5 (Write Single Coil), 6 (Write Single Register), 15 (Write Multiple Coils), and 16 (Write Multiple Registers) should only ever originate from engineering workstations listed in the zone registry. Any other source is anomalous.

Forward all zone boundary logs to the SIEM via a dedicated log forwarder in the DMZ. Logs must not traverse the Zone 3→Zone 4 path directly — route them through the DMZ forward chain with TLS encryption.

```bash
filebeat modules enable zeek

cat > /etc/filebeat/modules.d/zeek.yml << 'EOF'
- module: zeek
  connection:
    enabled: true
    var.paths: ["/var/log/zeek/current/conn.log"]
  dns:
    enabled: true
  modbus:
    enabled: true
    var.paths: ["/var/log/zeek/current/modbus.log"]
  dnp3:
    enabled: true
    var.paths: ["/var/log/zeek/current/dnp3.log"]
EOF

filebeat setup
systemctl enable --now filebeat
```

## Expected Behaviour After Hardening

**Conduit enforcement:** A ping from the Zone 3 historian (`10.10.40.1`) to the Zone 1 SCADA server (`10.10.20.1`) is dropped at the Zone 2/Zone 3 boundary firewall. The `zone23-boundary-drop` log line is written and forwarded to the SIEM. No conduit exists for ICMP between these zones. The historian can only initiate OPC-UA sessions on port 4840 to Zone 2 hosts, and only Zone 2 hosts are in `@zone2_hosts`. Zone 1 SCADA servers are unreachable from Zone 3.

**DMZ remote access:** An OT vendor technician connects via the vendor access gateway in the DMZ. Their session terminates on `vendor-gw-1` (10.10.50.3). The local OT engineer approves the session. The gateway proxies an RDP connection through conduit C-11 to the authorized Zone 2 HMI. The vendor's laptop at no point has a routable path to Zone 2 — the connection is session-proxied, not network-routed. Session recording captures the full interaction.

**AD separation:** The IT domain admin account `corp\dadmin` attempts to authenticate to `eng-ws-1` (Zone 2, OT AD forest). The authentication fails: `eng-ws-1` is joined to `ot.example.internal`, which has no trust relationship with `corp.example.com`. The IT admin credential has zero access to any OT-domain host. An OT-domain credential is required.

**Unauthorized PLC write detection:** Zeek on the Zone 0/Zone 1 boundary sensor detects a Modbus Write Single Register (FC 6) command originating from `10.10.20.2` (SCADA server), which is authorized. Ten minutes later it detects a second FC 6 command from `10.10.40.1` (historian). The second command triggers the unauthorized write detection query. A SIEM alert fires within 60 seconds.

## Trade-offs and Operational Considerations

**Asset discovery takes months, not days.** Zone definitions require a complete and accurate OT asset inventory, including passive protocol identification (which PLCs speak Modbus versus DNP3), IP addressing, and vendor communication requirements. Plan for 3–6 months of passive network capture using Zeek or a dedicated OT asset discovery tool (Claroty, Dragos, Nozomi) before finalizing zone assignments. Deploying conduit rules before the asset inventory is complete will break legitimate communication paths and may cause process interruptions.

**Vendor-certified communication paths constrain conduit design.** Some PLCs and DCS systems use ephemeral port ranges for certain engineering protocols — OPC-DA in particular relies on DCOM, which uses TCP 135 plus dynamically assigned high ports. Pinning these to specific ports requires configuring the DCOM endpoint mapper range on each server and may require vendor approval to avoid voiding support agreements. OPC-UA (the modern successor) uses fixed port 4840 and should be preferred for new deployments.

**Data diodes carry significant cost.** A hardware unidirectional gateway (Waterfall Security Solutions, Owl Cyber Defense, Phoenix Contact FL mGuard) costs between $20,000 and $80,000 per installation point and requires specialized maintenance expertise. Software-based unidirectional replication (rsync over SSH with `--no-perms` and a dedicated relay host with restrictive iptables OUTPUT rules) provides weaker guarantees but may be acceptable for lower-security-level conduits where the primary goal is operational separation rather than physical enforcement.

**OT forest separation breaks single sign-on.** OT engineers must maintain separate credentials for the OT domain. This increases password management overhead and creates a support burden when OT-domain accounts expire. Compensate with a dedicated privileged access workstation (PAW) for OT access that stores OT credentials in a vault (HashiCorp Vault, CyberArk) and injects them into sessions via the jump host — engineers never see the OT password.

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Zones defined on paper, not enforced at firewall | Conduit documentation exists but boundary firewalls have `policy accept` | Segmentation validation script shows unexpected connectivity between zones | Audit firewall ruleset against conduit definitions; enforce `policy drop` on all zone boundary chains |
| DMZ jump host in same VLAN as Zone 2 | Jump host has direct Layer 2 adjacency to engineering workstations; DMZ firewall is bypassed | Network topology audit; MAC table on zone boundary switch shows DMZ host in Zone 2 VLAN | Move jump host to dedicated DMZ VLAN; enforce Layer 3 routing through boundary firewall |
| Conduit monitoring deployed but logs not forwarded | Zeek generates Modbus anomaly alerts; nobody sees them; attacker operates freely | SIEM receives no OT protocol events; check filebeat status and TLS relay connectivity | Restore log forwarding path; verify SIEM receives events from all zone boundary sensors |
| Temporary vendor access that becomes permanent | Vendor gateway session never terminated; vendor has persistent access to Zone 2 for months | Access gateway session log shows continuous active sessions beyond maintenance window | Enforce automatic session expiry at gateway; require local OT engineer approval for each session extension |
| IT→OT route removed at router but static route remains on host | A host in Zone 3 has a manual static route to Zone 4 bypassing the DMZ | Routing table audit on all Zone 3 hosts; check for routes to 10.10.100.0/24 | Remove static route; add nftables OUTPUT rule on Zone 3 hosts blocking traffic to Zone 4 CIDRs |

## Related Articles

- [Network Segmentation Patterns](/articles/network/network-segmentation-patterns/)
- [Linux OT Jump Host Hardening](/articles/linux/linux-ot-jump-host-hardening/)
- [OT Network Monitoring Malcolm](/articles/observability/ot-network-monitoring-malcolm/)
- [WireGuard Mesh](/articles/network/wireguard-mesh/)
- [IPsec VPN Hardening](/articles/network/ipsec-vpn-hardening/)
