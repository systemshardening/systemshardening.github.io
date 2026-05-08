---
title: "VLAN Security and Trunk Hardening: Defeating VLAN Hopping, DTP Exploitation, and Lateral Movement"
description: "VLAN boundaries are weaker than most engineers assume. Switch spoofing, double-tagging, and native VLAN abuse let attackers cross segment boundaries without touching a router. This guide covers DTP disablement, native VLAN hardening, Private VLANs, Linux VLAN configuration, and detection strategies for 802.1Q attacks."
slug: vlan-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - vlan
  - network-segmentation
  - trunk-security
  - dtp
  - switch-hardening
personas:
  - security-engineer
  - network-engineer
article_number: 502
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/vlan-security-hardening/
---

# VLAN Security and Trunk Hardening: Defeating VLAN Hopping, DTP Exploitation, and Lateral Movement

## The Problem

VLANs are the primary segmentation primitive in most enterprise networks. Servers, workstations, IoT devices, and management interfaces are separated into distinct Layer 2 domains on the assumption that VLAN membership enforces isolation. That assumption breaks down in several well-documented ways.

VLAN hopping — the family of attacks that allow a host in one VLAN to send frames into another — does not require any routing vulnerability. It exploits the signalling protocols and default configurations that switches use to establish trunk links and assign frames to VLANs. The attacks are low-complexity, require only a standard network interface and freely available tools, and are effective against default Cisco IOS, some Aruba, and some Juniper configurations that have not been explicitly hardened.

The attacks are not theoretical. Security assessments of enterprise networks regularly find DTP enabled on access ports, VLAN 1 carrying management traffic, and native VLANs left at their defaults — a combination that provides a direct path from a guest workstation to infrastructure management interfaces.

The specific weaknesses this article addresses:

- Dynamic Trunking Protocol (DTP) negotiation enabled on access ports — an attacker can convince a switch to form a trunk, gaining access to every VLAN on that trunk.
- Native VLAN left at VLAN 1 — double-tagging attacks allow a single crafted frame to traverse into any VLAN on a trunk.
- VLAN 1 carrying production or management traffic — VLAN 1 is always on trunk ports by default and cannot be cleanly removed on many platforms.
- Overly permissive trunk allowed VLAN lists — a misconfigured trunk extends every VLAN to every switch, maximising blast radius.
- No intra-VLAN isolation — once an attacker is in a VLAN, they can reach every other host in that segment directly, enabling lateral movement and scanning.

**Target platforms:** Cisco IOS 15.2+, Cisco IOS-XE, Cisco NX-OS, Aruba CX, Linux bridge/VLAN interfaces, Open vSwitch 2.17+.

## Threat Model

- **Adversary 1 — Switch spoofing via DTP:** An attacker connects a device to an access port with DTP enabled and sends DTP frames claiming to be a switch. The access port negotiates a trunk, and the attacker's NIC receives traffic for all VLANs on the trunk. Tools: `yersinia`, custom DTP frame injection.
- **Adversary 2 — Double-tagging VLAN hop:** An attacker on a VLAN whose ID matches the native VLAN of an upstream trunk crafts 802.1Q-in-802.1Q frames. The first switch strips the outer tag (native VLAN, untagged) and forwards the inner-tagged frame onto the trunk. The destination switch delivers the frame to the inner tag's VLAN. The attack is one-directional but sufficient for UDP-based exploitation and is effective even when DTP is disabled.
- **Adversary 3 — Lateral movement within a VLAN:** An attacker who has compromised one host in a VLAN (e.g. a single workstation in the office VLAN) can enumerate and attack all other hosts in that segment directly — bypassing firewall rules that only inspect inter-VLAN traffic.
- **Adversary 4 — VLAN 1 management access:** VLAN 1 is the default native VLAN and is included on all trunk ports unless explicitly removed. An attacker who can inject or receive VLAN 1 traffic may reach switch management interfaces, Spanning Tree BPDU injection points, or CDP/LLDP data that reveals topology.
- **Access level:** Physical Layer 1 (Adversaries 1–2: plugged into an access port). Post-compromise within the network (Adversary 3). Network-adjacent (Adversary 4).
- **Objective:** Cross VLAN boundaries to reach higher-value segments; perform reconnaissance across the broadcast domain; reach out-of-band management infrastructure.

## VLAN Hopping Attacks: Mechanics

Understanding the attack mechanics precisely is prerequisite to choosing the right countermeasures.

### Switch Spoofing via DTP

The Dynamic Trunking Protocol (DTP) is a Cisco proprietary protocol that allows two adjacent switches to negotiate whether a link should become a trunk. A switch port in `dynamic auto` or `dynamic desirable` mode will form a trunk if the peer requests it.

An attacker sends DTP frames from their workstation pretending to be a Cisco switch requesting a trunk. If the target port is in `dynamic auto` or `dynamic desirable` mode, it responds affirmatively, the link enters trunk mode, and the attacker's interface starts receiving 802.1Q-tagged frames for every VLAN allowed on that trunk.

With `yersinia`:

```bash
# List available attacks
yersinia -I   # interactive mode

# Or non-interactively: send DTP frames to enable trunking
yersinia dtp -attack 1 -interface eth0
```

Once trunking is established, the attacker configures sub-interfaces on their machine:

```bash
# Create tagged sub-interfaces for each VLAN of interest
ip link add link eth0 name eth0.10 type vlan id 10
ip link add link eth0 name eth0.20 type vlan id 20
ip link set eth0.10 up
ip link set eth0.20 up
dhclient eth0.10   # obtain an address in VLAN 10
```

The attacker is now a member of every VLAN reachable via the trunk — with no credentials, no 802.1X authentication, and no log entry beyond the port going trunk.

### Double-Tagging Attack

The double-tagging attack exploits the behaviour of 802.1Q native VLAN handling. On a trunk port, frames belonging to the native VLAN are transmitted **untagged**. When a switch receives an untagged frame on a trunk port, it associates that frame with the native VLAN. When it receives a frame with a tag matching the native VLAN, it strips that tag before forwarding.

An attacker on VLAN 1 (or any VLAN matching the native VLAN of an upstream trunk) crafts a frame with two 802.1Q headers:

1. **Outer tag:** native VLAN (e.g. VLAN 1) — this tag will be stripped by the first switch.
2. **Inner tag:** target VLAN (e.g. VLAN 100) — this tag is revealed after stripping and delivered to the target VLAN.

The frame path:

```
Attacker (VLAN 1 access port)
  │  Frame: [Outer VLAN 1 tag][Inner VLAN 100 tag][payload]
  ▼
Access switch
  │  Strips outer VLAN 1 tag (native VLAN handling)
  │  Frame: [Inner VLAN 100 tag][payload]  → forwarded on trunk
  ▼
Distribution switch
  │  Receives inner VLAN 100 tag
  │  Delivers to VLAN 100 hosts
  ▼
Target host in VLAN 100
```

**Critical constraint:** The attack is asymmetric. Return traffic is routed back to the attacker's Layer 3 address, which is in VLAN 1 — not directly to the crafted MAC. This makes TCP connections unreliable, but UDP-based attacks (DNS poisoning, UDP service exploitation, RTP injection) work well. The attack also succeeds for reconnaissance purposes using network scanners that require only one-way probing.

The double-tagging attack works **even when DTP is disabled** as long as the native VLAN ID matches the attacker's access VLAN. The only reliable mitigation is changing the native VLAN to an unused VLAN ID and ensuring the attacker is never placed on that VLAN.

## Disabling DTP on Access Ports

The switch-spoofing attack is completely eliminated by removing the ability of access ports to negotiate trunk status.

### Cisco IOS / IOS-XE

```conf
! Apply to every access port — workstations, printers, IoT, phones
interface GigabitEthernet0/1
 description WORKSTATION-ACCESS
 switchport mode access
 switchport access vlan 20
 switchport nonegotiate
 spanning-tree portfast
 spanning-tree bpduguard enable
 no cdp enable
 no lldp transmit
 no lldp receive
!
! Apply to every unused port
interface GigabitEthernet0/48
 description UNUSED
 switchport mode access
 switchport access vlan 999
 switchport nonegotiate
 shutdown
```

Two commands work in tandem:

- `switchport mode access` — hard-codes the port as an access port; it will never negotiate trunk mode regardless of what it receives.
- `switchport nonegotiate` — disables DTP entirely; the switch will not send or respond to DTP frames on this port.

`switchport mode access` alone is sufficient to prevent trunking, but `switchport nonegotiate` is belt-and-suspenders: it prevents the switch from sending DTP frames that could be useful to an attacker doing passive reconnaissance (DTP frames reveal switch vendor, VTP domain, and port capabilities).

BPDU Guard is included here because an attacker who cannot spoof a trunk may attempt Spanning Tree manipulation instead — BPDU Guard shuts down the port immediately if a BPDU is received.

### Verifying DTP State

```bash
# Show DTP status for all interfaces
show dtp interface

# Show trunk status — no access ports should appear here
show interfaces trunk

# Show per-interface trunk negotiation mode
show interfaces GigabitEthernet0/1 trunk
```

Expected output for a hardened access port:

```
Port        Mode         Encapsulation  Status        Native vlan
Gi0/1       off          negotiate      not-trunking  1
```

`Mode: off` confirms `switchport nonegotiate` is in effect.

## Native VLAN Hardening

Preventing double-tagging requires two changes: move the native VLAN away from VLAN 1, and explicitly tag all native VLAN traffic on trunks.

### Change the Native VLAN to an Unused VLAN

Assign a dedicated VLAN ID (e.g. VLAN 999) that is not used for any host traffic, management traffic, or production workload. No switch virtual interface (SVI) should exist for this VLAN. No hosts should be assigned to it. It exists solely to be the native VLAN on trunk ports.

```conf
! Create the native VLAN and give it a name that makes its purpose clear
vlan 999
 name NATIVE-UNUSED-DO-NOT-USE
!
! Apply to all trunk ports
interface GigabitEthernet0/24
 description UPLINK-TO-DISTRIBUTION
 switchport mode trunk
 switchport nonegotiate
 switchport trunk native vlan 999
 switchport trunk allowed vlan 10,20,30,40,50
```

With this configuration, an attacker would need to be assigned to VLAN 999 — which has no DHCP scope, no SVI, and no production hosts — to attempt a double-tagging attack against any other VLAN.

### Tag Native VLAN Traffic Explicitly (Cisco Global)

The most complete protection is to require that all frames on trunk ports carry an explicit 802.1Q tag — including native VLAN frames. This eliminates the untagged frame handling that double-tagging exploits.

```conf
! Enable globally — forces tagging of native VLAN on all trunks
vlan dot1q tag native
```

With this setting, any untagged frame arriving on a trunk port is dropped rather than being silently assigned to the native VLAN. This breaks double-tagging at the first hop and is strongly recommended for all production environments.

Verify the setting is active:

```bash
show vlan dot1q tag native
! Output: dot1q native vlan tagging is enabled
```

### NX-OS Equivalent

```conf
! Cisco NX-OS — tag native VLAN on a per-interface basis
interface Ethernet1/1
  switchport trunk native vlan tag
```

## VLAN 1 Minimisation

VLAN 1 has special status on 802.1Q networks: it is the default native VLAN, the default management VLAN, and the VLAN that Spanning Tree BPDUs, CDP, VTP, and other control plane protocols use by default. It cannot be fully removed from trunk links on many platforms and is implicitly trusted in older network designs.

Minimisation strategy:

1. **Do not use VLAN 1 for any production traffic.** Create explicit VLANs for workstations, servers, management, voice, IoT, etc. VLAN 1 should carry nothing.
2. **Remove VLAN 1 from trunk allowed lists** wherever the platform permits.
3. **Move switch management interfaces (SVIs) off VLAN 1** to a dedicated out-of-band management VLAN.
4. **Do not assign any access ports to VLAN 1.**

```conf
! Correct — management SVI on dedicated VLAN 999 is wrong here,
! use a real management VLAN separate from the native VLAN
vlan 900
 name OOB-MANAGEMENT

interface Vlan900
 description SWITCH-MANAGEMENT
 ip address 10.90.0.2 255.255.255.0
 no ip proxy-arp

! Remove VLAN 1 from all trunk allowed lists
interface GigabitEthernet0/24
 switchport trunk allowed vlan remove 1
```

On Cisco platforms, VLAN 1 cannot be removed from trunk ports as the "native VLAN" if that is still the native VLAN setting — it must be changed to another VLAN first (VLAN 999 in our model), after which VLAN 1 can be removed from the allowed list.

## Trunk Port Security: Explicit Allowed VLAN Lists

Default trunk port configuration allows all VLANs. When a new VLAN is created anywhere in the VTP domain, it is automatically added to every trunk — including trunks that have no business carrying that VLAN. This maximises blast radius.

Every trunk port must carry an explicit, minimal VLAN list:

```conf
interface GigabitEthernet0/24
 description UPLINK-TO-DISTRIBUTION-SWITCH
 switchport mode trunk
 switchport nonegotiate
 switchport trunk native vlan 999
 ! Only VLANs explicitly required on this uplink
 switchport trunk allowed vlan 10,20,30,50,900,999

interface GigabitEthernet0/25
 description DOWNLINK-TO-ACCESS-SWITCH-FLOOR-2
 switchport mode trunk
 switchport nonegotiate
 switchport trunk native vlan 999
 ! Floor 2 only has workstations (VLAN 20) and voice (VLAN 50)
 switchport trunk allowed vlan 20,50,999
```

This is operationally equivalent to a firewall allowlist. New VLANs must be explicitly added to each trunk they need to traverse. The discipline prevents a misconfigured or compromised switch from receiving traffic for segments it should not see.

Audit current allowed VLAN lists:

```bash
show interfaces trunk
! Review "VLANs allowed and active in management domain" column
! Any trunk showing "1-4094" needs immediate remediation
```

## Private VLANs: Intra-VLAN Isolation

Standard VLANs isolate traffic between segments but not within them. Every host in VLAN 20 can reach every other host in VLAN 20 directly. Once an attacker compromises one workstation, the rest of the VLAN is directly accessible — no inter-VLAN routing, no firewall, no logging at the network layer.

Private VLANs (PVLANs) subdivide a VLAN into port groups with different forwarding rules, preventing lateral movement without requiring a routed hop.

### PVLAN Port Types

- **Promiscuous port:** Can communicate with all other ports in the PVLAN. Typically the router, firewall, or gateway that needs to reach all hosts.
- **Isolated port:** Can only communicate with the promiscuous port. Cannot reach any other isolated or community port — even in the same primary VLAN. Use for workstations, servers that need no peer communication.
- **Community port:** Can communicate with other ports in the same community, and with the promiscuous port. Cannot reach isolated ports or other communities. Use for application tiers that need internal communication (e.g. a cluster of web servers).

### Cisco IOS PVLAN Configuration

```conf
! Step 1: Create the secondary VLANs
vlan 201
 name PVLAN-ISOLATED
 private-vlan isolated
!
vlan 202
 name PVLAN-COMMUNITY-WEB
 private-vlan community
!
! Step 2: Create the primary VLAN and associate secondaries
vlan 200
 name PVLAN-PRIMARY
 private-vlan primary
 private-vlan association 201,202
!
! Step 3: Configure the promiscuous port (uplink to router/firewall)
interface GigabitEthernet0/1
 description PVLAN-PROMISCUOUS-UPLINK
 switchport mode private-vlan promiscuous
 switchport private-vlan mapping 200 201,202
!
! Step 4: Configure isolated ports (workstations, endpoints)
interface range GigabitEthernet0/2 - 0/20
 switchport mode private-vlan host
 switchport private-vlan host-association 200 201
!
! Step 5: Configure community ports (web tier cluster)
interface range GigabitEthernet0/21 - 0/24
 switchport mode private-vlan host
 switchport private-vlan host-association 200 202
```

With this configuration:
- Hosts on isolated ports (VLAN 201) can only send traffic to the promiscuous uplink — not to any other workstation.
- Hosts on community ports (VLAN 202) can reach each other and the promiscuous uplink.
- No host on an isolated or community port can reach another PVLAN segment directly.

Verify:

```bash
show vlan private-vlan
show interfaces GigabitEthernet0/2 private-vlan
```

PVLANs are particularly effective in environments with flat user VLANs where deploying individual /30 subnets per host is impractical. The containment is enforced in hardware at the switch ASIC level, not in software.

## Linux VLAN Configuration

Linux hosts — servers, hypervisors, firewalls — frequently need VLAN-aware interfaces. The configuration must be done correctly to prevent VLAN leakage and ensure proper trunk behaviour.

### ip link: VLAN Sub-Interface

```bash
# Create a VLAN-tagged sub-interface for VLAN 100 on physical eth0
ip link add link eth0 name eth0.100 type vlan id 100

# Optionally set 802.1p QoS egress mapping
ip link add link eth0 name eth0.100 type vlan id 100 egress-qos-map 0:0 1:1

# Bring it up and assign an address
ip link set eth0.100 up
ip addr add 10.100.0.10/24 dev eth0.100
ip route add default via 10.100.0.1 dev eth0.100

# Confirm VLAN ID and flags
ip -d link show eth0.100
```

For a server that needs to be in multiple VLANs (e.g. a hypervisor):

```bash
for vlan_id in 10 20 30 100 900; do
    ip link add link eth0 name "eth0.${vlan_id}" type vlan id "${vlan_id}"
    ip link set "eth0.${vlan_id}" up
done
```

### systemd-networkd VLAN Configuration

For persistent, boot-time VLAN configuration on servers running systemd:

```ini
# /etc/systemd/network/10-eth0.network
# Configure the physical interface — no IP, just carrier
[Match]
Name=eth0

[Network]
VLAN=eth0.100
VLAN=eth0.900
LinkLocalAddressing=no
```

```ini
# /etc/systemd/network/20-eth0.100.netdev
# Define the VLAN netdev
[NetDev]
Name=eth0.100
Kind=vlan

[VLAN]
Id=100
```

```ini
# /etc/systemd/network/20-eth0.100.network
# Assign IP to the VLAN interface
[Match]
Name=eth0.100

[Network]
Address=10.100.0.10/24
Gateway=10.100.0.1
DNS=10.0.0.53
```

```ini
# /etc/systemd/network/20-eth0.900.netdev
[NetDev]
Name=eth0.900
Kind=vlan

[VLAN]
Id=900
```

```ini
# /etc/systemd/network/20-eth0.900.network
[Match]
Name=eth0.900

[Network]
Address=10.90.0.10/24
Gateway=10.90.0.1
```

Apply:

```bash
networkctl reload
networkctl status eth0.100
```

### VLAN Filter on Linux Bridge

When using a Linux bridge (common with KVM/QEMU virtualisation), enable VLAN filtering on the bridge to enforce VLAN membership at the bridge level — otherwise all bridge ports can see all VLANs:

```bash
# Create a VLAN-aware bridge
ip link add name br0 type bridge vlan_filtering 1
ip link set br0 up

# Add a physical port to the bridge
ip link set eth0 master br0
ip link set eth0 up

# Add a VM tap interface to the bridge — VLAN 20 access port
ip link set tap0 master br0
bridge vlan add dev tap0 vid 20 pvid untagged

# Add an uplink tap as a trunk carrying VLANs 10, 20, 30
bridge vlan add dev eth0 vid 10
bridge vlan add dev eth0 vid 20
bridge vlan add dev eth0 vid 30

# Verify VLAN assignments
bridge vlan show
```

By default, the bridge adds a PVID of 1 to every port — remove VLAN 1 explicitly:

```bash
bridge vlan del dev tap0 vid 1
bridge vlan del dev eth0 vid 1
```

## Open vSwitch VLAN Security

Open vSwitch (OVS) is widely used in OpenStack, Kubernetes CNI plugins, and virtualisation platforms. Default OVS port configuration carries no VLAN tagging — an administrative oversight creates a flat network that bypasses all VLAN segmentation.

### Access Port (Tagged-to-Untagged)

```bash
# Configure a VM port as VLAN 20 access — VM sends/receives untagged, OVS tags/untags
ovs-vsctl set port vm-eth0 vlan_mode=access tag=20

# Verify
ovs-vsctl list port vm-eth0
# tag: 20
# vlan_mode: access
```

### Trunk Port with VLAN Allowlist

```bash
# Configure an uplink as a trunk — only carry VLANs 10, 20, 30
ovs-vsctl set port uplink0 vlan_mode=trunk trunks=10,20,30

# Native VLAN handling — explicitly set native_vlan if needed
ovs-vsctl set port uplink0 vlan_mode=native-untagged tag=999 trunks=10,20,30,999
```

### Preventing VLAN Escapes

A common misconfiguration in OVS-based environments is leaving ports in `vlan_mode=trunk` with an empty `trunks` list — which on some OVS versions means "allow all VLANs":

```bash
# Audit all ports for trunk mode with empty trunks lists
ovs-vsctl --format=table --columns=name,vlan_mode,tag,trunks list port

# Any port showing vlan_mode=trunk with trunks=[] is misconfigured
# Set an explicit list immediately
ovs-vsctl set port suspect-port trunks=10,20,30
```

For OVS in OpenStack or Kubernetes environments, audit flows directly:

```bash
# Check OVS flow tables for catch-all rules that bypass VLAN filtering
ovs-ofctl dump-flows br-int | grep -E "priority=0|NORMAL"
# A priority=0 NORMAL action passes all traffic without VLAN enforcement
```

## Monitoring and Detection

### Detecting Double-Tagging with Zeek

Zeek's `packet_filter` and custom scripts can detect anomalous 802.1Q framing:

```zeek
# /etc/zeek/site/detect-double-tag.zeek
# Alert on frames with more than one 802.1Q VLAN tag (double-tagging indicator)

event zeek_init()
    {
    Log::create_stream(DoubleTags::LOG, [$columns=DoubleTags::Info]);
    }

# Use raw packet capture to inspect Ethernet headers
# Zeek's packet_contents captures raw frames when enabled
event raw_packet(pkt: raw_pkt_hdr)
    {
    # EtherType 0x8100 = 802.1Q
    # A double-tagged frame has 0x8100 at offset 12 AND at offset 16
    if ( pkt$l2?$vlan && pkt$l2?$inner_vlan )
        {
        NOTICE([$note=DoubleTags::Double_Tagged_Frame,
                $msg=fmt("Double-tagged frame detected: outer VLAN %d inner VLAN %d src %s",
                         pkt$l2$vlan, pkt$l2$inner_vlan, pkt$l2$src),
                $identifier=cat(pkt$l2$src)]);
        }
    }
```

Load and test:

```bash
zeekctl deploy
# Or for ad-hoc testing against a pcap
zeek -r capture.pcap /etc/zeek/site/detect-double-tag.zeek
```

### Detecting DTP Traffic with Suricata

DTP frames use Cisco's multicast MAC `01:00:0c:cc:cc:cc` with LLC SNAP encapsulation. Any DTP frame arriving on an access port that should have DTP disabled is a strong indicator of reconnaissance or active spoofing:

```yaml
# /etc/suricata/rules/vlan-attacks.rules

# Alert on DTP frames (Cisco proprietary, should not appear on hardened access ports)
alert ethernet any any -> any any (msg:"VLAN HOPPING DTP Frame Detected"; \
    eth.dst: 01:00:0c:cc:cc:cc; \
    byte_test:2,=,0x2004,20,big; \
    classtype:policy-violation; sid:9000101; rev:1;)

# Alert on 802.1Q double-tagged frames (outer tag followed by inner 0x8100)
alert ethernet any any -> any any (msg:"VLAN HOPPING Double-Tagged 802.1Q Frame"; \
    vlan.id:1; \
    byte_test:2,=,0x8100,4,relative; \
    classtype:attempted-recon; sid:9000102; rev:1;)
```

### Switch Port Scanner: 802.1Q Audit

For scheduled audits of trunk and access port configuration across the fleet, use NAPALM to collect and validate switch state:

```python
#!/usr/bin/env python3
# audit_vlans.py — validate trunk and access port hardening

from napalm import get_network_driver
import json, sys

POLICY = {
    "native_vlan": 999,
    "vlan_1_allowed": False,
    "dtp_negotiation": False,
}

def audit_switch(hostname, username, password):
    driver = get_network_driver("ios")
    device = driver(hostname=hostname, username=username, password=password)
    device.open()

    findings = []
    interfaces = device.get_interfaces()
    vlans = device.get_vlans()

    # Get raw trunk data via CLI command
    trunk_raw = device.cli(["show interfaces trunk", "show dtp"])

    # Check for VLAN 1 on any trunk
    if "1" in trunk_raw["show interfaces trunk"]:
        findings.append(f"FAIL: VLAN 1 present on trunk — {hostname}")

    device.close()
    return findings

if __name__ == "__main__":
    hosts = sys.argv[1:]
    for host in hosts:
        issues = audit_switch(host, "admin", "password")
        for issue in issues:
            print(issue)
```

For continuous monitoring, integrate with your NMS or SIEM and alert on:

- Any port transitioning from access to trunk mode unexpectedly.
- DTP frames received on monitored segments (SPAN/RSPAN a distribution switch uplink).
- New VLANs appearing on trunk ports that were not in the approved allowlist.
- CDP/LLDP topology changes that suggest a new switch has been inserted.

## Documentation Discipline

VLAN security degrades over time through undocumented changes and scope creep. Two operational disciplines prevent this.

### VLAN Naming Conventions

Every VLAN must have a name that encodes its purpose and owner. Numbers alone are insufficient — engineers cannot determine whether a VLAN should be on a trunk without knowing what it carries.

Recommended convention: `<ZONE>-<PURPOSE>-<SEQUENCE>`

```
VLAN 10   PROD-SERVERS-01
VLAN 20   CORP-WORKSTATIONS-01
VLAN 30   CORP-VOICE-01
VLAN 40   CORP-PRINTERS-01
VLAN 50   GUEST-WIRELESS-01
VLAN 100  IOT-BUILDING-MGMT-01
VLAN 200  DMZ-EXTERNAL-01
VLAN 900  OOB-MANAGEMENT-01
VLAN 999  NATIVE-UNUSED
```

Enforce this via VTP or VLAN synchronisation tooling — if a VLAN exists in the database without a matching name entry in the authoritative source of truth (IPAM, NetBox, Nautobot), it is flagged for review.

### Change Management for VLAN Membership

Every change to VLAN membership on a production trunk must be approved, documented, and traceable:

1. **Request:** Which VLAN? Which trunk ports? What business justification?
2. **Impact assessment:** Does adding VLAN X to trunk Y extend that broadcast domain to a switch that should not see it?
3. **Implementation:** Config diff generated before and after. Tested in maintenance window.
4. **Validation:** `show interfaces trunk` output captured and compared to expected state.
5. **Documentation:** NetBox/Nautobot updated. Switch config backed up to Git.

Use network-as-code tooling (Ansible, Nornir, Batfish) to enforce the principle that no VLAN membership change is valid unless it appears in version-controlled configuration:

```yaml
# Nornir task: enforce trunk VLAN policy
# group_vars/distribution_switches.yaml
trunk_policy:
  uplinks:
    allowed_vlans: [10, 20, 30, 900, 999]
    native_vlan: 999
    dtp: disabled
  downlinks:
    native_vlan: 999
    dtp: disabled
```

Configuration drift from this policy is detected on every scheduled run and creates a ticket or fails the pipeline.

## Hardening Checklist

| Control | Command / Action | Verifies |
|---|---|---|
| Disable DTP on all access ports | `switchport mode access` + `switchport nonegotiate` | `show dtp interface` — mode off |
| Change native VLAN from VLAN 1 | `switchport trunk native vlan 999` | `show interfaces trunk` — native VLAN column |
| Tag native VLAN explicitly | `vlan dot1q tag native` (global) | `show vlan dot1q tag native` |
| Remove VLAN 1 from trunks | `switchport trunk allowed vlan remove 1` | `show interfaces trunk` — allowed list |
| Set explicit trunk VLAN allowlist | `switchport trunk allowed vlan <list>` | No trunk shows `1-4094` |
| Move management off VLAN 1 | SVI on dedicated VLAN 900 | `show ip interface brief` — no Vlan1 |
| Shut down VLAN 1 SVI | `interface Vlan1` + `shutdown` | `show interface Vlan1` — down/down |
| Deploy PVLANs for intra-VLAN isolation | PVLAN primary/secondary/port config | `show vlan private-vlan` |
| Remove VLAN 1 from Linux bridge | `bridge vlan del dev <port> vid 1` | `bridge vlan show` |
| OVS explicit trunk lists | `ovs-vsctl set port ... trunks=<list>` | `ovs-vsctl list port` |
| Enable DTP/double-tag detection | Zeek + Suricata rules | IDS alert on DTP frames |
| Audit VLAN membership regularly | NAPALM / Nornir policy checks | No policy violations in CI |

## Key Takeaways

VLAN segmentation is not self-enforcing. It depends on consistent, explicit configuration of every switch port and trunk link in the environment, and it degrades whenever defaults are left in place or changes are made without policy enforcement.

The highest-impact controls, in order:

1. `switchport mode access` + `switchport nonegotiate` on every non-trunk port. This alone eliminates switch spoofing.
2. `vlan dot1q tag native` globally. This eliminates double-tagging regardless of native VLAN assignment.
3. Native VLAN changed to a dedicated unused VLAN. Defence in depth against double-tagging even without global tagging.
4. VLAN 1 removed from all trunk allowed lists and no SVIs on VLAN 1.
5. Explicit minimum-VLAN trunk allowed lists. Limits blast radius when anything else fails.

Private VLANs and continuous monitoring are force multipliers — they limit what an attacker can do after reaching a segment and give your operations team the signal to detect and respond before a VLAN hop becomes a domain compromise.
