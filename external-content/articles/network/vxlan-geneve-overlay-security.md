---
title: "VXLAN and Geneve Overlay Network Security"
description: "Harden VXLAN and Geneve overlay networks against VTEP spoofing, BUM traffic amplification, VNI enumeration, and cross-tenant traffic injection in cloud-native environments."
slug: vxlan-geneve-overlay-security
date: 2026-05-02
lastmod: 2026-05-02
category: network
tags: ["vxlan", "geneve", "overlay", "vtep", "network-security", "cloud-native", "encapsulation"]
personas: ["systems-engineer", "sre", "security-engineer"]
article_number: 329
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/network/vxlan-geneve-overlay-security/index.html"
---

# VXLAN and Geneve Overlay Network Security

## Problem

VXLAN (RFC 7348) and Geneve (RFC 8926) are the dominant overlay protocols in cloud-native environments. Kubernetes CNI plugins — Flannel, Cilium in VXLAN mode, Calico with `vxlanMode: Always` or `CrossSubnet`, and Antrea — all tunnel pod traffic over VXLAN by default. OpenStack Neutron uses VXLAN for tenant network isolation. Hypervisor overlays in VMware NSX and AWS VPC internals rely on similar encapsulation semantics. The choice is not whether your environment uses overlay networks; it is whether you have secured them.

The fundamental security problem with VXLAN is explicit in the RFC: there is no authentication or encryption. VXLAN encapsulates Ethernet frames inside UDP datagrams sent to port 4789. Any host that can deliver a UDP packet to that port on a VTEP (VXLAN Tunnel Endpoint) can inject an arbitrary Ethernet frame into any VNI (VXLAN Network Identifier) it knows. The encapsulated frame will be decapsulated and delivered as if it originated from a legitimate tenant host. From the perspective of the receiving workload, the injected frame is indistinguishable from a genuine one.

VTEP spoofing exploits this directly. An attacker forges the outer IP source address of the VXLAN UDP datagram to match a legitimate VTEP — a Kubernetes node, a hypervisor host, or an OpenStack compute node. The receiving VTEP updates its forwarding database (FDB) to associate the forged source MAC with the attacker's IP, poisoning future unicast traffic toward that MAC. This is the overlay equivalent of ARP spoofing, operating at the tunnel layer rather than the local segment.

BUM traffic — Broadcast, Unknown-unicast, and Multicast — is an amplification vector specific to overlay networks. In a multicast-based VXLAN deployment, a BUM packet sent to the VTEP multicast group reaches every VTEP participating in that VNI. An attacker generating high-rate BUM traffic causes every node in the flooding domain to process and forward the traffic. The amplification factor scales with the number of VTEPs. In unicast VXLAN deployments using head-end replication, each VTEP floods BUM to every other VTEP individually; the computational load moves from the network to the host CPU.

VNI enumeration is a reconnaissance technique unique to VXLAN's 24-bit VNI space (0–16,777,215). An attacker with access to UDP/4789 on even a single VTEP can probe VNIs by sending VXLAN packets with different VNI values and observing ICMP unreachables, timing differences, or FDB responses. A full scan of the 24-bit space at moderate packet rates completes in minutes. Discovered VNIs reveal tenant network topology and may expose VNIs with weaker isolation.

Geneve (RFC 8926) extends VXLAN's capabilities with extensible TLV (Type-Length-Value) option headers and supports multiple inner protocol types. It uses UDP port 6081. Geneve is the encapsulation format used by OVN (Open Virtual Network), the control plane backing Kubernetes networking in OpenShift and many bare-metal deployments. The TLV extension mechanism is frequently cited as an advantage — operators can embed tenant metadata, security context labels, or flow identifiers in the option headers. However, these options add complexity without adding security. There is no authentication in the base Geneve spec. A receiver cannot verify that a TLV option value was set by a legitimate sender rather than an attacker.

The Linux kernel VXLAN implementation has accumulated CVEs alongside its growing feature set. CVE-2021-3773 (netfilter hook bypass via malformed VXLAN packets) and CVE-2022-0435 (TIPC stack overflow reachable from adjacent network, including VXLAN segments) illustrate how the kernel's overlay stack is part of the attack surface. Kernel version discipline — tracking the stable branch at ≥ 5.15 LTS — is a prerequisite, not a substitute, for configuration hardening.

The contrast with WireGuard-encrypted overlays is instructive. WireGuard enforces mutual authentication via public-key cryptography on every tunnel; there is no unauthenticated packet path. Cilium's WireGuard encryption mode replaces VXLAN as the overlay transport entirely. For environments that must remain on VXLAN or Geneve — due to CNI compatibility, existing tooling, or hardware offload requirements — layering IPsec in transport mode over the VXLAN UDP flows provides encryption equivalent to WireGuard at the cost of additional key management complexity.

Target systems: Linux kernel >= 5.15, Flannel 0.21+, Cilium 1.14+ (VXLAN mode), Calico 3.26+ (VXLAN mode), Antrea 1.13+.

## Threat Model

1. **Co-tenant VTEP injection.** An attacker on a shared hypervisor or cloud compute node, co-located with legitimate workloads, sends crafted VXLAN UDP packets to a neighbouring VTEP. By setting the outer source IP to a legitimate VTEP's address and choosing a known VNI, the attacker injects Ethernet frames into the target tenant's overlay segment. No kernel exploit is required — only the ability to send arbitrary UDP datagrams, which any unprivileged user can do with raw sockets if `CAP_NET_RAW` is available, or via `sendto()` on a UDP socket.

2. **BUM amplification DoS.** A network-adjacent attacker — or an insider on any node that can reach the multicast group or the VTEP unicast addresses — sends high-rate broadcast or unknown-unicast frames into a VNI. Every VTEP in the flooding domain receives and processes each packet. In a 500-node cluster where every node is a VTEP, a single-stream 100 Mbps BUM flood causes each of the 499 other nodes to process 100 Mbps. The effective amplification is close to the node count. CPU cycles consumed by VXLAN decapsulation are unavailable for tenant workloads.

3. **VNI enumeration.** An insider, contractor, or compromised node probes the 24-bit VNI space by iterating VNI values in VXLAN packets delivered to any accessible VTEP. Differences in ICMP responses, TCP RST behaviour from encapsulated stacks, or FDB side-channel timing reveal which VNIs are active, how many tenants are present, and the approximate size of each tenant's overlay segment. This map accelerates targeted injection and cross-tenant reconnaissance.

4. **ARP/ND spoofing inside the overlay.** A compromised Kubernetes node injects ARP replies inside an active VNI, associating a peer pod's IP with the attacker's MAC address. Subsequent traffic to that pod is redirected to the compromised node. Unlike classic on-link ARP spoofing, the attack originates at the overlay layer, bypassing physical network ARP inspection. CNI plugins that do not implement ARP proxy or static FDB entries are vulnerable.

The blast radius of an unmitigated overlay breach is large. VXLAN and Geneve overlays frequently carry East-West traffic that does not pass through perimeter firewalls or service mesh sidecars. A compromised VTEP can silently inspect, modify, or drop traffic between any pods or VMs sharing a VNI, with no log entries at the application layer. Multi-tenant clusters — common in managed Kubernetes services and private cloud environments — face the additional risk that a breach of one tenant's overlay segment enables lateral movement into adjacent VNIs if VTEP ACLs are absent.

## Configuration / Implementation

### VTEP access control with nftables

The first line of defence is limiting which source IPs can deliver VXLAN (UDP/4789) and Geneve (UDP/6081) packets to a VTEP. Build a nftables set of allowed VTEP source addresses and drop everything else. Apply this ruleset to every node in the cluster.

```nft
#!/usr/sbin/nft -f
# /etc/nftables.d/vtep-acl.nft
# Reload with: nft -f /etc/nftables.d/vtep-acl.nft

table inet vtep_acl {

  set allowed_vteps {
    type ipv4_addr
    flags interval
    # Enumerate all node IPs that act as VTEPs.
    # Automate population from your node registry.
    elements = {
      10.0.1.0/24,   # node subnet A
      10.0.2.0/24    # node subnet B
    }
  }

  chain input_vtep {
    type filter hook input priority filter - 5; policy accept;

    # Allow VXLAN only from known VTEPs
    udp dport 4789 ip saddr @allowed_vteps accept
    udp dport 4789 drop

    # Allow Geneve only from known VTEPs
    udp dport 6081 ip saddr @allowed_vteps accept
    udp dport 6081 drop
  }
}
```

Apply and persist:

```bash
# Install and test
nft -c -f /etc/nftables.d/vtep-acl.nft   # dry-run check
nft -f /etc/nftables.d/vtep-acl.nft

# Verify the set is loaded
nft list set inet vtep_acl allowed_vteps

# Persist across reboots (systemd)
systemctl enable --now nftables
```

When nodes are added to the cluster, append their IPs to the set atomically:

```bash
# Add a new node VTEP without replacing the full set
nft add element inet vtep_acl allowed_vteps { 10.0.3.5 }
```

### VXLAN with IPsec transport encryption

Linux's `ip xfrm` subsystem can encrypt VXLAN UDP traffic at the IP layer in transport mode. This wraps each VXLAN UDP datagram in ESP without changing the outer IP header, which preserves ECMP routing and hardware offload compatibility.

Configure a transport-mode ESP policy between two VTEPs (10.0.1.10 and 10.0.1.20):

```bash
# On both VTEPs: generate a shared key (for illustration; use IKEv2 in production)
SKEY=$(openssl rand -hex 32)
AKEY=$(openssl rand -hex 20)

# On VTEP A (10.0.1.10):
# Inbound SA from VTEP B
ip xfrm state add src 10.0.1.20 dst 10.0.1.10 \
  proto esp spi 0x1002 mode transport \
  auth sha256 0x${AKEY} enc aes 0x${SKEY}

# Outbound SA to VTEP B
ip xfrm state add src 10.0.1.10 dst 10.0.1.20 \
  proto esp spi 0x1001 mode transport \
  auth sha256 0x${AKEY} enc aes 0x${SKEY}

# Policy: encrypt outbound VXLAN to VTEP B
ip xfrm policy add src 10.0.1.10/32 dst 10.0.1.20/32 \
  proto udp dport 4789 dir out \
  tmpl src 10.0.1.10 dst 10.0.1.20 proto esp mode transport

# Policy: require encrypted inbound VXLAN from VTEP B
ip xfrm policy add src 10.0.1.20/32 dst 10.0.1.10/32 \
  proto udp sport 4789 dir in \
  tmpl src 10.0.1.20 dst 10.0.1.10 proto esp mode transport
```

For production, replace manual key management with StrongSwan IKEv2. A minimal `/etc/swanctl/conf.d/vxlan-mesh.conf`:

```conf
connections {
  vtep-mesh {
    version = 2
    local_addrs  = 10.0.1.10
    remote_addrs = 10.0.1.20
    proposals    = aes256gcm16-prfsha384-ecp384

    local {
      auth = pubkey
      certs = /etc/swanctl/x509/node-a.pem
    }
    remote {
      auth = pubkey
      certs = /etc/swanctl/x509/node-b.pem
    }

    children {
      vxlan-udp {
        local_ts  = 10.0.1.10[udp/4789]
        remote_ts = 10.0.1.20[udp/4789]
        mode      = transport
        esp_proposals = aes256gcm16-ecp384
        rekey_time = 3600
      }
    }
  }
}
```

Load and verify:

```bash
swanctl --load-all
swanctl --initiate --child vxlan-udp
swanctl --list-sas   # confirm ESP SA is ESTABLISHED
ip xfrm state list   # confirm SAs in kernel
```

### Cilium WireGuard encryption mode

For clusters running Cilium 1.14+, switching from VXLAN to WireGuard encryption eliminates the need for IPsec management. WireGuard provides authenticated encryption natively; there is no unauthenticated path.

Switch via Helm values:

```yaml
# values-cilium-wg.yaml
tunnel: disabled          # disable VXLAN encapsulation
encryption:
  enabled: true
  type: wireguard
  wireguard:
    userspaceFallback: false   # use kernel WireGuard (requires kernel >= 5.6)
```

Apply to an existing cluster:

```bash
helm upgrade cilium cilium/cilium \
  --namespace kube-system \
  --reuse-values \
  -f values-cilium-wg.yaml
```

Verify that all nodes have WireGuard tunnels active:

```bash
# On any Cilium-managed node
cilium-dbg encrypt status
# Expected output includes:
#   Encryption: Wireguard
#   Interface: cilium_wg0
#   Public key: <node-pubkey>
#   Peers: <N peers negotiated>

# Check WireGuard interface directly
wg show cilium_wg0
```

WireGuard mode requires that nodes can reach each other's WireGuard port (UDP/51871 by default in Cilium). Add this port to your VTEP ACL set or open it explicitly in nftables.

### BUM traffic limitation

Disable multicast-based VXLAN flooding and switch to unicast head-end replication with a static FDB. This bounds the BUM flooding domain to explicitly configured VTEPs.

Create a VXLAN interface in unicast mode (no `group` or `remote` default):

```bash
# Create VXLAN interface without a multicast group
ip link add vxlan100 type vxlan \
  id 100 \
  dstport 4789 \
  local 10.0.1.10 \
  nolearning        # disable dynamic MAC learning from the data plane

ip link set vxlan100 up
ip addr add 192.168.100.1/24 dev vxlan100
```

Populate the FDB with explicit per-VTEP entries. Use the all-zeros MAC to define flood targets (BUM goes only to these VTEPs):

```bash
# Add known VTEPs to the flood list
bridge fdb append 00:00:00:00:00:00 dev vxlan100 dst 10.0.1.20
bridge fdb append 00:00:00:00:00:00 dev vxlan100 dst 10.0.1.30

# Add a specific MAC-to-VTEP mapping (unicast, no flooding)
bridge fdb append aa:bb:cc:dd:ee:ff dev vxlan100 dst 10.0.1.20

# Verify the FDB
bridge fdb show dev vxlan100
```

For Flannel, bind the VTEP to a specific interface rather than the wildcard address to prevent unintended exposure on additional interfaces:

```bash
# In flannel systemd unit or ConfigMap
--iface=eth0    # bind VTEP to this interface only, not 0.0.0.0
```

### VNI isolation in multi-tenant environments

Assign a distinct VNI range per tenant and enforce strict VTEP ACLs so nodes belonging to tenant A cannot reach the VTEP port of nodes belonging to tenant B.

For Calico with VXLAN, configure per-pool `vxlanMode: CrossSubnet` to limit VXLAN tunneling to cross-subnet traffic and use direct routing within subnets:

```yaml
# calico-ippool-tenant-a.yaml
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: tenant-a-pool
spec:
  cidr: 10.100.0.0/16
  vxlanMode: CrossSubnet
  natOutgoing: true
  nodeSelector: "tenant == 'a'"
```

Use Linux network namespaces to ensure VXLAN interfaces for different VNIs live in separate namespaces, preventing cross-VNI packet leakage:

```bash
# Create isolated namespace for tenant B's VTEP
ip netns add tenant-b
ip link add vxlan200 type vxlan id 200 dstport 4789 local 10.0.1.10 nolearning
ip link set vxlan200 netns tenant-b

# Operate within the namespace
ip netns exec tenant-b ip link set vxlan200 up
ip netns exec tenant-b ip addr add 192.168.200.1/24 dev vxlan200
```

### Geneve security options

Geneve's TLV option headers can carry tenant metadata that the receiving VTEP validates before accepting inner frames. This does not authenticate the packet, but it provides a soft check that prevents accidental cross-tenant frame delivery from misconfigured endpoints.

Create a Geneve interface with explicit destination port and TOS inheritance:

```bash
ip link add geneve0 type geneve \
  id 100 \
  remote 10.0.1.20 \
  dstport 6081 \
  tos inherit \
  ttl 64

ip link set geneve0 up
ip addr add 192.168.100.1/24 dev geneve0
```

The `tos inherit` flag copies the inner frame's DSCP markings to the outer IP header, which preserves QoS treatment through the physical underlay. For security purposes, Geneve offers no advantage over VXLAN without an authenticated transport (IPsec or WireGuard) underneath. Prefer VXLAN for CNI compatibility; prefer Geneve only when OVN/OVS is the data plane, since OVN encodes flow metadata in Geneve TLV options natively.

### Monitoring VXLAN anomalies

Deploy an eBPF tc classifier to count VXLAN packets arriving from source IPs not in the allowed VTEP set and expose the count as a Prometheus metric:

```bash
# Attach a tc BPF filter to count unknown VTEP sources (illustrative; load compiled BPF object)
tc qdisc add dev eth0 clsact
tc filter add dev eth0 ingress protocol ip prio 1 bpf obj vtep-monitor.o sec classifier direct-action

# Verify filter is attached
tc filter show dev eth0 ingress
```

Prometheus alerting rule for unknown VTEP source traffic:

```yaml
# prometheus-rules/vxlan-anomaly.yaml
groups:
  - name: vxlan_security
    rules:
      - alert: UnknownVTEPSourceTraffic
        expr: rate(vxlan_unknown_vtep_packets_total[5m]) > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "VXLAN traffic from unknown VTEP source on {{ $labels.node }}"
          description: "{{ $value }} pps from unrecognised VTEP. Possible injection or misconfiguration."
```

For incident investigation, capture VXLAN traffic at the physical interface and decode the inner frames:

```bash
# Capture VXLAN on the underlay interface, decode inner frames
tcpdump -i eth0 -n udp port 4789 -w /tmp/vxlan-capture.pcap

# Decode with tshark (shows both outer and inner headers)
tshark -r /tmp/vxlan-capture.pcap -d udp.port==4789,vxlan -V | head -80

# Quick summary of outer source IPs seen on port 4789
tcpdump -i eth0 -n -c 10000 udp port 4789 2>/dev/null | \
  awk '{print $3}' | sort | uniq -c | sort -rn | head -20
```

## Expected Behaviour

| Signal | Without hardening | With hardening |
|---|---|---|
| Rogue VTEP injection (UDP/4789 from unlisted IP) | Frame decapsulated and delivered to tenant overlay; FDB poisoned | nftables drops packet at physical interface; rogue VTEP cannot reach VXLAN stack |
| BUM amplification flood (high-rate broadcast to VNI) | All VTEPs in multicast group process and forward; CPU saturation on all nodes | Static unicast FDB limits flood targets to known VTEPs; BUM rate alerts fire within 1 minute |
| VNI scan (sequential VNI probe via UDP/4789) | Probes reach VXLAN stack; FDB responses and ICMP leakage reveal active VNIs | nftables drops probes from unlisted sources; only legitimate VTEPs can probe; monitoring alerts on probe pattern |
| Cross-tenant ARP spoof (ARP reply injected in overlay) | ARP cache poisoned in target tenant segment; traffic redirected to attacker | `nolearning` flag prevents dynamic FDB updates; static FDB entries enforced; Calico ARP proxy mode returns authoritative responses |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| IPsec transport encryption over VXLAN | Encrypts all inter-VTEP traffic; compatible with existing VXLAN CNI deployments | 5–15% throughput reduction per hop; CPU overhead without hardware offload; IKEv2 key management complexity | Use AES-GCM (hardware-accelerated on x86); deploy StrongSwan with automated cert renewal; use NICs with IPsec offload (e.g., Mellanox ConnectX-6) |
| Static VTEP FDB table | Eliminates dynamic MAC learning as an attack surface; disables BUM amplification via unknown sources | Operational burden: every node add or remove requires FDB updates on all other nodes | Automate FDB updates via node lifecycle hooks in Kubernetes (DaemonSet or CNI plugin); use a cluster-state-driven reconciler |
| Cilium WireGuard encryption mode | Zero unauthenticated packet paths; simple key management (Cilium-managed); no IPsec SA negotiation overhead | Requires Cilium as CNI; not portable to Flannel, Calico, or Antrea without replacing CNI; requires kernel >= 5.6 | Standardise on Cilium for greenfield clusters; for brownfield, use IPsec transport as the encryption layer instead |
| nftables VTEP ACL maintenance | Blocks all unauthenticated VTEP injection from non-cluster IPs; simple to audit | Node IP changes (cloud instance replacement) temporarily break overlay until ACL is updated | Drive nftables set updates from the same source of truth (Kubernetes node object) that the CNI uses; update ACL before CNI is initialised on new nodes |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| nftables ACL blocks new node VTEP | Pods on new node cannot communicate with pods on existing nodes; new node shows as Ready in Kubernetes but pod-to-pod traffic fails | `tcpdump -i eth0 udp port 4789` on an existing node shows no packets from new node's IP; `nft list set inet vtep_acl allowed_vteps` does not include new node IP | Add new node IP to nftables set on all existing nodes: `nft add element inet vtep_acl allowed_vteps { <new-node-ip> }`; automate via node join hook |
| IPsec SA mismatch between VTEPs | Intermittent packet loss on paths between specific node pairs; loss disappears and reappears as SAs cycle | `swanctl --list-sas` shows SA in REKEYING or DELETING state; `ip xfrm state list` shows expired SAs; per-node traceroute drops on specific hops | `swanctl --terminate --ike vtep-mesh && swanctl --initiate --child vxlan-udp`; check system clock skew (NTP drift causes IKEv2 failures); verify certificate expiry |
| VXLAN FDB table overflow | Packet loss for unknown MACs after FDB capacity exceeded; `bridge fdb show` returns truncated output | `ip -s link show vxlan100` shows increasing RX drop counter; kernel log: `vxlan: fdb: maximum reached`; Prometheus alert on interface drop rate | Lower `nolearning` threshold; set `ageing` on FDB entries (`ip link set vxlan100 type vxlan ageing 300`); reduce FDB pressure by limiting pods per node or using ARP proxy |
| WireGuard key rotation disrupts existing connections | Active TCP connections through the Cilium WireGuard overlay drop during key rotation; brief connectivity gap (< 1 second typical) | `wg show cilium_wg0` shows `latest handshake` timestamp cycling; application-layer retransmit counters spike during rotation | Cilium manages WireGuard key rotation automatically (every 5 minutes by default in Cilium 1.14+); ensure application-layer retry logic handles < 2s gaps; verify `encryption.wireguard.persistentKeepalive` is set to keep NAT mappings alive |

## Related Articles

- [Network Segmentation Patterns](/articles/network/network-segmentation-patterns/)
- [WireGuard Mesh Networking](/articles/network/wireguard-mesh/)
- [Cilium Network Policy](/articles/kubernetes/cilium-network-policy/)
- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [Network Flow Analysis](/articles/observability/network-flow-analysis/)
