---
title: "BGP FlowSpec for DDoS Mitigation and Traffic Steering"
description: "Deploy BGP FlowSpec rules for real-time DDoS mitigation, black-hole routing, and traffic steering, with guidance on open source router implementation security and CVE monitoring."
slug: bgp-flowspec-ddos
date: 2026-05-02
lastmod: 2026-05-02
category: network
tags: ["bgp", "flowspec", "ddos", "rtbh", "gobgp", "frr", "traffic-engineering"]
personas: ["systems-engineer", "sre", "security-engineer"]
article_number: 337
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/network/bgp-flowspec-ddos/index.html"
---

# BGP FlowSpec for DDoS Mitigation and Traffic Steering

## Problem

BGP FlowSpec (originally RFC 5575, updated and refined by RFC 8955) is an extension to the Border Gateway Protocol that distributes traffic flow specification rules across a BGP peering topology. Where conventional BGP carries reachability information — which prefix is reachable via which next-hop — FlowSpec carries filtering policy. Each FlowSpec NLRI (Network Layer Reachability Information) encodes a flow tuple: match conditions drawn from source IP, destination IP, IP protocol, source port, destination port, DSCP value, TCP flags, packet length, and ICMP type/code. Alongside each match tuple sits an extended community encoding the action: drop, rate-limit to N bits/second, redirect to a VRF, or mark with a DSCP value. These rules are then propagated to all BGP peers that have negotiated the FlowSpec address family, giving every participating router in the network a consistent filtering view within the BGP convergence time.

The contrast with static ACLs is significant. A static ACL must be individually configured on every router that needs to enforce the rule. Deploying a new ACL entry across a 40-router edge fabric during an active attack means logging in to 40 routers, applying changes, verifying them, and hoping you caught every ingress point — a process that routinely takes 20–60 minutes. FlowSpec pushes a single rule from a controller (or from your upstream ISP), and within the BGP route-reflector convergence window — typically 2–10 seconds for well-tuned sessions — every participating router enforces the rule. No individual router logins required.

FlowSpec also differs materially from Remote Triggered Black Hole (RTBH) routing, which is the older and more widely deployed DDoS mitigation mechanism. RTBH works by advertising a host route (/32 or /128) tagged with a specific community that causes upstream routers to install a blackhole next-hop, dropping all traffic to that destination. This is all-or-nothing: you stop the attack by also stopping all legitimate traffic to the victim IP. FlowSpec is more surgical. You can write a rule that drops UDP traffic to the victim prefix on port 53 from 0.0.0.0/0 while allowing TCP/443 to the same prefix to pass unmolested. You can rate-limit instead of drop, accepting 10 Mbit/s of inbound traffic while discarding the rest of a 40 Gbit/s flood. This precision is the core operational value of FlowSpec over RTBH, and it is also why FlowSpec has become the standard mitigation surface offered by large transit providers and DDoS scrubbing services.

Why this matters for DDoS at scale: when a victim network has a FlowSpec peering session with their upstream transit provider, the transit provider's scrubbing controller can push a drop rule for the attack signature and have that rule enforced at the transit provider's own edge routers before traffic even arrives at the victim's border. The time-to-enforcement is the BGP session convergence time — seconds, not minutes. Volumetric attacks that would saturate a customer's uplinks are absorbed at the upstream edge. This is the operational model used by every major transit and CDN provider offering DDoS services: Telia, Lumen, Zayo, Cloudflare Magic Transit, and Amazon Shield Advanced all use FlowSpec (or proprietary equivalents) to push per-flow drop rules toward their edge.

The open source implementation landscape is mature but carries non-trivial security surface. FRR (Free Range Routing) is the most widely deployed open source BGP implementation and includes full FlowSpec support in both IPv4 and IPv6 address families. GoBGP (written in Go) provides a FlowSpec-capable BGP daemon with a gRPC management API, making it well-suited as a programmatic FlowSpec controller. BIRD 2 supports FlowSpec and is popular in IXP (Internet Exchange Point) deployments. ExaBGP, written in Python, is widely used as a FlowSpec injection tool because of its scriptable route-announcement interface. However, BGP parsing is historically one of the most vulnerability-prone areas in networking software. FRR's BGP daemon (`bgpd`) has had multiple serious CVEs related to malformed BGP UPDATE message parsing: CVE-2022-26126 allowed memory corruption via crafted BGP OPEN attributes; CVE-2023-38802 was an RCE-class vulnerability in BGP UPDATE attribute parsing that was widely reported as actively exploited in the wild before patches were universally deployed. A particularly dangerous pattern with FRR is that security-relevant commits regularly appear in the `stable/8.x` or `stable/9.x` branches with generic commit messages — "bgpd: fix attribute parsing", "bgpd: handle malformed flowspec NLRI" — days or weeks before a CVE is assigned and a security advisory published. Operators who only monitor CVE feeds miss this window entirely. The correct approach is to monitor `https://github.com/FRRouting/frr/security/advisories` for advisories AND watch the `stable/*` branch commit stream specifically for changes touching `bgpd/bgp_attr.c`, `bgpd/bgp_flowspec.c`, `bgpd/bgp_flowspec_util.c`, and `bgpd/bgp_packet.c`. GoBGP has had similar patterns where parsing-related fixes were merged to the main branch without CVE assignment.

Target systems: FRR 9.x, GoBGP 3.x, ExaBGP 4.x, Linux kernel 5.15 or later for kernel-side FlowSpec action enforcement via the `tc flower` classifier and eBPF.

## Threat Model

1. **Volumetric DDoS attacker targeting your prefix.** An attacker sends a 100 Gbit/s UDP amplification flood toward your prefix. Without FlowSpec, the attack saturates your upstream links and you begin manual ACL deployment across your edge routers — 20–60 minutes of outage while you work. With FlowSpec peering to your transit provider, you (or an automated scrubbing system) push a single FlowSpec rule and the transit provider's edge drops the flood in 2–10 seconds. The attack traffic never reaches your border routers.

2. **BGP peer exploiting an FRR or GoBGP parser CVE.** A malicious or compromised BGP peer sends a crafted BGP OPEN or UPDATE message designed to trigger a memory corruption bug — for example, the class of bugs addressed by CVE-2023-38802. If the exploit succeeds, the attacker achieves remote code execution on your FlowSpec controller or crashes the `bgpd` daemon. A daemon crash immediately removes all FlowSpec state from your network, undoing all active mitigations. An RCE gives the attacker the ability to inject arbitrary FlowSpec rules.

3. **Patch-gap attacker exploiting the FRR commit-to-CVE window.** A sophisticated attacker monitors the FRR `stable/9.x` branch on GitHub. They observe a commit to `bgpd/bgp_attr.c` with a message like "bgpd: validate MP_REACH_NLRI length before processing flowspec". They develop an exploit for the vulnerability that the commit fixes, knowing that most operators running distribution-packaged FRR will not update for 2–6 weeks — the time between a fix landing in the stable branch and it propagating through Linux distribution package repositories and operator patching cycles. This window is the most dangerous phase of a BGP implementation vulnerability's lifecycle.

4. **Unauthorized FlowSpec rule injection via BGP peer hijack or misconfiguration.** A BGP peer that should not be sending FlowSpec rules — or a peer whose session has been hijacked by a BGP hijack or credential theft — injects a FlowSpec rule with action `traffic-rate 0` (drop) matching your own legitimate traffic. This is FlowSpec as a DoS vector against yourself: the same mechanism that defends against attacks can be weaponized to silence your own prefixes if rule validation is absent.

The blast radius without mitigations is total: a compromised FlowSpec controller has network-wide impact, since every participating router accepts rules from it. The mitigations in the next section are not optional hardening — they are the minimum baseline for running FlowSpec in production.

## Configuration / Implementation

### FRR FlowSpec Configuration

Install FRR 9.x and enable the BGP daemon. The core FlowSpec configuration in `/etc/frr/frr.conf`:

```
frr version 9.1
frr defaults traditional
hostname frr-flowspec
log syslog informational
!
router bgp 65001
 bgp router-id 192.0.2.1
 no bgp ebgp-requires-policy
 !
 neighbor 192.0.2.2 remote-as 65002
 neighbor 192.0.2.2 description flowspec-controller
 neighbor 192.0.2.2 password <BGP-MD5-SECRET>
 neighbor 192.0.2.2 ttl-security hops 1
 neighbor 192.0.2.2 maximum-prefix 100
 !
 address-family ipv4 flowspec
  neighbor 192.0.2.2 activate
  neighbor 192.0.2.2 route-map FLOWSPEC-IN in
 exit-address-family
!
route-map FLOWSPEC-IN permit 10
 match ip flowspec dest-prefix TRUSTED-DEST-PREFIXES
!
ip prefix-list TRUSTED-DEST-PREFIXES seq 5 permit 203.0.113.0/24
ip prefix-list TRUSTED-DEST-PREFIXES seq 10 permit 198.51.100.0/24
!
```

The `route-map FLOWSPEC-IN` with `match ip flowspec dest-prefix` is critical: it rejects any FlowSpec rule whose destination does not match your own prefix space. A FlowSpec rule destined for someone else's address space should never be accepted or re-propagated.

To inject a FlowSpec rule interactively via `vtysh` — for example, to drop UDP traffic from an attack source `198.51.100.0/24` to your victim prefix `203.0.113.0/24` on destination port 80:

```
vtysh -c "conf t" -c "router bgp 65001" \
  -c "address-family ipv4 flowspec" \
  -c "bgp flowspec rule src 198.51.100.0/24 dst 203.0.113.0/24 proto udp dstport 80 action drop"
```

Verify active FlowSpec rules:

```
vtysh -c "show bgp ipv4 flowspec detail"
```

### GoBGP as FlowSpec Controller

GoBGP is well suited as a centralised FlowSpec controller: it exposes a gRPC API allowing programmatic rule injection, and it can peer with multiple FRR routers simultaneously, pushing rules to all of them. Start GoBGP with a minimal `gobgpd.conf`:

```toml
[global.config]
  as = 65099
  router-id = "192.0.2.99"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.1"
    peer-as = 65001
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
```

Inject a FlowSpec drop rule via the GoBGP CLI — rate-limit to 0 (effectively drop) all UDP traffic to the victim prefix on port 80:

```bash
gobgp global rib -a flowspec-ipv4 add \
  match destination 203.0.113.0/24 \
  protocol udp \
  destination-port ==80 \
  then action traffic-rate 0
```

Inject a rate-limit rule (instead of full drop) to allow 10 Mbit/s through:

```bash
gobgp global rib -a flowspec-ipv4 add \
  match destination 203.0.113.0/24 \
  protocol udp \
  then action traffic-rate 10000000
```

List active FlowSpec rules:

```bash
gobgp global rib -a flowspec-ipv4
```

For programmatic injection (e.g. from an automated scrubbing pipeline), use the GoBGP gRPC API:

```python
import grpc
from gobgp_pb2 import AddPathRequest
from gobgp_pb2_grpc import GobgpApiStub

channel = grpc.insecure_channel("192.0.2.99:50051")
stub = GobgpApiStub(channel)
# Build the FlowSpec NLRI via the protobuf API and call stub.AddPath()
```

### RTBH Integration

Combine FlowSpec rate-limiting with RTBH for full-drop escalation when the attack volume exceeds what rate-limiting can handle. Tag a FlowSpec rule with the RTBH community (`65535:666` by convention) to trigger upstream blackholing:

```
vtysh -c "conf t" -c "router bgp 65001" \
  -c "address-family ipv4 flowspec" \
  -c "bgp flowspec rule dst 203.0.113.5/32 action redirect-to-ip 192.0.2.254 community 65535:666 no-export"
```

The `no-export` community prevents the blackhole route from leaking beyond your direct upstream peers. The redirect-to-ip target `192.0.2.254` should be configured as a null route on all participating routers:

```bash
ip route add blackhole 203.0.113.5/32 metric 1
```

### Monitoring FRR for Silent Security Patches

The most dangerous FRR vulnerability window is between a fix landing in the stable branch and a CVE being published. Automate detection with a cron script:

```bash
#!/usr/bin/env bash
# /usr/local/bin/frr-security-watch.sh
# Runs daily; alerts if bgpd security-relevant files changed in the last 7 days

set -euo pipefail

FRR_REPO_DIR="/opt/frr-upstream"
BRANCH="stable/9.1"
ALERT_EMAIL="security-team@example.com"
FILES_TO_WATCH="bgpd/bgp_attr.c bgpd/bgp_flowspec.c bgpd/bgp_flowspec_util.c bgpd/bgp_packet.c bgpd/bgp_open.c"

if [ ! -d "${FRR_REPO_DIR}/.git" ]; then
    git clone --bare https://github.com/FRRouting/frr.git "${FRR_REPO_DIR}"
fi

git -C "${FRR_REPO_DIR}" fetch origin "${BRANCH}:${BRANCH}" --quiet

CHANGES=$(git -C "${FRR_REPO_DIR}" log --oneline \
    "origin/${BRANCH}" \
    --since="7 days ago" \
    -- ${FILES_TO_WATCH} 2>/dev/null)

if [ -n "${CHANGES}" ]; then
    echo "FRR security-watch: new commits to bgpd parser files on ${BRANCH}:" | \
        mail -s "[ALERT] FRR bgpd parser commits detected" "${ALERT_EMAIL}" <<EOF
Branch: ${BRANCH}
Commits in last 7 days touching bgpd parser/flowspec files:

${CHANGES}

Review at: https://github.com/FRRouting/frr/commits/${BRANCH}
Security advisories: https://github.com/FRRouting/frr/security/advisories
OSV query: https://api.osv.dev/v1/query (package: frr, ecosystem: Linux)
EOF
fi
```

Deploy as a daily cron job:

```
0 6 * * * /usr/local/bin/frr-security-watch.sh
```

Complement this with OSV.dev API queries to catch CVEs published for FRR:

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "frr", "ecosystem": "Linux"}}' | \
  jq '.vulns[] | {id, published, summary}'
```

Subscribe to `https://github.com/FRRouting/frr/security/advisories` via GitHub's "Watch" feature with security advisory notifications enabled. Configure your package manager to auto-apply FRR updates on a maximum 48-hour delay from availability:

```bash
# Debian/Ubuntu unattended-upgrades for FRR
echo 'Unattended-Upgrade::Allowed-Origins:: "FRR:stable/9.x";' \
  >> /etc/apt/apt.conf.d/50unattended-upgrades
```

### BGP Session Hardening for FlowSpec Peers

Every BGP session carrying FlowSpec must be hardened. Apply to all FlowSpec peer configurations in `frr.conf`:

```
neighbor 192.0.2.2 password <BGP-MD5-SECRET>
neighbor 192.0.2.2 ttl-security hops 1
neighbor 192.0.2.2 maximum-prefix 100
neighbor 192.0.2.2 maximum-prefix-out 50
neighbor 192.0.2.2 update-source lo
```

- `password`: MD5 TCP authentication prevents session hijacking from off-path attackers.
- `ttl-security hops 1`: requires the BGP TCP packet to arrive with TTL 255 (one hop away), defeating spoofed BGP OPEN/UPDATE packets from non-adjacent hosts.
- `maximum-prefix 100`: if your FlowSpec peer sends more than 100 FlowSpec NLRIs, the session is torn down, preventing rule injection floods.

Restrict FlowSpec acceptance to specific trusted ASNs with a neighbor-level policy:

```
neighbor 192.0.2.2 route-map FLOWSPEC-IN in
route-map FLOWSPEC-IN deny 5
 match as-path UNTRUSTED-AS
route-map FLOWSPEC-IN permit 10
 match ip flowspec dest-prefix TRUSTED-DEST-PREFIXES
ip as-path access-list UNTRUSTED-AS deny ^65099$
```

### Kernel-Side FlowSpec Enforcement with tc/eBPF

For FlowSpec rules enforced directly in the Linux kernel (without relying on `bgpd` to program the forwarding plane), use the `tc flower` classifier. This approach is useful for host-level DDoS mitigation and for validating that rules are in effect independently of the BGP stack:

```bash
# Create a qdisc root for the ingress interface
tc qdisc add dev eth0 ingress handle ffff:

# Drop UDP traffic to 203.0.113.0/24 on destination port 80
tc filter add dev eth0 protocol ip parent ffff: \
  flower \
  dst_ip 203.0.113.0/24 \
  ip_proto udp \
  dst_port 80 \
  action drop

# Rate-limit traffic from 198.51.100.0/24 to 10 Mbit/s
tc filter add dev eth0 protocol ip parent ffff: \
  flower \
  src_ip 198.51.100.0/24 \
  action police rate 10mbit burst 64k drop
```

List active filters:

```bash
tc filter show dev eth0 ingress
```

For RTBH null-routing at the kernel:

```bash
ip route add blackhole 203.0.113.5/32 metric 1
ip route show type blackhole
```

eBPF-based XDP programs can enforce FlowSpec-equivalent rules at line rate before packets enter the kernel network stack — see the related article on eBPF/XDP for DDoS for implementation detail.

## Expected Behaviour

| Signal | Without FlowSpec | With FlowSpec + Hardening |
|---|---|---|
| DDoS volumetric flood to your prefix | Manual ACL deployment: 20–60 min to full enforcement across all edge routers; uplinks saturated during that window | FlowSpec rule pushed to transit provider or local controller; enforcement at all participating routers within 2–10 seconds of BGP convergence |
| Rogue FlowSpec rule from untrusted peer | No protection; peer can inject rules matching any destination, potentially dropping your own traffic | `route-map FLOWSPEC-IN` with `match ip flowspec dest-prefix` rejects rules not matching your own prefix space; `maximum-prefix` tears down sessions injecting excessive rules |
| FRR `bgpd` crash from malformed UPDATE | All FlowSpec state lost; crash may go unnoticed for minutes; attack traffic re-enters the network | Process supervisor (systemd, supervisord) restarts `bgpd` within seconds; BGP sessions re-establish and FlowSpec rules are re-propagated from the controller; PagerDuty alert fires on `bgpd` restart |
| Patch-gap exploitation of silent FRR fix | 2–6 week window between commit and operator package update; attacker with GitHub commit visibility can exploit during this window | Daily `frr-security-watch.sh` cron detects commits to parser files within 24 hours; unattended-upgrades apply FRR packages within 48 hours of availability; MTTD < 24 hours |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| FlowSpec propagation vs static ACL | Rule takes effect at all routers within BGP convergence time (~2–10 s); no per-router login | BGP convergence time is non-zero; static ACL on a directly connected router is instantaneous | Accept the convergence latency for network-wide rules; use kernel `tc` rules locally for sub-second host-level enforcement |
| BGP session as new attack surface | Enables programmatic, network-wide rule distribution | The FlowSpec controller and its BGP sessions become a high-value attack target; compromise enables network-wide rule injection | MD5 TCP auth, TTL security, firewall restricting port 179 to trusted peers only, separate management VRF for BGP sessions |
| Rate-limit vs drop (collateral damage) | Rate-limiting preserves some legitimate traffic during attack | Rate-limiting still passes attack traffic proportionally; some legitimate traffic is still dropped by statistical packet loss under high rate-limit | Use rate-limiting first; escalate to drop if legitimate services are unacceptably impacted; use more specific match tuples to narrow collateral damage |
| Upstream ISP FlowSpec support | Upstream enforcement stops traffic before it consumes your own bandwidth | Not all ISPs support FlowSpec; support quality varies; you may have multiple transit providers with inconsistent capability | Verify FlowSpec capability before signing transit contracts; operate local kernel-side FlowSpec as a fallback for ISPs that don't support it; negotiate FlowSpec SLAs with primary transit |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| FRR `bgpd` crash drops all FlowSpec rules | Active DDoS mitigation rules disappear; attack traffic re-enters network; `bgpd` process absent from `ps` output | `systemd` unit failure alert; `vtysh -c "show bgp ipv4 flowspec"` returns empty; `journalctl -u frr` shows crash with backtrace | systemd `Restart=on-failure` restarts `bgpd`; controller re-pushes all FlowSpec rules after BGP session re-establishment; post-incident: check for matching CVE, file bug report, update FRR package |
| FlowSpec rule drops legitimate traffic (false positive) | Services behind the victim prefix become unreachable; support tickets and monitoring alerts for elevated 5xx or connection timeouts | Application latency/error-rate alerts; verify with `vtysh -c "show bgp ipv4 flowspec detail"` which rules are active; test with `hping3` or `scapy` |  Withdraw the offending FlowSpec rule: `vtysh -c "conf t" -c "no bgp flowspec rule ..."` or delete from GoBGP with `gobgp global rib -a flowspec-ipv4 del ...`; re-scope rule to narrower source/destination/port tuple |
| BGP peer rejects FlowSpec NLRI (capability not supported) | FlowSpec rules pushed to peer are silently ignored; no error logged on controller; DDoS mitigation has no effect on that router | `vtysh -c "show bgp neighbors 192.0.2.2"` shows FlowSpec capability absent; `tcpdump -i eth0 port 179` shows OPEN messages without FlowSpec capability code 133 | Verify FlowSpec AFI/SAFI capability negotiation in `frr.conf`; confirm peer FRR/GoBGP version supports FlowSpec; fall back to RTBH community tagging for that peer |
| TTL security misconfiguration breaks peering | BGP session to FlowSpec peer fails to establish; `bgpd` logs "TTL check failed" for incoming TCP SYN; FlowSpec rules cannot be distributed | `vtysh -c "show bgp neighbors"` shows session in `Active` or `Connect` state; `tcpdump port 179` shows TCP SYN arriving with TTL < 255 | Remove `ttl-security hops 1` temporarily to restore session; verify actual hop count between peers with `traceroute`; set `ttl-security hops N` to match actual topology hop count; re-enable |

## Related Articles

- [BGP Security and RPKI: Route Origin Validation](/articles/network/bgp-security-rpki/)
- [DDoS Defence at Megascale](/articles/network/ddos-megascale-defence/)
- [eBPF and XDP for DDoS Mitigation](/articles/network/ebpf-xdp-ddos/)
- [Network Flow Analysis and Threat Detection](/articles/observability/network-flow-analysis/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
