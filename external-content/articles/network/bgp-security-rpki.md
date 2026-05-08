---
title: "BGP Security and RPKI: Route Origin Validation for Production Networks"
description: "BGP hijacking lets attackers redirect your traffic to their infrastructure. RPKI Route Origin Validation, route filtering, and ASPA make hijacks detectable and preventable."
slug: "bgp-security-rpki"
date: 2026-04-29
lastmod: 2026-04-29
category: "network"
tags: ["bgp", "rpki", "routing", "network-security", "rov"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 241
difficulty: "advanced"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/network/bgp-security-rpki/index.html"
---

# BGP Security and RPKI: Route Origin Validation for Production Networks

## Problem

BGP (Border Gateway Protocol) is the routing protocol of the internet. It allows autonomous systems (ASes) — networks operated by ISPs, cloud providers, and large enterprises — to announce which IP prefixes they own and how to reach them. BGP has no built-in authentication: any AS can announce any prefix.

BGP hijacking occurs when an AS announces prefixes it doesn't own. Traffic destined for the legitimate owner is redirected to the hijacker's network instead. This is not hypothetical:

- **2018 Amazon Route 53 hijack:** An AS announced Amazon's DNS resolver prefixes. Attackers intercepted DNS queries, redirecting cryptocurrency exchange users to phishing sites. $150,000 in ETH stolen.
- **2022 Cloudflare hijack:** 70+ Cloudflare IP prefixes announced by a third-party AS. Cloudflare's services were partially unreachable during the incident.
- **2023 Verizon and Google prefix leaks:** Multiple route leaks caused widespread internet disruptions, misrouting traffic through unintended carriers.

RPKI (Resource Public Key Infrastructure) allows IP address holders to cryptographically certify which ASes are authorized to originate their prefixes. Route Origin Validation (ROV) rejects routes whose origin AS doesn't match the certified Route Origin Authorization (ROA). When broadly deployed, RPKI-ROV makes hijacking significantly harder — even a single hop that validates RPKI will reject the hijacked routes before they propagate.

The specific gaps in networks without RPKI:

- Outbound route announcements lack ROA coverage — your prefixes can be hijacked without detection.
- Inbound route acceptance has no RPKI validation — your routers accept hijacked routes from peers.
- No ASPA (Autonomous System Provider Authorization) — path-based attacks remain undetected even with ROA in place.
- Route filtering is manual and configuration-drift-prone — prefix lists become stale.
- No alerting when BGP routes change unexpectedly.

**Target systems:** Networks with their own AS number and IP address blocks; Juniper JunOS 21+, Cisco IOS-XR 7+, BIRD 2.0.x, FRRouting 8.x (all support RPKI-RTR); Routinator 0.13+ or OctoRPKI 1.5+ for local RPKI validators.

## Threat Model

- **Adversary 1 — Prefix hijack for traffic interception:** An attacker (or a compromised ISP) announces your IP prefixes from their AS with a more specific route. Your traffic is redirected to their network, enabling MITM or blackholing.
- **Adversary 2 — BGP route leak:** A peer accidentally redistributes your routes internally to their upstream providers, causing unintended traffic paths. Your traffic transits providers you haven't agreed to.
- **Adversary 3 — Sub-prefix hijack:** Your AS announces `203.0.113.0/24`. An attacker announces `203.0.113.0/25` and `203.0.113.128/25` — more specific routes that take precedence in BGP routing. Half your address space is redirected.
- **Adversary 4 — AS path poisoning:** An attacker manipulates the AS path in BGP announcements to bypass route filters, make routes appear to come from a different origin, or manipulate path selection.
- **Adversary 5 — ROA misconfiguration:** A network operator creates a ROA with `maxLength` too large, accidentally authorizing delegated sub-prefixes that attackers exploit.
- **Access level:** Adversaries 1 and 3 have BGP session access (an AS peering relationship, legitimate or hijacked). Adversary 2 is an accidental leak. Adversaries 4 and 5 require BGP session or RPKI publication access.
- **Objective:** Intercept, redirect, or blackhole traffic intended for the target network.
- **Blast radius:** An unchallenged prefix hijack can redirect 100% of a network's traffic. With RPKI-ROV deployed at peers and upstreams, hijacked routes are rejected before propagating. The blast radius shrinks to networks that don't perform ROV.

## Configuration

### Step 1: Create ROAs for Your Prefixes

ROAs are published in the RPKI repositories of your Regional Internet Registry (ARIN, RIPE, APNIC, LACNIC, AFRINIC). You create them through your RIR's portal, not via router configuration.

```
# RIPE NCC example (via RIPE portal or API).
# For prefix 203.0.113.0/24, authorized origin AS64496:

ROA:
  ASN: AS64496
  Prefix: 203.0.113.0/24
  Max Length: 24    # CRITICAL: Do not set > 24 unless you intentionally
                    # announce more-specifics from this AS. Larger maxLength
                    # lets attackers register valid sub-prefix ROAs.
  Valid Until: 2027-04-29
```

ROA `maxLength` best practices:

| Scenario | Correct maxLength | Incorrect (risky) maxLength |
|----------|------------------|-----------------------------|
| You announce `/24` only | 24 | 32 (allows any sub-prefix) |
| You announce `/24` and `/25` sub-prefixes | 25 | 32 |
| You never announce sub-prefixes | Same as prefix length | Anything larger |

Audit your ROAs regularly:

```bash
# Check ROA coverage for your prefixes using Routinator or web tools.
curl -s "https://rpki-validator.ripe.net/api/v1/validity/AS64496/203.0.113.0%2F24" \
  | jq '{state: .validated_route.validity.state, description: .validated_route.validity.description}'
```

States: `valid` (ROA matches), `invalid` (ROA exists but doesn't match), `not-found` (no ROA).

### Step 2: Deploy a Local RPKI Validator

Running a local RPKI validator (Routinator, OctoRPKI) is more reliable than relying on a third-party RTR server. The validator fetches ROAs from the five RIR repositories and serves them to your routers via the RPKI-to-Router (RTR) protocol.

```bash
# Install Routinator.
apt install routinator    # Debian/Ubuntu
# Or from source:
cargo install routinator

# Initialize and start.
routinator init --accept-arin-rpa
routinator server --rtr 127.0.0.1:3323 --http 127.0.0.1:9556 &

# Confirm it's syncing.
curl http://127.0.0.1:9556/metrics | grep routinator_last_update
curl http://127.0.0.1:9556/api/v1/status
```

Run two validators for redundancy:

```bash
# Primary validator on rtr1.internal:3323
# Secondary validator on rtr2.internal:3323
# Routers configure both as RTR sources; either can be unavailable.
```

### Step 3: Configure RTR on Routers

Connect your BGP routers to the RPKI validator via the RTR protocol. Configuration varies by platform.

**BIRD 2.x:**

```
# bird.conf
rpki rtr1 {
  remote "rtr1.internal" port 3323;
  retry keep 90;
  refresh keep 900;
  expire keep 172800;
}

rpki rtr2 {
  remote "rtr2.internal" port 3323;
  retry keep 90;
  refresh keep 900;
  expire keep 172800;
}

# Filter function for ROV.
function rpki_check() {
  if roa_check(rpki_roas, net, bgp_path.last) = ROA_INVALID then {
    print "RPKI INVALID: ", net, " origin AS ", bgp_path.last;
    reject;
  }
  if roa_check(rpki_roas, net, bgp_path.last) = ROA_UNKNOWN then {
    # Unknown = no ROA exists. Accept but prefer valid routes.
    bgp_local_pref = 90;   # Slightly lower preference for unvalidated routes.
  }
  accept;
}

protocol bgp upstream_peer {
  import filter {
    rpki_check();   # Apply ROV on all inbound routes.
  };
}
```

**FRRouting:**

```
# frr.conf
rpki
 rpki polling-period 3600
 rpki cache 192.0.2.1 3323 preference 1
 rpki cache 192.0.2.2 3323 preference 2
exit

route-map BGP_IN permit 10
 match rpki valid
 set local-preference 200

route-map BGP_IN permit 20
 match rpki notfound
 set local-preference 150

route-map BGP_IN deny 30
 match rpki invalid
 ! Reject INVALID routes.
exit

router bgp 64496
 neighbor upstream_peer route-map BGP_IN in
```

**Cisco IOS-XR:**

```
rpki server 192.0.2.1
 transport tcp port 3323
 username rpki
 refresh-time 3600
 response-time 60
!
route-policy RPKI_IN
  if validation-state is invalid then
    drop
  endif
  if validation-state is valid then
    set local-preference 200
  elseif validation-state is unknown then
    set local-preference 150
  endif
  pass
end-policy
```

### Step 4: Outbound Route Filtering — Prefix Lists

Beyond RPKI (which validates inbound routes), filter your outbound announcements to prevent leaking routes you shouldn't be announcing:

```
# BIRD: filter outbound announcements to only your prefixes.
function export_filter() {
  # Only announce your own prefixes; never transit routes.
  if net ~ [ 203.0.113.0/24, 198.51.100.0/22 ] then accept;
  reject;
}

protocol bgp upstream_peer {
  export filter export_filter;
}
```

For large networks, generate prefix lists from IRR (Internet Routing Registry) using bgpq4:

```bash
# Generate prefix list for AS64496 from IRR data.
bgpq4 -4 -l AS64496_PREFIXES AS64496

# Output (import into router config):
# ip prefix-list AS64496_PREFIXES seq 10 permit 203.0.113.0/24 le 24
# ip prefix-list AS64496_PREFIXES seq 20 permit 198.51.100.0/22 le 22
```

Automate prefix list refresh — IRR data changes as you acquire or return address space:

```bash
# Cron: refresh prefix lists from IRR weekly.
0 2 * * 0 bgpq4 -4 -l AS64496_PREFIXES AS64496 > /etc/bird/prefix-list-outbound.conf \
  && birdc configure
```

### Step 5: ASPA — Path Validation (Next Layer)

RPKI-ROV validates the origin AS but not the full AS path. AS Path Validation (ASPA, RFC 9582) extends validation to the entire path, detecting path-based hijacks.

ASPA works by publishing which upstream providers each AS is authorized to use:

```
ASPA object:
  Customer AS: AS64496
  Provider Set: [AS64497, AS64498]   # Legitimate upstreams.
```

A route whose AS path shows AS64496 transiting through AS64499 (not in its provider set) is flagged as anomalous.

ASPA is deployable now in Routinator (0.13+) and is in active deployment by major operators. Configure once ROA coverage and ROV enforcement are stable:

```bash
# Check ASPA coverage for a given AS.
curl http://127.0.0.1:9556/api/v1/aspa/AS64496
```

### Step 6: Monitor BGP Route Changes

Alert when your prefixes are announced from unexpected ASes:

```bash
# BGPalerter: monitors BGP routing tables and alerts on anomalies.
npm install -g bgpalerter

# config.yml
monitoredPrefixes:
  - prefix: 203.0.113.0/24
    asn: 64496
    description: "Primary prefix"
    ignoreMorespecifics: false

alertRules:
  - name: hijack-detection
    type: hijack
    thresholds:
      - maxLength: 25     # Alert if a more-specific is seen.
      - origin: 64496     # Alert if origin AS changes.

notifications:
  - type: slack
    url: https://hooks.slack.com/services/xxx/yyy/zzz
```

Also monitor via RIPE RIS or RouteViews for external visibility:

```bash
# Check current routing table entries for your prefix (external view).
curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=203.0.113.0/24" \
  | jq '.data.origins'
```

Alert on any origin AS that is not your own.

### Step 7: Test ROV Enforcement

Verify your inbound ROV is working:

```bash
# On BIRD: show ROV state for a specific prefix.
birdc show route 198.51.100.0/24 all | grep -i rpki

# Check which routes are being filtered as INVALID.
birdc show route filtered | grep -c "INVALID"

# Routinator: look up validation state for a specific prefix+origin.
routinator validate --asn 64500 --prefix 203.0.113.0/24
# Output: state=invalid (if AS64500 has no ROA for this prefix — correctly rejected)
```

Test from an external perspective:

```bash
# RIPE RPKI validator API.
curl -s "https://rpki-validator.ripe.net/api/v1/validity/AS64500/203.0.113.0%2F24" \
  | jq .validated_route.validity.state
# Expected: "invalid" — confirming your prefixes are protected.
```

### Step 8: Telemetry

```
rpki_rtr_session_state{validator, router}              gauge (1=up, 0=down)
rpki_roas_total{rir}                                   gauge
rpki_routes_valid_total                                counter
rpki_routes_invalid_rejected_total                     counter
rpki_routes_notfound_total                             counter
bgp_prefix_change_total{prefix, from_as, to_as}        counter
bgp_session_state{peer}                                gauge
```

Alert on:

- `rpki_rtr_session_state` == 0 — validator connection lost; routers may be operating on stale data (fall-back to last-known-good or to accept-all depending on configuration — know which).
- `bgp_prefix_change_total` for your own prefixes with an unexpected origin AS — possible hijack in progress.
- `rpki_routes_invalid_rejected_total` sudden spike — a peer is sending hijacked routes; investigate.

## Expected Behaviour

| Signal | Without RPKI | With RPKI-ROV |
|--------|-------------|--------------|
| Hijacked prefix accepted | Yes — routers accept any announcement | Rejected at routers that perform ROV (your peers and upstreams that validate) |
| Your prefix hijacked externally | Silent; traffic diverted | RIPE stat shows unexpected origin; BGPalerter alerts; ROV at remote peers blocks propagation |
| Sub-prefix hijack | Succeeds if more specific | Blocked if maxLength set correctly in ROA |
| Route leak to upstream | Silent | IRR-generated prefix lists block export |
| RPKI validator down | No impact (no validation was happening) | Routers fall back to last-known-good ROA table; brief window of reduced protection |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| ROV enforcement (reject INVALID) | Hijacked routes not accepted | A misconfigured ROA on your side causes your routes to be rejected by remote peers | Carefully set maxLength; test ROAs with the RIPE validator before propagating. |
| Local RPKI validator | No dependency on third-party RTR service | Operational overhead of running Routinator | Lightweight; two instances for HA; minimal ops burden. |
| IRR-generated prefix lists | Automation prevents filter drift | IRR data quality varies; stale IRR objects cause filtering of legitimate routes | Supplement IRR with RPKI; use both. Prefer RPKI where both exist. |
| ASPA deployment | Path-level hijack detection | Still in early deployment; most peers don't validate ASPA yet | Deploy defensively (publish your ASPA objects); adopt ASPA filtering as peer support grows. |
| BGPalerter monitoring | External view of your routing | Requires internet egress from monitoring system | Deploy in a separate network zone with internet access. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| ROA maxLength too large | Attacker registers valid sub-prefix ROA; hijack appears ROA-valid | RIPE stat shows unexpected sub-prefix origin that is ROA-valid | Update your ROA maxLength; publish new ROA; wait for propagation (~15 min). |
| RPKI validator unreachable | Routers lose RTR session; may accept all or use stale cache | `rpki_rtr_session_state` == 0; router logs show RTR timeout | Restore validator; or configure routers to use stale data for 24h before falling back to permissive mode. |
| ROA not published for your prefix | Your prefix shows `not-found`; remote ROV routers accept but downprefer | RIPE validator API returns `notfound` for your prefix | Create ROA in your RIR portal; propagation takes 15–60 minutes. |
| IRR object stale after IP block return | Routes for returned space still in prefix list | Announced to peers but traffic goes to new owner | Audit IRR objects quarterly; remove stale objects immediately on space return. |
| BGP session flap during ROV update | Routes briefly withdrawn then re-announced | BGP session state changes in monitoring | Normal during Routinator refresh cycle; configure RTR refresh-time to align with BGP hold-timers. |
| False positive: your own route marked INVALID | Your routes rejected by peers that validate RPKI | Routes missing from peers' tables; traffic blackholed | Fix ROA maxLength or origin AS mismatch; takes 15-60 min to propagate. |

## Related Articles

- [DNS Security: DNSSEC and CAA](/articles/network/dns-security-dnssec-caa/)
- [DDoS Megascale Defence](/articles/network/ddos-megascale-defence/)
- [eBPF XDP DDoS Mitigation](/articles/network/ebpf-xdp-ddos/)
- [WireGuard Mesh Networking](/articles/network/wireguard-mesh/)
- [Zero-Trust Networking](/articles/cross-cutting/zero-trust-networking/)
