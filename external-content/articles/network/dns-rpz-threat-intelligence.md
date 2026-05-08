---
title: "DNS Response Policy Zones: Blocking C2 Domains with Internal Resolver Threat Intelligence"
description: "DNS RPZ lets an internal resolver return NXDOMAIN (or a sinkhole) for known-malicious domains before a connection is ever made. One control blocks C2, phishing, and malware distribution network-wide."
slug: "dns-rpz-threat-intelligence"
date: 2026-04-30
lastmod: 2026-04-30
category: "network"
tags: ["dns", "rpz", "threat-intelligence", "c2", "resolver"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 265
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/network/dns-rpz-threat-intelligence/index.html"
---

# DNS Response Policy Zones: Blocking C2 Domains with Internal Resolver Threat Intelligence

## Problem

Almost every network attack requires DNS. C2 beacons resolve operator domains. Phishing pages have hostnames. Malware distribution networks use CDN-style DNS to rotate IPs. Exfiltration uses DNS tunnelling. If you control the DNS resolver that all internal clients use, you can intercept every one of these lookups before a packet reaches the attacker's infrastructure.

DNS Response Policy Zones (RPZ) is an extension to BIND (and other resolvers) that lets you define override rules: when a client queries for a domain matching a rule, the resolver returns a policy response — typically `NXDOMAIN` (domain doesn't exist) or a sinkhole IP — instead of performing normal resolution.

The operational advantage over firewall-based blocking: RPZ acts at the resolution stage, before any connection is attempted. A firewall rule blocks traffic to known-bad IPs, but IP addresses change hourly for sophisticated C2. RPZ blocks by domain name, which changes much more slowly.

Specific gaps without RPZ:

- Internal resolvers forward all queries to upstream without any policy filtering.
- Threat intelligence feeds (Abuse.ch, Emerging Threats, AlienVault OTX) contain thousands of malicious domains that are never operationalised into blocking.
- DNS tunnelling exfiltration (tools like `dnscat2`, `iodine`) requires resolving attacker-controlled domains; RPZ blocks these lookups.
- No visibility into which internal hosts are attempting to resolve malicious domains — a key early-warning signal.

**Target systems:** BIND 9.9+ (RPZ support); Unbound 1.6+ with RPZ module; PowerDNS Recursor 4.4+; Infoblox, BlueCat, or Cisco Umbrella for managed DNS with threat intelligence; threat intelligence feeds: Abuse.ch OSINT, Emerging Threats, Quad9.

## Threat Model

- **Adversary 1 — C2 beacon resolution:** Malware installed on an internal host attempts to resolve the C2 domain (e.g., `random-string.attacker.com`). The internal resolver would normally forward this to the upstream recursive resolver and return the C2 IP. RPZ intercepts the query and returns NXDOMAIN; the malware cannot reach its controller.
- **Adversary 2 — Phishing redirect via internal host:** An employee clicks a phishing link. The browser resolves the phishing domain. RPZ intercepts and redirects to a sinkhole page explaining the block.
- **Adversary 3 — DNS tunnelling for exfiltration:** An attacker uses `iodine` or `dnscat2` to exfiltrate data via DNS queries to attacker-controlled nameservers. RPZ blocks resolution of the attacker's tunnelling domain.
- **Adversary 4 — RPZ bypass via alternative resolver:** An attacker configures the compromised host to use `8.8.8.8` instead of the internal resolver, bypassing RPZ. This is detectable if DNS egress on port 53 to non-internal resolvers is firewall-blocked.
- **Adversary 5 — False positive blocks legitimate domain:** A threat intelligence feed incorrectly lists a legitimate domain. Internal clients cannot reach the service. Over-aggressive RPZ causes service disruption.
- **Access level:** Adversaries 1–3 have code execution on an internal host. Adversary 4 has code execution and can modify the host's DNS resolver configuration. Adversary 5 is a threat intelligence quality problem.
- **Objective:** Establish C2 communication, exfiltrate data, deliver phishing content.
- **Blast radius:** Without RPZ, every DNS query for a malicious domain resolves normally. With RPZ, queries for listed domains are blocked network-wide, affecting all clients regardless of their individual security posture.

## Configuration

### Step 1: BIND RPZ Configuration

```
# /etc/named.conf

options {
    directory "/var/named";
    recursion yes;

    # Block direct DNS to external resolvers on port 53 (force use of internal resolver).
    # This prevents RPZ bypass via 8.8.8.8.
    # This is a firewall rule, not a named.conf option — see Step 6.

    # Response Policy Zone configuration.
    response-policy {
        zone "rpz.abuse-ch" policy NXDOMAIN;
        zone "rpz.emerging-threats" policy NXDOMAIN;
        zone "rpz.local-blocklist" policy NXDOMAIN;
        zone "rpz.sinkhole" policy CNAME rpz-sinkhole.internal.;
    } break-dnssec yes;   # Apply RPZ even if DNSSEC validates (C2 domains can be DNSSEC-signed).

    # Log RPZ hits for SIEM.
    query-log yes;
};

# Internal RPZ zone (manually managed or from a local feed processor).
zone "rpz.local-blocklist" {
    type primary;
    file "/var/named/rpz/local-blocklist.db";
    allow-transfer { none; };
};

# External threat feed zones (fetched automatically by a feed processor).
zone "rpz.abuse-ch" {
    type primary;
    file "/var/named/rpz/abuse-ch.db";
    allow-transfer { none; };
};

zone "rpz.emerging-threats" {
    type primary;
    file "/var/named/rpz/emerging-threats.db";
    allow-transfer { none; };
};
```

### Step 2: RPZ Zone File Format

```dns
; /var/named/rpz/local-blocklist.db
; RPZ zone format: the zone name is the RPZ zone name.
; Entries are relative to the zone name.

$TTL 3600
@ SOA localhost. admin.localhost. (
    2026043001  ; Serial (date-based: YYYYMMDDNN)
    1H          ; Refresh
    15M         ; Retry
    30D         ; Expire
    2H          ; Minimum TTL
)
  NS localhost.

; NXDOMAIN policy entries.
; Format: <domain-to-block>.rpz-zone-name.  CNAME  .
;                                                   ^ single dot = NXDOMAIN

c2-operator.evil.com                              CNAME  .
*.malware-cdn.net                                 CNAME  .
ransomware-tracker.dyndns.org                     CNAME  .

; Wildcard: block all subdomains of a known bad domain.
*.known-bad-tld.cc                                CNAME  .
known-bad-tld.cc                                  CNAME  .
```

To sinkhole (redirect to a local page instead of NXDOMAIN):

```dns
; Entries that redirect to a sinkhole IP for logging and user notification.
; These go in the rpz.sinkhole zone.
phishing-site.com                                 CNAME  rpz-sinkhole.internal.
```

The sinkhole IP (`rpz-sinkhole.internal`) should run a simple HTTP server that returns a "This site has been blocked by your security policy" page.

### Step 3: Automated Threat Feed Ingestion

```python
#!/usr/bin/env python3
# /usr/local/bin/update-rpz-feeds.py
# Fetches threat intelligence feeds and converts them to RPZ zone files.

import requests
import datetime
import os

FEEDS = {
    "abuse-ch": {
        "url": "https://urlhaus.abuse.ch/downloads/rpz/",
        "format": "rpz",   # Already in RPZ format.
        "output": "/var/named/rpz/abuse-ch.db",
    },
    "emerging-threats": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "format": "domains",   # Plain domain list; convert to RPZ.
        "output": "/var/named/rpz/emerging-threats.db",
    },
}

def domain_list_to_rpz(domains: list[str], zone_name: str) -> str:
    serial = datetime.datetime.now().strftime("%Y%m%d%H")
    header = f"""$TTL 3600
@ SOA localhost. admin.localhost. (
    {serial}
    1H 15M 30D 2H
)
  NS localhost.

"""
    entries = []
    for domain in domains:
        domain = domain.strip().lower()
        if domain and not domain.startswith('#'):
            entries.append(f"{domain}  CNAME  .")
            entries.append(f"*.{domain}  CNAME  .")

    return header + "\n".join(entries) + "\n"

def update_feed(name: str, config: dict):
    resp = requests.get(config["url"], timeout=30)
    resp.raise_for_status()

    if config["format"] == "rpz":
        content = resp.text
    elif config["format"] == "domains":
        domains = [line for line in resp.text.splitlines()
                   if line and not line.startswith('#')]
        content = domain_list_to_rpz(domains, name)

    # Write atomically.
    tmp = config["output"] + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
    os.rename(tmp, config["output"])

    print(f"Updated {name}: {len(content.splitlines())} lines")

if __name__ == "__main__":
    for name, config in FEEDS.items():
        update_feed(name, config)

    # Reload BIND to pick up new zone data.
    os.system("rndc reload")
    print("BIND reloaded.")
```

Run via cron:

```bash
# /etc/cron.d/rpz-feed-update
0 * * * * root /usr/local/bin/update-rpz-feeds.py >> /var/log/rpz-feed-update.log 2>&1
```

### Step 4: Logging RPZ Hits for SIEM

BIND logs RPZ policy hits to syslog when query logging is enabled:

```
# /etc/named.conf logging block
logging {
    channel rpz_log {
        file "/var/log/named/rpz-hits.log" versions 10 size 50M;
        severity info;
        print-category yes;
        print-severity yes;
        print-time yes;
    };

    channel security_log {
        syslog security;
        severity info;
    };

    category rpz { rpz_log; security_log; };
    category queries { rpz_log; };
};
```

RPZ hit log format:

```
30-Apr-2026 14:23:01.456 rpz: info: client @0xXXXX 10.0.1.42#54321
    (c2-operator.evil.com): rpz QNAME Local-Data rewrite
    c2-operator.evil.com/CNAME/IN via c2-operator.evil.com.rpz.local-blocklist
```

Parse and ship to SIEM:

```yaml
# Vector pipeline: parse RPZ hits and forward to Elasticsearch.
sources:
  named_rpz:
    type: file
    include: ["/var/log/named/rpz-hits.log"]

transforms:
  parse_rpz:
    type: remap
    inputs: [named_rpz]
    source: |
      . = parse_regex!(.message, r'client @\w+ (?P<client_ip>[\d.]+)#\d+ \((?P<queried_domain>[^)]+)\): rpz .* via (?P<rpz_zone>\S+)')
      .event_type = "dns.rpz.block"
      .timestamp = now()

sinks:
  siem:
    type: elasticsearch
    inputs: [parse_rpz]
    endpoint: https://siem.internal:9200
    index: security-dns-%Y.%m.%d
```

### Step 5: Unbound RPZ Configuration

For environments using Unbound:

```
# /etc/unbound/unbound.conf
server:
    # Load the RPZ module.
    module-config: "respip iterator"

rpz:
    name: "rpz.local-blocklist"
    zonefile: "/etc/unbound/rpz/local-blocklist.zone"
    rpz-action-override: nxdomain
    rpz-log: yes
    rpz-log-name: "local-blocklist"

rpz:
    name: "rpz.abuse-ch"
    zonefile: "/etc/unbound/rpz/abuse-ch.zone"
    rpz-action-override: nxdomain
    rpz-log: yes
```

### Step 6: Block Direct DNS Egress (Prevent RPZ Bypass)

Malware can bypass RPZ by using a hardcoded alternative resolver (`8.8.8.8`, `1.1.1.1`). Block direct port 53 egress to non-internal resolvers:

```bash
# nftables: block outbound DNS to any resolver except the internal one.
nft add rule inet filter output \
  ip protocol udp udp dport 53 \
  ip daddr != { 10.0.0.53, 10.0.0.54 } \  # Internal resolver IPs.
  drop

nft add rule inet filter output \
  ip protocol tcp tcp dport 53 \
  ip daddr != { 10.0.0.53, 10.0.0.54 } \
  drop

# Also block DNS-over-HTTPS bypasses (port 443 to known DoH providers).
# This requires SNI inspection or IP-based blocking.
# Block known DoH IPs (Google, Cloudflare, Quad9).
nft add rule inet filter output \
  ip daddr { 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9 } \
  drop
```

### Step 7: Telemetry

```
dns_rpz_block_total{zone, queried_domain, client_ip}       counter
dns_rpz_zone_size{zone_name}                               gauge
dns_rpz_feed_last_updated{feed_name}                       gauge (unix timestamp)
dns_rpz_feed_update_failure_total{feed_name}               counter
dns_query_total{resolver, result}                          counter
dns_direct_egress_blocked_total{client_ip, destination}    counter
```

Alert on:

- `dns_rpz_block_total` spike from a specific `client_ip` — that host is exhibiting malicious activity (C2 beaconing, malware attempting resolution).
- `dns_rpz_feed_last_updated` > 2 hours old — feed update failed; blocklist is stale.
- `dns_direct_egress_blocked_total` non-zero — a host is attempting to bypass the internal resolver; investigate immediately.
- Multiple distinct clients resolving the same blocked domain — possible lateral movement or worm.

## Expected Behaviour

| Signal | Internal resolver without RPZ | Internal resolver with RPZ |
|--------|------------------------------|---------------------------|
| C2 domain resolution | Returns C2 IP | NXDOMAIN; connection never attempted |
| Phishing domain resolution | Returns phishing IP | Redirected to sinkhole; user sees block page |
| DNS tunnelling domain | Resolved to attacker NS | NXDOMAIN; tunnelling fails |
| Unknown malicious domain | Not blocked | Not blocked (RPZ only covers listed domains) |
| Threat feed update | N/A | Hourly automatic update; new domains blocked within 1h |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| NXDOMAIN policy | Simple; malware can't connect | No user notification | Use sinkhole policy for user-facing domains; NXDOMAIN for headless services. |
| Broad wildcard blocks (`*.evil.com`) | Covers all subdomains (used by DGA malware) | May block legitimate CDNs if parent domain is wrong | Audit feeds for false positives; use a passlist for known-good subdomains. |
| Blocking direct DNS egress | Prevents RPZ bypass | Applications using hardcoded DNS may break | Identify and fix applications using hardcoded resolvers; redirect port 53 to internal resolver. |
| Hourly feed updates | Current threat intelligence | Feed update failures leave stale blocklist | Alert on feed age > 2h; fall back to last-good feed file on update failure. |
| Multiple zones (priority-ordered) | Granular control; local overrides | Zone management overhead | Keep local-blocklist small; use automated feeds for volume; local list for exceptions only. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| False positive blocks legitimate domain | Service unavailable for internal clients | Support tickets; DNS block metric for specific domain | Add domain to a passlist zone with `CNAME rpz-passthru.` (special RPZ action to bypass other zones). |
| Feed update fails | Blocklist becomes stale | `dns_rpz_feed_last_updated` alert | Check feed URL accessibility; restore from last-good file; investigate upstream. |
| BIND RPZ zone syntax error | BIND fails to load the zone; falls back to pass-through | `named-checkzone` fails; BIND log shows parse error | Validate zone files with `named-checkzone rpz.local-blocklist local-blocklist.db` before deploying. |
| DNS-over-HTTPS bypasses RPZ | Malware resolves domains via DoH; RPZ doesn't intercept | No RPZ hit despite known malware | Block DoH by IP; use TLS inspection for DoH traffic; enforce DNS-over-TLS to internal resolver only. |
| RPZ rewrite breaks DNSSEC validation | Clients with DNSSEC validation reject sinkhole answers | DNSSEC validation failures in client logs | Use `break-dnssec yes` in named.conf to allow RPZ to override DNSSEC-validated responses. |
| High query volume floods RPZ logging | Log files fill disk; log pipeline lags | Disk usage alert; log pipeline latency | Sample RPZ hits at 10% for logging; always count all hits as metrics. |

## Related Articles

- [DNS Security: DNSSEC and CAA Records](/articles/network/dns-security-dnssec-caa/)
- [DNS Resolution Hardening](/articles/linux/dns-resolution-hardening/)
- [Detection Rules and Sigma Correlation](/articles/observability/detection-rules/)
- [Lateral Movement Detection](/articles/observability/lateral-movement-detection/)
- [BGP Security and RPKI](/articles/network/bgp-security-rpki/)
