---
title: "Private Encrypted DNS Infrastructure with DoH and DoT"
description: "Deploy and harden internal DNS-over-HTTPS and DNS-over-TLS resolvers with Unbound or dnsdist to prevent DNS surveillance, hijacking, and NIDS bypass."
slug: encrypted-dns-infrastructure
date: 2026-05-01
lastmod: 2026-05-01
category: network
tags: ["dns", "doh", "dot", "dnscrypt", "unbound", "resolver", "privacy", "tls"]
personas: ["systems-engineer", "sre", "security-engineer"]
article_number: 321
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/network/encrypted-dns-infrastructure/index.html"
---

# Private Encrypted DNS Infrastructure with DoH and DoT

## Problem

Every hostname your servers, pods, and developer laptops resolve travels over UDP port 53 in plain text. A passive observer anywhere on the path — a cloud VPC tap, a datacenter span port, a rogue switch — captures a complete record of your internal service topology, third-party SaaS dependencies, and user browsing history without touching a single application packet. DNS is the most information-dense plaintext protocol on the average enterprise network, and it is almost universally left unencrypted.

The exposure goes beyond passive surveillance. In environments where clients trust DHCP for resolver configuration — coffee shop Wi-Fi, hotel networks, and surprisingly many cloud VPC setups — an attacker who controls DHCP can redirect UDP/53 queries to a rogue resolver. That resolver can return arbitrary A records for any domain, including your internal services, enabling credential phishing, session hijacking, and SSRF pivot chains. ARP spoofing on a shared subnet achieves the same result without touching DHCP at all.

The instinctive fix is to point all clients at a public DoH provider such as Cloudflare 1.1.1.1 or Google 8.8.8.8. This closes the plaintext leak but introduces three new problems. First, your internal FQDNs — `db-primary.prod.internal`, `vault.corp.example.com` — are now resolved by a third-party service that logs every query associated with your IP space. Second, public resolvers have no knowledge of your RPZ threat-intelligence feeds or split-horizon zones, so malware on any endpoint can bypass your internal DNS blocklists simply by hardcoding `8.8.8.8:443` in a DoH client. Third, your NIDS and DLP tooling that monitors DNS traffic for exfiltration patterns stops receiving plaintext queries entirely, leaving a large detection blind spot rather than closing one.

Split-horizon DNS breaks silently when clients use external resolvers. An internal record for `api.corp.example.com` that resolves to `10.0.1.50` on your internal resolver will resolve to a public IP or NXDOMAIN on Cloudflare, causing intermittent failures that are difficult to diagnose and often blamed on the application rather than resolver misconfiguration.

CISA's 2023 guidance on encrypted DNS (AA23-270A) specifically warns against wholesale adoption of public DoH without organizational controls. The recommended posture is to deploy internal DoH and DoT resolvers that encrypt transit between client and resolver while keeping query visibility, RPZ policy enforcement, and split-horizon logic within your own infrastructure.

DoH and DoT do not eliminate all DNS-layer attack surface. DNS rebinding attacks — where a malicious page causes a browser to resolve an attacker-controlled domain to a private IP range — are not prevented by transport encryption. Rebinding defenses require the resolver to actively refuse answers that map public FQDNs to RFC 1918 addresses, which Unbound implements via the `private-address` and `private-domain` configuration directives. This article covers that configuration alongside transport encryption.

**Target systems:** Unbound 1.19+, dnsdist 1.9+, Ubuntu 22.04/24.04, Kubernetes CoreDNS 1.11+.

---

## Threat Model

1. **Passive on-path observer in datacenter or cloud.** A logging tap on a shared transit VLAN, a cloud VPC flow mirror, or a compromised network device captures UDP/53 traffic. The observer reconstructs your full internal FQDN namespace, maps service-to-service dependencies, and identifies third-party relationships (auth providers, payment gateways, telemetry endpoints) without triggering any application-layer alert. Blast radius: complete DNS surveillance with no detectable footprint.

2. **ARP/BGP hijacker redirecting UDP/53 to a rogue resolver.** An attacker on the same L2 segment uses ARP poisoning to intercept UDP/53 traffic from clients configured to use a legitimate internal resolver IP. The rogue resolver returns crafted A records for internal domains, redirecting authentication flows to attacker-controlled infrastructure. In BGP environments, more-specific prefix injection achieves the same result at scale across routing domains. Blast radius: credential harvest for any service whose clients trust DNS-returned IPs without certificate validation.

3. **Insider or malware using public DoH to bypass RPZ blocklists.** A compromised endpoint or a malicious insider configures an application or OS resolver to query `1.1.1.1:443` over HTTPS, bypassing the internal resolver entirely. Because public DoH traffic looks identical to HTTPS to port-based filtering, it passes through most firewalls undetected. C2 domains blocked by RPZ on the internal resolver are now resolvable. Exfiltration via DNS tunnelling over public DoH becomes feasible. Blast radius: complete RPZ policy bypass, loss of DNS-based threat detection coverage.

4. **DNS amplification attacker targeting an open resolver.** An internal resolver that accepts queries from any source IP (a common misconfiguration when internal resolvers are also reachable from DMZ or partner networks) can be used as a reflection amplifier. DNS ANY queries produce responses five to fifty times larger than the request, making even a modest resolver a useful amplifier in a volumetric DDoS. Blast radius: bandwidth exhaustion on the resolver's uplink, potential involvement of your IP space in attacks on third parties.

Deploying authenticated encrypted DNS with strict ACLs shrinks all four blast radii simultaneously: on-path observers see TLS handshakes and ciphertext, rogue resolvers cannot intercept authenticated TLS sessions, clients that cannot reach the internal DoT/DoH endpoint get no resolution at all (forcing attention to the misconfiguration), and ACL-restricted resolvers reject amplification queries before response generation.

---

## Configuration / Implementation

### Unbound as DoT and DoH Resolver

Install Unbound on a dedicated resolver node. On Ubuntu 22.04/24.04:

```bash
apt-get install -y unbound
systemctl stop systemd-resolved
systemctl disable systemd-resolved
rm -f /etc/resolv.conf
echo "nameserver 127.0.0.1" > /etc/resolv.conf
```

The core `/etc/unbound/unbound.conf` configuration below enables DoT on port 853, DoH on port 443, enforces DNSSEC validation, blocks DNS rebinding, and restricts access to internal CIDR ranges:

```conf
server:
    # Logging
    verbosity: 1
    log-queries: no          # enable temporarily for debugging only
    log-replies: no

    # Network interfaces
    interface: 0.0.0.0@53    # keep for local-only use; block externally via firewall
    interface: 0.0.0.0@853   # DNS-over-TLS
    interface: 0.0.0.0@443   # DNS-over-HTTPS (via http block below)

    # TLS credentials (replace with your cert paths)
    tls-service-key: /etc/unbound/tls/resolver.key
    tls-service-pem: /etc/unbound/tls/resolver.crt
    tls-port: 853

    # Access control — allow only internal ranges
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: 0.0.0.0/0 refuse

    # DNSSEC
    auto-trust-anchor-file: /var/lib/unbound/root.key

    # DNS rebinding protection
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10

    # Cache and performance
    cache-max-ttl: 86400
    cache-min-ttl: 60
    num-threads: 4
    msg-cache-slabs: 8
    rrset-cache-slabs: 8
    infra-cache-slabs: 8
    key-cache-slabs: 8
    rrset-cache-size: 256m
    msg-cache-size: 128m

    # Hardening
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    use-caps-for-id: yes
    qname-minimisation: yes
    aggressive-nsec: yes
    deny-any: yes              # no ANY queries (amplification mitigation)

# DNS-over-HTTPS
http:
    endpoint: "/dns-query"
    port: 443

# Forward to upstream over DoT (choose a trustworthy upstream or recurse directly)
# To recurse directly, remove or comment out this block.
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net

# Local data for split-horizon (example)
# local-zone: "corp.example.com" transparent
# local-data: "api.corp.example.com. 60 IN A 10.0.1.50"
```

After writing the config, validate and reload:

```bash
unbound-checkconf /etc/unbound/unbound.conf
systemctl restart unbound
# Verify DoT
kdig -d @127.0.0.1 +tls-ca example.com A
# Verify DoH
curl -sS "https://resolver.corp.example.com/dns-query?dns=$(echo -n 'example.com' | base64)" -H 'Content-Type: application/dns-message'
```

### TLS Certificate Management

Unbound requires a TLS certificate for the resolver's FQDN (e.g., `resolver.corp.example.com`). Use Let's Encrypt via certbot for internet-reachable resolvers, or cert-manager for Kubernetes-issued internal PKI.

**Let's Encrypt with certbot (standalone, DNS challenge):**

```bash
apt-get install -y certbot

# DNS-01 challenge avoids exposing port 80; use your DNS provider plugin.
# Example with Route 53:
apt-get install -y python3-certbot-dns-route53
certbot certonly \
  --dns-route53 \
  --dns-route53-propagation-seconds 30 \
  -d resolver.corp.example.com \
  --email security@corp.example.com \
  --agree-tos \
  --non-interactive

# Link certs into Unbound's config directory
ln -sf /etc/letsencrypt/live/resolver.corp.example.com/privkey.pem \
    /etc/unbound/tls/resolver.key
ln -sf /etc/letsencrypt/live/resolver.corp.example.com/fullchain.pem \
    /etc/unbound/tls/resolver.crt
chown -R unbound:unbound /etc/unbound/tls
chmod 640 /etc/unbound/tls/resolver.key
```

Add a certbot renewal deploy hook so Unbound reloads after each renewal:

```bash
cat > /etc/letsencrypt/renewal-hooks/deploy/unbound-reload.sh << 'EOF'
#!/bin/bash
systemctl reload unbound || true
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/unbound-reload.sh
```

For internal PKI with cert-manager in Kubernetes, annotate the Unbound Deployment to mount a `Certificate` resource volume and configure a `postStart` lifecycle hook to reload Unbound on cert rotation.

### dnsdist as a DoH Frontend

For high-throughput environments (>50,000 queries/second), Unbound's built-in DoH is sufficient for most workloads, but dnsdist provides more flexibility: per-client rate limiting, advanced ACL logic, and a Lua scripting API. dnsdist acts as a DoH terminator and proxies queries back to Unbound on DoT port 853.

Install on a separate frontend node or co-locate on the same host:

```bash
apt-get install -y dnsdist
```

`/etc/dnsdist/dnsdist.conf`:

```lua
-- Listen for DoH
addDOHLocal("0.0.0.0:443", "/etc/dnsdist/tls/server.crt",
            "/etc/dnsdist/tls/server.key",
            "/dns-query",
            { reusePort=true, sendCacheControlHeaders=true })

-- Listen for DoT
addTLSLocal("0.0.0.0:853", "/etc/dnsdist/tls/server.crt",
            "/etc/dnsdist/tls/server.key",
            { reusePort=true })

-- Plain DNS for clients that can't do encrypted (restrict at firewall)
addLocal("0.0.0.0:53", { reusePort=true })

-- Backend: Unbound on DoT
newServer({
    address="127.0.0.1:853",
    tls="openssl",
    subjectName="resolver.corp.example.com",
    validateCertificates=true,
    caStore="/etc/ssl/certs/ca-certificates.crt",
    healthCheckMode="active",
    checkInterval=5,
    maxCheckFailures=3,
    name="unbound-dot"
})

-- ACL: allow only internal ranges
setACL({"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"})

-- Rate limiting per client IP
addAction(MaxQPSIPRule(200), DelayAction(100))
addAction(MaxQPSIPRule(500), DropAction())
```

Start and verify:

```bash
systemctl enable --now dnsdist
# Check backend health
dnsdist -e "showServers()"
```

### Blocking Plain UDP/53 from Clients

Force all internal clients to use encrypted DNS by dropping outbound UDP/53 at the firewall. With nftables (preferred on Ubuntu 22.04+):

```bash
# /etc/nftables.conf additions — run on the gateway/firewall node
nft add table inet dns_enforcement
nft add chain inet dns_enforcement forward '{ type filter hook forward priority 0; policy accept; }'

# Drop UDP/53 to any destination except the internal resolver
nft add rule inet dns_enforcement forward \
    ip protocol udp udp dport 53 \
    ip daddr != { 10.0.1.100, 10.0.1.101 } \
    drop

# Drop TCP/53 to any destination except the internal resolver
nft add rule inet dns_enforcement forward \
    ip protocol tcp tcp dport 53 \
    ip daddr != { 10.0.1.100, 10.0.1.101 } \
    drop

# Redirect any UDP/53 aimed at external IPs back to internal resolver (optional catch-all)
nft add rule inet dns_enforcement forward \
    ip protocol udp udp dport 53 \
    ip daddr != { 10.0.1.100, 10.0.1.101 } \
    dnat to 10.0.1.100

nft -f /etc/nftables.conf
```

Also block outbound DoH to public resolvers by domain via your forward proxy, or by blocking `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `208.67.222.222` on TCP/443 at the perimeter. Document the policy clearly so developers understand why hardcoded resolver IPs are disallowed.

### CoreDNS in Kubernetes with DoT Upstream

Replace the default CoreDNS ConfigMap upstream with your internal DoT resolver:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health {
            lameduck 5s
        }
        ready
        kubernetes cluster.local in-addr.arpa ip6.arpa {
            pods insecure
            fallthrough in-addr.arpa ip6.arpa
            ttl 30
        }
        forward . tls://10.0.1.100 tls://10.0.1.101 {
            tls_servername resolver.corp.example.com
            health_check 5s
            max_fails 3
        }
        cache 30
        loop
        reload
        loadbalance
    }
```

Apply and verify CoreDNS is using DoT:

```bash
kubectl apply -f coredns-configmap.yaml
kubectl rollout restart deployment/coredns -n kube-system
# Trace a query from a pod
kubectl run -it --rm dns-test --image=busybox --restart=Never -- nslookup kubernetes.default
```

Verify on the Unbound side that queries arriving from CoreDNS pods appear with TLS in query logs (enable `log-queries: yes` temporarily):

```bash
journalctl -u unbound -f | grep "10.96."   # CoreDNS service CIDR
```

### Client Enforcement with systemd-resolved

On Ubuntu hosts that should use DoT:

```ini
# /etc/systemd/resolved.conf
[Resolve]
DNS=10.0.1.100#resolver.corp.example.com 10.0.1.101#resolver.corp.example.com
FallbackDNS=
DNSOverTLS=yes
DNSSEC=yes
DNSStubListener=yes
```

```bash
systemctl restart systemd-resolved
resolvectl status
# Confirm DoT is active
resolvectl query example.com
```

Set `DNSOverTLS=opportunistic` during initial rollout to avoid breaking resolution when the resolver is unreachable; switch to `yes` (strict) once resolver HA is confirmed.

### RPZ Integration

Add threat-intelligence RPZ feeds to Unbound to block C2 and malware domains. Unbound 1.19+ includes native RPZ support:

```conf
# Add to /etc/unbound/unbound.conf
rpz:
    name: "threat-intel-rpz"
    zonefile: /var/lib/unbound/rpz/threat-intel.zone
    rpz-log: yes
    rpz-log-name: "threat-intel"
    # If using an AXFR feed:
    # primary: 192.0.2.10
    # allow-notify: 192.0.2.10
```

Sync a commercial or open-source feed via a cron job:

```bash
#!/bin/bash
# /usr/local/bin/update-rpz-feed.sh
set -euo pipefail
FEED_URL="https://rpz-feed.corp.example.com/threat-intel.zone"
DEST="/var/lib/unbound/rpz/threat-intel.zone"
TMP="$(mktemp)"

curl -fsSL --max-time 30 "$FEED_URL" -o "$TMP"
# Basic sanity check
grep -q "\$ORIGIN" "$TMP" || { echo "Feed invalid"; rm "$TMP"; exit 1; }
mv "$TMP" "$DEST"
chown unbound:unbound "$DEST"
systemctl reload unbound
```

```bash
chmod +x /usr/local/bin/update-rpz-feed.sh
echo "*/30 * * * * root /usr/local/bin/update-rpz-feed.sh >> /var/log/rpz-update.log 2>&1" \
    > /etc/cron.d/rpz-feed-update
```

---

## Expected Behaviour

After deployment, the following observable changes confirm the system is working correctly:

| Signal | Before | After |
|--------|--------|-------|
| Wireshark capture on UDP/53 from a client | All hostnames visible in plaintext query and response packets | No UDP/53 traffic from clients; only TLS handshakes on TCP/853 or TCP/443 |
| Wireshark on TCP/853 | No traffic | TLS application data; hostnames not recoverable without key material |
| RPZ block test: query a known-bad domain from endpoint | NXDOMAIN or real IP returned depending on upstream | NXDOMAIN returned by internal resolver; RPZ log entry written |
| Attempt to query 8.8.8.8:53 directly | Succeeds, bypassing all internal policy | Connection dropped by nftables; client receives no response |
| Attempt to query 1.1.1.1:443 (public DoH) | Succeeds (HTTPS to port 443 allowed) | Blocked at perimeter by IP-based firewall rule or forward proxy deny list |
| NIDS DNS inspection (Suricata/Zeek on internal segment) | Full hostname visibility for all UDP/53 queries | DoH/DoT traffic on internal segment is encrypted; NIDS must use resolver tap or DNS logging |
| CoreDNS upstream query from pod | Plaintext UDP/53 to kube-dns VIP | TLS-wrapped TCP/853 to internal Unbound, confirmed by Unbound query log |
| resolvectl status on Ubuntu host | `DNSOverTLS: no` | `DNSOverTLS: yes`, current DNS server shows `#resolver.corp.example.com` |
| DNS rebinding probe: resolve public name to 10.x.x.x | Resolution succeeds; browser can reach internal service | Unbound refuses answer; SERVFAIL returned due to `private-address` check |

---

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| DoH vs DoT detectability | DoH blends with HTTPS traffic; harder to block rogue DoH clients | Port 853 (DoT) is easily detectable and blockable; DoH on 443 cannot be blocked by port alone | Use DNS-layer inspection or forward proxy with SNI filtering to detect and block public DoH endpoints |
| TLS handshake overhead | Authenticated, encrypted queries prevent MITM and surveillance | Each new connection adds 1–3 ms TLS overhead; mitigated by TCP keep-alive and session resumption | Enable TLS 1.3 session tickets in Unbound; tune `num-queries-per-thread` and connection pools in dnsdist |
| Single-resolver SPOF | Simplified deployment on a single host | Resolver failure causes complete DNS outage for all clients | Deploy two resolver nodes behind a VIP (keepalived/ECMP); configure `FallbackDNS` in systemd-resolved |
| NIDS DNS blind spot | Transit encryption prevents passive eavesdropping | NIDS/DLP tooling that inspects UDP/53 loses visibility | Collect DNS logs from Unbound (`log-queries: yes`) and forward to SIEM; deploy response logging via dnstap |
| Debugging difficulty | Encrypted DNS reduces attacker ability to map your environment | Engineers can no longer tcpdump port 53 to diagnose issues | Use `kdig +tls`, `q` CLI, or `dnsdist -e "topQueries()"` for encrypted queries; enable query logging on resolver during incidents |
| Public DoH blocking completeness | Blocking 8.8.8.8:443 stops naive bypass attempts | DoH over CDN endpoints (Cloudflare proxied) shares IPs with legitimate HTTPS traffic | Combine IP blocking with forward proxy SNI inspection for `cloudflare-dns.com`, `dns.google`, `dns.quad9.net` |

---

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| TLS certificate expiry on resolver | All DoT/DoH clients receive TLS handshake failure; DNS resolution stops entirely for strict-mode clients; opportunistic-mode clients may fall back to unencrypted | Certificate expiry alert from monitoring (check cert expiry on port 853 with `openssl s_client`); sudden spike in DNS errors across all hosts | Renew certificate immediately (`certbot renew --force-renewal`); reload Unbound; verify renewal hook is configured and tested monthly |
| Unbound OOM on large RPZ zone | Unbound process killed by OOM killer; DNS resolution stops; systemd restarts Unbound with RPZ zone removed | `dmesg \| grep oom` shows Unbound killed; `/var/log/syslog` shows repeated Unbound restarts | Increase `rrset-cache-size` and `msg-cache-size`; reduce RPZ zone size by pruning stale entries; add swap or increase RAM; use AXFR streaming instead of full zone load |
| CoreDNS DoT upstream timeout | Pod DNS queries time out; Kubernetes service discovery fails; applications log connection errors | CoreDNS error log: `plugin/forward: no healthy upstream`; `kubectl logs -n kube-system coredns-*` shows health check failures | Verify Unbound is reachable from CoreDNS pod CIDR; check TLS cert validity; temporarily revert CoreDNS ConfigMap to UDP/53 upstream while investigating |
| RPZ feed unavailable or corrupt | If feed sync fails silently, stale RPZ blocks remain active (false positives) or if Unbound restarts with missing zone, RPZ policy is absent (false negatives) | RPZ sync cron job exit code monitoring; absence of RPZ log entries for domains that should be blocked | Configure cron job to alert on failure; validate zone file before replacing; keep a known-good backup zone; set Unbound `rpz-action-override` to `passthru` as a safe default if zone is absent |
| Client fallback to cleartext after resolver outage | Clients with `DNSOverTLS=opportunistic` silently revert to UDP/53; traffic bypasses all encryption and RPZ policy | Monitoring: check for UDP/53 traffic on network tap; `resolvectl status` on hosts shows `DNSOverTLS: no` | Set `DNSOverTLS=yes` (strict) after confirming resolver HA; maintain secondary resolver to prevent outage-driven fallback; alert on any UDP/53 traffic to non-resolver IPs |
| dnsdist backend health check failure | dnsdist marks Unbound backend as down; all DoH/DoT queries return SERVFAIL | dnsdist console: `showServers()` shows `DOWN`; query error rate spike in metrics | Restart Unbound; verify DoT port 853 is listening (`ss -tlnp \| grep 853`); check TLS cert; increase `checkInterval` if flapping due to brief Unbound reloads during cert rotation |

---

## Related Articles

- [DNS Security with DNSSEC and CAA Records](/articles/network/dns-security-dnssec-caa/)
- [DNS RPZ for Threat Intelligence](/articles/network/dns-rpz-threat-intelligence/)
- [DNS Resolution Hardening on Linux](/articles/linux/dns-resolution-hardening/)
- [Network Flow Analysis and Observability](/articles/observability/network-flow-analysis/)
- [Zero Trust Networking Principles](/articles/cross-cutting/zero-trust-networking/)
