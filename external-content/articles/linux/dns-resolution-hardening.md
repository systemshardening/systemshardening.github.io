---
title: "Hardening DNS Resolution on Linux: systemd-resolved, Unbound, and DNS-over-TLS"
description: "Most Linux hosts resolve DNS in plaintext over UDP port 53. On a stock Ubuntu 24.04 or RHEL 9 system:"
slug: "dns-resolution-hardening"
date: 2026-04-11
lastmod: 2026-04-11
category: "linux"
tags: ["dns", "systemd-resolved", "unbound", "dns-over-tls", "dnssec", "linux"]
personas: ["systems-engineer", "sre"]
article_number: 13
difficulty: "intermediate"
estimated_reading_time: 15
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
published: true
layout: article.njk
permalink: "/articles/linux/dns-resolution-hardening/index.html"
---

# Hardening DNS Resolution on Linux: [systemd](https://systemd.io)-resolved, [Unbound](https://nlnetlabs.nl/projects/unbound/about/), and DNS-over-TLS

## Problem

Most Linux hosts resolve DNS in plaintext over UDP port 53. On a stock Ubuntu 24.04 or RHEL 9 system:

- Every DNS query is visible to anyone on the network path between your host and the resolver. An attacker on the same network segment, a compromised router, or a malicious ISP can observe which domains your servers are querying, revealing your infrastructure dependencies, third-party integrations, and internal service names.
- DNS responses are unauthenticated. Without DNSSEC, an attacker can forge responses (DNS cache poisoning) to redirect your application to a malicious server. The application has no way to detect that the response was tampered with.
- Multicast DNS (mDNS) and Link-Local Multicast Name Resolution (LLMNR) are enabled by default on many distributions. These protocols broadcast queries on the local network, allowing any host on the segment to respond, and are a known lateral movement vector in enterprise networks.
- Fallback DNS servers are often configured to well-known public resolvers (8.8.8.8, 1.1.1.1) without encryption, creating a plaintext DNS leak even when the primary resolver uses encryption.

DNS is the first network operation for almost every connection your host makes. A compromised DNS response can redirect any outbound connection to an attacker-controlled server, bypassing TLS if the attacker also controls a valid certificate for the target domain (or if the application does not validate certificates properly).

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9.

## Threat Model

- **Adversary:** Network-adjacent attacker who can observe or modify traffic between the host and its DNS resolver (ARP spoofing, compromised switch, rogue DHCP), or a compromised upstream resolver.
- **Access level:** Network access on the same segment, or control of a network device between the host and the resolver.
- **Objective:** Reconnaissance (observe which domains the host queries to map infrastructure), redirection (poison DNS responses to redirect traffic to attacker-controlled servers), or denial of service (block or corrupt DNS responses to prevent the host from connecting to legitimate services).
- **Blast radius:** Every service on the host that depends on DNS resolution. A single poisoned DNS response can redirect database connections, API calls, package manager updates, and certificate validation checks.

## Configuration

### Hardening systemd-resolved

systemd-resolved is the default resolver on Ubuntu 24.04 and is available on all systemd-based distributions. It supports DNS-over-TLS, DNSSEC, and per-link DNS configuration.

```ini
# /etc/systemd/resolved.conf
[Resolve]
# Use DNS-over-TLS for all queries
# "yes" = strict mode (fails if TLS is not available)
# "opportunistic" = tries TLS, falls back to plaintext
DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net
DNSOverTLS=yes

# Enable DNSSEC validation
# "yes" = enforce validation (reject responses that fail DNSSEC)
# "allow-downgrade" = validate when possible, allow unsigned responses
DNSSEC=yes

# Clear fallback DNS to prevent plaintext DNS leak
# By default, systemd-resolved falls back to Google/Cloudflare in plaintext
FallbackDNS=

# Disable multicast DNS (mDNS) - used for .local discovery, not needed on servers
MulticastDNS=no

# Disable Link-Local Multicast Name Resolution
# LLMNR is a Windows protocol and a known lateral movement vector
LLMNR=no

# Cache size (number of entries)
CacheFromLocalhost=no
```

Apply the changes:

```bash
sudo systemctl restart systemd-resolved

# Verify DNS-over-TLS is active
resolvectl status
# Look for:
#   DNS over TLS: yes
#   DNSSEC: yes
#   Current DNS Server: 1.1.1.1#cloudflare-dns.com

# Test resolution
resolvectl query example.com
# Should show A/AAAA records with DNSSEC validation status
```

### Deploying Unbound as a Local Resolver

For hosts that need more control than systemd-resolved provides, Unbound is a validating, recursive, caching DNS resolver that supports DNS-over-TLS upstream and DNSSEC validation.

Install Unbound:

```bash
# Ubuntu/Debian
sudo apt install unbound dns-root-data

# RHEL/Rocky
sudo dnf install unbound
```

Configure Unbound:

```yaml
# /etc/unbound/unbound.conf
server:
    # Listen only on localhost
    interface: 127.0.0.1
    interface: ::1
    port: 53
    
    # Access control - only localhost
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    
    # DNSSEC validation
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    
    # Harden against known DNS attacks
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    harden-below-nxdomain: yes
    harden-large-queries: yes
    
    # Use 0x20 encoding for query name randomisation
    # This adds entropy to DNS queries to prevent cache poisoning
    use-caps-for-id: yes
    
    # Rate limiting to prevent abuse
    ratelimit: 1000
    ip-ratelimit: 1000
    
    # Privacy: minimise data sent to upstream
    qname-minimisation: yes
    
    # Performance
    num-threads: 2
    msg-cache-size: 64m
    rrset-cache-size: 128m
    cache-min-ttl: 60
    cache-max-ttl: 86400
    prefetch: yes
    
    # Disable unnecessary features
    do-not-query-localhost: yes
    
    # Logging (set verbosity to 0 in production, 1 for debugging)
    verbosity: 0
    log-queries: no
    log-replies: no
    log-servfail: yes

# DNS-over-TLS to upstream resolvers
forward-zone:
    name: "."
    forward-tls-upstream: yes
    # Cloudflare
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    # Quad9
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
```

Enable and start Unbound:

```bash
# Test configuration
sudo unbound-checkconf

# Enable and start
sudo systemctl enable unbound
sudo systemctl start unbound

# Point the system resolver to Unbound
# If using systemd-resolved, configure it to forward to Unbound:
# Or set /etc/resolv.conf directly:
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

### DNS-over-TLS Verification

Confirm that DNS queries are encrypted and no plaintext DNS is leaving the host:

```bash
# Test DNSSEC validation
dig @127.0.0.1 example.com +dnssec
# Look for the "ad" (authenticated data) flag in the response

# Test that DNS-over-TLS is working
# Capture traffic on port 53 (plaintext DNS) - should show nothing
sudo tcpdump -i any port 53 -c 10 &
dig @127.0.0.1 example.com
# Expected: no packets captured on port 53

# Capture traffic on port 853 (DNS-over-TLS) - should show encrypted traffic
sudo tcpdump -i any port 853 -c 10 &
dig @127.0.0.1 example.com
# Expected: TLS-encrypted packets to upstream resolvers

# Test DNSSEC failure (this domain has intentionally broken DNSSEC)
dig @127.0.0.1 dnssec-failed.org
# Expected: SERVFAIL (the resolver refuses to return unvalidated responses)
```

### DNS Leak Prevention

Ensure all DNS resolution goes through the hardened resolver, not through any alternative path:

```bash
# Block outbound plaintext DNS from all processes except the resolver
# Add to /etc/nftables.conf:
table inet dns_leak_prevention {
    chain output {
        type filter hook output priority 0; policy accept;
        
        # Allow the Unbound user to send DNS queries (port 853 for DoT)
        meta skuid "unbound" tcp dport 853 accept
        
        # Allow localhost DNS
        ip daddr 127.0.0.1 udp dport 53 accept
        ip daddr 127.0.0.1 tcp dport 53 accept
        
        # Block all other outbound DNS
        udp dport 53 drop
        tcp dport 53 drop
    }
}
```

```bash
sudo nft -f /etc/nftables.conf
```

### [CoreDNS](https://coredns.io) Hardening in [Kubernetes](https://kubernetes.io)

For Kubernetes clusters, CoreDNS handles pod DNS resolution. Harden it with rate limiting and query logging:

```yaml
# CoreDNS ConfigMap with hardening
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
        
        # Rate limiting per source IP
        ratelimit 100
        
        kubernetes cluster.local in-addr.arpa ip6.arpa {
            pods insecure
            fallthrough in-addr.arpa ip6.arpa
            ttl 30
        }
        
        # Forward external queries over TLS
        forward . tls://1.1.1.1 tls://9.9.9.9 {
            tls_servername cloudflare-dns.com
            health_check 5s
        }
        
        cache 30
        loop
        reload
        loadbalance
    }
```

Apply network policies to restrict access to CoreDNS pods:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: coredns-access
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      k8s-app: kube-dns
  policyTypes: ["Ingress"]
  ingress:
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
      from:
        - namespaceSelector: {}
```

## Expected Behaviour

After hardening DNS resolution:

- `resolvectl status` (systemd-resolved) or `unbound-control status` (Unbound) shows the resolver is active with DNS-over-TLS and DNSSEC enabled
- `dig example.com +dnssec` returns results with the `ad` (authenticated data) flag set
- `dig dnssec-failed.org` returns `SERVFAIL` (broken DNSSEC is rejected)
- `tcpdump -i any port 53` captures no plaintext DNS traffic leaving the host (only encrypted traffic on port 853)
- `resolvectl query` or `dig` resolve standard domains without errors
- mDNS and LLMNR are disabled: `resolvectl status` shows "MulticastDNS: no" and "LLMNR: no"
- DNS resolution latency for cache misses increases by 10-30ms (TLS handshake overhead)
- DNS resolution for cached queries is unchanged (sub-millisecond)

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| DNS-over-TLS (strict mode) | All DNS queries are encrypted | 10-30ms additional latency per cache miss. Total DNS failure if all DoT upstreams are unreachable. | Use at least two DoT upstream providers (Cloudflare + Quad9). Set reasonable cache TTLs to reduce upstream queries. |
| DNSSEC validation (strict) | Forged DNS responses are rejected | Some domains have broken DNSSEC configurations. Queries for those domains fail with SERVFAIL. | Monitor for DNSSEC-related SERVFAIL responses. Maintain a list of known broken domains. Consider "allow-downgrade" mode if strict mode causes too many failures. |
| Blocking plaintext DNS | Prevents DNS leaks from any process | Applications that hardcode DNS servers (some [Docker](https://www.docker.com) containers, VPN clients) will fail | Audit applications for hardcoded DNS. Update container configurations to use the host resolver. |
| Disabling mDNS/LLMNR | Eliminates local name resolution attack surface | Local service discovery (Avahi, printer discovery) stops working | Not relevant for production servers. Only affects desktop-like usage. |
| Local Unbound resolver | Full control over DNS resolution, local cache | Additional service to maintain. Unbound must be monitored and updated. | Run Unbound as a systemd service with auto-restart. Monitor with [Prometheus](https://prometheus.io) and the unbound_exporter. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| All DoT upstreams unreachable | All DNS resolution fails. Every service that needs to resolve a hostname breaks simultaneously. | `dig @127.0.0.1 example.com` returns SERVFAIL or times out. All HTTP requests fail with "Could not resolve host". | Add additional DoT upstreams from different providers. Temporarily switch to `DNSOverTLS=opportunistic` to allow plaintext fallback while debugging. Check if a firewall is blocking port 853 outbound. |
| DNSSEC validation fails for a legitimate domain | Queries for a specific domain return SERVFAIL while other domains resolve fine | `dig @127.0.0.1 broken-domain.com +dnssec +cd` succeeds (checking disabled), but without `+cd` it fails | The domain owner has a broken DNSSEC configuration. As a workaround, add a local override in Unbound: `domain-insecure: "broken-domain.com"`. Report the issue to the domain owner. |
| Unbound crashes or runs out of memory | DNS resolution stops. Services fail to connect. | `systemctl status unbound` shows the service as failed. Memory usage in monitoring spiked before the crash. | Restart Unbound: `systemctl restart unbound`. Reduce cache size if memory is the issue. Set `MemoryMax` in the systemd service to prevent Unbound from consuming all host memory. |
| DNS leak through application bypass | Application resolves DNS directly instead of through the local resolver | `tcpdump port 53` shows plaintext DNS from the host. nftables drop counter increments. | The nftables DNS leak prevention rules (from the Configuration section) block these queries. Identify the source process and configure it to use the system resolver. |
| Cache poisoning despite hardening | Application connects to wrong server. TLS certificate verification fails (if the attacker does not have a valid cert). | TLS errors in application logs. `dig +dnssec` shows the response lacks the `ad` flag. | This should not happen with DNSSEC and DoT enabled. If it does, check that DNSSEC validation is actually active. Verify the resolver is using DoT (check port 853 traffic). |

## When to Consider a Managed Alternative

**Transition point:** When you need high-availability DNS resolution across more than a handful of hosts, or when DNSSEC key rotation (needed roughly every 90 days for self-hosted authoritative zones) becomes an operational burden.

**What managed providers handle:**

[Cloudflare](https://www.cloudflare.com) provides free DNS resolution with DNSSEC validation, DNS-over-TLS, and DNS-over-HTTPS. Pointing your hosts at 1.1.1.1 with DoT enabled (as shown in this article) gives you encrypted, validated DNS without running your own resolver infrastructure. For authoritative DNS, Cloudflare handles DNSSEC key rotation automatically.

deSEC provides DNSSEC-by-default authoritative DNS hosting. Every zone is signed automatically with no configuration required.

[DNSimple](https://dnsimple.com) provides automated DNSSEC key management with rotation handled by the platform.

**What you still control:** The choice of upstream resolver, the configuration of DNS-over-TLS on each host, and the DNS leak prevention rules are your responsibility regardless of which upstream provider you use. A managed DNS provider encrypts and validates the upstream path; you still need to ensure that every process on your host actually uses that path.

**Automation path:** For self-managed infrastructure, deploy Unbound with the configuration from this article using your configuration management tool. Monitor DNS health with Prometheus using the `unbound_exporter` and alert when DNSSEC validation failures or upstream timeouts exceed your threshold.
