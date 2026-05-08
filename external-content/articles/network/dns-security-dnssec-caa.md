---
title: "DNS Security for Production Infrastructure: DNSSEC, CAA Records, and Internal Resolution"
description: "DNS is the most critical single point of failure in any infrastructure, and the least hardened layer for most teams."
slug: "dns-security-dnssec-caa"
date: 2026-03-02
lastmod: 2026-03-02
category: "network"
tags: ["dns", "dnssec", "caa", "unbound", "coredns", "dns-over-tls"]
personas: ["systems-engineer", "sre"]
article_number: 41
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "dns"
  - name: "DNSimple"
    id: 77
    category: "dns"
  - name: "deSEC"
    id: 0
    category: "dns"
premium_pack: "dns-hardening-configs"
published: true
layout: article.njk
permalink: "/articles/network/dns-security-dnssec-caa/index.html"
---

# DNS Security for Production Infrastructure: DNSSEC, CAA Records, and Internal Resolution

## Problem

DNS is the most critical single point of failure in any infrastructure, and the least hardened layer for most teams. Every service depends on DNS resolution. A DNS compromise is silent and total, traffic redirects to attacker-controlled infrastructure with no firewall, WAF, or TLS configuration providing protection, because the client believes it is connecting to the correct destination.

The specific gaps in most production DNS setups:

- **No DNSSEC.** DNS responses are unsigned. Any attacker who can intercept or poison DNS traffic can forge responses, redirecting your users or services to arbitrary IP addresses. This is not theoretical, BGP hijacking combined with DNS poisoning is a documented attack pattern used against cryptocurrency exchanges and financial institutions.
- **No CAA records.** Without Certificate Authority Authorization records, any CA in the world can issue a valid TLS certificate for your domain. An attacker who compromises or social-engineers a CA can obtain a legitimate certificate for your domain and use it for man-in-the-middle attacks that pass TLS validation.
- **Plaintext internal resolution.** Hosts resolve DNS over plaintext UDP. An attacker on the network can observe every domain your hosts query (leaking your internal service topology, vendor relationships, and activity patterns) and poison responses.
- **Default [CoreDNS](https://coredns.io) in [Kubernetes](https://kubernetes.io).** CoreDNS runs with default configuration, no query logging for security analysis, no rate limiting to prevent DNS amplification from compromised pods, and no network policy restricting which pods can access DNS.

**Target systems:** Any Linux host or Kubernetes cluster. Specific configurations for [Unbound](https://nlnetlabs.nl/projects/unbound/about/) (host-level resolver), CoreDNS (Kubernetes), and integration with managed DNS providers.

## Threat Model

- **Adversary:** Network-adjacent attacker (DNS cache poisoning), compromised registrar account (domain hijacking), rogue or compromised Certificate Authority (unauthorized certificate issuance), or compromised pod in Kubernetes (DNS-based reconnaissance or data exfiltration via DNS tunnelling).
- **Access level:** Network access for poisoning (same subnet or upstream path). Credential access for registrar compromise. No access needed for CA abuse without CAA records.
- **Objective:** Redirect traffic to attacker-controlled infrastructure (phishing, credential theft), issue fraudulent TLS certificates (man-in-the-middle), exfiltrate data through DNS queries (DNS tunnelling), or map internal infrastructure through DNS enumeration.
- **Blast radius:** Total. A DNS compromise affects every service on the domain. Combined with a fraudulent certificate, the attacker has a valid TLS-encrypted impersonation of your infrastructure that passes all client-side validation.

## Configuration

### DNSSEC: Signing Your Zone

DNSSEC adds cryptographic signatures to DNS responses, allowing resolvers to verify that the response came from the authoritative server and was not modified in transit.

**If you use a managed DNS provider** (recommended for most teams), DNSSEC is typically a single toggle:

```bash
# Verify DNSSEC is active for your domain
dig +dnssec example.com A

# Look for the 'ad' (authenticated data) flag in the response:
# ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
#                    ^^
# 'ad' means the resolver validated the DNSSEC signatures.

# If 'ad' is missing, DNSSEC is not configured or not validating.
```

```bash
# Use delv for detailed DNSSEC validation:
delv @1.1.1.1 example.com A

# Expected output for a properly signed zone:
# ; fully validated
# example.com.    300    IN    A    93.184.216.34
# example.com.    300    IN    RRSIG    A 13 2 300 ...

# If validation fails:
# ;; resolution failed: SERVFAIL
# This means the DNSSEC chain is broken.
```

**DNSSEC at the registrar level:**

After enabling DNSSEC at your DNS provider, you must add the DS (Delegation Signer) record at your registrar. The DS record links your zone's signing key to the parent zone (e.g., `.com`), completing the chain of trust.

```
# Example DS record (your DNS provider will give you these values):
example.com.  IN  DS  12345 13 2 AABBCCDD...

# Fields: key-tag, algorithm, digest-type, digest
# Algorithm 13 = ECDSA P-256 (recommended)
# Digest type 2 = SHA-256 (recommended)
```

**Monitoring DNSSEC health:**

```bash
# Check signature expiry (RRSIG records have expiry timestamps)
dig +dnssec +short example.com RRSIG | awk '{print $5}'
# Output: 20260501120000 (format: YYYYMMDDHHmmss)
# Signatures must be refreshed before expiry.
# Managed DNS providers handle this automatically.

# Monitor with Prometheus blackbox exporter:
# Add a DNS probe that checks for the 'ad' flag.
# Alert if the flag disappears (DNSSEC broken).
```

### CAA Records: Restricting Certificate Issuance

CAA (Certificate Authority Authorization) records specify which Certificate Authorities are permitted to issue certificates for your domain. Without CAA records, any of the ~150 publicly trusted CAs can issue a certificate.

```bash
# Add CAA records to your DNS zone.
# These restrict certificate issuance to Let's Encrypt only.

# Allow Let's Encrypt to issue standard certificates:
example.com.  IN  CAA  0 issue "letsencrypt.org"

# Allow Let's Encrypt to issue wildcard certificates:
example.com.  IN  CAA  0 issuewild "letsencrypt.org"

# Send violation reports to your security team:
example.com.  IN  CAA  0 iodef "mailto:security@example.com"
```

**Multiple CAs:** If you use more than one CA (e.g., Let's Encrypt for automation and ZeroSSL as a backup):

```bash
example.com.  IN  CAA  0 issue "letsencrypt.org"
example.com.  IN  CAA  0 issue "sectigo.com"
example.com.  IN  CAA  0 issuewild "letsencrypt.org"
example.com.  IN  CAA  0 iodef "mailto:security@example.com"
```

**Verify CAA records:**

```bash
dig CAA example.com

# Expected output:
# example.com.    300    IN    CAA    0 issue "letsencrypt.org"
# example.com.    300    IN    CAA    0 issuewild "letsencrypt.org"
# example.com.    300    IN    CAA    0 iodef "mailto:security@example.com"
```

**Common mistake:** Forgetting `issuewild`. If you only set `issue` records, any CA can still issue wildcard certificates. Always set both `issue` and `issuewild`.

### Certificate Transparency Monitoring

CAA records prevent issuance, but you should also monitor for certificates that are issued, detecting any that should not exist:

```bash
# Monitor Certificate Transparency logs for your domain.
# crt.sh provides a free web interface and API:
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  python3 -c "import sys,json; [print(c['common_name'], c['issuer_name'], c['not_before']) for c in json.load(sys.stdin)]"

# For automated monitoring, use a CT log monitor:
# - certspotter (free for 1 domain): https://sslmate.com/certspotter/
# - Prometheus ct_exporter for metric-based alerting
```

### Internal DNS Resolver Hardening with Unbound

For Linux hosts that need a local caching resolver with DNSSEC validation and DNS-over-TLS to upstream, Unbound is the recommended choice.

Install and configure:

```bash
# Install Unbound
# Debian/Ubuntu:
sudo apt install unbound

# RHEL/Rocky:
sudo dnf install unbound
```

Create `/etc/unbound/unbound.conf.d/hardening.conf`:

```yaml
# /etc/unbound/unbound.conf.d/hardening.conf
# Hardened Unbound configuration for local caching resolver
# with DNSSEC validation and DNS-over-TLS upstream.

server:
    # Listen on localhost only. This is a local resolver, not authoritative.
    interface: 127.0.0.1
    interface: ::1
    port: 53

    # Access control: only localhost can query.
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
    harden-below-nxdomain: yes
    harden-referral-path: yes

    # Hide identity and version
    hide-identity: yes
    hide-version: yes

    # Rate limiting to prevent abuse
    ratelimit: 1000

    # Logging for security analysis
    verbosity: 1
    log-queries: yes
    log-replies: yes
    log-tag-queryreply: yes
    logfile: /var/log/unbound/unbound.log

    # Disable unnecessary protocols
    do-not-query-localhost: yes

    # Prefetch popular domains before TTL expires
    prefetch: yes
    prefetch-key: yes

    # Use DNS-over-TLS for upstream queries
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

forward-zone:
    name: "."
    # Cloudflare DNS over TLS
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    # Quad9 DNS over TLS (malware blocking)
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
    forward-tls-upstream: yes
```

```bash
# Enable and start Unbound
sudo systemctl enable --now unbound

# Configure the system to use Unbound as its resolver
# On systemd-resolved systems:
sudo systemctl disable --now systemd-resolved
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

# Verify DNS-over-TLS is working (no plaintext DNS should leave the host)
# On another terminal, capture DNS traffic:
sudo tcpdump -i eth0 port 53 -c 5
# Expected: no packets captured (all DNS goes over TLS on port 853)

sudo tcpdump -i eth0 port 853 -c 5
# Expected: TLS-encrypted packets to 1.1.1.1 and 9.9.9.9

# Verify DNSSEC validation
dig @127.0.0.1 +dnssec example.com
# Look for 'ad' flag in response
```

### Kubernetes CoreDNS Hardening

CoreDNS in Kubernetes runs with minimal security configuration by default. Harden it with query logging, rate limiting, and network policy.

**CoreDNS ConfigMap with security additions:**

```bash
kubectl edit configmap coredns -n kube-system
```

```
# Add logging and rate limiting to the Corefile:
.:53 {
    errors
    health {
        lameduck 5s
    }
    ready

    # Query logging for security analysis.
    # Log all queries with client IP, query name, and response code.
    log . {
        class denial error
    }

    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }

    prometheus :9153

    forward . /etc/resolv.conf {
        max_concurrent 1000
    }

    cache 30

    loop
    reload
    loadbalance
}
```

**Network policy for CoreDNS:**

```yaml
# coredns-network-policy.yaml
# Restrict which pods can access CoreDNS.
# By default, all pods can query DNS. This policy restricts to
# pods in namespaces with the label 'dns-access: allowed'.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: coredns-allow
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      k8s-app: kube-dns
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              dns-access: "allowed"
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

```bash
# Label namespaces that should have DNS access:
kubectl label namespace default dns-access=allowed
kubectl label namespace production dns-access=allowed
kubectl label namespace kube-system dns-access=allowed

# Apply the network policy:
kubectl apply -f coredns-network-policy.yaml
```

**Warning:** Restricting DNS access can break pods in unlabelled namespaces. Apply the namespace labels before the network policy, and test in a non-production cluster first.

### DNS Monitoring and Anomaly Detection

```yaml
# Prometheus blackbox exporter DNS probe configuration.
# Add to blackbox-exporter ConfigMap:
modules:
  dns_external:
    prober: dns
    timeout: 5s
    dns:
      query_name: "example.com"
      query_type: "A"
      valid_rcodes:
        - NOERROR
      validate_answer_rrs:
        fail_if_not_matches_regexp:
          - ".*93\\.184\\.216\\.34.*"  # Expected IP address
      validate_additional_rrs:
        fail_if_not_matches_regexp:
          - ".*"
  dns_dnssec:
    prober: dns
    timeout: 5s
    dns:
      query_name: "example.com"
      query_type: "A"
      valid_rcodes:
        - NOERROR
      # Check that the AD (authenticated data) flag is set
      validate_authority_rrs:
        fail_if_not_matches_regexp:
          - ".*"
```

```yaml
# Prometheus alert rules for DNS security
groups:
  - name: dns-security
    rules:
      - alert: DNSSECValidationFailed
        expr: probe_dns_lookup_time_seconds{module="dns_dnssec"} == 0 and probe_success{module="dns_dnssec"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "DNSSEC validation failed for {{ $labels.instance }}"
          runbook: "Check DNSSEC DS record at registrar. Verify signing key has not expired."

      - alert: DNSResolutionChanged
        expr: changes(probe_dns_answer_rrs{module="dns_external"}[1h]) > 0
        labels:
          severity: warning
        annotations:
          summary: "DNS resolution for {{ $labels.instance }} has changed"
          runbook: "Verify the change is expected. Check for DNS hijacking."
```

## Expected Behaviour

After applying all DNS hardening:

- `dig +dnssec example.com` returns responses with the `ad` (authenticated data) flag
- `dig CAA example.com` returns your configured CAA records
- Attempting to issue a certificate from a non-allowlisted CA fails with a CAA denial
- `tcpdump port 53` on a hardened host shows no plaintext DNS traffic (all queries go over TLS on port 853)
- CoreDNS query logs capture client IP and query details for security analysis
- Certificate Transparency monitoring alerts within 1 hour of any new certificate issuance for your domain
- Prometheus DNS probes verify resolution returns expected IPs and DNSSEC validates

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| DNSSEC | 1-5ms added latency for first resolution (cached after) | DNSSEC misconfiguration causes total DNS failure for the zone. SERVFAIL for all queries | Monitor DNSSEC health. Use a managed DNS provider that handles signing and key rotation automatically. |
| CAA records | None | Forgetting to add a new CA before switching certificate providers causes issuance failure ([cert-manager](https://cert-manager.io) fails to renew) | Add the new CA to CAA records before migrating. Include in certificate provider change checklist. |
| DNS-over-TLS (Unbound) | 10-30ms added latency for cache misses | Dependency on upstream DoT provider availability. If both Cloudflare and Quad9 DoT are unreachable, all DNS fails. | Configure multiple upstream providers. Consider adding a non-DoT fallback for availability (trades privacy for availability during upstream outage). |
| CoreDNS query logging | Disk I/O for high-volume clusters (>100K queries/day) | Log volume can fill node storage on busy clusters | Log only errors and denials (`class denial error`). Ship to external storage. |
| CoreDNS network policy | Pods in unlabelled namespaces lose DNS resolution | Immediate breakage for any namespace without the DNS label | Label all namespaces before applying the policy. Test in staging first. |
| Certificate Transparency monitoring | None (passive monitoring) | Alert fatigue if you issue certificates frequently (cert-manager renewals trigger alerts) | Filter known cert-manager issuances from CT alerts. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| DNSSEC signature expired | All DNS resolution for the zone fails (SERVFAIL) | `delv` shows expired signatures; Prometheus probe fires; every service reports DNS errors | Emergency: disable DNSSEC at registrar (propagation: 15-60 minutes). Long-term: fix signing configuration at DNS provider. |
| DS record mismatch after key rotation | Zone becomes unresolvable (broken chain of trust) | `dig +dnssec` shows no `ad` flag; `delv` shows validation failure | Update DS record at registrar to match the new key. Wait for propagation (up to 48 hours for TTL expiry of old DS). |
| CAA blocks legitimate cert issuance | cert-manager fails to issue or renew certificates | cert-manager logs: `CAA record for example.com prevents issuance`; Let's Encrypt error in ACME logs | Add the CA's domain to CAA records. Wait for DNS propagation (TTL). Retry issuance. |
| DNS-over-TLS upstream unreachable | All DNS resolution fails on the host | Unbound logs show upstream timeout; every service fails to resolve | Restart Unbound (flushes connections). If upstream is down, temporarily add a non-DoT fallback in `forward-zone`. |
| CoreDNS network policy blocks DNS | Pods in unlabelled namespace fail all DNS resolution | Application logs show DNS timeout; `nslookup` from pod fails | Label the namespace: `kubectl label namespace <name> dns-access=allowed`. The policy takes effect immediately. |
| CT monitor detects unauthorized cert | Certificate issued by unexpected CA | CT monitoring alert fires with unknown issuer | Investigate: is this a legitimate cert (new team, new provider) or unauthorized? If unauthorized: revoke the certificate, rotate affected credentials, investigate CA compromise vector. |

## When to Consider a Managed Alternative

**DNS is the easiest first managed service for most teams.** Consider switching when:

- You need DNSSEC but do not have the expertise for key rotation (ZSK every 90 days, KSK annually). Managed providers handle this automatically.
- Self-managed DNS availability does not meet your uptime requirements. A 5-minute DNS outage affects 100% of your services.
- You need anycast distribution for global resolution performance. Self-hosted DNS serves from one or two locations.

**Recommended providers:**

- **[Cloudflare](https://www.cloudflare.com):** Free DNS hosting with automatic DNSSEC (one-click enable), global anycast network, DDoS-resilient. The easiest starting point. Free tier covers everything most teams need.
- **deSEC:** Free, non-profit, DNSSEC-by-default, API-driven, privacy-focused. No account required for basic usage. Good for teams that want DNSSEC without vendor dependency.
- **[DNSimple](https://dnsimple.com):** Automatic DNSSEC key rotation, Let's Encrypt integration, developer-friendly API. From $5/month per zone. For teams wanting automated key management.
- **[NS1](https://ns1.com):** Advanced traffic steering, real-time analytics, Filter Chain for complex routing. From $100/month. For teams needing DNS-level traffic management.

**What you still control:** Internal DNS resolution (Unbound on hosts, CoreDNS in Kubernetes) stays self-managed. CAA records are configured at whichever provider hosts your zone. Split-horizon DNS for internal zones remains on internal infrastructure.

**What changes:** Authoritative DNS serving, DNSSEC key management, anycast distribution, and DDoS resilience for DNS are handled by the provider. You no longer need to manage BIND/PowerDNS/NSD infrastructure, monitor signing key expiry, or maintain multiple authoritative DNS servers for redundancy.


## Related Articles

- [Hardening DNS Resolution on Linux: systemd-resolved, Unbound, and DNS-over-TLS](/articles/linux/dns-resolution-hardening/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [HTTP Security Headers in Production: CSP, HSTS, and Permissions-Policy Without Breaking Your App](/articles/network/http-security-headers/)
- [Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared](/articles/network/rate-limiting-ingress/)
- [NGINX Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls](/articles/network/nginx-hardening-beyond-tls/)
