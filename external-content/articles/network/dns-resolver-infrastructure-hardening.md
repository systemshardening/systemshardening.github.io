---
title: "DNS Resolver Infrastructure Hardening: Recursive Resolvers, DNSSEC, DoT, and Split-Horizon DNS"
description: "Harden your internal recursive resolver infrastructure against cache poisoning, DNS rebinding, and lateral movement. Covers BIND 9 and Unbound hardening, DNSSEC validation, DNS over TLS, split-horizon views, and Kubernetes CoreDNS security."
slug: dns-resolver-infrastructure-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - dns
  - resolver-security
  - dnssec
  - dns-over-tls
  - split-horizon
personas:
  - security-engineer
  - network-engineer
article_number: 509
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/dns-resolver-infrastructure-hardening/
---

# DNS Resolver Infrastructure Hardening: Recursive Resolvers, DNSSEC, DoT, and Split-Horizon DNS

## The Problem

Your internal recursive resolver is the most trusted machine in your network that your users never think about. Every hostname — internal services, cloud APIs, SaaS endpoints, authentication providers — passes through it. That makes it a high-value target for attackers and a high-leverage control point for defenders.

The threats are real and well-documented. The Kaminsky attack (2008) demonstrated that an unpatched resolver could be cache-poisoned in seconds, redirecting internal users to attacker-controlled IPs for any domain. DNS rebinding attacks abuse the same-origin policy gap between DNS TTLs and browser security boundaries, allowing a malicious web page to pivot into internal network addresses. Attackers who compromise an internal host often leverage the resolver for lateral movement: querying internal service discovery names, enumerating SRV records, or using the resolver as a covert DNS tunnel for exfiltration.

Most organisations run their internal recursive resolver as a default BIND or Unbound install — recursor open to any RFC1918 client, version string exposed, no DNSSEC validation, no encrypted forwarding, split-horizon configured with a comment saying "TODO: review". This article closes those gaps systematically.

**Scope:** BIND 9.16+ and Unbound 1.13+ on Linux. CoreDNS for Kubernetes. Specific hardening controls with production-ready configuration snippets.

---

## Internal Recursive Resolver Threats

Before configuration, establish the threat model:

**Cache poisoning (Kaminsky attack):** An attacker sends a flood of forged DNS responses to the resolver, racing to inject a poisoned record before the legitimate response arrives. The classic mitigation is source port randomisation — the attacker must guess both the 16-bit transaction ID and the source port, making brute-force statistically infeasible. Without it, a resolver can be poisoned in under 10 seconds on a fast network.

**DNS rebinding:** A malicious domain returns a public IP on the first lookup (passing same-origin checks), then quickly changes its DNS to return an RFC1918 address. The browser caches the original origin but now makes requests to `192.168.1.1`, bypassing network firewalls entirely. The resolver is the correct enforcement point: it should refuse to return RFC1918 addresses in responses to public domain queries.

**Resolver-based lateral movement:** An attacker with a foothold on one internal host can query the internal resolver for hostnames that are only visible internally — service discovery via SRV records, internal hostnames leaked from split-horizon zones, PTR records that reveal naming conventions. A hardened resolver limits what unprivileged clients can enumerate.

**DNS tunnelling exfiltration:** Tools like `dnscat2` and `iodine` encode data in DNS query and response payloads, using the resolver as a carrier. High query rates to a single external domain, unusually long hostnames, or TXT record abuse are all detectable from query logs.

---

## BIND 9 Hardening

A default BIND 9 installation as a recursive resolver exposes several configuration risks. The following `named.conf.options` block addresses them:

```conf
options {
    directory "/var/cache/bind";

    // Restrict recursion to internal clients only
    // Never allow open recursion — it enables DNS amplification attacks
    allow-recursion { 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; 127.0.0.1; ::1; };
    allow-query     { 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; 127.0.0.1; ::1; };
    allow-query-cache { 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16; 127.0.0.1; ::1; };

    // Only listen on internal interfaces
    listen-on       { 10.0.1.5; 127.0.0.1; };
    listen-on-v6    { ::1; };

    // Hide version string — never expose to external queries
    version "none";
    hostname "none";
    server-id "none";

    // Response Rate Limiting — prevents DNS amplification abuse
    // Applies even to internal resolvers that might be abused by a compromised host
    rate-limit {
        responses-per-second 15;
        window 5;
        log-only no;
    };

    // Return minimal responses — don't include extra section glue for unsolicited names
    minimal-responses yes;

    // Source port randomisation (should be enabled by default, verify it is)
    use-v4-udp-ports { range 1024 65535; };
    avoid-v4-udp-ports { };

    // DNSSEC validation
    dnssec-validation auto;

    // Do not allow zone transfers except to explicit secondaries
    allow-transfer { none; };

    // Limit recursion depth to reduce NXDOMAIN amplification
    max-recursion-depth 12;
    max-recursion-queries 75;

    // Fetch limits — prevent a single resolver from being used as a DDoS reflector
    fetch-quota-params 100 0.1 0.3 0.5;

    // Disable CHAOS class queries (used for version probing)
    // Already handled by version "none" but belt-and-suspenders
    deny-answer-addresses { 100.64.0.0/10; };

    // Stale-answer-enable as fallback during upstream outages
    stale-answer-enable yes;
    stale-answer-ttl 30;
    stale-cache-enable yes;
    stale-answer-client-timeout 2000;
};
```

Verify the configuration with:

```bash
named-checkconf /etc/bind/named.conf
# Check that recursion is not open
dig +short version.bind TXT CHAOS @127.0.0.1
# Should return nothing or "none"
dig @127.0.0.1 example.com A
# Verify external queries resolve correctly for internal clients
```

---

## Unbound Hardening

Unbound is the preferred resolver for many security-focused deployments. Its configuration is more granular than BIND for recursive resolver hardening:

```conf
server:
    # Interface binding — restrict to internal interfaces
    interface: 10.0.1.5
    interface: 127.0.0.1
    port: 53

    # Access control — deny everything, then allow internal ranges
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: ::1 allow

    # DNSSEC validation
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no   # Hard fail on DNSSEC validation errors

    # DNS rebinding prevention — refuse RFC1918 addresses in responses to public names
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 100.64.0.0/10
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    # Allow known internal domains to return RFC1918 (split-horizon)
    private-domain: "internal.example.com"
    private-domain: "corp.example.com"

    # QNAME minimisation — reduces query privacy leakage to root/TLD servers
    # Only sends the minimum necessary labels upstream
    qname-minimisation: yes
    qname-minimisation-strict: no  # Fall back if upstream breaks; set yes for strict environments

    # Harden against cache poisoning and injection
    harden-glue: yes              # Only accept glue for delegated zones
    harden-dnssec-stripped: yes   # Reject unsigned responses for DNSSEC-signed zones
    harden-below-nxdomain: yes    # Do not return data for subdomains of NXDOMAIN
    harden-referral-path: yes     # Validate the entire referral path
    harden-algo-downgrade: yes    # Reject algorithm downgrades in DNSSEC

    # Cache poisoning mitigations
    use-caps-for-id: yes          # 0x20 bit randomisation (mixed-case queries)

    # Hide version string
    hide-version: yes
    hide-identity: yes

    # Prefetch popular records before TTL expiry — reduces latency
    prefetch: yes
    prefetch-key: yes

    # Aggressive NSEC — use NSEC/NSEC3 records to synthesise NXDOMAIN faster
    aggressive-nsec: yes

    # Rate limiting
    ratelimit: 1000               # queries per second total
    ratelimit-for-domain: 100     # per upstream domain

    # Logging for security monitoring
    use-syslog: yes
    log-queries: yes              # Enable in production for SIEM ingestion
    log-replies: yes
    log-tag-queryreply: yes

    # dnstap for structured query logging
    dnstap-enable: yes
    dnstap-socket-path: "/run/unbound/dnstap.sock"
    dnstap-send-identity: yes
    dnstap-send-version: yes
    dnstap-log-resolver-query-messages: yes
    dnstap-log-resolver-response-messages: yes
    dnstap-log-client-query-messages: yes
    dnstap-log-client-response-messages: yes

    # Outgoing port randomisation
    outgoing-num-tcp: 10
    num-queries-per-thread: 1024
    jostle-timeout: 200

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
    # Use TLS for remote control
    control-use-cert: yes
    server-key-file: "/etc/unbound/unbound_server.key"
    server-cert-file: "/etc/unbound/unbound_server.pem"
    control-key-file: "/etc/unbound/unbound_control.key"
    control-cert-file: "/etc/unbound/unbound_control.pem"
```

Generate control TLS certificates:

```bash
unbound-control-setup
# Verify configuration syntax
unbound-checkconf /etc/unbound/unbound.conf
# Check DNSSEC trust anchor is loaded
unbound-control status | grep trust
```

---

## DNSSEC Validation at the Resolver

DNSSEC validation at the recursive resolver is the definitive defence against cache poisoning. The resolver cryptographically verifies that each response was signed by the authoritative zone owner. A forged response — even one with a correct transaction ID and source port — fails signature verification and is discarded.

**Bootstrapping trust anchors in Unbound:**

```bash
# Fetch and install the root trust anchor
unbound-anchor -a /var/lib/unbound/root.key
chown unbound:unbound /var/lib/unbound/root.key

# Verify DNSSEC validation is working
unbound-host -D -v dnssec-failed.org
# Should return: validation failure (the test domain deliberately fails)

dig +dnssec +multi @127.0.0.1 cloudflare.com A
# Look for 'ad' flag in the header (Authenticated Data)
```

**Handling validation failures:** When a zone is incorrectly signed, clients will receive SERVFAIL for all queries to that zone. This is correct behaviour — a SERVFAIL from DNSSEC is not the same as a network failure. Document your escalation procedure: validation failures require the zone owner to correct their signing, not your resolver to disable validation.

**BIND 9 DNSSEC validation:**

```conf
options {
    dnssec-validation auto;
    # auto loads the built-in root trust anchor from bind.keys
    # Use explicit trust anchors for internal zones:
};

# For an internally-signed zone, add the KSK public key:
trusted-keys {
    "internal.example.com." 256 3 8 "AwEAAb...base64...";
};
```

---

## DNS over TLS for Internal Resolvers

Encrypting DNS traffic between clients and the internal resolver prevents passive interception and manipulation of DNS queries on internal network segments — relevant when networks are shared, untrusted endpoints exist, or compliance requires in-transit encryption for all traffic.

**Running Unbound with DoT on port 853:**

```conf
server:
    interface: 10.0.1.5@853
    tls-service-key: "/etc/unbound/tls/resolver.key"
    tls-service-pem: "/etc/unbound/tls/resolver.crt"
    # Include the full chain if using an internal CA
    # tls-cert-bundle includes trusted CAs for outgoing TLS (DoT to upstream)

# Forward queries upstream via DoT
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
    # Pin by SPKI hash if you want to detect upstream cert rotation
```

Generate an internal CA-signed cert for the resolver:

```bash
# Generate key and CSR
openssl genrsa -out /etc/unbound/tls/resolver.key 4096
openssl req -new -key /etc/unbound/tls/resolver.key \
    -subj "/CN=dns.internal.example.com" \
    -addext "subjectAltName=DNS:dns.internal.example.com,IP:10.0.1.5" \
    -out /etc/unbound/tls/resolver.csr

# Sign with internal CA
openssl x509 -req -in /etc/unbound/tls/resolver.csr \
    -CA /etc/pki/internal-ca/ca.crt \
    -CAkey /etc/pki/internal-ca/ca.key \
    -CAcreateserial \
    -days 825 \
    -extensions v3_req \
    -out /etc/unbound/tls/resolver.crt

chmod 640 /etc/unbound/tls/resolver.key
chown root:unbound /etc/unbound/tls/resolver.key
```

**Configure `systemd-resolved` on clients to use DoT:**

```ini
# /etc/systemd/resolved.conf
[Resolve]
DNS=10.0.1.5
DNSOverTLS=yes
DNSSEC=yes
Domains=~internal.example.com ~corp.example.com
```

Distribute the internal CA certificate to clients:

```bash
# On each Linux client
cp internal-ca.crt /usr/local/share/ca-certificates/internal-ca.crt
update-ca-certificates

# Verify DoT is working
resolvectl status
# Look for: DNS over TLS setting: yes
# Current DNS over TLS: yes
```

---

## DNS Rebinding Prevention

DNS rebinding is a class of attack where an attacker-controlled domain first resolves to a public IP (passing browser same-origin checks), then switches its DNS to an internal RFC1918 address. The browser reuses the existing origin and sends requests to internal infrastructure.

The resolver is the correct control point. Unbound's `private-address` directive makes the resolver refuse to return RFC1918 addresses from publicly-resolvable names:

```conf
server:
    # Block all RFC1918 and link-local returns from public name resolution
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 127.0.0.0/8
    private-address: 169.254.0.0/16
    private-address: ::ffff:0:0/96
    private-address: 100.64.0.0/10
    private-address: fd00::/8

    # Whitelist legitimate internal domains that intentionally return RFC1918
    # Without this, your internal zone lookups would also be blocked
    private-domain: "internal.example.com"
    private-domain: "corp.example.com"
    private-domain: "10.in-addr.arpa"
    private-domain: "168.192.in-addr.arpa"
```

Test the protection:

```bash
# A public domain that returns RFC1918 should be blocked
# (this simulates a rebinding attempt)
dig @127.0.0.1 rebind.it A
# Should return SERVFAIL, not the RFC1918 address
```

BIND 9 equivalent using RPZ (Response Policy Zones):

```conf
rpz {
    zone "rpz.internal" {
        type master;
        file "rpz.internal.db";
    };
};
```

With zone records denying RFC1918 responses for non-private domains — but Unbound's built-in `private-address` is simpler and less error-prone.

---

## Split-Horizon DNS

Split-horizon DNS (also called split-brain DNS) serves different answers to internal versus external clients for the same domain name. Internal clients get the internal IP for `app.example.com`; external clients get the load balancer IP. This is operationally convenient but introduces security considerations.

**BIND 9 views:**

```conf
# named.conf
acl "internal" {
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
};

view "internal" {
    match-clients { internal; };
    recursion yes;
    allow-recursion { internal; };

    zone "example.com" {
        type master;
        file "/etc/bind/zones/example.com.internal";
    };

    # Internal view includes all public zones via recursion
    # plus override zones for internal services
};

view "external" {
    match-clients { any; };
    recursion no;    // Never allow recursion on the external-facing view
    allow-recursion { none; };

    zone "example.com" {
        type master;
        file "/etc/bind/zones/example.com.external";
    };
};
```

**Security considerations for split-horizon:**

Information leakage is the primary risk. If the internal zone file for `example.com` includes hostnames like `vpn.example.com`, `admin.example.com`, `jira.example.com`, and those hostnames are reachable from outside, an attacker who can query the internal resolver (e.g., from a compromised host or via SSRF) learns your full internal service map.

Mitigations:
- Audit internal zone files for hostnames that reveal architecture (e.g., `k8s-master-01.internal.example.com`).
- Use separate namespaces: `example.com` for public, `corp.example.com` for internal-only services.
- Never serve internal zone data on the external-facing authoritative server.
- Use TSIG (Transaction Signature) to authenticate zone transfers between internal primaries and secondaries.

**Separate Unbound instances for strict isolation:**

For environments where a single BIND views misconfiguration could expose internal data, run two physically separate Unbound instances:

```bash
# Internal resolver: 10.0.1.5:53
# Handles recursion + internal zone stubs
# Only reachable from RFC1918 clients

# External resolver (or none at all)
# Handles authoritative responses for public zones only
# Does not recurse
```

Use `stub-zone` in the internal Unbound to forward internal domain queries to an internal authoritative:

```conf
stub-zone:
    name: "corp.example.com"
    stub-addr: 10.0.1.10@53   # Internal authoritative nameserver
    stub-prime: no
```

---

## Cache Poisoning Mitigations Beyond DNSSEC

DNSSEC is the definitive fix for cache poisoning, but not all domains are DNSSEC-signed. Layered mitigations:

**Source port randomisation:** The Kaminsky attack requires guessing both the 16-bit transaction ID and the ephemeral source port. With a 16-bit port space (~64,000 values), the combined entropy makes brute-force impractical. Both BIND and Unbound do this by default — verify it has not been disabled by checking that `avoid-v4-udp-ports` is not restricting too many ports:

```bash
# Verify Unbound is using randomised ports
unbound-control stats | grep num.query.tcp
# Most queries should be UDP; TCP spike can indicate poisoning attempts
ss -u -l -n | grep :53
# Should show multiple source ports in use
```

**0x20 bit randomisation (use-caps-for-id):** Unbound randomises the capitalisation of query labels (e.g., `eXaMpLe.cOm`) and verifies the authoritative server echoes the same capitalisation in its response. A forged response that doesn't match the original mixed-case query is discarded. This adds approximately 20 bits of additional randomness for a typical domain name.

```conf
# Unbound
server:
    use-caps-for-id: yes
```

Note: some authoritative servers do not correctly echo 0x20 labels. Unbound falls back gracefully, but you may see rare resolution failures for broken implementations.

**Minimising cache poisoning blast radius:** Set aggressive TTL minimums to limit how long a poisoned entry persists, without setting them so low that your resolver hammers upstream on every query:

```conf
# Unbound
server:
    cache-min-ttl: 60    # Minimum 60 seconds regardless of authoritative TTL
    cache-max-ttl: 86400 # Maximum 24 hours
    cache-max-negative-ttl: 900
```

---

## DNS Query Logging for Security

Resolver query logs are a primary signal source for detecting DNS tunnelling, C2 beacon activity, and internal reconnaissance. Unstructured syslog is insufficient at scale; use `dnstap` for structured binary logging.

**Unbound dnstap to file via `fstrm_capture`:**

```bash
# Install fstrm tools
apt install fstrm-bin

# Start fstrm capture daemon reading from Unbound's dnstap socket
fstrm_capture -t protobuf:dnstap.Dnstap \
    -r /run/unbound/dnstap.sock \
    -w /var/log/dns/dnstap.fstrm &

# Convert to JSON for SIEM ingestion
dnstap-ldns -j < /var/log/dns/dnstap.fstrm | jq .
```

**BIND 9 dnstap:**

```conf
options {
    dnstap { client; resolver; auth; forwarder; };
    dnstap-output file "/var/log/named/dnstap.bin" versions 10 size 50m;
    dnstap-identity "resolver-01";
    dnstap-version yes;
};
```

**Detecting DNS tunnelling from query logs:** DNS tunnelling tools encode data as subdomains — a typical exfiltration query looks like `aGVsbG8gd29ybGQ.exfil.attacker.com`. Detection heuristics:

```bash
# Find unusually long hostnames — base64/hex encoded data
# Normal queries rarely exceed 40 characters in the queried name
awk -F'"' '{ if (length($2) > 50) print }' /var/log/named/queries.log | \
    sort | uniq -c | sort -rn | head -20

# Find high query rates to a single parent domain
# DNS tunnels generate dozens of queries per second
dnstap-ldns -j < /var/log/dns/dnstap.fstrm | \
    jq -r '.message.query_name' | \
    awk -F. '{print $(NF-1)"."$NF}' | \
    sort | uniq -c | sort -rn | head -20

# Find TXT and NULL record queries (often used for data return channel)
grep -E '"type":"TXT"|"type":"NULL"' /var/log/dns/queries.json | \
    jq -r '.qname' | sort | uniq -c | sort -rn
```

Ship dnstap output to your SIEM (Elasticsearch/Splunk) via Filebeat or a custom Logstash pipeline. Index on `qname`, `rcode`, `qtype`, and `client_address` for effective threat hunting queries.

---

## Kubernetes CoreDNS Security Hardening

CoreDNS is the default DNS resolver for Kubernetes. Default configurations have several security gaps:

**Restrict external forwarding to a controlled upstream:**

```yaml
# coredns ConfigMap
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
        prometheus :9153
        # Forward only to known internal resolvers, not 8.8.8.8
        forward . 10.0.1.5 10.0.1.6 {
           max_concurrent 1000
           expire 10s
           health_check 5s
           # Use TLS if internal resolvers support DoT
           # tls /etc/coredns/tls.crt /etc/coredns/tls.key /etc/coredns/ca.crt
        }
        cache 30 {
           success 9984 30
           denial 9984 5
        }
        loop
        reload
        loadbalance
        # Log queries for security monitoring
        log . {
            class all
        }
    }
```

**Block exfiltration via DNS from pods:** Use a CoreDNS policy plugin or NetworkPolicy to prevent pods from making arbitrary DNS queries to external resolvers, bypassing the cluster resolver:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-external-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # Allow DNS only to CoreDNS in kube-system
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
      to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
    # Allow all other egress (adjust to least-privilege)
    - ports:
        - port: 443
          protocol: TCP
        - port: 80
          protocol: TCP
```

**Harden CoreDNS RBAC:** The CoreDNS ServiceAccount needs only read access to endpoints, services, and pods — not write access or access to secrets:

```bash
# Audit CoreDNS RBAC permissions
kubectl describe clusterrole system:coredns
# Verify no write verbs (create, update, patch, delete) are granted
kubectl get clusterrolebinding system:coredns -o yaml | \
    grep -A5 subjects
```

**Enable CoreDNS metrics for anomaly detection:**

```bash
# CoreDNS exposes Prometheus metrics at :9153/metrics
# Key metrics to alert on:
# coredns_dns_requests_total{rcode="SERVFAIL"} — spike indicates DNSSEC failures or resolver issues
# coredns_forward_requests_total — unexpected external forwarding
# coredns_cache_hits_total vs coredns_cache_misses_total — low hit rate indicates cache bypass attempts
kubectl port-forward -n kube-system svc/kube-dns 9153:9153
curl -s http://localhost:9153/metrics | grep coredns_dns
```

---

## Operational Checklist

Run this against your resolver deployment:

```bash
#!/bin/bash
# DNS Resolver Security Audit

RESOLVER="127.0.0.1"

echo "=== Open Recursion Test ==="
# Should fail (REFUSED or timeout) from any IP not in allow-recursion
dig +time=3 @${RESOLVER} example.com A 2>&1 | grep -E "REFUSED|NOERROR|SERVFAIL"

echo "=== Version String Exposure ==="
dig @${RESOLVER} version.bind TXT CHAOS +short
# Should return empty or "none"

echo "=== DNSSEC Validation ==="
dig @${RESOLVER} dnssec-failed.org A +dnssec 2>&1 | grep -E "SERVFAIL|NXDOMAIN|ad"
# Should return SERVFAIL (validation failure for intentionally-broken zone)

dig @${RESOLVER} cloudflare.com A +dnssec 2>&1 | grep "^;; flags"
# Should include 'ad' flag

echo "=== DNS Rebinding Protection ==="
# Query a domain known to return RFC1918 (test with a lab domain or rebind.it)
dig @${RESOLVER} rebind.it A +short 2>&1
# Should return SERVFAIL, not an RFC1918 address

echo "=== Zone Transfer Restriction ==="
dig @${RESOLVER} example.com AXFR 2>&1 | grep -E "REFUSED|Transfer"
# Should be REFUSED

echo "=== Query Logging ==="
ls -la /var/log/dns/ 2>/dev/null || \
journalctl -u unbound --since "1 minute ago" | grep -c "query"
```

---

## Summary

DNS resolver infrastructure hardening is a force-multiplier control: a well-hardened resolver blocks rebinding attacks, resists cache poisoning for all clients simultaneously, validates DNSSEC for every query, and produces the query logs needed to detect tunnelling and C2 activity. The configuration changes are low-risk and high-leverage — most can be applied to a running resolver without service interruption by testing with `unbound-checkconf` or `named-checkconf` before reload.

Priority order for brownfield deployments:
1. Restrict recursion to internal clients only (`allow-recursion`, `access-control`) — this closes the open resolver risk immediately.
2. Enable DNSSEC validation — the most impactful single change against cache poisoning.
3. Enable `private-address` in Unbound for DNS rebinding protection.
4. Enable `use-caps-for-id` for 0x20 randomisation.
5. Configure dnstap and ship to SIEM.
6. Migrate clients to DoT once the resolver cert is in place.
7. Audit split-horizon zone files for information leakage.
