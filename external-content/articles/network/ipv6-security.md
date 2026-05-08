---
title: "IPv6 Security in Production: Hardening Dual-Stack Deployments"
description: "Most production environments run dual-stack (IPv4 and IPv6) whether the team intended it or not. Linux enables IPv6 by default."
slug: "ipv6-security"
date: 2026-04-21
lastmod: 2026-04-21
category: "network"
tags: ["ipv6", "dual-stack", "nftables", "ndp", "firewall", "kubernetes", "network-security"]
personas: ["systems-engineer", "security-engineer"]
article_number: 48
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
published: true
layout: article.njk
permalink: "/articles/network/ipv6-security/index.html"
---

# IPv6 Security in Production: Hardening Dual-Stack Deployments

## Problem

Most production environments run dual-stack (IPv4 and IPv6) whether the team intended it or not. Linux enables IPv6 by default. Cloud providers assign IPv6 addresses automatically. [Kubernetes](https://kubernetes.io) supports dual-stack since v1.23. The result is an IPv6 attack surface that most teams never audit:

- **Firewall gaps.** Teams write detailed iptables rules for IPv4 and forget that ip6tables is a separate ruleset. The IPv6 interface is wide open while IPv4 is locked down.
- **NDP spoofing.** Neighbor Discovery Protocol (NDP) is the IPv6 equivalent of ARP. NDP spoofing lets an attacker on the local network redirect traffic, perform man-in-the-middle attacks, or cause denial of service. Unlike ARP, NDP uses ICMPv6 and has additional attack vectors through Router Advertisements.
- **Rogue Router Advertisements.** Any device on the local network can send IPv6 Router Advertisements (RAs), causing other hosts to configure themselves with attacker-controlled default routes and DNS servers.
- **Scan evasion.** Security scanners often only scan IPv4 addresses. Services listening on IPv6 addresses bypass vulnerability scanning entirely.
- **Dual-stack application binding.** Applications that bind to `0.0.0.0` only listen on IPv4. Applications that bind to `::` listen on both IPv4 and IPv6 (on most systems), but security controls may only apply to the IPv4 path.
- **Tunnel-based bypass.** IPv6 tunneling protocols (6to4, Teredo, ISATAP) can encapsulate IPv6 traffic inside IPv4 packets, bypassing IPv4 firewalls that do not inspect tunnel contents.

**Target systems:** Linux servers (Ubuntu, Debian, RHEL), Kubernetes clusters with dual-stack networking, any environment where IPv6 is enabled by default but not explicitly managed.

## Threat Model

- **Adversary:** Local network attacker (for NDP and RA attacks), external attacker (for IPv6 firewall bypass), or compromised host on the same network segment.
- **Access level:** Layer 2 adjacency for NDP/RA attacks. Network access to IPv6 addresses for remote attacks.
- **Objective:** Man-in-the-middle through NDP spoofing or rogue Router Advertisements. Bypass IPv4 firewall rules by accessing services on their IPv6 addresses. Enumerate and exploit services that are only scanned on IPv4. Exfiltrate data through IPv6 tunnels that bypass IPv4 inspection.
- **Blast radius:** All hosts on the local network segment for NDP/RA attacks. All services with IPv6 listeners for firewall bypass. Entire network for rogue RA attacks (can redirect all traffic).

## Configuration

### Option 1: Disable IPv6 When Not Needed

If your environment does not require IPv6 connectivity, disabling it eliminates the attack surface entirely. This is the safest option for environments that operate IPv4-only:

```bash
# /etc/sysctl.d/99-disable-ipv6.conf
# Disable IPv6 on all interfaces.

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

Apply without reboot:

```bash
sudo sysctl --system

# Verify IPv6 is disabled
ip -6 addr show
# Expected: no IPv6 addresses (or only link-local on lo if lo is not disabled)

cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# Expected: 1
```

**Warning:** Some applications depend on IPv6 loopback (`::1`). If you disable IPv6 on loopback and an application connects to `localhost` which resolves to `::1`, it will fail. Test thoroughly before disabling IPv6 in production. Common affected services include [PostgreSQL](https://www.postgresql.org) (which may bind to `::1`), Java applications (which prefer IPv6 by default on some JVMs), and [systemd](https://systemd.io)-resolved.

Disable IPv6 tunneling protocols even if you keep IPv6 enabled:

```bash
# /etc/modprobe.d/disable-ipv6-tunnels.conf
# Block IPv6 tunneling that can bypass IPv4 firewalls.

# Disable 6to4 tunneling
install sit /bin/true

# Disable ISATAP
install tunnel6 /bin/true
```

```bash
# Apply module blacklist
sudo depmod -a
sudo update-initramfs -u
```

### Option 2: Dual-Stack [nftables](https://nftables.org) Firewall

If your environment uses IPv6, you need a firewall ruleset that covers both address families. nftables handles IPv4 and IPv6 in a single ruleset using the `inet` family:

```nftables
#!/usr/sbin/nft -f
# /etc/nftables.conf
# Dual-stack firewall for production servers.
# Covers both IPv4 and IPv6 in a single ruleset.

flush ruleset

table inet filter {
    # Rate limiting for ICMPv6 (prevent NDP flooding)
    set icmpv6_meter {
        type ipv6_addr
        flags dynamic,timeout
        timeout 10s
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # Allow established and related connections
        ct state established,related accept

        # Drop invalid state packets
        ct state invalid drop

        # Allow loopback
        iif lo accept

        # --- ICMPv4: allow essential types ---
        ip protocol icmp icmp type {
            echo-request,
            echo-reply,
            destination-unreachable,
            time-exceeded
        } accept

        # Rate limit ICMPv4 echo requests
        ip protocol icmp icmp type echo-request \
            limit rate 10/second burst 20 packets accept

        # --- ICMPv6: allow essential types ---
        # ICMPv6 is critical for IPv6 operation. Do not block all ICMPv6.
        # These types are required for basic IPv6 connectivity:

        # Neighbor Discovery (required for IPv6 to function)
        ip6 nexthdr icmpv6 icmpv6 type {
            nd-neighbor-solicit,
            nd-neighbor-advert
        } accept

        # Router Discovery (required for SLAAC)
        # Only accept RAs from link-local addresses (fe80::/10)
        # to prevent rogue RA from remote addresses.
        ip6 nexthdr icmpv6 icmpv6 type nd-router-advert \
            ip6 saddr fe80::/10 accept

        ip6 nexthdr icmpv6 icmpv6 type nd-router-solicit accept

        # Echo (ping6)
        ip6 nexthdr icmpv6 icmpv6 type {
            echo-request,
            echo-reply
        } limit rate 10/second burst 20 packets accept

        # Destination unreachable and packet too big
        # (required for Path MTU Discovery)
        ip6 nexthdr icmpv6 icmpv6 type {
            destination-unreachable,
            packet-too-big,
            time-exceeded,
            parameter-problem
        } accept

        # --- Service ports ---
        tcp dport 22 accept comment "SSH"
        tcp dport { 80, 443 } accept comment "HTTP/HTTPS"

        # --- Drop everything else ---
        # Log dropped packets for analysis (rate limited)
        limit rate 5/minute burst 10 packets \
            log prefix "nft-drop: " level info
        drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        # Allow forwarding for established connections
        ct state established,related accept

        # Add specific forwarding rules if this host routes traffic
    }

    chain output {
        type filter hook output priority filter; policy accept;

        # Output is permissive by default.
        # Restrict if this server should only communicate with
        # specific destinations.
    }
}
```

Apply and verify:

```bash
# Apply the nftables ruleset
sudo nft -f /etc/nftables.conf

# Verify rules are loaded
sudo nft list ruleset

# Enable nftables on boot
sudo systemctl enable nftables

# Test IPv6 connectivity still works
ping6 -c 3 ::1
# Expected: 3 packets transmitted, 3 received

# Test that IPv6 firewall blocks unexpected ports
nmap -6 -p 1-1000 <your-ipv6-address>
# Expected: only ports 22, 80, 443 shown as open
```

### NDP Security: RA Guard and Neighbor Table Limits

Rogue Router Advertisement protection using nftables:

```nftables
# Additional chain for RA Guard.
# Add to the inet filter table above.

table inet filter {
    chain ra_guard {
        # Only accept Router Advertisements from known routers.
        # Replace with your actual router's link-local addresses.

        ip6 nexthdr icmpv6 icmpv6 type nd-router-advert \
            ip6 saddr fe80::1 accept comment "Known router 1"

        ip6 nexthdr icmpv6 icmpv6 type nd-router-advert \
            ip6 saddr fe80::2 accept comment "Known router 2"

        # Drop RAs from all other sources
        ip6 nexthdr icmpv6 icmpv6 type nd-router-advert \
            log prefix "rogue-ra: " drop
    }
}
```

Kernel parameters to limit NDP table size and prevent NDP table exhaustion attacks:

```bash
# /etc/sysctl.d/99-ipv6-ndp-hardening.conf

# Maximum entries in the IPv6 neighbor table.
# Default is 4096. Reduce on servers that communicate with
# a limited number of peers. Increase on routers.
net.ipv6.neigh.default.gc_thresh3 = 4096
net.ipv6.neigh.default.gc_thresh2 = 2048
net.ipv6.neigh.default.gc_thresh1 = 1024

# How frequently to run garbage collection on the neighbor table (seconds).
net.ipv6.neigh.default.gc_interval = 30

# Time (seconds) an entry stays in REACHABLE state before re-probing.
net.ipv6.neigh.default.base_reachable_time_ms = 30000

# Do not accept Router Advertisements on this host.
# Set to 0 on servers that have static IPv6 configuration.
# Only routers or SLAAC-configured hosts should accept RAs.
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Do not accept redirects (prevents redirect-based MITM)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not accept source-routed packets
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable IPv6 forwarding unless this host is a router
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
```

```bash
sudo sysctl --system
```

### Kubernetes Dual-Stack Network Policy

Kubernetes NetworkPolicy applies to both IPv4 and IPv6 traffic. Verify your CNI plugin supports dual-stack policy enforcement:

```yaml
# dual-stack-netpol.yaml
# This policy applies to both IPv4 and IPv6 traffic.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-app-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: web-app
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress
      ports:
        - protocol: TCP
          port: 8080
  egress:
    # Allow DNS (both IPv4 and IPv6)
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
    # Allow specific backend services
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
```

Verify dual-stack policy enforcement:

```bash
# Check if pods have both IPv4 and IPv6 addresses
kubectl get pods -n production -o wide
# Look for dual-stack addresses in the IP column

# Test IPv6 connectivity between allowed pods
kubectl exec -n ingress deploy/ingress-controller -- \
  curl -6 -s --max-time 3 http://[<pod-ipv6>]:8080/healthz
# Expected: 200

# Test IPv6 connectivity from disallowed pods
kubectl exec -n default deploy/test-pod -- \
  curl -6 -s --max-time 3 http://[<pod-ipv6>]:8080/healthz
# Expected: timeout (blocked by policy)
```

### Testing IPv6 Firewall Rules

```bash
#!/bin/bash
# test-ipv6-firewall.sh
# Verify IPv6 firewall rules are working correctly.

TARGET_V6="2001:db8::1"  # Replace with your server's IPv6 address

echo "=== Testing IPv6 firewall ==="

# Test allowed ports
for port in 22 80 443; do
  result=$(nmap -6 -p "$port" "$TARGET_V6" 2>/dev/null | grep "$port")
  echo "Port $port: $result"
done

# Test blocked ports
for port in 3306 5432 6379 8080 9090; do
  result=$(nmap -6 -p "$port" "$TARGET_V6" 2>/dev/null | grep "$port")
  if echo "$result" | grep -q "filtered\|closed"; then
    echo "Port $port: BLOCKED (correct)"
  else
    echo "Port $port: OPEN (UNEXPECTED - check firewall)"
  fi
done

# Test ICMPv6
ping6 -c 1 -W 3 "$TARGET_V6" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "ICMPv6 echo: ALLOWED (correct)"
else
  echo "ICMPv6 echo: BLOCKED (check firewall rules)"
fi

# Test for rogue RA vulnerability (requires radvd or similar)
# Only run this in a test environment
# radvdump -d 2>/dev/null &
# sleep 5
# kill %1
```

Scan for services listening on IPv6 that are not listening on IPv4:

```bash
#!/bin/bash
# audit-ipv6-listeners.sh
# Find services that listen on IPv6 but may not have IPv6 firewall rules.

echo "=== Services listening on IPv6 ==="
ss -6 -tlnp | grep LISTEN

echo ""
echo "=== Services listening on IPv4 ==="
ss -4 -tlnp | grep LISTEN

echo ""
echo "=== IPv6-only listeners (not on IPv4) ==="
# Find ports that appear in IPv6 but not IPv4
comm -23 \
  <(ss -6 -tlnp | grep LISTEN | awk '{print $4}' | sed 's/.*://' | sort -u) \
  <(ss -4 -tlnp | grep LISTEN | awk '{print $4}' | sed 's/.*://' | sort -u)
```

## Expected Behaviour

After applying the IPv6 security configuration:

```bash
# If IPv6 is disabled:
ip -6 addr show
# Expected: no IPv6 addresses

cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# Expected: 1

# If IPv6 is enabled with firewall:
sudo nft list ruleset | grep "ip6"
# Expected: rules covering ICMPv6, NDP, and service ports

# Verify RA acceptance is disabled on servers
cat /proc/sys/net/ipv6/conf/all/accept_ra
# Expected: 0

# Verify redirects are rejected
cat /proc/sys/net/ipv6/conf/all/accept_redirects
# Expected: 0

# Verify IPv6 firewall blocks unauthorized ports
nmap -6 -p 3306,5432,6379 <your-ipv6-address>
# Expected: all ports filtered or closed

# Verify IPv6 services match IPv4 services
diff \
  <(ss -4 -tlnp | grep LISTEN | awk '{print $4}' | sed 's/.*://' | sort -u) \
  <(ss -6 -tlnp | grep LISTEN | awk '{print $4}' | sed 's/.*://' | sort -u)
# Expected: no differences (same ports open on both stacks)
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Disable IPv6 entirely | Eliminates IPv6 attack surface | Applications depending on IPv6 loopback (`::1`) break; future migration to IPv6 requires re-enabling | Test all applications with IPv6 disabled before production deployment; document the decision for future teams |
| `accept_ra = 0` on servers | Servers ignore Router Advertisements | Servers using SLAAC for address configuration lose IPv6 connectivity | Use static IPv6 configuration on servers; only use SLAAC on workstations |
| Blocking ICMPv6 too aggressively | Incomplete ICMPv6 filtering | Path MTU Discovery breaks (packet-too-big is needed); NDP fails (IPv6 connectivity lost) | Always allow NDP types (133-136) and packet-too-big; test connectivity after applying rules |
| nftables inet family rules | Single ruleset covers both IPv4 and IPv6 | Rules must be written to handle both address families; some rules are IPv4-only or IPv6-only | Use `ip` and `ip6` qualifiers in rules where behaviour differs between families |
| NDP table size limits | Prevents NDP table exhaustion DoS | Legitimate large-subnet environments may exceed the table limit | Increase `gc_thresh3` proportionally to the expected number of IPv6 neighbors |
| Disabling IPv6 tunnels | Prevents tunnel-based firewall bypass | Legitimate uses of 6to4 or sit tunnels break | Only disable tunnels if your environment does not use them; audit before blocking |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| IPv6 disabled breaks application | Application fails to start or cannot connect to localhost | Application logs show "connection refused" on `::1` or "[::1]" | Configure application to bind to `127.0.0.1` explicitly; or re-enable IPv6 on loopback only (`net.ipv6.conf.lo.disable_ipv6 = 0`) |
| ICMPv6 packet-too-big blocked | Large packets silently dropped; connections hang after initial handshake | TCP connections stall when sending data larger than path MTU; works fine for small responses | Add explicit accept rule for ICMPv6 type packet-too-big in the nftables ruleset |
| NDP types blocked | IPv6 connectivity lost entirely on the local segment | All IPv6 connections fail; `ping6` to link-local addresses fails | Allow ICMPv6 types 133 (Router Solicitation), 134 (Router Advertisement), 135 (Neighbor Solicitation), 136 (Neighbor Advertisement) |
| RA guard blocks legitimate router | Host loses IPv6 default route after reboot | No IPv6 internet connectivity; `ip -6 route` shows no default route | Add the legitimate router's link-local address to the RA guard allow list |
| Dual-stack network policy not enforced by CNI | NetworkPolicy has no effect on IPv6 traffic | IPv6 connections succeed where they should be blocked (test with curl -6) | Verify CNI plugin supports dual-stack policy; switch to [Calico](https://www.tigera.io/project-calico/) or [Cilium](https://cilium.io) if current CNI does not enforce |
| IPv6 tunnel bypass undetected | Data exfiltrated through 6to4 or Teredo tunnel inside permitted IPv4 traffic | Unusual traffic patterns on permitted IPv4 ports; deep packet inspection detects tunnel headers | Block tunnel protocols at the kernel module level; deploy network monitoring that detects encapsulated traffic |

## When to Consider a Managed Alternative

**Transition point:** When your team lacks IPv6 networking expertise and managing dual-stack firewall rules, NDP security, and tunnel detection becomes a source of ongoing security gaps, or when you need IPv6 connectivity for external users but want to avoid the operational complexity of dual-stack infrastructure.

**What managed providers handle:**

- **[Cloudflare](https://www.cloudflare.com):** Provides IPv6 edge termination, allowing external users to connect over IPv6 while your origin infrastructure remains IPv4-only. Cloudflare translates IPv6 client connections to IPv4 connections to your origin, eliminating the need for dual-stack infrastructure behind the edge. This removes the IPv6 firewall, NDP security, and dual-stack complexity from your environment entirely. Included in all plans.

**What you still control:** If your internal infrastructure requires IPv6 (service mesh, dual-stack Kubernetes, or IPv6-only environments), the firewall rules, NDP security, and tunnel prevention in this article remain your responsibility. Cloudflare only handles the external-facing IPv6 surface. Internal IPv6 security is always on you.

**Architecture:** For most teams, the simplest approach is Cloudflare for external IPv6 plus disabled or tightly firewalled IPv6 on internal infrastructure. If you must run dual-stack internally, apply every control in this article and audit regularly with the testing scripts provided.


## Related Articles

- [mTLS for Service-to-Service Communication: Istio, Linkerd, and DIY with cert-manager](/articles/network/mtls-service-mesh/)
- [Protecting Internal APIs: Network Segmentation, Authentication, and Access Logging](/articles/network/internal-api-protection/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [HTTP Security Headers in Production: CSP, HSTS, and Permissions-Policy Without Breaking Your App](/articles/network/http-security-headers/)
- [Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared](/articles/network/rate-limiting-ingress/)
