---
title: "Linux Firewall Hardening with nftables: Replacing iptables in Production"
description: "iptables is deprecated. nftables is the replacement in every modern Linux kernel (5.0+)."
slug: "nftables"
date: 2026-02-26
lastmod: 2026-02-26
category: "linux"
tags: ["nftables", "firewall", "iptables", "linux", "network-security"]
personas: ["systems-engineer", "sre"]
article_number: 8
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
premium_pack: "nftables-ruleset-collection"
published: true
layout: article.njk
permalink: "/articles/linux/nftables/index.html"
---

# Linux Firewall Hardening with [nftables](https://nftables.org): Replacing iptables in Production

## Problem

iptables is deprecated. nftables is the replacement in every modern Linux kernel (5.0+). Most teams either still use iptables (accumulating technical debt and missing nftables performance improvements), or have no host-level firewall at all, relying entirely on cloud security groups or [Kubernetes](https://kubernetes.io) network policies. Host-level firewalling provides defence in depth that survives misconfigured higher-level abstractions.

## Threat Model

- **Adversary:** Network-adjacent attacker scanning for open ports, or attacker who has compromised one service and is pivoting to other services on the same host.
- **Blast radius:** Without host firewall, every listening port is reachable from the network. With nftables default-deny, only explicitly allowed ports are accessible.

## Configuration

### Web Server Ruleset

```bash
#!/usr/sbin/nft -f
# /etc/nftables.conf - hardened ruleset for a web server

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established and related connections
        ct state established,related accept

        # Drop invalid packets
        ct state invalid drop

        # Allow loopback
        iif lo accept

        # Allow ICMP (ping) - rate limited
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 5/second accept

        # Allow SSH - rate limited to prevent brute force
        tcp dport 22 ct state new limit rate 10/minute accept

        # Allow HTTP and HTTPS
        tcp dport { 80, 443 } accept

        # Log dropped packets (rate limited to prevent log flooding)
        limit rate 5/minute log prefix "nftables-drop: " level warn
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        # No forwarding on a web server
    }

    chain output {
        type filter hook output priority 0; policy accept;
        # Allow all outbound by default.
        # For stricter control, change to policy drop and allowlist.
    }
}
```

### Database Server Ruleset

```bash
#!/usr/sbin/nft -f
# Hardened ruleset for a database server (PostgreSQL)

flush ruleset

table inet filter {
    # Define IP sets for allowed sources
    set app_servers {
        type ipv4_addr
        elements = { 10.0.1.10, 10.0.1.11, 10.0.1.12 }
    }

    set admin_hosts {
        type ipv4_addr
        elements = { 10.0.0.5 }
    }

    chain input {
        type filter hook input priority 0; policy drop;

        ct state established,related accept
        ct state invalid drop
        iif lo accept

        # SSH from admin hosts only
        ip saddr @admin_hosts tcp dport 22 accept

        # PostgreSQL from application servers only
        ip saddr @app_servers tcp dport 5432 accept

        # Prometheus node_exporter from monitoring
        ip saddr 10.0.3.0/24 tcp dport 9100 accept

        limit rate 5/minute log prefix "nftables-drop: " level warn
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

### Kubernetes Node Ruleset

```bash
#!/usr/sbin/nft -f
# Hardened ruleset for a Kubernetes node

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        ct state established,related accept
        ct state invalid drop
        iif lo accept

        # SSH from bastion only
        ip saddr 10.0.0.5/32 tcp dport 22 accept

        # Kubelet API (from control plane)
        ip saddr 10.0.0.0/24 tcp dport 10250 accept

        # NodePort range (30000-32767) - if using NodePort services
        tcp dport 30000-32767 accept

        # Calico/Cilium CNI (BGP, VXLAN, health checks)
        ip saddr 10.0.0.0/8 tcp dport 179 accept       # BGP
        ip saddr 10.0.0.0/8 udp dport 4789 accept       # VXLAN
        ip saddr 10.0.0.0/8 tcp dport 4240 accept       # Cilium health

        # Pod CIDR (container traffic)
        ip saddr 10.244.0.0/16 accept

        limit rate 5/minute log prefix "nftables-drop: " level warn
    }

    chain forward {
        # MUST allow forwarding for container traffic
        type filter hook forward priority 0; policy accept;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

### Applying and Persisting

```bash
# Apply the ruleset
sudo nft -f /etc/nftables.conf

# Verify active rules
sudo nft list ruleset

# Enable nftables service for persistence across reboots
sudo systemctl enable nftables

# Test: attempt to connect to a blocked port
nc -zv host 3306
# Expected: Connection refused (if MySQL is not in the allowlist)
```

### Migration from iptables

```bash
# Export current iptables rules as nftables format
sudo iptables-save | sudo iptables-restore-translate > /etc/nftables.conf

# Review and clean up the generated nftables config
# (iptables-translate output is functional but not optimised)

# Disable iptables and enable nftables
sudo systemctl disable iptables
sudo systemctl enable nftables
sudo systemctl start nftables
```

## Expected Behaviour

- `nft list ruleset` shows active rules matching the configured policy
- Default policy is drop, only explicitly allowed traffic passes
- SSH rate-limited to 10 new connections per minute
- Database ports accessible only from allowed source IPs
- Dropped packets logged (rate-limited to prevent log flooding)
- Rules persist across reboots via [systemd](https://systemd.io) service

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Default-deny input policy | Blocks all unexpected inbound traffic | New services fail until firewall rule is added | Add firewall rule updates to service deployment checklist. |
| SSH rate limiting | Blocks SSH brute force | Legitimate users may be rate-limited during high-connect periods | Increase rate for trusted source IPs (admin set). |
| IP set for allowed sources | Easy to manage allowed IPs | IP changes require ruleset update | Use DNS-based sets or integrate with cloud metadata for dynamic IPs. |
| nftables over iptables | Better performance (atomic rule updates, native sets) | Team must learn nftables syntax | Syntax is straightforward; most iptables concepts map directly. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Ruleset locks out SSH | Cannot SSH to the host | SSH connection refused; only console access works | Use console/BMC access. Fix the ruleset. Or: reboot (if nftables.conf is correct, it will reload correctly). |
| Missing rule for new service | New service unreachable | Service monitoring shows connection refused; users report outage | Add the required port/source to the nftables ruleset. Apply with `nft -f`. |
| Forward chain blocks K8s pods | Pod-to-pod communication fails on the node | Pods show network errors; CNI health check fails | Ensure forward chain policy is `accept` on Kubernetes nodes (required for container networking). |

## When to Consider a Managed Alternative

Host-level firewall management does not scale past 20+ hosts with different rulesets. Kubernetes network policies and cloud security groups provide more appropriate abstractions at scale.

- **[Cloudflare](https://www.cloudflare.com):** Edge DDoS/WAF protection before traffic reaches your hosts.
- **CrowdSec:** Collaborative IP blocking with community threat intelligence.
- **Managed K8s:** Provider handles node firewall configuration.

**Premium content pack:** nftables ruleset collection. pre-built rulesets for web servers, databases, Kubernetes nodes, bastion hosts, and monitoring servers. Includes migration script from iptables.


## Related Articles

- [Hardening DNS Resolution on Linux: systemd-resolved, Unbound, and DNS-over-TLS](/articles/linux/dns-resolution-hardening/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [Filesystem Mount Options That Matter: noexec, nosuid, nodev, and Beyond](/articles/linux/filesystem-mount-options/)
- [Linux Audit Framework Deep Dive: auditd Rules, auditctl, and ausearch for Security Monitoring](/articles/linux/auditd-deep-dive/)
