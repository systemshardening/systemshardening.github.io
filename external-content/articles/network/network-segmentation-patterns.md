---
title: "Network Segmentation Patterns: Micro-segmentation, East-West Controls, and Zero-Trust Zones"
description: "Flat networks give an attacker who reaches any host access to every other host. Network segmentation limits lateral movement by enforcing that traffic between hosts must be explicitly permitted. Micro-segmentation, network zones, and east-west controls are the practical implementations."
slug: "network-segmentation-patterns"
date: 2026-05-01
lastmod: 2026-05-01
category: "network"
tags: ["network-segmentation", "micro-segmentation", "east-west", "zero-trust", "vlan", "firewall"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 305
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/network/network-segmentation-patterns/index.html"
---

# Network Segmentation Patterns: Micro-segmentation, East-West Controls, and Zero-Trust Zones

## Problem

The traditional network security model placed a firewall at the perimeter: traffic coming in from the internet was inspected; traffic between internal hosts was trusted. This model has failed. The majority of breach damage now comes from lateral movement — an attacker who gains a foothold on one internal host traverses the flat internal network to reach databases, domain controllers, and sensitive services without encountering any additional controls.

Lateral movement is fast and quiet on flat networks:
- An attacker who compromises a web application server connects directly to the database on port 5432 — the database accepts all connections from internal IPs.
- A compromised workstation scans the internal subnet and finds an unpatched SMB service on a file server.
- Malware on a container exfiltrates data to an adjacent container using its private IP — no traffic leaves the host, so perimeter controls never see it.

Network segmentation limits this by applying the principle of least privilege to network traffic: hosts communicate only with the specific peers they need, on the specific ports they need, and all other traffic is denied.

Implementations span multiple layers:

- **VLAN segmentation:** Hardware-layer isolation of network segments. Works at L2; simple but coarse-grained.
- **Security zones:** Logical groupings of hosts by trust level. Traffic between zones goes through a firewall. Provides coarse east-west control.
- **Micro-segmentation:** Fine-grained policy per workload, enforced by the hypervisor or kernel. Each VM/container/pod has its own firewall policy. The most effective model for cloud and container environments.
- **Zero-trust networking:** No implicit trust based on network location. Every connection is authenticated, authorised, and encrypted regardless of source network.

**Target systems:** Physical networks (VLAN, ACL); VMware NSX, AWS VPCs with Security Groups; Kubernetes NetworkPolicy and Cilium; nftables and iptables for host-level segmentation; Palo Alto PAN-OS for security zones.

## Threat Model

- **Adversary 1 — Lateral movement from compromised web tier:** An attacker compromises a web application server. On a flat network, they pivot directly to the database server, the internal admin portal, and the CI/CD system — all reachable from the web server's IP.
- **Adversary 2 — Container-to-container attack:** A containerised application is compromised via a dependency vulnerability. The attacker uses the container's network connectivity to probe adjacent containers in the same pod network, reaching a metadata service or another application's API.
- **Adversary 3 — Workstation-to-server attack:** An employee's workstation is phished. The attacker uses the workstation's trusted network position to connect to SMB shares, RDP servers, and internal admin interfaces inaccessible from the internet.
- **Adversary 4 — VLAN hopping:** An attacker on a misconfigured trunk port sends double-tagged 802.1Q frames to reach a different VLAN. Without additional firewall controls at the L3 boundary, they access a "segregated" segment.
- **Adversary 5 — East-west exfiltration:** Malware on a compromised host sends data to an adjacent internal host (acting as a staging server) before exfiltrating to the internet. Perimeter controls only see the final hop; the internal exfil is invisible.
- **Access level:** Adversaries 1, 2, and 3 start with one compromised host. Adversary 4 needs physical or logical access to a switch trunk port. Adversary 5 has network access.
- **Objective:** Reach high-value targets (databases, credentials stores, domain controllers) by traversing internal networks from the initial compromise.
- **Blast radius:** On a flat network, one compromised host provides lateral movement access to every host on the same L2 segment. Micro-segmentation limits this to only the explicit paths the attacker controls.

## Configuration

### Step 1: Security Zone Model

Define security zones based on trust level and data sensitivity:

```yaml
# network-zones.yaml — zone definitions and inter-zone policy.
zones:
  - name: dmz
    description: "Internet-facing services"
    trust_level: 0
    examples: ["Web servers", "API gateways", "WAF"]
    allowed_inbound: ["internet"]
    allowed_outbound: ["app-tier"]

  - name: app-tier
    description: "Application servers; no direct internet access"
    trust_level: 1
    examples: ["Backend APIs", "Worker processes"]
    allowed_inbound: ["dmz"]
    allowed_outbound: ["data-tier", "management"]

  - name: data-tier
    description: "Databases, message queues, caches"
    trust_level: 2
    examples: ["PostgreSQL", "Redis", "Kafka"]
    allowed_inbound: ["app-tier"]  # Only app servers can reach data tier.
    allowed_outbound: ["management"]  # Only for monitoring.

  - name: management
    description: "Monitoring, logging, CI/CD — high trust"
    trust_level: 3
    examples: ["Prometheus", "Loki", "Jenkins", "Vault"]
    allowed_inbound: ["all-zones"]  # Can receive metrics from all zones.
    allowed_outbound: ["all-zones"] # Can reach all zones for management.

  - name: workstations
    description: "Developer workstations — untrusted"
    trust_level: 0
    allowed_inbound: []
    allowed_outbound: ["management"]  # Only to internal tooling via VPN.
    # NOT allowed direct access to: app-tier, data-tier.
```

### Step 2: AWS VPC Segmentation with Security Groups

```hcl
# terraform/network/security-groups.tf

# Web tier: accepts HTTP/HTTPS from internet, all outbound to app tier.
resource "aws_security_group" "web_tier" {
  name   = "web-tier"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    # Only to app tier; NOT to data tier directly.
  }
}

# App tier: accepts from web tier only; connects to data tier.
resource "aws_security_group" "app_tier" {
  name   = "app-tier"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
    # No ingress from internet; only from web tier.
  }

  egress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.data_tier.id]
  }
}

# Data tier: accepts only from app tier.
resource "aws_security_group" "data_tier" {
  name   = "data-tier"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    # No ingress from web tier; no ingress from workstations.
  }

  # No egress rules — data tier does not initiate connections.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = []  # Deny all egress.
  }
}
```

### Step 3: Kubernetes Micro-segmentation with Network Policies

Apply micro-segmentation at the pod level using Kubernetes NetworkPolicy:

```yaml
# Default deny all ingress and egress in every namespace.
# Apply before any other policies to ensure explicit-allow-only model.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector: {}   # Selects all pods in the namespace.
  policyTypes:
    - Ingress
    - Egress

---
# Allow the payments API to receive from the API gateway.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-ingress
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: payments-api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: api-gateway
          podSelector:
            matchLabels:
              app: envoy-gateway
      ports:
        - port: 8080

---
# Allow payments API to reach its database only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-payments-egress
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: payments-api
  policyTypes:
    - Egress
  egress:
    # Database access.
    - to:
        - podSelector:
            matchLabels:
              app: payments-db
      ports:
        - port: 5432
    # DNS resolution (required for service discovery).
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - port: 53
          protocol: UDP
```

### Step 4: Host-Level Micro-segmentation with nftables

For bare-metal or VM hosts without a container orchestrator:

```bash
# /etc/nftables.conf — micro-segmentation for an application server.

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    # Established connections.
    ct state established,related accept

    # Loopback.
    iifname "lo" accept

    # SSH: only from bastion host.
    tcp dport 22 ip saddr 10.0.100.10 accept
    tcp dport 22 drop  # Reject SSH from all other sources.

    # Application port: only from load balancer subnet.
    tcp dport 8080 ip saddr 10.0.10.0/24 accept

    # Metrics scrape: only from monitoring server.
    tcp dport 9090 ip saddr 10.0.200.5 accept

    # ICMP: allow ping from management network only.
    icmp type echo-request ip saddr 10.0.200.0/24 accept

    # Drop everything else.
  }

  chain output {
    type filter hook output priority 0; policy drop;

    # Established connections.
    ct state established,related accept
    iifname "lo" accept

    # Database: only to the specific database server.
    tcp dport 5432 ip daddr 10.0.30.10 accept

    # External API: only to approved endpoint.
    tcp dport 443 ip daddr 192.0.2.100 accept

    # DNS: only to internal resolver.
    udp dport 53 ip daddr 10.0.0.53 accept
    tcp dport 53 ip daddr 10.0.0.53 accept

    # NTP: only to internal NTP server.
    udp dport 123 ip daddr 10.0.0.10 accept

    # Drop all other outbound.
  }
}
```

### Step 5: East-West Visibility and Detection

Segmentation only works if you can detect violations:

```bash
# Enable connection tracking logging for rejected packets.
# nftables: log dropped connections for investigation.
table inet filter {
  chain input {
    # ... accept rules ...
    log prefix "nft-input-drop: " flags all drop
  }
  chain output {
    # ... accept rules ...
    log prefix "nft-output-drop: " flags all drop
  }
}

# Ship firewall drop logs to SIEM.
# /etc/rsyslog.d/40-nftables.conf
:msg, contains, "nft-" /var/log/nftables.log
:msg, contains, "nft-" @syslog.internal.example.com:514
```

```python
# east_west_analyser.py — detect unexpected lateral movement.
# Parse firewall drop logs for patterns.

import re
from collections import defaultdict
from datetime import datetime

DROP_PATTERN = re.compile(
    r'nft-output-drop.*SRC=(\S+) DST=(\S+) .* DPORT=(\d+)'
)

def analyse_drops(log_lines: list[str]) -> dict:
    """Returns hosts attempting connections to unexpected destinations."""
    attempts = defaultdict(list)

    for line in log_lines:
        match = DROP_PATTERN.search(line)
        if match:
            src, dst, dport = match.groups()
            attempts[src].append({"dst": dst, "dport": int(dport)})

    # Flag hosts with many different destination attempts (scanning behaviour).
    suspicious = {
        src: conns
        for src, conns in attempts.items()
        if len(set(c["dst"] for c in conns)) > 10   # >10 unique destinations.
    }
    return suspicious
```

### Step 6: VLAN Security

```
# Cisco IOS: VLAN best practices.

# 1. Disable unused ports and assign to a dead VLAN.
interface range GigabitEthernet 1/0/24 - 48
  shutdown
  switchport access vlan 999   # Dead VLAN — no routing.

# 2. Disable VLAN 1 on all trunk ports (prevent VLAN 1 hopping).
interface GigabitEthernet 1/0/1
  switchport trunk allowed vlan remove 1

# 3. Set native VLAN to a dedicated, unused VLAN on all trunks.
interface GigabitEthernet 1/0/1
  switchport trunk native vlan 999

# 4. Use Private VLANs for isolation within a segment (e.g., DMZ hosts).
# Primary VLAN 100; isolated secondary 101.
vlan 100
  private-vlan primary
vlan 101
  private-vlan isolated

# 5. Enable DHCP snooping (prevents rogue DHCP servers).
ip dhcp snooping
ip dhcp snooping vlan 10,20,30

# 6. Enable Dynamic ARP Inspection (prevents ARP spoofing).
ip arp inspection vlan 10,20,30
```

### Step 7: Segmentation Validation Testing

```bash
#!/bin/bash
# validate-segmentation.sh — test that firewall rules are enforced as intended.

# Test that web server CANNOT reach database directly.
# Run from the web server host.
test_blocked() {
  local TARGET_IP=$1
  local TARGET_PORT=$2
  local DESCRIPTION=$3

  timeout 3 bash -c "echo >/dev/tcp/${TARGET_IP}/${TARGET_PORT}" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "FAIL: $DESCRIPTION — connection succeeded (should be blocked)"
  else
    echo "PASS: $DESCRIPTION — correctly blocked"
  fi
}

test_blocked "10.0.30.10" "5432" "Web tier → Database (should be blocked)"
test_blocked "10.0.200.5"  "22"  "Web tier → Monitoring SSH (should be blocked)"
test_blocked "10.0.100.50" "80"  "Web tier → Workstation (should be blocked)"

# Test that app server CAN reach database.
test_allowed() {
  local TARGET_IP=$1
  local TARGET_PORT=$2
  local DESCRIPTION=$3

  timeout 3 bash -c "echo >/dev/tcp/${TARGET_IP}/${TARGET_PORT}" 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "PASS: $DESCRIPTION — connection allowed"
  else
    echo "FAIL: $DESCRIPTION — connection blocked (should be allowed)"
  fi
}

test_allowed "10.0.30.10" "5432" "App tier → Database (should be allowed)"
```

### Step 8: Telemetry

```
network_segmentation_drops_total{src_zone, dst_zone, port}     counter
network_lateral_movement_attempts_total{src_host, dst_host}    counter
network_policy_violations_total{namespace, src_pod, dst_pod}   counter
network_zone_traffic_bytes{src_zone, dst_zone, direction}      counter
vlan_arp_inspection_drops_total{vlan}                          counter
firewall_policy_changes_total{policy, change_type}             counter
```

Alert on:

- `network_lateral_movement_attempts_total` — a host is making connection attempts to multiple unexpected destinations; possible scanning.
- `network_policy_violations_total` — Kubernetes NetworkPolicy drop; a pod is attempting connections outside its allowed paths.
- `network_zone_traffic_bytes{src_zone="dmz",dst_zone="data-tier"}` — direct DMZ to data tier traffic; firewall policy bypass.
- `vlan_arp_inspection_drops_total` spike — ARP spoofing attempt detected.
- Firewall policy change outside change management window — investigate immediately.

## Expected Behaviour

| Signal | Flat network | Segmented network |
|--------|-------------|-------------------|
| Compromised web server reaches database | Direct TCP connection succeeds | Firewall blocks; no path from web tier to data tier |
| Container scans adjacent pods | All pods reachable via pod CIDR | NetworkPolicy default-deny blocks all unexpected connections |
| Workstation reaches internal API | Direct connection from workstation IP | Workstation zone has no route to app tier; rejected |
| VLAN hopping from DMZ | Double-tagged frame reaches other VLAN | Native VLAN hardened; VLAN 1 disabled on trunks |
| East-west exfiltration via staging host | Undetected | Firewall drop log detects unexpected outbound; alert fires |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Default-deny NetworkPolicy | All lateral movement blocked by default | Every permitted path must be explicitly defined | Use a policy generator to bootstrap from existing traffic patterns |
| nftables output filtering | Prevents egress to unexpected destinations | Legitimate service calls must be whitelisted | Start with monitoring-only mode; add drop after baseline established |
| Security groups per tier | AWS-native; no additional tooling | Security group limits (5 per ENI by default) | Use prefix lists; request limit increase for complex topologies |
| Micro-segmentation at pod level | Finest granularity; per-workload | Most complex to manage; policy proliferation | Automate via Cilium or Kyverno; generate policies from service mesh telemetry |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| NetworkPolicy too restrictive | Application cannot reach dependency | Connection timeout errors; pod health check fails | Add specific allow rule; check Cilium/Calico policy audit log for drops |
| Security group missing rule | New service cannot connect to dependency | Connection refused from new service | Add specific SG rule; use Infrastructure as Code to enforce intent |
| VLAN misconfiguration | Traffic from one zone reaches another unexpectedly | Unexpected east-west traffic in firewall logs | Audit VLAN trunk configuration; validate with segmentation test script |
| Default-deny applied to kube-system | CoreDNS unreachable; all DNS fails | DNS resolution failure across cluster | Exclude kube-system from default-deny; add explicit DNS egress rule |

## Related Articles

- [Zero Trust Networking](/articles/cross-cutting/zero-trust-networking/)
- [Cilium Network Policy](/articles/kubernetes/cilium-network-policy/)
- [WireGuard Mesh Networking](/articles/network/wireguard-mesh/)
- [nftables Firewall Hardening](/articles/linux/nftables/)
- [Istio Egress Gateway](/articles/network/istio-egress-gateway/)
