---
title: "Detecting Harvest-Now-Decrypt-Later: Monitoring for Quantum-Era Adversary Collection"
description: "Nation-state adversaries are actively recording encrypted traffic today for future quantum decryption. HNDL attacks are detectable through anomalous network tap placement, bulk TLS session recording patterns, and unusual data volume exfiltration. This guide covers HNDL threat indicators, network monitoring for bulk collection behaviour, and using PQC adoption as a detection tripwire."
slug: harvest-now-decrypt-later-detection
date: 2026-05-08
lastmod: 2026-05-08
category: observability
tags:
  - harvest-now-decrypt-later
  - quantum-security
  - threat-detection
  - network-monitoring
  - advanced-persistent-threat
personas:
  - security-engineer
  - security-analyst
article_number: 637
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/harvest-now-decrypt-later-detection/
---

# Detecting Harvest-Now-Decrypt-Later: Monitoring for Quantum-Era Adversary Collection

## Problem

Harvest-Now-Decrypt-Later (HNDL) is not a theoretical future concern. NSA, CISA, and NCSC advisories published between 2022 and 2025 explicitly identify it as a current, active threat. Nation-state adversaries with projected access to cryptographically relevant quantum computers (CRQC) within a 5–15 year window are recording encrypted traffic today — banking on the ability to decrypt it retroactively once quantum compute capability matures. The NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) guidance and CISA's post-quantum cryptography roadmap both frame HNDL as a present operational threat, not a future planning problem.

The core asymmetry that makes HNDL dangerous is that **the attacker bears the cost today and collects value later**. An adversary recording TLS sessions in 2026 does not need to break any encryption at the time of capture. The value proposition improves as the data ages: credentials that cannot be rotated, encryption keys embedded in firmware, personally identifiable information subject to decade-long re-identification risk, classified communications, and proprietary algorithms that retain competitive or intelligence value for years all become more valuable as decryption capability approaches.

**What makes traffic worth harvesting:**

- Government communications encrypted with classical algorithms (RSA-2048, ECDH on P-256) before PQC migration is complete
- Long-lived credentials: API keys, device certificates with multi-year validity, private keys for code signing
- Healthcare data subject to 50-year retention requirements, where the PII remains actionable indefinitely
- Financial transaction data whose retroactive exposure enables fraud, insider trading reconstruction, or sanctions circumvention
- Defence contractor IP: schematics, cryptographic protocols embedded in weapons systems, procurement pricing
- Authentication exchanges that reveal credential structure even when the TLS session is decrypted offline

**The detection challenge:**

Passive traffic interception does not trigger IDS signatures, does not generate authentication events, and does not produce error logs. A fibre tap on a backbone link is invisible to every layer of conventional security monitoring. This is the canonical argument against investing in HNDL detection: the adversary leaves no footprints at the point of capture.

That framing is incomplete. While the passive capture itself may be invisible, the full adversary operation generates detectable signals at several stages:

1. The infrastructure used to capture traffic must be installed somewhere — physically or logically
2. Captured traffic must be stored and eventually exfiltrated to the adversary's controlled environment
3. Adversaries attempting to reduce future decryption cost may actively interfere with TLS negotiation
4. Internal forwarding or aggregation infrastructure on compromised networks has a network-visible footprint
5. Migration to post-quantum cryptography creates a new category of detectable downgrade attacks

**Target systems:** Enterprise networks with high-value data flows; ISP and cloud infrastructure peering points; any organisation that the NSA's CNSA 2.0 guidance applies to (national security systems, defence contractors, critical infrastructure operators). The monitoring stack addressed here spans Zeek, Suricata, auditd, Falco, and Prometheus.

## Threat Model

**Adversary 1 — Nation-state with internet exchange access:**
A sophisticated state actor with lawful or covert access to an internet exchange point or submarine cable landing station installs passive optical splitters. All traffic transiting that exchange — including TLS-encrypted sessions between cloud regions and corporate VPN tunnels — is copied to a bulk collection system. No active exploitation occurs. The adversary archives sessions for later decryption. Target data: government agency communications, financial institution inter-bank messaging, healthcare data in transit. Detection surface: anomalous flows originating from the IXP, unexpected traffic volume at border routers, BGP route manipulation that redirects traffic through collection infrastructure.

**Adversary 2 — Insider threat on core network infrastructure:**
A network engineer with legitimate access to data centre switching infrastructure installs a hardware tap device on a trunk port or mirror port on a core switch. The device passively copies traffic to a hidden network segment or records to onboard storage for periodic physical retrieval. Detection surface: physical audit of switch rack cabling, unexpected MAC addresses on trunk ports, new SPAN sessions created without change management tickets, promiscuous mode on unexpected interfaces.

**Adversary 3 — Supply chain firmware modification:**
Network equipment shipped from a manufacturer or transiting a logistics chain is modified so that firmware copies traffic to a covert channel — a hidden management interface, DNS exfiltration tunnel, or periodic upload to a cloud storage endpoint. The device functions normally in all other respects. Detection surface: firmware hash mismatch against vendor-published golden hashes, unexpected outbound connections from network infrastructure, unusual DNS query patterns from routers or switches.

**Adversary 4 — Cloud infrastructure compromise:**
An adversary with access to a hyperscaler's internal switching fabric — through employee compromise, supply chain access, or exploitation of cloud management plane vulnerabilities — records traffic between cloud tenants or between cloud regions at the hypervisor layer. Detection surface: anomalous traffic volumes in cloud flow logs (VPC Flow Logs, Azure NSG Flow Logs), unexpected inter-region data transfer costs, TLS inspection artefacts visible in client-side TLS fingerprinting.

**Adversary 5 — Active key exchange downgrade:**
An adversary conducting active HNDL — rather than pure passive collection — attempts to downgrade TLS sessions from PQC hybrid key exchange (X25519MLKEM768) to classical-only ECDH. This makes captured sessions cheaper to decrypt when quantum compute is available. Detection surface: JA3/JA4 anomalies, unexpected cipher suite negotiation failures, clients that normally negotiate X25519MLKEM768 suddenly negotiating X25519-only.

## Configuration

### Detecting Network Tap Placement

**Physical and logical network auditing** is the first line of defence against insider tap installation. Establish a baseline of physical fibre connections, switch port assignments, and MAC address tables across all core network equipment. Any deviation from that baseline — new fibre strands on a trunk, an unexpected device on a switch port, a new MAC appearing on a trunk port — is a detection event.

```bash
# Audit switch MAC address tables via SNMP (run against all core switches).
# Alert on MACs not in the authorised device inventory.
snmpwalk -v3 -u monitor_user -l authPriv \
  -a SHA -A "$AUTH_PASS" -x AES -X "$PRIV_PASS" \
  core-switch-01 1.3.6.1.2.1.17.4.3.1.1 \
  | awk '{print $NF}' | sort > /var/lib/mac-audit/$(date +%Y%m%d).txt

# Compare against yesterday's baseline.
diff /var/lib/mac-audit/$(date -d yesterday +%Y%m%d).txt \
     /var/lib/mac-audit/$(date +%Y%m%d).txt
```

**Detecting promiscuous mode on network interfaces** is a reliable indicator of passive capture tooling. Legitimate systems do not run network interfaces in promiscuous mode outside explicitly documented packet capture scenarios. Audit this continuously.

```bash
# Auditd rule: alert when any interface enters promiscuous mode.
# /etc/audit/rules.d/promisc.rules
-a always,exit -F arch=b64 -S setsockopt \
  -F a2=100 -k promisc_mode_enable
# Alternatively, monitor IFF_PROMISC flag via ip link show.
```

```bash
# Cron job to detect promiscuous interfaces (run every 5 minutes via systemd timer).
ip link show | grep -i promisc | while read -r line; do
  iface=$(echo "$line" | awk -F: '{print $2}' | xargs)
  echo "ALERT: Interface $iface in PROMISC mode on $(hostname) at $(date)" \
    >> /var/log/promisc-alert.log
  # Forward to SIEM via syslog.
  logger -p security.alert -t promisc-monitor \
    "PROMISC mode detected on $iface"
done
```

**Monitoring for unexpected SPAN sessions on managed switches** requires integration with your network management system. SPAN (Switched Port Analyser) sessions are the legitimate mechanism for packet capture on switches — they are also the mechanism an attacker uses to mirror traffic to a collection device. SPAN session creation should generate a change management alert.

```bash
# Example: detect new SPAN sessions via Cisco IOS RESTCONF.
curl -s -u "$NMS_USER:$NMS_PASS" \
  "https://core-switch-01/restconf/data/Cisco-IOS-XE-monitor:monitor-session" \
  | jq '.["Cisco-IOS-XE-monitor:monitor-session"][] | {id: .id, source: .source, destination: .destination}'
```

**Firmware integrity monitoring** closes the supply chain adversary threat. Network vendors publish SHA-256 hashes for all firmware releases. Periodic automated verification that running firmware matches a known-good hash is a necessary control.

```bash
# Collect running firmware version and hash via SNMP or RESTCONF.
# Compare against a local database of vendor-published hashes.
RUNNING_HASH=$(ssh -o StrictHostKeyChecking=yes network-admin@router-01 \
  "show version | include System image file")
grep "$RUNNING_HASH" /var/lib/firmware-hashes/cisco-ios-xe-verified.txt \
  || logger -p security.crit -t firmware-integrity \
       "FIRMWARE HASH MISMATCH on router-01: $RUNNING_HASH not in verified list"
```

### Detecting Bulk TLS Session Recording

**Zeek network monitoring** provides the richest source of TLS session metadata. The `ssl.log` captures cipher suite negotiation, certificate chains, TLS version, and key exchange group for every TLS session. Monitoring for anomalies in these fields detects both active downgrade attempts and infrastructure that may be recording sessions.

```zeek
# /etc/zeek/site/hndl-detection.zeek
# Alert on TLS 1.2 sessions where TLS 1.3 is expected.
# Adversaries may attempt to force TLS 1.2 negotiation to obtain
# sessions that use static RSA key exchange (no forward secrecy).

event ssl_established(c: connection) {
  if (c$ssl$version == "TLSv12") {
    # Check if client advertised TLS 1.3 support.
    # Downgrade from 1.3 to 1.2 on a service that should enforce 1.3
    # is a potential active HNDL interception indicator.
    if (c$ssl$client_hello_extensions["supported_versions"] ?? F) {
      NOTICE([$note=SSL::TLS_Downgrade_Detected,
              $conn=c,
              $msg=fmt("TLS 1.2 session established despite client supporting 1.3: %s -> %s",
                       c$id$orig_h, c$id$resp_h),
              $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }
  }
}
```

```zeek
# Monitor for cipher suites that lack forward secrecy.
# Static RSA key exchange (TLS_RSA_WITH_*) means a captured session
# can be decrypted retroactively if the server's private key is compromised.

event ssl_established(c: connection) {
  local cipher = c$ssl$cipher;
  if (/^TLS_RSA_WITH_/ in cipher) {
    NOTICE([$note=SSL::No_Forward_Secrecy,
            $conn=c,
            $msg=fmt("Non-forward-secret cipher negotiated: %s on %s",
                     cipher, c$id$resp_h),
            $identifier=cat(c$id$resp_h, cipher)]);
  }
}
```

**Suricata rules for TLS recording artefacts** detect patterns consistent with bulk recording infrastructure or MITM insertion.

```yaml
# /etc/suricata/rules/hndl.rules

# Alert on JA3 hashes associated with known TLS inspection proxies.
# Build and maintain a list of JA3 hashes from MITM/inspection appliances
# observed in your environment that should NOT appear on sensitive flows.
alert tls any any -> $HIGH_VALUE_SERVERS any (
  msg:"HNDL Possible TLS MITM on high-value server";
  ja3.hash; content:"known_mitm_ja3_hash_here";
  sid:9000001; rev:1; classtype:policy-violation;
)

# Alert on abnormally high volume of TLS ClientHello from a single source.
# Bulk session recording infrastructure may replay collected ClientHellos
# or scan for negotiation capabilities.
alert tls any any -> any any (
  msg:"HNDL Bulk TLS ClientHello scanning";
  detection_filter: track by_src, count 500, seconds 60;
  sid:9000002; rev:1; classtype:network-scan;
)
```

**Detecting PCAP archives in outbound flows** using DPI catches adversaries exfiltrating collected traffic archives. Libpcap-format files have a well-known 4-byte magic number (`0xd4c3b2a1` or `0xa1b2c3d4`). Detecting this signature in outbound network flows is a high-confidence indicator that captured packet data is being exfiltrated.

```yaml
# Suricata rule: detect pcap magic bytes in outbound connections.
alert tcp $INTERNAL_NET any -> $EXTERNAL_NET any (
  msg:"HNDL Possible PCAP file exfiltration";
  flow:established,to_server;
  content:"|d4 c3 b2 a1|"; offset:0; depth:4;
  sid:9000003; rev:1; classtype:data-loss;
)
alert tcp $INTERNAL_NET any -> $EXTERNAL_NET any (
  msg:"HNDL Possible PCAP file exfiltration (big-endian magic)";
  flow:established,to_server;
  content:"|a1 b2 c3 d4|"; offset:0; depth:4;
  sid:9000004; rev:1; classtype:data-loss;
)
```

**Monitoring for sustained symmetric high-bandwidth flows** identifies traffic patterns consistent with bulk collection forwarding. A legitimate internal service rarely generates a sustained 10+ Gbps symmetric flow to an unexpected destination. Netflow/IPFIX analysis for these patterns is achievable with ntopng, Grafana + flow data, or purpose-built tools.

```bash
# Using nfdump to find flows with sustained high bandwidth to unexpected destinations.
# Run against exported NetFlow data hourly.
nfdump -R /var/lib/nfcapd/$(date +%Y/%m/%d)/ \
  -s srcip/bytes \
  -n 20 \
  -o "fmt:%sa %da %byt %fl" \
  'bytes > 10000000000 and not src net 10.0.0.0/8' \
  | tee /var/log/hndl-flow-anomalies.log
```

### PQC Adoption as a Detection Tripwire

The deployment of post-quantum cryptography creates a new and powerful detection capability: **key exchange downgrade detection**. Once your services and clients negotiate PQC hybrid key exchange (X25519MLKEM768 per NIST/IETF standardisation), any session that should be negotiating X25519MLKEM768 but instead falls back to classical X25519-only is an anomaly worth investigating. This anomaly is consistent with an active HNDL adversary intercepting the TLS handshake and stripping PQC key share extensions.

```zeek
# /etc/zeek/site/pqc-downgrade-detection.zeek
# Track expected PQC negotiation for designated high-value services.
# Alert when a PQC-capable client connects to a PQC-capable server
# but negotiates classical-only key exchange.

const pqc_required_servers: set[addr] = {
  10.0.1.10,  # Payment processing API
  10.0.1.11,  # Authentication service
  10.0.1.12,  # Secrets management (Vault)
} &redef;

# X25519MLKEM768 = TLS group ID 25497 (0x6399)
# X25519         = TLS group ID 29
event ssl_established(c: connection) {
  if (c$id$resp_h in pqc_required_servers) {
    local key_group = c$ssl$curve ?? "";
    if (key_group != "X25519MLKEM768" && key_group != "") {
      NOTICE([$note=SSL::PQC_Downgrade_Detected,
              $conn=c,
              $msg=fmt("PQC downgrade on high-value server %s: negotiated %s not X25519MLKEM768",
                       c$id$resp_h, key_group),
              $identifier=cat(c$id$orig_h, c$id$resp_h),
              $suppress_for=5min]);
    }
  }
}
```

**Prometheus metrics for PQC adoption posture** provide a continuous audit of migration progress and create a dashboard visible to security leadership.

```yaml
# Prometheus scrape config for a TLS endpoint scanner.
# Use tlsscan or a custom exporter that probes TLS endpoints
# and records key exchange groups negotiated.
scrape_configs:
  - job_name: tls_endpoint_pqc_audit
    static_configs:
      - targets:
          - tls-scanner:9115
    metrics_path: /probe
    params:
      module: [tls_connect]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - target_label: instance
        source_labels: [__param_target]
```

```promql
# Alert: service that should support PQC is negotiating classical-only.
# Requires custom exporter that records negotiated key exchange group.
alert: PQCDowngradeOnCriticalService
expr: |
  tls_endpoint_key_exchange_group{
    service=~"payment|auth|vault|secrets",
    key_exchange_group!="X25519MLKEM768"
  } == 1
for: 5m
labels:
  severity: critical
  category: hndl
annotations:
  summary: "PQC key exchange not negotiated on {{ $labels.service }}"
  description: >
    Service {{ $labels.service }} is negotiating {{ $labels.key_exchange_group }}
    instead of X25519MLKEM768. This may indicate active key exchange downgrade
    by an HNDL adversary or a misconfiguration. Investigate immediately.
```

### Endpoint Indicators of Collection Infrastructure

**Falco rules** detect processes that acquire `CAP_NET_RAW` or open raw sockets outside expected contexts. tcpdump, Wireshark, and custom collection tools all require these capabilities. Their presence on production servers — outside an explicitly approved capture window — is an anomaly.

```yaml
# /etc/falco/rules.d/hndl.yaml
- rule: Unexpected Network Capture Process
  desc: >
    A process is performing network capture outside approved tooling.
    Legitimate capture only occurs during approved maintenance windows
    from the designated network-ops user.
  condition: >
    evt.type in (socket, setsockopt) and
    evt.arg.domain = AF_PACKET and
    not proc.name in (allowed_capture_tools) and
    not user.name = "network-ops" and
    container.id = host
  output: >
    Network capture socket opened by unexpected process
    (proc=%proc.name pid=%proc.pid user=%user.name
     container=%container.id cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [network, hndl, capture]

- list: allowed_capture_tools
  items: [tcpdump, tshark, zeek, suricata]

- rule: Interface Placed in Promiscuous Mode
  desc: A network interface was placed in promiscuous mode.
  condition: >
    evt.type = ioctl and
    evt.arg.request = SIOCSIFFLAGS and
    evt.arg.argument contains "IFF_PROMISC" and
    not proc.name in (allowed_capture_tools)
  output: >
    Interface set to promiscuous mode
    (proc=%proc.name pid=%proc.pid user=%user.name)
  priority: CRITICAL
  tags: [network, hndl, promisc]
```

**Auditd rules** for raw socket creation and interface flag modification provide a kernel-level audit trail that persists even if the collecting process attempts to clean up after itself.

```bash
# /etc/audit/rules.d/hndl.rules

# Monitor raw socket creation (AF_PACKET = 17, SOCK_RAW = 3).
-a always,exit -F arch=b64 -S socket \
  -F a0=17 -F a1=3 -k raw_socket_create

# Monitor promiscuous mode changes via ioctl SIOCSIFFLAGS (0x8914).
-a always,exit -F arch=b64 -S ioctl \
  -F a1=0x8914 -k interface_flags_change

# Monitor access to /proc/net/dev — collection tools read this
# to enumerate available interfaces.
-w /proc/net/dev -p r -k proc_net_dev_read
```

### Monitoring Quantum Vulnerability Posture

Tracking the percentage of TLS endpoints that have migrated to PQC key exchange provides a continuous risk metric. As the percentage of classical-only endpoints declines, the HNDL attack surface shrinks. It also gives you a defined remediation timeline to enforce.

```bash
# Weekly scan of all internal TLS endpoints for PQC support.
# Requires OpenSSL 3.3+ or a recent Go TLS scanner with ML-KEM support.
while IFS= read -r host; do
  result=$(openssl s_client -connect "$host" \
    -groups X25519MLKEM768:X25519 \
    -brief 2>&1 | grep "Server Temp Key")
  if echo "$result" | grep -q "ML-KEM"; then
    echo "$host,pqc_supported" >> /var/lib/pqc-audit/$(date +%Y%m%d).csv
  else
    echo "$host,classical_only" >> /var/lib/pqc-audit/$(date +%Y%m%d).csv
  fi
done < /etc/hndl-monitoring/tls-endpoints.txt

# Produce a metric for Prometheus pushgateway.
PQC_COUNT=$(grep -c pqc_supported /var/lib/pqc-audit/$(date +%Y%m%d).csv)
TOTAL_COUNT=$(wc -l < /var/lib/pqc-audit/$(date +%Y%m%d).csv)
echo "tls_pqc_adoption_ratio $(echo "scale=4; $PQC_COUNT/$TOTAL_COUNT" | bc)" \
  | curl --data-binary @- http://pushgateway:9091/metrics/job/pqc_audit
```

## Expected Behaviour

The following table maps HNDL indicators to detection methods, alert thresholds, and expected response actions.

| HNDL Indicator | Detection Method | Alert Threshold | Response Action |
|---|---|---|---|
| New MAC address on trunk port | SNMP MAC table diff vs baseline | Any deviation from approved baseline | Network ops investigation; physical inspection of port |
| Interface in promiscuous mode | auditd `SIOCSIFFLAGS` + Falco rule | Any occurrence outside approved capture window | Immediate incident response; isolate host |
| Unexpected SPAN session on switch | RESTCONF/NETCONF polling vs change management | New session not in approved tickets | Escalate to network security; verify session legitimacy |
| Firmware hash mismatch on network device | Vendor hash comparison | Any hash mismatch | Device quarantine; vendor engagement; forensic image |
| TLS 1.2 session where 1.3 expected | Zeek `ssl.log` TLS version anomaly | Any session to TLS-1.3-enforced service | Investigate source; check for MITM insertion |
| Non-forward-secret cipher negotiated | Zeek `ssl.log` cipher suite monitoring | Any `TLS_RSA_WITH_*` cipher on internal services | Remediate server config; investigate clients negotiating it |
| PQC key exchange downgrade | Zeek PQC group monitoring + Prometheus alert | Any classical-only session on PQC-required service | Immediate investigation; potential active MITM |
| PCAP magic bytes in outbound flow | Suricata DPI rule | Any occurrence | Immediate data exfiltration response; block source |
| JA3 hash matching known MITM tool | Suricata JA3 rule | Any match against MITM fingerprint list | Investigate source host; check for rogue inspection proxy |
| Sustained symmetric high-bandwidth flow | Netflow anomaly detection | >10 Gbps symmetric to unexpected destination | Traffic analysis; check BGP routes; contact upstream |
| CAP_NET_RAW on unexpected process | Falco `AF_PACKET` socket rule | Any occurrence outside approved tool list | Kill process; investigate host for collection tooling |
| Classical-only TLS endpoints > threshold | Prometheus PQC adoption metric | >5% of critical services not PQC-capable past migration deadline | Escalate to service owners; accelerate PQC migration |
| Bulk compressed outbound transfer from network device | Netflow + SNMP interface counters | Unusual outbound volume from router/switch management interface | Firmware integrity check; contact vendor PSIRT |

## Trade-offs

**Detection coverage vs false positive rate.** Passive tap placement genuinely may not generate any detectable signal. A passive optical splitter on a fibre pair inside a data centre — installed by an insider with physical access during a routine maintenance window — produces no network events, no log entries, and no electrical signature detectable by software. The controls described here dramatically narrow the undetectable attack surface but do not close it entirely. Accepting this limitation is necessary; the alternative is false confidence.

JA3 and JA4 fingerprint-based detection carries a meaningful false positive rate. TLS library updates, OS patches, and application deployments all change TLS fingerprints legitimately. A detection programme built on JA3 matching requires active maintenance of the baseline or it will generate noise that degrades analyst response quality.

PQC downgrade detection is currently hampered by incomplete client and library support. Until X25519MLKEM768 is universally supported across client platforms, alerting on classical-only negotiation for all services will produce false positives from legitimate legacy clients. Scope PQC downgrade alerts narrowly to services where you have verified that all production clients support PQC.

**Network monitoring overhead.** Deep packet inspection sufficient to detect PCAP magic bytes in outbound flows requires stateful reassembly of TCP sessions. At 40+ Gbps link speeds, this is computationally expensive. Deploying DPI-based exfiltration detection should be scoped to egress points for network segments containing high-value data, not applied uniformly across all network links.

**Physical security limitations.** No amount of software monitoring detects a well-placed passive optical splitter on a fibre run that is never digitally audited. Physical security controls — locked cabinets, tamper-evident seals on fibre connections, video monitoring of IDF/MDF rooms, and access logs for all physical network infrastructure — are prerequisites for making software-layer detection meaningful. Physical security is out of scope for this article but is a hard dependency for the controls described here.

## Failure Modes

**Undetectable passive optical taps.** A passive optical splitter installed at a dark-fibre level — in a conduit, at a building entry point, or within a telecommunications carrier's infrastructure — generates no electrical or logical signal. The only detection mechanism is physical inspection of the fibre path, which for carrier-provided circuits may be legally and practically impossible. For government and critical infrastructure operators, this risk is addressed at a policy level through circuit diversity, end-to-end encryption that does not rely on the carrier, and PQC migration to reduce the value of captured sessions.

**Encrypted exfiltration of traffic archives blending with normal traffic.** An adversary exfiltrating a collected PCAP archive via HTTPS to a cloud storage endpoint (S3, Azure Blob, GCS) using a legitimate-looking domain will not be detected by DPI looking for PCAP magic bytes — the content is encrypted. The exfiltration may blend with normal HTTPS egress traffic and be undetectable at the content level. Detection falls back to behavioural anomalies: unusual upload volumes, unexpected data transfer to cloud storage from network infrastructure hosts, or endpoint anomalies on the exfiltrating system.

**Insider threat with legitimate network access.** An adversary who is a legitimate network engineer with authorised access to switches and fibre infrastructure can install collection hardware during an approved change window, document the change as routine maintenance, and exit with no anomaly in any log. This failure mode is addressed through separation of duties (requiring two-person authorisation for changes to core infrastructure), mandatory periodic physical audits of all switching infrastructure, and background reinvestigation programmes for personnel with this level of access. It is not addressable through technical monitoring alone.

**JA3 baseline drift rendering fingerprint detection ineffective.** If the JA3 baseline is not actively maintained as TLS libraries are updated, the alert list becomes either perpetually firing (if updates are not incorporated) or silent (if the baseline is too permissive). Both outcomes degrade the detection capability to zero over time without generating a visible failure signal. Automate baseline updates and require security review of any new JA3 fingerprints being added to the approved list.

**PQC migration lag creating persistent HNDL exposure.** The most consequential failure mode is not a detection failure but a remediation failure. If PQC migration is delayed past the adversary's CRQC acquisition timeline, all classical-only sessions recorded in the interim are retroactively decryptable. Monitoring for PQC adoption percentage with hard deadlines tied to the organisation's quantum risk assessment is the only control here. Detection without remediation does not reduce the HNDL attack surface — it only tells you how large it is.
