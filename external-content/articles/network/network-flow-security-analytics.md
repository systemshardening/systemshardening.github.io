---
title: "Network Flow Analysis: NetFlow, sFlow, and IPFIX for Security Monitoring"
description: "Packet capture is too expensive to run continuously at scale. Network flow records — metadata about every connection without payload content — provide scalable, long-term visibility into who talked to whom, when, and how much data moved. NetFlow, sFlow, and IPFIX are the protocols that make this work."
slug: network-flow-security-analytics
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - netflow
  - sflow
  - ipfix
  - network-monitoring
  - threat-detection
personas:
  - security-engineer
  - network-engineer
article_number: 495
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/network-flow-security-analytics/
---

# Network Flow Analysis: NetFlow, sFlow, and IPFIX for Security Monitoring

## The Problem

Full packet capture (PCAP) is the gold standard for network forensics. It is also prohibitively expensive at any meaningful scale. Capturing and storing raw packets on a 10 Gbps link generates roughly 100 TB per day before compression. Most production environments cannot afford the storage, and even if they could, querying terabytes of PCAP data to investigate an incident takes hours.

The result is a visibility gap: defenders either capture everything for a short retention window (hours to days), capture a small fraction of traffic, or capture nothing at all. In all three cases, an attacker who operates over days or weeks leaves behind no reliable record of their movements.

Network flow analysis closes this gap. Flow records are metadata — source IP, destination IP, ports, protocol, byte count, packet count, timestamps — without payload content. A connection that transfers 4 GB of data becomes a single 200-byte flow record. A 10 Gbps link generates roughly 500 MB of flow data per day at typical traffic patterns. Six months of retention becomes feasible on commodity storage. The payload is gone, but for detecting the *pattern* of attacks — scanning, beaconing, exfiltration, lateral movement — the metadata is sufficient.

Common failure modes this article addresses:

- **No flow export configured.** Linux servers, cloud instances, and Kubernetes nodes generate no flow telemetry by default. The only visibility into network activity is firewall logs, which capture permit/deny decisions but not connection duration, data volume, or traffic patterns.
- **Flows exported but not queried.** A flow collector receives data, but nobody has built detection queries. The data exists and is never used.
- **Detection without enrichment.** Raw flow records contain IP addresses. Without GeoIP, ASN, and threat intelligence enrichment, analysts spend time manually looking up every unfamiliar IP instead of the query doing that work automatically.
- **No baseline, so no anomaly detection.** Thresholds for "large outbound flow" or "high connection fan-out" are guessed rather than derived from measured baselines. This produces either excessive false positives or missed detections.
- **No Kubernetes visibility.** Traditional flow export covers physical and VM network interfaces. Pod-to-pod traffic inside a Kubernetes cluster, and traffic between namespaces, is invisible to host-level flow probes.

**Target systems:** Linux servers (kernel 5.4+), network devices with flow export capability, Kubernetes clusters with Cilium or Calico CNI; flow collectors including ntopng, nProbe, pmacct; Elasticsearch, VictoriaMetrics for storage and querying; Zeek for enriched connection logging.

## Threat Model

- **Adversary 1 — Data exfiltration:** An attacker who has compromised an internal host copies a database dump and transfers it to an external IP. The exfil is a large outbound flow — hundreds of gigabytes to an IP that has never previously received data from this environment.
- **Adversary 2 — C2 beaconing:** Malware on a compromised host phones home at regular intervals: a small HTTPS connection every 60 seconds to a cloud IP. Each individual connection is unremarkable; the *regularity* over hours and days is the signal.
- **Adversary 3 — Internal reconnaissance:** An attacker on a compromised host scans the internal subnet to find additional targets. Port scanning creates a high fan-out pattern: one source IP making connections to hundreds of destination IPs in a short window.
- **Adversary 4 — DNS tunnelling:** An attacker exfiltrates data by encoding it in DNS query names. The payload per query is small, but the aggregate data volume and query frequency to a single nameserver is anomalously high.
- **Adversary 5 — Lateral movement:** A compromised host starts connecting to internal services it has no business reason to reach — SMB to file servers, RDP to workstations, the Kubernetes API server. This shows up as new east-west flows with no historical precedent.
- **Access level:** Adversaries 1–5 are post-compromise, operating from a host already inside the environment.
- **Objective:** Establish persistence, expand access, exfiltrate data.
- **Blast radius without flow analysis:** All five attack patterns proceed undetected. Incident response relies on endpoint telemetry (if deployed) or forensic imaging after the fact. Dwell time averages weeks or months.

## Flow Protocols: NetFlow, sFlow, IPFIX

### NetFlow v5 and v9

NetFlow was developed by Cisco in the 1990s. **NetFlow v5** is fixed-format: 48-byte records containing src/dst IP (IPv4 only), src/dst port, protocol, byte/packet counts, TCP flags, and timestamps. Its simplicity is also its limitation — no IPv6, no MPLS, no extensibility.

**NetFlow v9** (RFC 3954) introduced templates: exporters announce the structure of their records before sending data, allowing arbitrary fields including IPv6 addresses, MPLS labels, VLAN IDs, and BGP next-hop information. Most modern network gear exports v9. Software exporters on Linux should use v9 or IPFIX rather than v5.

### IPFIX (NetFlow v10)

IPFIX (IP Flow Information Export, RFC 7011) is the IETF standardisation of NetFlow v9. The protocol is nearly identical in structure but adds enterprise-specific information elements, variable-length fields, and options templates. IPFIX is the current standard — use it when the exporter and collector both support it.

Key IPFIX capabilities relevant to security:

- **Flow direction** (`flowDirection`): distinguishes ingress from egress flows on the same interface
- **Application ID** (`applicationId`): NBAR-style application classification if the exporter supports it
- **Interface fields** (`ingressInterface`, `egressInterface`): correlates flows to physical or logical interfaces
- **Observation domain ID**: distinguishes flows from different logical exporters on the same physical device

### sFlow

sFlow (RFC 3176) takes a different approach. Instead of tracking every connection as a flow, sFlow **samples packets** — typically 1 in every 1000 or 1 in every 4096 — and exports the raw packet header plus interface counters. This makes sFlow extremely lightweight on the exporting device and suitable for high-speed links (40 Gbps+) where maintaining per-flow state would be prohibitive.

The trade-off is accuracy: a flow that transfers 10 packets may never be sampled. sFlow gives a statistically accurate view of traffic composition but will miss short-lived connections. For security use cases, sFlow is appropriate for traffic volume and protocol distribution monitoring, but NetFlow/IPFIX (which track every flow) are preferred for connection-level threat detection.

| Feature | NetFlow v5 | NetFlow v9 | IPFIX | sFlow |
|---|---|---|---|---|
| IPv6 | No | Yes | Yes | Yes |
| Extensible fields | No | Yes (templates) | Yes (RFC 7012) | Yes |
| Sampling | No | Optional | Optional | Yes (mandatory) |
| Per-packet data | No | No | No | Yes (sampled headers) |
| Standard body | Cisco | Cisco | IETF | sFlow.org |
| Typical use | Legacy gear | Network devices | Modern deployments | High-speed links |

## Generating Flows on Linux

Linux hosts do not export flows by default. Three tools cover the main use cases.

### softflowd: Lightweight Passive Probe

`softflowd` sniffs a network interface and generates flow records from observed connections. It is the simplest option for instrumenting a single server.

```bash
# Install softflowd.
apt-get install softflowd    # Debian/Ubuntu
dnf install softflowd        # RHEL/Rocky

# Export NetFlow v9 to a collector at 192.168.1.100:2055.
softflowd -i eth0 -n 192.168.1.100:2055 -v 9 -t maxlife=60

# Run as a daemon with IPFIX export.
cat /etc/softflowd/softflowd.conf
interface=eth0
host=192.168.1.100:4739
version=10
timeout=maxlife=300

systemctl enable softflowd
systemctl start softflowd
```

`softflowd` uses `libpcap` for packet capture. On busy interfaces it will drop packets — it is not suitable for links above ~1 Gbps. For high-traffic servers, use `pmacct` with kernel-assisted capture.

### pmacct: Production-Grade Flow Exporter

`pmacct` is a full-featured traffic accounting and flow export suite. It supports multiple capture methods including `AF_PACKET`, `PF_RING`, and `DPDK`, making it suitable for 10 Gbps links.

```bash
apt-get install pmacct

# /etc/pmacct/pmacctd.conf — IPFIX export with GeoIP enrichment.
daemonize: true
pidfile: /var/run/pmacctd.pid
interface: eth0
capture_method: AF_PACKET

# Export IPFIX to collector.
plugins: nfprobe
nfprobe_receiver: 192.168.1.100:4739
nfprobe_version: 10
nfprobe_timeouts: expint=60:maxlife=300:tcp.rst=5:tcp.fin=5

# Enrich with GeoIP and BGP ASN.
geoip_ipv4_file: /usr/share/GeoIP/GeoLite2-Country.mmdb
bgp_daemon: true
bgp_daemon_ip: 127.0.0.1
bgp_daemon_port: 179

systemctl enable pmacctd
systemctl start pmacctd
```

### nProbe: Enriched Flow Export with DPI

nProbe (ntop) performs deep packet inspection to add application-layer metadata to flow records: HTTP hostname, DNS query names, TLS SNI, and JA3 TLS fingerprints. This makes flows far more actionable for security — a flow record that includes the TLS SNI and JA3 fingerprint of a C2 connection is much easier to detect than a plain IP:port tuple.

```bash
# nProbe requires ntop subscription for production use; free for lab.
# Export enriched IPFIX with application metadata.
nprobe --interface eth0 \
       --collector-port 4739 \
       --ntopng @192.168.1.100:5556 \
       --flow-version 10 \
       --ndpi-proto-ports /etc/nprobe/ndpi.conf \
       --ja3-as-string \
       --http-parse-response
```

The JA3 fingerprint (`--ja3-as-string`) is particularly useful: it hashes the TLS ClientHello parameters (cipher suites, extensions, elliptic curves) into a 32-character hex string. Known malware families have consistent JA3 fingerprints that appear in threat intelligence feeds regardless of which IP they connect to.

## Flow Collectors and Storage

### ntopng

ntopng provides a web-based flow analysis interface with built-in alerting. It integrates directly with nProbe for enriched flow data and supports IPFIX, NetFlow v5/v9, and sFlow input.

```bash
apt-get install ntopng

# /etc/ntopng/ntopng.conf
-i=@192.168.1.100:2055    # Listen for NetFlow/IPFIX on UDP 2055.
-w=3000                   # Web UI on port 3000.
--community               # Community edition.

# Enable security alerts.
--alerts-manager=sqlite   # Or: elasticsearch, kafka, syslog.
--disable-alerts=false
```

For production environments, ntopng Enterprise adds anomaly detection, historical flow search, and Elasticsearch output. The community edition covers basic flow collection and top-talker analysis.

### Elasticsearch with Flow Input

The Elastic Stack handles flow data through Logstash or the `elastic-agent` with a network flows integration.

```yaml
# logstash-netflow.conf — receive NetFlow/IPFIX, enrich, send to Elasticsearch.
input {
  udp {
    port  => 2055
    codec => netflow {
      versions => [5, 9, 10]
    }
  }
}

filter {
  if [netflow][direction] == 0 {
    mutate { add_field => { "flow_direction" => "ingress" } }
  } else {
    mutate { add_field => { "flow_direction" => "egress" } }
  }

  # GeoIP enrichment on destination.
  geoip {
    source => "[netflow][ipv4_dst_addr]"
    target => "dst_geo"
    fields => ["country_code2", "country_name", "autonomous_system_number",
               "autonomous_system_organization"]
  }

  # Flag RFC 1918 destinations as internal.
  cidr {
    address  => [ "%{[netflow][ipv4_dst_addr]}" ]
    network  => [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ]
    add_tag  => ["internal_dst"]
  }
}

output {
  elasticsearch {
    hosts    => ["https://es-01:9200"]
    index    => "netflow-%{+YYYY.MM.dd}"
    user     => "logstash_writer"
    password => "${LOGSTASH_ES_PASSWORD}"
    ssl_certificate_verification => true
  }
}
```

### Grafana + VictoriaMetrics for Flow Dashboards

For high-volume environments where Elasticsearch becomes expensive, VictoriaMetrics handles time-series flow aggregates efficiently. `pmacct` can write flow summaries directly to VictoriaMetrics via its `prometheus_exporter` plugin.

```yaml
# pmacct plugin for VictoriaMetrics output.
plugins: print
print_output: json
print_refresh_time: 60
print_output_file: /var/log/pmacct/flows_%Y%m%d_%H%M.json

# Or use the native prometheus plugin for scraping.
plugins: prometheus
prometheus_http_port: 9090
prometheus_labels: src_host,dst_host,proto,port
```

Grafana dashboards query VictoriaMetrics for top source/destination pairs, protocol distribution, and byte volume trends. Alert rules on top-N queries detect bandwidth anomalies.

## Security Detection Use Cases

### Data Exfiltration Detection

Large outbound flows to previously unseen external IPs are the primary exfiltration signal.

```
# Elasticsearch DSL — detect large outbound flows to new external destinations.
GET netflow-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "netflow.in_bytes": { "gte": 104857600 } } },
        { "term":  { "flow_direction": "egress" } },
        { "term":  { "tags": "internal_src" } }
      ],
      "must_not": [
        { "term": { "tags": "internal_dst" } }
      ]
    }
  },
  "aggs": {
    "by_dest": {
      "terms": { "field": "netflow.ipv4_dst_addr", "size": 20 }
    }
  }
}
```

A more sophisticated approach tracks the "first seen" date for each (src, dst) pair. Any flow to a destination that has never appeared in the previous 30 days warrants investigation, regardless of size.

### Port Scanning Detection

Port scanning produces a high fan-out ratio: one source IP connecting to many destination IPs or ports in a short time window. A normal host might initiate connections to 10–20 distinct destination IPs per minute; a scanner initiates hundreds.

```bash
# Using nfdump with a NetFlow file — top scanners by destination IP count.
nfdump -r /var/netflow/nfcapd.current -s srcip/bytes -n 20 \
  'proto tcp and (flags S and not flags AFRPU)'

# Detection query: hosts with >200 unique destination IPs in 5 minutes.
nfdump -r /var/netflow/nfcapd.current \
  -A srcip,dstip -s srcip -n 100 \
  -o "fmt:%sa %da %Pf %byt" \
  'not net 0.0.0.0/8'
```

### C2 Beacon Detection

C2 beacons are regular, small, outbound connections at consistent intervals. Beacon analysis looks for periodicity: does a (src, dst, port) tuple appear repeatedly at a consistent inter-arrival time?

```python
# Python snippet: beacon analysis on flow records from Elasticsearch.
import pandas as pd
import numpy as np

def beacon_score(timestamps):
    """Score a flow tuple for beaconing. Returns 0-1 (1 = perfect beacon)."""
    if len(timestamps) < 10:
        return 0.0
    intervals = np.diff(sorted(timestamps))
    if len(intervals) == 0:
        return 0.0
    cv = np.std(intervals) / np.mean(intervals)  # Coefficient of variation.
    # Low CV = consistent intervals = beaconing behaviour.
    return max(0.0, 1.0 - cv)

# Load flows, group by (src, dst, dst_port), compute beacon score.
# Flows with score > 0.7 and > 20 occurrences in 24h warrant investigation.
```

Tools like [RITA (Real Intelligence Threat Analytics)](https://github.com/activecm/rita) automate this analysis against Zeek conn.log or imported flow data.

### DNS Tunnelling Detection

DNS tunnelling encodes data in query names. The aggregate flow signature: unusually large bytes transferred via UDP/53 to a single destination nameserver, with high query frequency.

```
# nfdump query: DNS flows with anomalously large byte totals.
nfdump -r /var/netflow/nfcapd.current \
  -s dstip/bytes \
  -n 20 \
  'proto udp and dst port 53 and bytes > 512'
```

Normal DNS queries are 20–100 bytes. A flow record showing 50 KB transferred per minute over UDP/53 is almost certainly tunnelling or a misconfigured DNS implementation.

### Lateral Movement Detection

East-west flows between hosts that have no business relationship are the lateral movement signal. This requires a baseline: for each host pair, what protocols and ports have they communicated on historically? New east-west flows on SMB (445), RDP (3389), WinRM (5985/5986), or SSH (22) from hosts that have never made those connections warrant investigation.

```bash
# Using pmacct aggregate tables: generate a "connection matrix" for internal hosts.
# Baseline: capture all internal-to-internal flows for 30 days.
# Alert: any (src, dst, port) tuple not seen in the baseline window.

# Example nfdump query for internal SMB connections not from known file servers.
nfdump -r /var/netflow/nfcapd.current \
  'src net 10.0.0.0/8 and dst net 10.0.0.0/8 and dst port 445'
```

## Enrichment: GeoIP, ASN, and Threat Intelligence

Raw IP addresses in flow records require manual lookup. Enrichment at ingest time adds:

**GeoIP and ASN:** MaxMind GeoLite2 databases (free with registration) map IPs to country, city, and autonomous system number. An outbound flow to AS13335 (Cloudflare) is less suspicious than a flow to AS206728 (a bullet-proof hosting provider in Eastern Europe).

**Threat intelligence reputation lists:** MISP, abuse.ch URLhaus, Emerging Threats IP blocklists, and commercial threat feeds publish IPs associated with known malware C2, scanners, and botnets. Matching flow destination IPs against these lists at ingest generates immediate high-confidence alerts.

```yaml
# Logstash threat intelligence enrichment with MISP feed.
filter {
  translate {
    field       => "[netflow][ipv4_dst_addr]"
    destination => "threat_intel_match"
    dictionary_path => "/etc/logstash/threat-ips.yml"
    fallback    => "clean"
  }

  if [threat_intel_match] != "clean" {
    mutate { add_tag => ["threat_intel_hit"] }
  }
}
```

Refresh threat intelligence lists hourly. Stale lists miss recent infrastructure and generate false confidence.

## Zeek conn.log as a Richer Flow Alternative

Zeek (formerly Bro) generates a `conn.log` that is functionally a flow record but richer: it includes connection state (established, rejected, S0 — SYN with no response), service identification (HTTP, DNS, SSL), and duration. Zeek also generates protocol-specific logs — `dns.log`, `http.log`, `ssl.log` — that provide the application-layer context that NetFlow lacks.

```bash
# Zeek conn.log fields relevant for security analysis.
# ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
# proto, service, duration, orig_bytes, resp_bytes, conn_state,
# missed_bytes, history, orig_pkts, resp_pkts

# Filter for long-duration connections (C2 keep-alives).
zeek-cut ts id.orig_h id.resp_h service duration conn_state \
  < /var/log/zeek/conn.log | \
  awk '$6 > 3600 && $7 == "SF"'  # Established connections lasting > 1 hour.
```

Zeek requires full packet access (libpcap on a mirror port or tap), so it does not scale to 10 Gbps without purpose-built hardware. For environments where Zeek is deployable, it replaces NetFlow for connection-level analysis while NetFlow remains appropriate for high-speed links and router-level visibility.

## Retention, Storage Sizing, and Compliance

Flow data is forensic evidence. When an incident is discovered weeks after initial compromise, flow records are often the only source of truth for the attacker's early reconnaissance and lateral movement.

**Storage sizing:** At typical enterprise traffic patterns (~5 flows per Mbps per second), a 1 Gbps link generates roughly 400–600 MB of raw IPFIX data per day. Compression with zstd achieves 4–6x reduction, making 90-day retention of a 1 Gbps link approximately 25–40 GB. Scale linearly.

```bash
# nfcapd rotation and compression — retain 90 days.
# /etc/cron.d/netflow-rotate
0 * * * * root nfexpire -e /var/netflow -t 90d
5 * * * * root find /var/netflow -name 'nfcapd.*' -mmin +60 \
  -exec zstd --rm -q {} \;
```

**Compliance alignment:**

- **PCI DSS 10.6.3:** Retain audit logs (including network logs) for at least 12 months, with 3 months immediately available.
- **NIST SP 800-137:** Continuous monitoring includes network flow monitoring as a key information security continuous monitoring strategy.
- **SOC 2 CC7.2:** Detection of security events requires network monitoring controls.

For compliance, flow data should be stored in tamper-evident storage (append-only S3 buckets with Object Lock, or WORM storage). Chain of custody documentation is required for incident response use in legal proceedings.

## Kubernetes Flow Visibility: Cilium Hubble

Traditional flow export is blind to pod-to-pod traffic inside a Kubernetes node. All three common attack paths — container escape, lateral movement between pods, and namespace breakout — generate east-west traffic that never leaves the node and is therefore invisible to interface-level flow probes.

**Cilium Hubble** instruments eBPF hooks at the kernel level and generates flow records for every pod-to-pod connection, including connections on the loopback interface within a pod and connections between pods on the same node.

```bash
# Install Cilium with Hubble enabled.
helm upgrade --install cilium cilium/cilium \
  --namespace kube-system \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --set hubble.metrics.enabled="{dns,drop,tcp,flow,icmp,http}"

# Install Hubble CLI.
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -LO "https://github.com/cilium/hubble/releases/download/${HUBBLE_VERSION}/hubble-linux-amd64.tar.gz"
tar xzvf hubble-linux-amd64.tar.gz
mv hubble /usr/local/bin/

# Port-forward Hubble relay for local CLI access.
kubectl port-forward -n kube-system svc/hubble-relay 4245:80 &

# Observe all flows in the production namespace.
hubble observe --namespace production --follow

# Filter for dropped flows (policy violations).
hubble observe --namespace production --verdict DROPPED --follow

# Export flows to IPFIX for external analysis.
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: hubble-ipfix-exporter
  namespace: kube-system
data:
  config.yaml: |
    exporters:
      - type: ipfix
        host: 192.168.1.100
        port: 4739
        version: 10
EOF
```

**Calico flow logs** provide equivalent visibility for Calico-based clusters. Enable them in the Calico Enterprise or Calico Cloud configuration:

```yaml
# calico-enterprise flowlogs config.
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  name: default
spec:
  flowLogsEnabled: true
  flowLogsFlushInterval: 30s
  flowLogsFileReporterEnabled: true
  # Export to S3 for long-term retention.
  flowLogsFileDirectory: /var/log/calico/flowlogs
```

Kubernetes flow logs should capture at minimum: source namespace, destination namespace, source workload, destination workload, destination port, protocol, verdict (allowed/denied), and byte count. This data populates the east-west connection matrix used for lateral movement detection.

## Anomaly Detection: Baselining and VAST

Static thresholds for "large flow" and "high fan-out" require manual tuning and drift over time as traffic patterns change. Effective anomaly detection starts with a measured baseline.

**Baselining approach:**

1. Collect 30 days of flow data without alerting. Compute per-source-host distributions for: bytes transferred per hour, unique destination IPs per hour, unique destination ports per hour, and top destination countries.
2. Compute the 95th and 99th percentiles for each metric per host or host group.
3. Set alert thresholds at the 99th percentile. Tune over the following two weeks, raising thresholds for legitimate high-volume sources and lowering them for hosts with predictable, low-variance traffic.

**VAST (Versatile, Accelerated Security Telemetry)** is an open-source security telemetry platform designed for high-volume log and flow data. It supports PCAP, Zeek logs, and IPFIX as input formats and provides a SQL-like query language for interactive investigation.

```bash
# Import IPFIX data into VAST for analysis.
vast import netflow < /var/netflow/nfcapd.current

# Query for beacon candidates: high-frequency, low-byte connections.
vast export json \
  'netflow | where dst.port == 443 and bytes < 2048 | \
   summarize count() by src.addr, dst.addr, dst.port | \
   where count > 500'
```

## Operational Checklist

Before considering flow analysis operational for security monitoring:

```
[ ] Flow export configured on all internet-facing servers and network devices
[ ] Flow export configured on all servers handling sensitive data
[ ] Kubernetes/container flow visibility enabled (Hubble or Calico)
[ ] Flow collector receiving and storing data with < 5 minute lag
[ ] GeoIP and ASN enrichment active at ingest
[ ] Threat intelligence IP list updated hourly and joined at query time
[ ] Baseline established for top-N metrics per host
[ ] Detection queries running for: large outbound flows, port scanning, C2 beaconing, DNS anomalies, new lateral east-west flows
[ ] Alert pipeline connected to SIEM or incident response system
[ ] Retention policy enforced: minimum 90 days, ideally 12 months
[ ] Flow storage in tamper-evident format for forensics use
[ ] Runbook exists for investigating each alert type
```

## Key Takeaways

Flow analysis is not a replacement for endpoint detection or deep packet inspection — it is a scalable complement. Where packet capture is impractical at scale and endpoint agents are absent or compromised, flows provide the metadata layer that answers the first questions in any investigation: what hosts were involved, what ports, how much data, and when.

The patterns that matter — exfiltration, beaconing, scanning, lateral movement — are visible in flow metadata without payload content. A defender with 90 days of enriched flow data and working detection queries has a substantial advantage over an attacker who assumes that post-compromise network activity is invisible.

The investment required is modest: softflowd or pmacct on Linux hosts, a flow collector (ntopng or Logstash), and a set of detection queries built from the use cases above. The operational overhead is low once collectors and enrichment are in place. The forensic value, when it is needed, is significant.
