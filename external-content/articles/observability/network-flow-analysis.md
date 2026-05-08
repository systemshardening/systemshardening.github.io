---
title: "Network Flow Analysis: NetFlow, IPFIX, and eBPF for Traffic Anomaly Detection"
description: "Flow records capture who talked to whom, when, and how much — without packet payload. They detect C2 beaconing, lateral movement, data exfiltration, and port scanning that signature-based tools miss."
slug: "network-flow-analysis"
date: 2026-04-30
lastmod: 2026-04-30
category: "observability"
tags: ["netflow", "ipfix", "ebpf", "flow-analysis", "anomaly-detection"]
personas: ["security-engineer", "sre", "platform-engineer"]
article_number: 275
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/observability/network-flow-analysis/index.html"
---

# Network Flow Analysis: NetFlow, IPFIX, and eBPF for Traffic Anomaly Detection

## Problem

Packet capture (tcpdump, Wireshark) is too expensive to run continuously on production networks — both in terms of storage and CPU. TLS encryption makes payload inspection increasingly useless even when packet capture is feasible.

Network flow records offer a middle ground: they capture metadata about network connections (source IP, destination IP, ports, protocol, byte count, packet count, start/end time) without capturing payload. A flow record answers "who talked to whom, when, and how much" — enough to detect most attack patterns.

Flow-based detection is complementary to signature-based detection (which looks at payload content) and log-based detection (which looks at application events). Flows cover the network layer patterns that neither endpoint logs nor application logs capture:

- **C2 beaconing:** Malware that checks in with a C2 server every N seconds creates periodic flows to an external IP. This regularity is detectable in flow data even if the connection is TLS-encrypted.
- **Lateral movement:** A compromised host connecting to many internal hosts on SSH/RDP/SMB port within a short window. Application logs on those hosts show failed auth attempts; flow records show the scan.
- **Data exfiltration:** Abnormally large outbound flows to external IPs. A host that normally sends 10MB/day to external destinations but sends 50GB is anomalous.
- **DNS tunnelling:** High-frequency DNS queries with large query/response payloads to a single external nameserver.
- **Port scanning:** A host making SYN connections to many ports on many hosts over a short window.

**Target systems:** Linux kernel 5.8+ (eBPF-based flow collection); Cisco/Juniper routers with NetFlow v9 or IPFIX; cloud VPC flow logs (AWS, GCP, Azure); Grafana Alloy or Vector for flow ingestion; Zeek for flow enrichment; Elasticsearch/OpenSearch for storage.

## Threat Model

- **Adversary 1 — Encrypted C2 beaconing:** Malware installed on an internal host makes periodic HTTPS connections to its C2 domain. The connections are TLS-encrypted; payload inspection fails. Flow records show regular 30-second intervals of outbound connections to the same external IP.
- **Adversary 2 — Internal port scanning:** A compromised host scans the internal network for open ports on SSH (22), RDP (3389), and SMB (445). Flow records show one source IP making connections to hundreds of destination IPs in a short window.
- **Adversary 3 — Slow exfiltration:** An attacker copies data at a rate designed to blend with normal traffic — 100MB/hour. Over 10 hours, 1GB leaves the network. Flow records accumulate to show an abnormally large total bytes-out for that source.
- **Adversary 4 — DNS exfiltration:** An attacker uses DNS tunnelling (`dnscat2`) to exfiltrate data. Flow records show high-frequency DNS queries (100+ per minute) with large response sizes to a single external nameserver.
- **Adversary 5 — Lateral movement via service account:** A compromised service account connects to the database server on port 5432 from a host it never previously talked to. Flow records capture the new connection pattern; application-level logs may not, if the credentials are valid.
- **Access level:** All adversaries have achieved some form of internal access (malware on a host, compromised credentials, compromised pod). Flows detect the network behaviour that follows.
- **Objective:** Establish C2, move laterally, exfiltrate data without triggering signature-based detection.
- **Blast radius:** Without flow analysis, these attacks can persist for days or weeks. Flow-based detection typically catches beaconing within 2–4 beacon cycles (2–4 minutes for 30-second beaconing) and port scanning within seconds.

## Configuration

### Step 1: eBPF-Based Flow Collection on Linux Hosts

For Kubernetes and Linux hosts, eBPF provides per-connection flow data without router configuration:

```bash
# Using Hubble (Cilium's observability layer) for Kubernetes flow collection.
# Already configured if you're running Cilium — see cilium-network-policy article.
hubble observe --follow --output json | \
  jq 'select(.verdict != null) | {
    src: .source.pod_name,
    dst: .destination.pod_name,
    dst_svc: .destination_service.name,
    proto: .l4 | keys[0],
    verdict: .verdict,
    bytes: .reply
  }'
```

For non-Kubernetes Linux hosts, use eBPF via `bpftrace` or dedicated agents:

```bash
# Simple eBPF flow collector using bpftrace.
# Captures TCP connection events (connect, accept, close).
bpftrace -e '
kprobe:tcp_v4_connect {
  printf("FLOW connect src=%s:%d dst=%s:%d pid=%d comm=%s\n",
    ntop(AF_INET, ((struct sock *)arg0)->__sk_common.skc_rcv_saddr),
    ((struct sock *)arg0)->__sk_common.skc_num,
    ntop(AF_INET, ((struct sock *)arg0)->__sk_common.skc_daddr),
    ntohs(((struct sock *)arg0)->__sk_common.skc_dport),
    pid, comm);
}
' | process_to_flow_records

# Production: use dedicated flow agents.
# Options: Grafana Alloy with eBPF receiver, Datadog Agent eBPF, or custom.
```

Grafana Alloy with eBPF receiver (recommended for production):

```river
// alloy-config.river
ebpf.flow_collector "default" {
  enable_tcp = true
  enable_udp = true
  output {
    flows = [loki.write.default.receiver]
  }
}

loki.write "default" {
  endpoint {
    url = "http://loki.monitoring.svc:3100/loki/api/v1/push"
  }
  external_labels = {
    host = sys.env("HOSTNAME"),
    cluster = "prod",
  }
}
```

### Step 2: VPC Flow Logs (AWS)

```bash
# Enable VPC Flow Logs for all traffic in all regions.
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-xxxxxx \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::vpc-flow-logs-prod \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr}'

# Forward to Elasticsearch via Lambda or Kinesis Firehose.
# Or: use Athena for batch analysis.
aws glue create-table \
  --database-name vpc_flows \
  --table-input '{
    "Name": "flows",
    "StorageDescriptor": {
      "Location": "s3://vpc-flow-logs-prod/",
      "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
      "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
      "Columns": [
        {"Name": "srcaddr", "Type": "string"},
        {"Name": "dstaddr", "Type": "string"},
        {"Name": "srcport", "Type": "int"},
        {"Name": "dstport", "Type": "int"},
        {"Name": "bytes", "Type": "bigint"}
      ]
    }
  }'
```

### Step 3: Beaconing Detection

Detect periodic outbound connections characteristic of C2 malware:

```python
# beacon_detection.py
# Analyses flow records for regular periodic connections (beaconing).

import pandas as pd
import numpy as np
from scipy import stats

def detect_beaconing(flows_df: pd.DataFrame, threshold_cv: float = 0.3) -> pd.DataFrame:
    """
    Detect beaconing using coefficient of variation of inter-flow intervals.
    A CV < 0.3 indicates highly regular timing (suspicious).
    """
    # Group flows by source-destination pair.
    pairs = flows_df.groupby(['src_ip', 'dst_ip', 'dst_port'])

    beaconing_suspects = []
    for (src, dst, port), group in pairs:
        if len(group) < 10:
            continue   # Need enough samples.

        # Calculate inter-flow intervals.
        times = group['start_time'].sort_values()
        intervals = times.diff().dropna().dt.total_seconds()

        if len(intervals) < 5:
            continue

        # Coefficient of variation: std/mean. Low CV = very regular.
        cv = intervals.std() / intervals.mean()
        mean_interval = intervals.mean()

        # Regular beaconing: CV < 0.3, interval between 10s and 1h.
        if cv < threshold_cv and 10 <= mean_interval <= 3600:
            beaconing_suspects.append({
                'src_ip': src,
                'dst_ip': dst,
                'dst_port': port,
                'cv': cv,
                'mean_interval_seconds': mean_interval,
                'flow_count': len(group),
                'total_bytes': group['bytes'].sum(),
            })

    return pd.DataFrame(beaconing_suspects).sort_values('cv')

# Usage:
flows = pd.read_parquet('flows/2026-04-30.parquet')
suspects = detect_beaconing(flows)
print(suspects[suspects['cv'] < 0.1])  # Highly regular beaconing.
```

### Step 4: Lateral Movement Detection

```python
# lateral_movement.py
# Detect port scanning and unusual internal connection patterns.

def detect_port_scan(flows_df: pd.DataFrame,
                     window_minutes: int = 5,
                     threshold_dst_count: int = 20) -> pd.DataFrame:
    """
    Detect port scanning: one source connecting to many destinations on the same port,
    or to many ports on the same destination.
    """
    # Filter to internal traffic only.
    internal_flows = flows_df[
        flows_df['dst_ip'].str.startswith(('10.', '172.16.', '192.168.'))
    ]

    # Group by source in time windows.
    internal_flows['window'] = internal_flows['start_time'].dt.floor(f'{window_minutes}min')

    # Detect: one source → many destinations on the same port.
    horizontal_scan = internal_flows.groupby(['src_ip', 'window', 'dst_port'])['dst_ip'].nunique()
    horizontal_suspects = horizontal_scan[horizontal_scan >= threshold_dst_count].reset_index()
    horizontal_suspects['scan_type'] = 'horizontal'

    # Detect: one source → many ports on the same destination.
    vertical_scan = internal_flows.groupby(['src_ip', 'window', 'dst_ip'])['dst_port'].nunique()
    vertical_suspects = vertical_scan[vertical_scan >= 50].reset_index()
    vertical_suspects['scan_type'] = 'vertical'

    return pd.concat([horizontal_suspects, vertical_suspects])

def detect_new_internal_connection(flows_df: pd.DataFrame,
                                   baseline_df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect new source-destination pairs not seen in the baseline window.
    """
    # Baseline: flows from the previous 7 days.
    baseline_pairs = set(zip(baseline_df['src_ip'], baseline_df['dst_ip'], baseline_df['dst_port']))

    # Current: flows from the last hour.
    today = set(zip(flows_df['src_ip'], flows_df['dst_ip'], flows_df['dst_port']))

    new_pairs = today - baseline_pairs
    if not new_pairs:
        return pd.DataFrame()

    return pd.DataFrame(list(new_pairs), columns=['src_ip', 'dst_ip', 'dst_port'])
```

### Step 5: Exfiltration Detection

```python
# exfiltration_detection.py

def detect_exfiltration(flows_df: pd.DataFrame,
                         baseline_gb_per_day: dict,
                         threshold_multiplier: float = 5.0) -> list:
    """
    Alert when outbound bytes from a host significantly exceed its baseline.
    """
    # Filter outbound (external destination) flows.
    external_flows = flows_df[
        ~flows_df['dst_ip'].str.startswith(('10.', '172.', '192.168.'))
    ]

    # Sum outbound bytes per source IP.
    outbound = external_flows.groupby('src_ip')['bytes'].sum()

    alerts = []
    for src_ip, total_bytes in outbound.items():
        baseline = baseline_gb_per_day.get(src_ip, 0.1) * 1e9   # Convert to bytes.
        if total_bytes > baseline * threshold_multiplier:
            alerts.append({
                'src_ip': src_ip,
                'bytes_today': total_bytes,
                'bytes_baseline': baseline,
                'multiplier': total_bytes / baseline,
            })

    return sorted(alerts, key=lambda x: x['multiplier'], reverse=True)
```

### Step 6: DNS Flow Anomaly Detection

```python
# dns_anomaly.py

def detect_dns_tunnelling(flows_df: pd.DataFrame,
                           threshold_rps: float = 5.0,
                           threshold_avg_bytes: int = 200) -> pd.DataFrame:
    """
    Detect DNS tunnelling: high query rate + large response size to a single nameserver.
    """
    dns_flows = flows_df[flows_df['dst_port'] == 53]

    # Group by source + DNS server.
    dns_stats = dns_flows.groupby(['src_ip', 'dst_ip']).agg(
        flow_count=('bytes', 'count'),
        avg_bytes=('bytes', 'mean'),
        duration_minutes=('start_time', lambda x: (x.max() - x.min()).total_seconds() / 60)
    ).reset_index()

    dns_stats['queries_per_minute'] = dns_stats['flow_count'] / dns_stats['duration_minutes'].clip(lower=1)

    # Flag: high query rate AND large average response.
    suspicious = dns_stats[
        (dns_stats['queries_per_minute'] >= threshold_rps * 60) &
        (dns_stats['avg_bytes'] >= threshold_avg_bytes)
    ]

    return suspicious.sort_values('queries_per_minute', ascending=False)
```

### Step 7: Elasticsearch Queries for SIEM Integration

```json
// Kibana/Elasticsearch: detect beaconing patterns.
GET flow-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"term": {"direction": "outbound"}},
        {"range": {"dst_port": {"gte": 443, "lte": 443}}}
      ]
    }
  },
  "aggs": {
    "by_source_dest": {
      "composite": {
        "sources": [
          {"src": {"terms": {"field": "src_ip"}}},
          {"dst": {"terms": {"field": "dst_ip"}}}
        ]
      },
      "aggs": {
        "flow_times": {
          "date_histogram": {
            "field": "@timestamp",
            "calendar_interval": "minute"
          }
        },
        "stddev_interval": {
          "extended_stats_bucket": {
            "buckets_path": "flow_times._count"
          }
        }
      }
    }
  }
}
```

### Step 8: Telemetry

```
flow_records_ingested_total{source, protocol}              counter
flow_beaconing_suspects_total{src_ip, dst_ip}              counter
flow_lateral_movement_detected_total{type}                 counter
flow_exfiltration_alert_total{src_ip}                      counter
flow_dns_tunnelling_suspected_total{src_ip, dst_ip}        counter
flow_processing_lag_seconds{pipeline_stage}                gauge
```

Alert on:

- `flow_beaconing_suspects_total` with CV < 0.1 — near-perfect beaconing; high confidence C2 activity.
- `flow_lateral_movement_detected_total{type="horizontal"}` — port scan detected; investigate the source.
- `flow_exfiltration_alert_total` — outbound bytes 5× baseline; potential data exfiltration.
- `flow_processing_lag_seconds` > 300 — flow pipeline is delayed; detections are running behind real time.

## Expected Behaviour

| Signal | No flow analysis | Flow analysis deployed |
|--------|-----------------|----------------------|
| C2 beaconing over HTTPS | Undetected (TLS encrypted) | Detected by interval regularity within 2–4 beacon cycles |
| Internal port scan | Detected only if reaching hosts with auditd/Falco | Detected within seconds from flow volume |
| Data exfiltration (slow) | Undetected if rate is low | Accumulates over the day; alert when threshold breached |
| DNS tunnelling | Undetected unless DNS proxy logs inspected | Query rate + byte size anomaly detected |
| New internal connection pair | Not captured unless host logs checked | Detects new src-dst pairs compared to 7-day baseline |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| eBPF-based collection | No router configuration; per-process flows | ~2-4% CPU overhead on busy hosts | Acceptable; sample at 1:10 for extremely high-volume hosts. |
| VPC Flow Logs | Covers all traffic; no agent needed | S3 storage cost; 5–15 minute lag | Enable S3 intelligent tiering; use Athena for batch analysis vs Kinesis for real-time. |
| Statistical beaconing detection | Catches encrypted C2; no signatures needed | False positives from legitimate periodic services (health checks) | Build a baseline allowlist of known-periodic legitimate services. |
| 7-day baseline for new connection pairs | Context-aware anomaly detection | New deployments generate high false positives | Suppress alerts for hosts in the first 7 days of their baseline. |
| Flow storage at scale | Long-term forensic capability | Flow records: ~100 bytes/flow; TB at scale | Aggregate to 5-minute bins after 7 days; keep only anomalous raw flows longer. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Flow collection agent crashes | No flows from that host | `flow_records_ingested_total` drops for host; agent health metric | Restart agent; systemd auto-restart configured. |
| Flow pipeline lag | Detections delayed > 5 minutes | `flow_processing_lag_seconds` alert | Scale up Elasticsearch ingestion; check Kinesis/Kafka consumer lag. |
| Beaconing detector false positive | Legitimate service flagged as C2 | High volume of alerts for a known service IP | Add to allowlist; tune CV threshold; verify legitimate periodicity. |
| VPC Flow Logs delivery delay | Flows arrive 15+ minutes late | Detection age metric grows | For real-time use cases, combine with eBPF on hosts; VPC flows for retrospective analysis. |
| Baseline poisoned during attack | Attacker's traffic becomes part of baseline | Detection misses attacker on next window | Use a rolling baseline with outlier exclusion; never include confirmed-compromised hosts in the baseline. |

## Related Articles

- [eBPF and Tetragon Runtime Detection](/articles/observability/ebpf-tetragon/)
- [Lateral Movement Detection](/articles/observability/lateral-movement-detection/)
- [Cloud Provider Audit Logs](/articles/observability/cloud-provider-audit-logs/)
- [DNS Response Policy Zones](/articles/network/dns-rpz-threat-intelligence/)
- [Honeypot and Deception Technology in Kubernetes](/articles/observability/honeypot-deception-kubernetes/)
