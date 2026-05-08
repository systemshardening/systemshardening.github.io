---
title: "Detecting Data Exfiltration Through Log Analysis and Network Monitoring"
description: "Attackers who reach your data will use HTTP/S, DNS tunnelling, ICMP, cloud storage, and email to move it out. This article builds a layered detection stack: volumetric alerts on VPC flow logs, covert channel detection via Zeek and Elasticsearch, Falco rules for staging behaviour, cloud DLP integration, and a high-confidence correlation rule that combines internal staging with external transfer."
slug: data-exfiltration-detection
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - data-exfiltration
  - dlp
  - network-monitoring
  - threat-detection
  - siem
personas:
  - security-engineer
  - security-analyst
article_number: 546
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/data-exfiltration-detection/
---

# Detecting Data Exfiltration Through Log Analysis and Network Monitoring

## Problem

Data exfiltration is the final stage of most serious breaches. By the time an attacker starts moving data out, they have already compromised credentials, escalated privileges, and found what they want. Detection at exfiltration time is last-resort — but it is also the last opportunity to limit the blast radius before the data is gone.

The specific challenges:

- **Exfiltration channels are legitimate protocols.** HTTPS, DNS, ICMP, SMTP, and cloud storage APIs are used by normal business operations every day. You cannot block them. You must detect abuse within them.
- **Volumetric detection alone misses covert channels.** An attacker using DNS tunnelling or ICMP encoding transfers data at kilobytes per minute — well below any threshold-based alert on raw bytes. Detection requires protocol-level analysis, not just byte counts.
- **Staging is the last warning before data leaves.** Before external transfer, attackers consolidate data internally: bulk S3 reads, NFS writes, tar/zip archives of sensitive directories. Detecting staging buys response time before anything leaves the network perimeter.
- **Context determines signal quality.** A 5GB outbound transfer from your backup service is normal. The same transfer from an EC2 instance that has never previously sent more than 100MB is a high-confidence exfiltration indicator.

This article builds a detection stack covering: exfiltration channel taxonomy, volumetric detection via VPC flow logs and Elasticsearch, covert channel detection for DNS tunnelling and ICMP, Zeek `conn.log` analysis for exfiltration patterns, Falco rules for staging behaviour, cloud-native detection with CloudTrail and GCP DLP, and a correlation rule that combines internal staging with external transfer for high-confidence alerting.

**Target systems:** AWS VPC or GCP VPC with flow logging enabled. [Zeek](https://zeek.org) (formerly Bro) for network analysis. [Elasticsearch](https://www.elastic.co) for log storage and queries. [Falco](https://falco.org) for runtime detection. CloudTrail and GCP DLP API for cloud-native signals.

## Threat Model

- **Adversary:** An attacker who has achieved internal access — compromised host, stolen cloud credentials, or insider threat. Their goal is to extract a large volume of sensitive data (PII, source code, secrets, financial records) to an external location without triggering detection.
- **Channels used:**
  - **HTTPS to unusual domains** (most common): bulk POST requests to attacker-controlled infrastructure or anonymous cloud storage.
  - **DNS tunnelling**: data encoded in DNS queries and responses, typically via `dnscat2` or `iodine`. Slow but extremely covert.
  - **ICMP tunnelling**: data encoded in ICMP echo payloads. Bypasses many firewall rules that permit ping traffic.
  - **Cloud storage abuse**: legitimate S3 or GCS buckets under attacker control used as exfiltration drop points. Traffic looks indistinguishable from normal cloud API calls.
  - **Email**: SMTP or webmail (HTTPS to mail.google.com, outlook.com) used to forward attached sensitive files.
- **Staging behaviour:** Large internal data movements precede external transfer by minutes to hours. Attackers consolidate data from multiple sources into a single staging location before initiating the outbound transfer.
- **Blast radius:** Without exfiltration detection, breaches are discovered an average of 194 days after initial compromise. Flow-based volumetric detection cuts discovery time for large transfers to minutes. Covert channel detection requires deeper Zeek and DNS analysis but catches slow-exfil attempts that volumetric rules miss.

## Exfiltration Channel Reference

| Channel | Detection Surface | Typical Transfer Rate | Covert? |
|---------|------------------|----------------------|---------|
| HTTPS POST to external domain | Flow bytes, JA3 fingerprint, domain age | High (MB/s) | Low — volumetric detection works |
| DNS tunnelling | Query entropy, TXT record size, query rate | Low (10–100 KB/min) | High — requires DNS-specific analysis |
| ICMP tunnelling | ICMP payload size, sustained bidirectional flow | Low (5–50 KB/min) | High — often bypasses firewalls |
| Cloud storage (S3, GCS) | CloudTrail GetObject/PutObject, destination bucket owner | High (MB/s) | Medium — normal API, abnormal destination |
| SMTP/webmail | Flow to port 25/465/587, HTTPS to mail providers | Medium | Low — destination and volume are detectable |
| USB/removable media | Falco kernel events, udev, auditd | Physical only | N/A for network monitoring |

## Configuration

### Step 1: Baseline Outbound Data Volumes per Workload

You cannot detect volumetric anomalies without a baseline. Establish per-application normal outbound data volumes using a 14-day rolling window stored as Prometheus recording rules or Elasticsearch aggregations.

```python
# build_baselines.py
# Reads 14 days of VPC flow log data from Elasticsearch and computes
# per-source-IP daily outbound byte baselines.

from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json

es = Elasticsearch("https://elasticsearch.prod.internal:9200")

def compute_outbound_baseline(days: int = 14) -> dict:
    """
    Returns {src_ip: {"mean_bytes_per_day": float, "p95_bytes_per_day": float}}
    for all source IPs seen in the last `days` days of VPC flow logs.
    Only counts flows destined to non-RFC1918 addresses (external traffic).
    """
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
                    {"term": {"action": "ACCEPT"}}
                ],
                "must_not": [
                    # Exclude RFC1918 destinations — we want external flows only.
                    {"prefix": {"dst_addr": "10."}},
                    {"prefix": {"dst_addr": "172.16."}},
                    {"prefix": {"dst_addr": "192.168."}}
                ]
            }
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "src_addr", "size": 5000},
                "aggs": {
                    "by_day": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "calendar_interval": "day"
                        },
                        "aggs": {
                            "bytes_out": {"sum": {"field": "bytes"}}
                        }
                    },
                    "avg_daily_bytes": {
                        "avg_bucket": {
                            "buckets_path": "by_day>bytes_out"
                        }
                    },
                    "p95_daily_bytes": {
                        "percentiles_bucket": {
                            "buckets_path": "by_day>bytes_out",
                            "percents": [95]
                        }
                    }
                }
            }
        }
    }
    resp = es.search(index="vpc-flow-logs-*", body=query)
    baselines = {}
    for bucket in resp["aggregations"]["by_source"]["buckets"]:
        src = bucket["key"]
        baselines[src] = {
            "mean_bytes_per_day": bucket["avg_daily_bytes"]["value"] or 0,
            "p95_bytes_per_day": bucket["p95_daily_bytes"]["values"].get("95.0") or 0
        }
    return baselines
```

### Step 2: Volumetric Exfiltration — Elasticsearch Detection Rules

Detect large outbound flows and sustained high-bandwidth connections:

```json
// Kibana Detection Rule (Elasticsearch Security):
// Alert when a source IP's outbound bytes in the last hour exceed
// 5× its 14-day p95 baseline.
//
// Store baselines in a separate index (enrichment table) populated by
// the baseline script above. Use Elasticsearch Enrich Processor or
// a runtime field to join baseline data into flow log documents.

GET vpc-flow-logs-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"term": {"action": "ACCEPT"}}
      ],
      "must_not": [
        {"prefix": {"dst_addr": "10."}},
        {"prefix": {"dst_addr": "172.16."}},
        {"prefix": {"dst_addr": "192.168."}}
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": {"field": "src_addr", "size": 500},
      "aggs": {
        "total_bytes_out": {"sum": {"field": "bytes"}},
        "unique_destinations": {"cardinality": {"field": "dst_addr"}},
        "max_single_flow_bytes": {"max": {"field": "bytes"}},
        "sustained_connections": {
          "filter": {
            "range": {"duration_seconds": {"gte": 300}}
          }
        }
      }
    }
  }
}
```

As a Kibana detection rule with threshold:

```yaml
# Kibana Detection Rule: volumetric exfiltration signal.
# Rule type: threshold
name: "Volumetric Outbound Transfer Anomaly"
description: >
  Source IP sending more than 1GB outbound in a single hour.
  Enrich with baseline data to tune threshold per workload.
index:
  - "vpc-flow-logs-*"
query: |
  action: ACCEPT AND NOT dst_addr: 10.* AND NOT dst_addr: 172.16.* AND NOT dst_addr: 192.168.*
threshold:
  field: src_addr
  value: 1073741824   # 1GB in bytes
  cardinality:
    field: bytes
    value: 1073741824
severity: high
risk_score: 73
interval: "1h"
from: "now-1h"
tags:
  - "Data Exfiltration"
  - "Exfiltration: Exfiltration Over Web Service"
  - "MITRE: T1048"
```

### Step 3: DNS Tunnelling Detection via Zeek and Elasticsearch

DNS tunnelling is detected through three signals: high query entropy (random-looking subdomain labels), large TXT record responses, and abnormally high query rates to a single nameserver.

#### Zeek DNS Log Enrichment

Zeek's `dns.log` captures all DNS queries with query names and response record types. Feed this into Elasticsearch:

```zeek
# dns-exfil-detection.zeek
# Adds an entropy score to each DNS query name.
# High entropy subdomains are a primary indicator of DNS tunnelling.

@load base/protocols/dns

module DNSExfil;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:          time    &log;
        uid:         string  &log;
        id:          conn_id &log;
        query:       string  &log;
        qtype_name:  string  &log;
        rtt:         interval &log &optional;
        subdomain_entropy: double &log &default=0.0;
        label_length: count  &log &default=0;
        txt_response_size: count &log &default=0;
    };

    global log_dns_exfil: event(rec: Info);
}

function shannon_entropy(s: string): double {
    local counts: table[string] of count;
    local n = |s|;
    if (n == 0) return 0.0;
    for (i in s) {
        local c = s[i];
        if (c !in counts) counts[c] = 0;
        ++counts[c];
    }
    local entropy: double = 0.0;
    for (c in counts) {
        local p: double = counts[c] / (n + 0.0);
        entropy -= p * log(p) / log(2.0);
    }
    return entropy;
}

event dns_request(c: connection, msg: dns_msg, qtype: count, qclass: count) {
    local query_str = c$dns$query;
    # Extract the leftmost subdomain label (most variable in tunnelling).
    local parts = split_string(query_str, /\./);
    local first_label = (|parts| > 0) ? parts[0] : query_str;

    local rec: DNSExfil::Info = [
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id,
        $query = query_str,
        $qtype_name = (qtype == 16) ? "TXT" : (qtype == 1) ? "A" : fmt("%d", qtype),
        $subdomain_entropy = shannon_entropy(first_label),
        $label_length = |first_label|
    ];

    Log::write(DNSExfil::LOG, rec);
}
```

#### Elasticsearch Query: DNS Tunnelling Signals

```json
// Detect DNS tunnelling: high average query entropy + large TXT records.
// Run over dns-zeek-* index populated by Zeek's dns.log via Filebeat.

GET dns-zeek-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"range": {"subdomain_entropy": {"gte": 3.5}}}
      ]
    }
  },
  "aggs": {
    "by_source_and_resolver": {
      "composite": {
        "sources": [
          {"src_ip": {"terms": {"field": "id.orig_h"}}},
          {"resolver": {"terms": {"field": "id.resp_h"}}}
        ],
        "size": 200
      },
      "aggs": {
        "query_count":       {"value_count": {"field": "query"}},
        "avg_entropy":       {"avg": {"field": "subdomain_entropy"}},
        "avg_label_length":  {"avg": {"field": "label_length"}},
        "txt_query_count": {
          "filter": {"term": {"qtype_name": "TXT"}}
        },
        "max_txt_response": {"max": {"field": "txt_response_size"}}
      }
    }
  }
}
```

Alert when:
- `avg_entropy > 3.8` and `query_count > 100` per hour (random-looking labels at high rate)
- `txt_query_count > 20` per hour (TXT record abuse for data encoding)
- `avg_label_length > 40` (long subdomain labels used to pack data)

#### ICMP Tunnelling Detection

```json
// VPC flow log query: ICMP flows with large payloads and sustained duration.
// Normal ICMP echo (ping) uses 56-84 byte packets. Tunnelling uses max-size payloads.

GET vpc-flow-logs-*/_search
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"term": {"protocol": 1}},
        {"range": {"bytes": {"gte": 65000}}},
        {"range": {"duration_seconds": {"gte": 60}}}
      ],
      "must_not": [
        {"prefix": {"dst_addr": "10."}},
        {"prefix": {"dst_addr": "172.16."}},
        {"prefix": {"dst_addr": "192.168."}}
      ]
    }
  }
}
```

### Step 4: Zeek `conn.log` Analysis for Exfiltration Patterns

Zeek's `conn.log` records full connection metadata including `orig_bytes` (bytes sent by the initiator) and `resp_bytes` (bytes sent by the responder). A high `orig_bytes / resp_bytes` ratio on outbound connections to external IPs is a direct exfiltration signal — the host is sending far more than it receives.

```python
# zeek_exfil_analysis.py
# Analyses Zeek conn.log (loaded into Elasticsearch or from a NDJSON file)
# for asymmetric outbound flows indicating data exfiltration.

import pandas as pd
import numpy as np

def detect_asymmetric_flows(conn_df: pd.DataFrame,
                             min_orig_bytes: int = 10_000_000,   # 10MB minimum
                             min_ratio: float = 20.0,
                             external_only: bool = True) -> pd.DataFrame:
    """
    Flag connections where the originator sent 20× or more data than
    it received — characteristic of upload-only exfiltration.
    """
    df = conn_df.copy()

    if external_only:
        # Exclude RFC1918 destinations.
        rfc1918 = df["id.resp_h"].str.startswith(("10.", "172.16.", "192.168."))
        df = df[~rfc1918]

    # Avoid division by zero: add 1 to resp_bytes.
    df["upload_ratio"] = df["orig_bytes"] / (df["resp_bytes"] + 1)

    suspicious = df[
        (df["orig_bytes"] >= min_orig_bytes) &
        (df["upload_ratio"] >= min_ratio)
    ].copy()

    suspicious = suspicious[[
        "ts", "id.orig_h", "id.resp_h", "id.resp_p",
        "proto", "service", "duration",
        "orig_bytes", "resp_bytes", "upload_ratio",
        "conn_state"
    ]].sort_values("orig_bytes", ascending=False)

    return suspicious


def detect_sustained_high_bandwidth(conn_df: pd.DataFrame,
                                    bandwidth_threshold_mbps: float = 10.0,
                                    duration_threshold_s: float = 300.0) -> pd.DataFrame:
    """
    Detect sustained high-bandwidth connections to external IPs.
    Normal interactive HTTPS sessions are bursty. Exfiltration is sustained.
    """
    df = conn_df.copy()
    rfc1918 = df["id.resp_h"].str.startswith(("10.", "172.16.", "192.168."))
    df = df[~rfc1918]

    # Bytes per second.
    df["bps"] = df["orig_bytes"] / (df["duration"] + 0.001)
    df["mbps"] = df["bps"] / 1e6

    sustained = df[
        (df["duration"] >= duration_threshold_s) &
        (df["mbps"] >= bandwidth_threshold_mbps)
    ].sort_values("orig_bytes", ascending=False)

    return sustained[[
        "ts", "id.orig_h", "id.resp_h", "id.resp_p",
        "duration", "orig_bytes", "mbps", "service"
    ]]
```

### Step 5: Detecting Staging — Falco Rules

Staging is the internal consolidation of data before external transfer. Detecting it provides an earlier warning than network-level exfiltration detection. Key staging behaviours: bulk reads of sensitive directories, creation of archives (tar, zip, gzip), and large writes to network-accessible locations (S3-mounted paths, NFS shares).

```yaml
# falco-exfil-staging.yaml
# Falco rules for detecting data staging behaviour.

- rule: Sensitive Directory Archive
  desc: >
    A process is creating an archive (tar, zip, gzip) from a sensitive
    directory. This is a common staging pattern before exfiltration.
  condition: >
    spawned_process and
    proc.name in (tar, zip, gzip, 7z, xz, bzip2) and
    (
      proc.args contains "/etc/secrets" or
      proc.args contains "/var/lib/kubelet" or
      proc.args contains "/home" or
      proc.args contains "/.ssh" or
      proc.args contains "/opt/app/config" or
      proc.args contains "/var/lib/postgresql"
    ) and
    not proc.pname in (known_backup_tools)
  output: >
    Sensitive directory archived
    (user=%user.name user_uid=%user.uid command=%proc.cmdline
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: WARNING
  tags: [exfiltration, staging, T1074]

- rule: Large File Copy From Sensitive Mount
  desc: >
    A process is reading more than 100MB from a sensitive bind-mount
    path. Detects bulk reads from secrets volumes or config maps.
  condition: >
    open_read and
    fd.typechar = 'f' and
    fd.num_files > 1000 and
    (
      fd.directory startswith "/mnt/secrets" or
      fd.directory startswith "/run/secrets" or
      fd.directory startswith "/var/run/secrets/kubernetes.io"
    )
  output: >
    Bulk read from secrets mount
    (user=%user.name file=%fd.name count=%fd.num_files
     container=%container.name image=%container.image.repository
     k8s_pod=%k8s.pod.name)
  priority: WARNING
  tags: [exfiltration, staging, secrets, T1552]

- rule: Unexpected Outbound Transfer Process
  desc: >
    A process not in the expected egress allowlist is initiating a
    large outbound network connection. Covers curl/wget abuse, rclone,
    s3cmd, and similar data transfer utilities.
  condition: >
    outbound and
    proc.name in (curl, wget, rclone, s3cmd, gsutil, aws, nc, ncat) and
    not proc.pname in (allowed_deploy_tools) and
    fd.sport > 0
  output: >
    Unexpected data transfer utility making outbound connection
    (user=%user.name command=%proc.cmdline
     connection=%fd.name container=%container.name
     image=%container.image.repository k8s_pod=%k8s.pod.name)
  priority: ERROR
  tags: [exfiltration, T1048, T1567]

- macro: known_backup_tools
  condition: proc.pname in (restic, duplicati, velero, backup-agent)

- macro: allowed_deploy_tools
  condition: proc.pname in (deploy, helm, kubectl, argocd)
```

### Step 6: Cloud-Specific Detection

#### AWS CloudTrail: S3 Exfiltration via GetObject

Attackers with valid S3 credentials can bulk-read an entire bucket. CloudTrail logs every `GetObject` call; the signal is in the volume and the caller identity.

```json
// Elasticsearch query: detect bulk S3 GetObject calls from
// unexpected principals on sensitive buckets.
// Ingest CloudTrail logs to cloudtrail-* index via Firehose or Lambda.

GET cloudtrail-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-1h"}}},
        {"term": {"eventName": "GetObject"}},
        {"terms": {"requestParameters.bucketName": [
          "prod-customer-data",
          "prod-pii-exports",
          "prod-financial-reports",
          "prod-source-code"
        ]}}
      ],
      "must_not": [
        {"terms": {"userIdentity.arn": [
          "arn:aws:iam::123456789:role/BackupServiceRole",
          "arn:aws:iam::123456789:role/DataLakeCrawler"
        ]}}
      ]
    }
  },
  "aggs": {
    "by_principal": {
      "terms": {"field": "userIdentity.arn", "size": 50},
      "aggs": {
        "object_count":       {"value_count": {"field": "requestParameters.key"}},
        "unique_keys":        {"cardinality": {"field": "requestParameters.key"}},
        "source_ips":         {"terms": {"field": "sourceIPAddress", "size": 10}},
        "total_bytes": {
          "sum": {"field": "additionalEventData.bytesTransferredOut"}
        }
      }
    }
  }
}
```

Alert when `unique_keys > 500` in one hour from a principal not in the allowlist, or when `total_bytes > 1GB` from any single principal in one hour.

#### GCP DLP Integration

GCP's Cloud DLP API can scan Cloud Storage objects and BigQuery datasets for sensitive data classifications. DLP findings feed into Security Command Center and Cloud Logging. Use the finding stream to detect when sensitive objects are being read at scale.

```python
# gcp_dlp_exfil_monitor.py
# Polls GCP Security Command Center for DLP findings and correlates
# with Cloud Audit Logs for large GCS object reads.

from google.cloud import securitycenter_v1
from google.cloud import logging_v2
from datetime import datetime, timedelta, timezone

def get_recent_dlp_findings(project_id: str, hours: int = 1) -> list:
    """
    Retrieve recent Cloud DLP findings from Security Command Center.
    Returns findings with HIGH or CRITICAL severity on data access events.
    """
    client = securitycenter_v1.SecurityCenterClient()
    org_name = f"projects/{project_id}/sources/-"

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    findings = client.list_findings(
        request={
            "parent": org_name,
            "filter": (
                f'category="SENSITIVE_DATA_ACCESS" '
                f'AND severity="HIGH" OR severity="CRITICAL" '
                f'AND event_time > "{cutoff}"'
            )
        }
    )
    return list(findings)


def correlate_dlp_with_gcs_reads(project_id: str, bucket_name: str) -> list:
    """
    Find GCS read operations (storage.objects.get) on buckets that have
    active DLP HIGH/CRITICAL findings. Returns principal + object count pairs.
    """
    log_client = logging_v2.Client(project=project_id)
    filter_str = (
        f'resource.type="gcs_bucket" '
        f'protoPayload.methodName="storage.objects.get" '
        f'resource.labels.bucket_name="{bucket_name}" '
        f'timestamp>="{(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}"'
    )
    entries = log_client.list_entries(filter_=filter_str, page_size=1000)
    reads_by_principal: dict = {}
    for entry in entries:
        principal = entry.http_request and entry.payload.get(
            "authenticationInfo", {}
        ).get("principalEmail", "unknown")
        reads_by_principal[principal] = reads_by_principal.get(principal, 0) + 1

    return sorted(reads_by_principal.items(), key=lambda x: x[1], reverse=True)
```

### Step 7: DLP Integration — Classification-Aware Exfiltration Detection

Data classification tags applied at ingestion time let you distinguish between a 1GB transfer of log files and a 1GB transfer of PII. Integrate classification metadata into the detection pipeline:

```yaml
# Elasticsearch ingest pipeline: enrich flow and CloudTrail documents
# with data classification labels from your classification service.
# Classification labels are stored in a separate enrichment index
# (data_classification) keyed by resource ARN / S3 key prefix / hostname.

PUT _ingest/pipeline/enrich-classification
{
  "description": "Attach data classification label to outbound flow and CloudTrail events",
  "processors": [
    {
      "enrich": {
        "policy_name": "data_classification_policy",
        "field": "requestParameters.bucketName",
        "target_field": "classification",
        "max_matches": 1
      }
    },
    {
      "set": {
        "if": "ctx.classification?.sensitivity == null",
        "field": "classification.sensitivity",
        "value": "UNCLASSIFIED"
      }
    }
  ]
}
```

With classification in every document, you can now write detection rules that fire only on transfers of `CONFIDENTIAL` or `RESTRICTED` data, dramatically reducing false positives from large-but-legitimate transfers of public or low-sensitivity data.

### Step 8: Correlation Rule — Staging Plus External Transfer

Individual signals (internal bulk read, archive creation, large outbound flow) each have moderate false positive rates. The combination of internal staging followed by external transfer in a short time window from the same host is a high-confidence exfiltration indicator.

```python
# correlation_engine.py
# Combines staging signals (Falco) and external transfer signals (flow logs)
# into a high-confidence exfiltration alert.

from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict

@dataclass
class StagingEvent:
    host: str
    timestamp: datetime
    event_type: str    # "archive_created", "bulk_read", "nfs_write"
    bytes_involved: int
    detail: str

@dataclass
class ExfilEvent:
    host: str
    timestamp: datetime
    dst_ip: str
    dst_port: int
    bytes_sent: int
    protocol: str

def correlate_staging_and_exfil(
    staging_events: list[StagingEvent],
    exfil_events: list[ExfilEvent],
    correlation_window_minutes: int = 60,
    min_bytes_staging: int = 50_000_000,    # 50MB
    min_bytes_exfil: int = 10_000_000       # 10MB
) -> list[dict]:
    """
    For each staging event, look for an exfiltration event from the same host
    within the correlation window. Returns high-confidence alert dicts.
    """
    alerts = []

    # Index exfil events by host for efficient lookup.
    exfil_by_host: dict[str, list[ExfilEvent]] = defaultdict(list)
    for ev in exfil_events:
        if ev.bytes_sent >= min_bytes_exfil:
            exfil_by_host[ev.host].append(ev)

    for staging in staging_events:
        if staging.bytes_involved < min_bytes_staging:
            continue
        host_exfils = exfil_by_host.get(staging.host, [])
        for exfil in host_exfils:
            time_delta = exfil.timestamp - staging.timestamp
            if timedelta(0) <= time_delta <= timedelta(minutes=correlation_window_minutes):
                alerts.append({
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "alert_type": "CORRELATED_EXFILTRATION",
                    "host": staging.host,
                    "staging_event": staging.event_type,
                    "staging_bytes": staging.bytes_involved,
                    "staging_detail": staging.detail,
                    "exfil_dst": exfil.dst_ip,
                    "exfil_dst_port": exfil.dst_port,
                    "exfil_bytes": exfil.bytes_sent,
                    "exfil_protocol": exfil.protocol,
                    "staging_time": staging.timestamp.isoformat(),
                    "exfil_time": exfil.timestamp.isoformat(),
                    "delta_minutes": time_delta.total_seconds() / 60,
                    "recommended_action": (
                        "ISOLATE HOST IMMEDIATELY. "
                        "Preserve memory image before network isolation. "
                        "Review all outbound connections from this host in the past 24 hours."
                    )
                })

    return sorted(alerts, key=lambda x: x["exfil_bytes"], reverse=True)
```

The correlation rule logic: if a host has both a staging event (bulk archive, sensitive directory read, NFS write) and a large outbound transfer to an external IP within 60 minutes, the combined signal represents a high-confidence exfiltration attempt that warrants immediate response regardless of per-signal thresholds.

### Step 9: Telemetry

```
exfil_volumetric_alerts_total{src_ip, dst_ip, protocol}        counter
exfil_dns_tunnelling_suspected_total{src_ip, resolver}         counter
exfil_icmp_tunnel_suspected_total{src_ip, dst_ip}              counter
exfil_staging_events_total{host, event_type}                   counter
exfil_correlated_alerts_total{host, severity}                  counter
exfil_s3_bulk_read_alerts_total{principal, bucket}             counter
exfil_dlp_findings_total{sensitivity, resource}                counter
exfil_detection_pipeline_lag_seconds{stage}                    gauge
```

Alert on:

- `exfil_correlated_alerts_total` any increment — correlated staging + external transfer is highest confidence; page immediately.
- `exfil_volumetric_alerts_total` where bytes > 1GB per hour from a non-backup source.
- `exfil_dns_tunnelling_suspected_total` where query count > 500 per hour — investigate DNS resolver destination.
- `exfil_detection_pipeline_lag_seconds{stage="flow_ingestion"}` > 300 — detections are running 5 minutes behind real time; tuning required.

## Expected Behaviour

| Signal | Approximate detection latency | False positive rate (tuned) |
|--------|------------------------------|------------------------------|
| Volumetric outbound anomaly (5× baseline) | 5–10 minutes | ~3 per day (pre-tuning); <1 per day after baseline |
| DNS tunnelling (entropy + rate) | 2–5 minutes | ~1 per day; primarily legitimate CDN-based services |
| ICMP tunnelling (large payload + duration) | 2–3 minutes | Very low; almost no legitimate large ICMP flows |
| Falco staging: archive of sensitive directory | Immediate (kernel event) | ~2 per day; exclude known backup tools |
| CloudTrail S3 bulk GetObject | 3–7 minutes (CloudTrail delivery lag) | Low with principal allowlist |
| Correlated staging + external transfer | 1–2 minutes after exfil begins | Very low; requires two independent signals |

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| 14-day rolling baseline | Context-aware volumetric alerts; low false positives for known workloads | New instances have no baseline; miss or false-positive during baseline period | Apply conservative fixed threshold (1GB/hour) for instances with < 14 days of data. |
| Shannon entropy for DNS tunnelling | Detects obfuscated subdomain data encoding without payload inspection | Legitimate CDN services with hash-based subdomains trigger false positives | Maintain an allowlist of high-entropy-but-legitimate domains (CDN, ACME challenge responses). |
| Zeek `conn.log` upload ratio | Directly measures asymmetric transfer (upload >> download) | High ratio threshold misses slow exfil; low threshold hits CDN uploads | Combine with duration: high ratio AND duration > 5 minutes is more specific. |
| Falco staging rules on archive tools | Catches operator-visible staging; works without network telemetry | Backup jobs using tar/gzip trigger rules | Tag backup service accounts and exclude via Falco macro. |
| 60-minute correlation window | Catches staged exfiltration with preparation time | Short window misses slow attackers who stage and wait | Run a secondary 24-hour correlation job for lower-confidence, longer-horizon cases. |
| Classification-aware alerting | Eliminates false positives on large transfers of non-sensitive data | Classification must be accurate; untagged sensitive data escapes detection | Default-to-sensitive policy: treat unclassified large transfers as sensitive pending review. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| VPC Flow Logs delivery delay | Exfil alerts arrive 15–30 minutes after the transfer completes | `exfil_detection_pipeline_lag_seconds` alert | For real-time requirements, supplement with eBPF-based host-level flow collection. VPC flow logs remain valuable for retrospective analysis. |
| Zeek drops packets under high load | DNS tunnelling and conn.log analysis have gaps | Zeek's `weird.log` logs dropped packets; monitor `zeek_dropped_packets_total` | Scale Zeek cluster; enable Zeek AF_PACKET or PF_RING for high-throughput capture. |
| Falco staging rules over-fire during deployment | Deployment pipelines that tar/copy large config sets flood alerts | Elevated `exfil_staging_events_total` during CI/CD windows | Add deployment window suppression: suppress staging alerts when a deployment is in progress in the same namespace. |
| Baseline poisoned by previous exfiltration | Attacker's transfer becomes part of the 14-day baseline; future transfers are undetected | Post-incident review shows transfer within baseline band | Exclude confirmed-compromised host data from baseline recalculation. Audit the baseline monthly for outlier days. |
| CloudTrail delivery lag exceeds 15 minutes | S3 exfiltration alerts are delayed past the point of response | Alert on CloudTrail delivery lag metric in CloudWatch | Enable CloudTrail with S3 data event logging and deliver to CloudWatch Logs in addition to S3 for lower-latency analysis. |
| DNS sinkhole bypasses Zeek analysis | Attacker uses DoH (DNS over HTTPS) to a public resolver (8.8.8.8:443) | No DNS query in Zeek logs; only an HTTPS flow to a known resolver IP | Block DoH to external resolvers at the firewall; force all DNS through an internal resolver visible to Zeek. |

## Related Articles

- [Network Flow Analysis: NetFlow, IPFIX, and eBPF for Traffic Anomaly Detection](/articles/observability/network-flow-analysis/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
- [Data Loss Prevention: Classifying and Controlling Sensitive Data Flows](/articles/cross-cutting/data-loss-prevention/)
- [Cloud Provider Audit Logs: CloudTrail, GCP Audit Logs, and Azure Monitor](/articles/observability/cloud-provider-audit-logs/)
- [Threat Hunting with osquery: Fleet-Wide Query Patterns for Compromise Detection](/articles/observability/threat-hunting-osquery/)
- [Alert Correlation: Combining Weak Signals into High-Confidence Incidents](/articles/observability/alert-correlation/)
