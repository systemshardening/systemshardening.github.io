---
title: "Zeek Network Security Monitoring: Protocol Analysis, Threat Detection, and SIEM Integration"
description: "Zeek transforms raw packet streams into structured, queryable logs covering every TCP/UDP flow, DNS query, HTTP transaction, TLS handshake, and file transfer on your network. Unlike alert-based IDS tools, Zeek gives you a complete network audit trail for threat hunting, incident response, and compliance."
slug: zeek-network-security-monitoring
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - zeek
  - network-monitoring
  - ids
  - threat-detection
  - log-analysis
personas:
  - security-engineer
  - network-engineer
article_number: 499
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/zeek-network-security-monitoring/
---

# Zeek Network Security Monitoring: Protocol Analysis, Threat Detection, and SIEM Integration

## The Problem

Firewall logs tell you what was permitted or denied. IDS signatures tell you what matched a known-bad pattern. Neither tells you what actually happened on the network. When an incident occurs, analysts need to answer questions like:

- Which internal host made a DNS query for that C2 domain, and when exactly?
- What TLS certificate was presented on port 4444 three weeks ago?
- Did the compromised workstation exfiltrate data, and if so how much and to where?
- Which files were transferred over HTTP in the 24 hours before the alert fired?

Alert-only tooling cannot answer these questions retroactively. Without a full network audit trail you are blind to everything that did not trigger a signature — which includes most attacker activity.

Common gaps in network visibility programmes:

- **No flow-level accounting.** NetFlow captures source/destination/bytes but not application-layer content. Protocol anomalies, certificate details, and DNS answers are invisible.
- **Alert fatigue from signature tools.** Suricata and Snort produce per-event alerts. Security teams tune signatures so aggressively to eliminate noise that genuine detections are suppressed.
- **No retrospective capability.** Without a full log of network sessions, incident response is limited to the window covered by the alerting system. Dwell time for APTs averages over 200 days — most of that activity predates any alert.
- **Container east-west blindness.** Kubernetes workloads communicate on overlay networks that bypass host-level monitoring. Pod-to-pod lateral movement is invisible unless the monitoring plane sits inside the network fabric.
- **TLS opacity without certificate metadata.** Encrypted traffic cannot be decrypted in most environments, but JA3/HASSH fingerprints and certificate attributes reveal TLS tooling, autonomous system anomalies, and self-signed certificates used by malware.

**Target systems:** Zeek 6.x; Ubuntu 22.04+ / Rocky Linux 9; zeekctl cluster mode; Kubernetes DaemonSet deployment; Elasticsearch 8.x for SIEM ingestion.

## Zeek vs Suricata: Complementary, Not Competing

The most common misconception is that Zeek and Suricata serve the same purpose. They do not.

**Suricata** is a signature-matching engine. It evaluates each packet against a rule set and emits an alert when a rule fires. It is excellent at detecting known threats — exploit payloads, known C2 beacon patterns, protocol abuse that matches a written signature. It produces alerts, not logs.

**Zeek** is a protocol analyser. It reconstructs application-layer sessions from raw packets and writes structured log records for every observed protocol interaction, regardless of whether anything suspicious occurred. It produces logs, not (primarily) alerts.

The two tools are complementary. Suricata answers "did anything known-bad happen?" Zeek answers "what happened, completely?" A mature SOC runs both: Suricata for real-time alerting on known patterns, Zeek for the audit trail that enables retrospective threat hunting and incident reconstruction.

Zeek can also generate alerts via its Notice framework — but its primary value is the comprehensive log archive that makes every network event queryable.

## Core Logs and What They Contain

Zeek writes one log file per protocol. Each line is a tab-separated (or JSON, configurable) record of a single protocol event.

### conn.log

Every TCP, UDP, and ICMP flow produces a `conn.log` record. This is the foundational log for network accounting.

Key fields:

| Field | Meaning |
|---|---|
| `ts` | Timestamp of first packet |
| `uid` | Unique connection ID (correlates across logs) |
| `id.orig_h` / `id.resp_h` | Source and destination IP |
| `id.orig_p` / `id.resp_p` | Source and destination port |
| `proto` | `tcp`, `udp`, `icmp` |
| `service` | Detected application protocol |
| `duration` | Connection duration in seconds |
| `orig_bytes` / `resp_bytes` | Payload bytes in each direction |
| `conn_state` | TCP state: `S1` (established, no FIN), `SF` (normal close), `REJ` (rejected), `RSTO` (reset by originator) |
| `missed_bytes` | Bytes Zeek could not capture — indicates packet loss |
| `history` | Packet history string: `ShADadfFR` encodes SYN, SYN-ACK, data, FIN, RST sequencing |

`conn_state` is particularly useful for distinguishing port scans (`S0` — SYN sent, no response) from established sessions and identifying abruptly terminated connections (`RSTO`, `RSTR`) that may indicate exploit attempts.

### dns.log

Every DNS query and response, including the answers returned, is logged. This makes DNS tunnelling and domain generation algorithm (DGA) detection tractable without deploying a separate DNS security tool.

Key fields: `query` (the FQDN queried), `qtype_name` (A, AAAA, TXT, MX, etc.), `rcode_name` (NOERROR, NXDOMAIN, SERVFAIL), `answers` (comma-separated response records), `TTL`.

### http.log

HTTP request/response metadata — not body content, but everything in headers and the request line.

Key fields: `method`, `host`, `uri`, `referrer`, `user_agent`, `status_code`, `request_body_len`, `response_body_len`, `tags`.

Large `request_body_len` values on POST requests to external hosts are a primary exfiltration indicator.

### ssl.log

One record per TLS handshake. Critical for encrypted traffic analysis.

Key fields: `version` (TLSv12, TLSv13), `cipher`, `curve`, `server_name` (SNI), `subject` and `issuer` (certificate DN), `validation_status` (certificate chain result), `ja3` and `ja3s` (client and server TLS fingerprints, with the ja3 package installed).

`validation_status: self signed certificate in certificate chain` combined with an unusual port or a new destination IP is a high-fidelity C2 indicator.

### files.log

Every file transferred over HTTP, SMTP, FTP, or other protocols Zeek reconstructs gets a `files.log` record.

Key fields: `source` (protocol), `depth` (nesting level), `analyzers` (file type detectors run), `mime_type`, `filename`, `md5`, `sha1`, `sha256` (with file hashing enabled), `extracted` (path if Zeek extracted the file to disk).

File hashes can be submitted to threat intelligence APIs or checked against known-malware hash sets during incident response.

## Deploying Zeek

### Standalone Installation

```bash
# Ubuntu 22.04.
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
  | tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
apt-get update && apt-get install -y zeek-6.0

# Rocky Linux 9.
dnf install -y https://download.opensuse.org/repositories/security:/zeek/CentOS_9_Stream/noarch/zeek-release-1.0-1.noarch.rpm
dnf install -y zeek

# Add zeekctl to PATH.
echo 'export PATH=/opt/zeek/bin:$PATH' >> /etc/profile.d/zeek.sh
source /etc/profile.d/zeek.sh
```

### Interface Configuration

```bash
# /opt/zeek/etc/node.cfg — standalone mode.
[zeek]
type=standalone
host=localhost
interface=eth0    # Replace with the capture interface.

# For a SPAN port or tap, disable IP forwarding and set the interface promisc.
ip link set eth0 promisc on
ethtool -K eth0 rx-checksumming off tx-checksumming off \
  gso off tso off gro off lro off
```

For high-throughput environments (>1 Gbps), use AF_PACKET with multiple workers:

```bash
# /opt/zeek/etc/node.cfg — cluster mode with AF_PACKET fanout.
[manager]
type=manager
host=127.0.0.1

[proxy-1]
type=proxy
host=127.0.0.1

[worker-1]
type=worker
host=127.0.0.1
interface=af_packet::eth0
lb_method=custom
lb_procs=4
pin_cpus=0,1,2,3

[worker-2]
type=worker
host=127.0.0.1
interface=af_packet::eth1
lb_method=custom
lb_procs=4
pin_cpus=4,5,6,7
```

AF_PACKET with `lb_method=custom` uses kernel fanout to distribute flows across Zeek worker processes by connection 5-tuple hash, ensuring packets belonging to the same connection always reach the same worker.

### zeekctl Lifecycle

```bash
# Initial deployment — installs scripts, validates config.
zeekctl deploy

# Day-to-day operations.
zeekctl start
zeekctl stop
zeekctl restart
zeekctl status

# Scheduled log rotation and crash recovery — add to cron.
# /etc/cron.d/zeekctl
*/5 * * * * root /opt/zeek/bin/zeekctl cron
```

`zeekctl cron` rotates logs every hour by default (configurable via `LogRotationInterval` in `zeekctl.cfg`), checks for worker crashes, and restarts failed processes automatically.

## Writing Zeek Scripts

Zeek includes a full programming language designed around network events. Scripts handle events emitted by the protocol analysers and can generate notices, update state tables, or write custom logs.

### Event-Driven Programming Model

```zeek
# /opt/zeek/share/zeek/site/local.zeek — load custom scripts.
@load ./scripts/detect-dns-tunneling
@load ./scripts/detect-c2-beaconing
@load ./scripts/detect-exfiltration
```

A Zeek script handling a DNS request event:

```zeek
# scripts/detect-dns-tunneling.zeek

module DNSTunneling;

export {
    redef enum Notice::Type += {
        HighEntropyDNSQuery,
        LargeDNSTXTRecord,
    };
}

# Calculate Shannon entropy of a string.
function entropy(s: string): double {
    local counts: table[string] of count;
    local len = |s|;
    if ( len == 0 )
        return 0.0;

    for ( i in s ) {
        local c = s[i];
        if ( c !in counts )
            counts[c] = 0;
        ++counts[c];
    }

    local h = 0.0;
    for ( c in counts ) {
        local p = counts[c] / (len + 0.0);
        h -= p * log2(p);
    }
    return h;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Strip the registered domain to get the subdomain label.
    local parts = split_string(query, /\./);
    if ( |parts| < 2 )
        return;

    local label = parts[0];

    # Flag high-entropy subdomain labels longer than 20 characters.
    # Legitimate subdomains are human-readable; DGA/tunnel labels are random.
    if ( |label| > 20 && entropy(label) > 3.8 ) {
        NOTICE([$note=HighEntropyDNSQuery,
                $conn=c,
                $msg=fmt("High-entropy DNS query: %s (entropy=%.2f)", query, entropy(label)),
                $identifier=cat(c$id$orig_h),
                $suppress_for=10min]);
    }
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) { }

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec) {
    for ( i in strs ) {
        # TXT records over 100 bytes are unusual and a common tunnelling channel.
        if ( |strs[i]| > 100 ) {
            NOTICE([$note=LargeDNSTXTRecord,
                    $conn=c,
                    $msg=fmt("Large DNS TXT record (%d bytes) for %s", |strs[i]|, ans$query),
                    $identifier=cat(c$id$orig_h),
                    $suppress_for=10min]);
        }
    }
}
```

### Detecting C2 Beaconing

Beaconing detection requires tracking connection intervals to the same destination over time. Zeek tables with expiry provide a stateful approach:

```zeek
# scripts/detect-c2-beaconing.zeek

module Beaconing;

export {
    redef enum Notice::Type += { C2Beacon };

    # Minimum number of equally-spaced connections to trigger.
    const beacon_count_threshold = 10 &redef;
    # Maximum jitter (seconds) between intervals to qualify as beaconing.
    const beacon_jitter_threshold = 5.0 &redef;
}

# Track connection timestamps per src->dst pair.
global conn_times: table[addr, addr] of vector of time
    &create_expire=1hr
    &redef;

event connection_established(c: connection) {
    local key = [c$id$orig_h, c$id$resp_h];

    if ( key !in conn_times )
        conn_times[key] = vector();

    conn_times[key] += c$start_time;

    local times = conn_times[key];
    if ( |times| < beacon_count_threshold )
        return;

    # Compute intervals between consecutive connections.
    local intervals: vector of double = vector();
    for ( i in times ) {
        if ( i == 0 )
            next;
        intervals += interval_to_double(times[i] - times[i-1]);
    }

    # Calculate mean interval.
    local sum = 0.0;
    for ( i in intervals )
        sum += intervals[i];
    local mean = sum / |intervals|;

    if ( mean < 10.0 )  # Ignore intervals under 10 seconds — normal keep-alives.
        return;

    # Calculate standard deviation.
    local variance = 0.0;
    for ( i in intervals )
        variance += (intervals[i] - mean) ^ 2;
    local stddev = sqrt(variance / |intervals|);

    if ( stddev < beacon_jitter_threshold ) {
        NOTICE([$note=C2Beacon,
                $src=c$id$orig_h,
                $dst=c$id$resp_h,
                $msg=fmt("Potential C2 beaconing: %s -> %s, interval=%.1fs, stddev=%.2fs, count=%d",
                         c$id$orig_h, c$id$resp_h, mean, stddev, |times|),
                $identifier=cat(c$id$orig_h, c$id$resp_h),
                $suppress_for=1hr]);
    }
}
```

### Detecting Large Outbound Exfiltration

```zeek
# scripts/detect-exfiltration.zeek

module Exfiltration;

export {
    redef enum Notice::Type += { LargeOutboundPost };

    # POST bodies over 10 MB to external hosts are suspicious.
    const exfil_threshold_bytes = 10 * 1024 * 1024 &redef;
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) {
    if ( ! is_orig )  # Only inspect requests, not responses.
        return;

    if ( c$http$method != "POST" )
        return;

    # Only flag traffic to external IPs.
    if ( Site::is_local_addr(c$id$resp_h) )
        return;

    if ( stat$body_length > exfil_threshold_bytes ) {
        NOTICE([$note=LargeOutboundPost,
                $conn=c,
                $msg=fmt("Large HTTP POST to external host: %s -> %s%s (%s bytes)",
                         c$id$orig_h,
                         c$http?$host ? c$http$host : cat(c$id$resp_h),
                         c$http?$uri ? c$http$uri : "/",
                         stat$body_length),
                $identifier=cat(c$id$orig_h),
                $suppress_for=30min]);
    }
}
```

## Package Manager: zkg

Zeek's package manager installs community scripts that would take weeks to write from scratch.

```bash
# Install the package manager (included with Zeek 4.0+).
pip3 install zkg
zkg autoconfig

# Essential packages for a production deployment.

# JA3/JA3S TLS fingerprinting — enriches ssl.log with fingerprint hashes.
zkg install zeek/salesforce/ja3

# HASSH SSH client/server fingerprinting — enriches ssh.log.
zkg install zeek/salesforce/hassh

# Community ID flow hash — adds RFC-standard flow ID for cross-tool correlation.
zkg install zeek/corelight/zeek-community-id

# MITRE ATT&CK-mapped detections.
zkg install zeek/mitre-attack/bzar

# Long connection detector — flags sessions > configurable duration.
zkg install zeek/corelight/longconn

# List installed packages.
zkg list installed

# Update all packages.
zkg upgrade
```

After installing packages, redeploy:

```bash
zeekctl deploy
```

JA3 fingerprints in `ssl.log` enable correlation of TLS tooling across different IP addresses. A threat actor switching C2 infrastructure keeps the same JA3 fingerprint if they use the same malware implant.

## Notice Framework

The Notice framework is how Zeek scripts escalate findings to actionable alerts.

```zeek
# /opt/zeek/share/zeek/site/notice-config.zeek

# Email critical notices to the security team.
redef Notice::mail_dest = "security-alerts@example.com";

# NOTICE_ALARM_ALWAYS forces a notice to appear in alarm.log regardless
# of suppression settings — use for highest-fidelity detections only.
redef Notice::alarmed_types += {
    Beaconing::C2Beacon,
    Exfiltration::LargeOutboundPost,
};

# Configure email for specific notice types.
redef Notice::emailed_types += {
    Beaconing::C2Beacon,
};

# Suppress lower-confidence notices to control noise.
redef Notice::not_suppressed_types -= {
    DNSTunneling::HighEntropyDNSQuery,
};
```

Notices appear in `notice.log`. The `alarm.log` contains only those notices marked with `NOTICE_ALARM_ALWAYS` or via `Notice::alarmed_types` — this is the high-confidence feed suitable for automated response or PagerDuty integration.

## SIEM Integration

Zeek logs are most powerful when indexed in a searchable data store. The standard pipeline uses Filebeat to ship logs to Elasticsearch.

### Filebeat Configuration

```yaml
# /etc/filebeat/filebeat.yml

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/zeek/logs/current/*.log
    fields:
      log_source: zeek
    fields_under_root: true
    # Zeek JSON format — enable JSON output in local.zeek first.
    json.keys_under_root: true
    json.add_error_key: true
    # Multiline is not needed for Zeek JSON logs.
    exclude_files: ['\.gz$']

processors:
  - add_host_metadata: ~
  - add_fields:
      target: ''
      fields:
        environment: production
        datacenter: us-east-1

output.logstash:
  hosts: ["logstash.internal:5044"]
```

Enable JSON output in Zeek before shipping:

```zeek
# /opt/zeek/share/zeek/site/local.zeek

# Write logs as JSON instead of TSV.
@load policy/tuning/json-logs
redef LogAscii::use_json = T;
```

### Logstash Pipeline for Zeek Enrichment

```ruby
# /etc/logstash/conf.d/zeek.conf

filter {
  if [log_source] == "zeek" {

    # Parse timestamp from Zeek's epoch float.
    date {
      match => ["ts", "UNIX"]
      target => "@timestamp"
    }

    # Enrich conn.log with GeoIP data on the responder IP.
    if [_path] == "conn" {
      geoip {
        source => "id.resp_h"
        target => "geoip"
        fields => ["city_name", "country_code2", "location", "autonomous_system_number"]
      }
    }

    # Tag self-signed TLS certificates.
    if [_path] == "ssl" {
      if [validation_status] =~ /self.signed/ {
        mutate { add_tag => ["self_signed_cert"] }
      }
    }
  }
}

output {
  if [log_source] == "zeek" {
    elasticsearch {
      hosts => ["https://elasticsearch.internal:9200"]
      index => "zeek-%{[_path]}-%{+YYYY.MM.dd}"
      user => "zeek_shipper"
      password => "${ZEEK_ES_PASSWORD}"
      ssl_certificate_verification => true
    }
  }
}
```

With separate indices per log type (`zeek-conn-*`, `zeek-ssl-*`, `zeek-dns-*`), index lifecycle policies can apply different retention periods — `conn.log` at 90 days, `ssl.log` at 365 days for certificate forensics.

## Performance Tuning

### AF_PACKET and PF_RING

At line rates above 1 Gbps, kernel packet capture becomes the bottleneck. AF_PACKET with zero-copy (`PACKET_MMAP`) eliminates most kernel overhead:

```bash
# /opt/zeek/etc/zeekctl.cfg
lb_method=custom         # Use kernel fanout for load balancing.
lb_procs=8               # One worker per CPU core dedicated to capture.
```

For 10+ Gbps deployments, PF_RING with DNA mode (direct NIC access) is the next tier:

```bash
# Install PF_RING kernel module.
apt-get install pfring-dkms
modprobe pf_ring enable_tx_capture=0 min_num_slots=65536

# Configure Zeek to use PF_RING.
# In node.cfg:
interface=pfring::eth0
```

### CPU Pinning

```bash
# Pin Zeek workers to specific CPU cores to avoid NUMA crossings.
# /opt/zeek/etc/node.cfg
[worker-1]
type=worker
host=127.0.0.1
interface=af_packet::eth0
lb_method=custom
lb_procs=4
pin_cpus=0,1,2,3   # Physical cores on socket 0.

[worker-2]
type=worker
host=127.0.0.1
interface=af_packet::eth0
lb_method=custom
lb_procs=4
pin_cpus=4,5,6,7   # Physical cores on socket 1 (if NUMA node 1 is close to NIC).
```

### Log Rotation and Disk Management

```bash
# /opt/zeek/etc/zeekctl.cfg
LogRotationInterval = 3600   # Rotate logs every hour.
LogExpireInterval = 0        # Disable built-in expiry — handle via external policy.
CompressLogs = 1             # gzip rotated logs.
CompressCmd = gzip           # Or zstd for better ratios: CompressCmd = zstd
CompressExtension = gz

# External retention policy via find — keep 30 days of conn.log, 90 days of ssl.log.
# /etc/cron.daily/zeek-retention
find /opt/zeek/logs -name 'conn.*.gz' -mtime +30 -delete
find /opt/zeek/logs -name 'ssl.*.gz' -mtime +90 -delete
find /opt/zeek/logs -name 'dns.*.gz' -mtime +30 -delete
```

## Kubernetes Deployment

Deploying Zeek inside Kubernetes requires access to pod network traffic. The most effective approach is a DaemonSet with `hostNetwork: true` that captures on the node's primary interface or the CNI bridge.

```yaml
# zeek-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: zeek
  namespace: security
spec:
  selector:
    matchLabels:
      app: zeek
  template:
    metadata:
      labels:
        app: zeek
    spec:
      hostNetwork: true          # Access host network interfaces.
      hostPID: false
      tolerations:
        - operator: Exists       # Schedule on all nodes including masters.
      initContainers:
        - name: set-promisc
          image: busybox:1.36
          command: ["sh", "-c", "ip link set $(IFACE) promisc on"]
          env:
            - name: IFACE
              value: "eth0"
          securityContext:
            privileged: true
      containers:
        - name: zeek
          image: zeek/zeek:6.0
          args: ["-i", "eth0", "-C", "/opt/zeek/share/zeek/site/local.zeek"]
          env:
            - name: ZEEK_DISABLE_CHECKSUMS
              value: "1"
          securityContext:
            capabilities:
              add:
                - NET_RAW
                - NET_ADMIN
            runAsNonRoot: false   # Zeek requires root for raw socket.
            readOnlyRootFilesystem: false
          volumeMounts:
            - name: zeek-logs
              mountPath: /opt/zeek/logs
            - name: zeek-config
              mountPath: /opt/zeek/share/zeek/site
              readOnly: true
          resources:
            requests:
              cpu: "2"
              memory: "2Gi"
            limits:
              cpu: "4"
              memory: "4Gi"
      volumes:
        - name: zeek-logs
          hostPath:
            path: /var/log/zeek
            type: DirectoryOrCreate
        - name: zeek-config
          configMap:
            name: zeek-site-config
```

For Calico or Cilium CNI environments, capture on `cali+` or `lxc+` interfaces respectively to see pod-to-pod traffic. The wildcard interface syntax `af_packet::cali+` (with Zeek compiled with AF_PACKET interface glob support) fans out across all matching interfaces.

A sidecar Filebeat container on the same pod ships `zeek-logs` to Elasticsearch, maintaining per-node log shipping without a separate deployment.

## Operational Checklist

Before treating a Zeek deployment as production-ready, verify each of the following.

**Capture completeness:**
- `zeekctl status` shows all workers in `running` state with 0 restarts in the last 24 hours.
- `conn.log` `missed_bytes` field is consistently 0 — non-zero values indicate packet drops.
- DNS resolution traffic appears in `dns.log`; absence means the capture interface is not seeing DNS traffic.

**Log integrity:**
- Rotated logs are compressed and checksummed. Use `md5sum` on archived logs and store checksums for forensic integrity.
- Disk usage is bounded by retention policy. `df -h /opt/zeek/logs` should not exceed 80%.

**Detection coverage:**
- Test DNS tunnelling detection with `iodine` or `dnscat2` in a lab environment — confirm `notice.log` entries appear within 60 seconds.
- Test beaconing detection with a script that connects to a test host every 60 seconds for 15 minutes.
- Verify `alarm.log` notices trigger email delivery to the security mailbox.

**SIEM pipeline:**
- Confirm `zeek-conn-*` index in Elasticsearch receives documents within 5 minutes of connection events.
- JA3 hashes appear in `zeek-ssl-*` documents. A missing `ja3` field means the ja3 package failed to load.
- Community ID field matches equivalent field in Suricata EVE JSON events — this enables cross-tool correlation by flow.

## Summary

Zeek turns a network interface into a structured, queryable audit trail of everything that crossed it. The core deployment — standalone `zeekctl`, JSON logs, Filebeat to Elasticsearch — is achievable in under an hour and immediately answers questions that neither firewall logs nor alert-based IDS can address.

The scripting layer is what separates Zeek from passive monitoring tools. Event-driven scripts track connection intervals for beaconing detection, compute entropy over DNS labels for tunnelling detection, and flag anomalous HTTP POST sizes for exfiltration detection — all without signature rules that require constant maintenance.

Run Zeek alongside Suricata, not instead of it. Suricata catches known threats in real time; Zeek records everything for when the unknown threat is discovered six months later and you need to reconstruct exactly what it did.
