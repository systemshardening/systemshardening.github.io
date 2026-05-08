---
title: "Suricata IDS/IPS: Host and Container Network Intrusion Detection"
description: "Suricata inspects network traffic against rule sets to detect exploit attempts, lateral movement, C2 communication, and data exfiltration. Running it inline as an IPS blocks malicious traffic in real time; running it on mirrored traffic provides detection without packet risk."
slug: "suricata-ids-ips"
date: 2026-05-01
lastmod: 2026-05-01
category: "network"
tags: ["suricata", "ids", "ips", "intrusion-detection", "network-security", "nfqueue"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 281
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/network/suricata-ids-ips/index.html"
---

# Suricata IDS/IPS: Host and Container Network Intrusion Detection

## Problem

Firewall rules control whether traffic is permitted; they do not inspect the content of permitted traffic. An HTTP request to port 80 passes a firewall rule allowing port 80 regardless of whether it contains a SQL injection payload, a known exploit, or a command-and-control beacon pattern.

Intrusion detection fills this gap: deep packet inspection against a signature database catches threats that perimeter rules cannot. Suricata is the open-source standard — multi-threaded, maintained by the OISF, supports the Emerging Threats and Suricata rule sets, runs in both passive (IDS) and active blocking (IPS) modes.

Common deployment gaps:

- **Detection is passive-only and unactioned.** Suricata logs alerts to a file that nobody reads. Alerts are not connected to a SIEM, not correlated, and not fed into automated response.
- **Default rules without tuning generate noise.** Deploying Emerging Threats Open without tuning produces thousands of alerts per hour — false positives from legitimate internal traffic. Alert fatigue sets in and the system is disabled.
- **No container network coverage.** Suricata is deployed on the host but inspects only traffic leaving the host. East-west traffic between containers on the same node — container-to-container lateral movement — goes uninspected.
- **IPS mode misconfigured.** Suricata is deployed in inline IPS mode (`nfqueue`) but rules with `drop` action are applied to all traffic including internal services. Legitimate traffic is blocked; Suricata is reconfigured to IDS-only mode, eliminating blocking capability.
- **Rules not updated.** The initial rule set is installed at deployment and never updated. New exploits and C2 patterns added to threat intelligence feeds go undetected.

**Target systems:** Suricata 7.0+ (multi-threaded, Rust-based detection engine improvements); Emerging Threats Open/Pro rule sets; AF_PACKET and NFQUEUE capture modes; Kubernetes node inspection via CNI plugin integration; EVE JSON output for Elasticsearch/Loki ingestion.

## Threat Model

- **Adversary 1 — Known exploit against exposed service:** An attacker sends a known exploit (CVE-matched) against an exposed web service. The exploit pattern is in the Emerging Threats rule set. Without IDS, the request reaches the application.
- **Adversary 2 — C2 beaconing from compromised host:** Malware on a compromised host beacons to a C2 server using HTTP, DNS, or HTTPS. C2 communication patterns — beacon intervals, JA3 TLS fingerprints, known C2 domain patterns — are detectable in Suricata rules.
- **Adversary 3 — Lateral movement over SMB/RDP:** An attacker who has compromised one host attempts SMB brute force or pass-the-hash against adjacent hosts. SMB anomaly and authentication rules fire on this pattern.
- **Adversary 4 — Data exfiltration via DNS tunnelling:** An attacker tunnels data out via DNS queries (long TXT records, high-frequency subdomain lookups). DNS tunnelling detection rules in Suricata catch this pattern.
- **Adversary 5 — Container-to-container exploit:** A compromised container exploits another container on the same node over the local bridge interface. Host-level packet inspection misses this if Suricata only inspects the physical interface.
- **Access level:** Adversaries 1 and 2 operate externally. Adversaries 3, 4, and 5 are post-compromise lateral movement and exfiltration.
- **Objective:** Exploit services, establish persistence via C2, move laterally, exfiltrate data.
- **Blast radius:** Without IDS, all post-compromise activity proceeds undetected. With IPS mode, known exploit traffic is blocked before reaching the application.

## Configuration

### Step 1: Install and Basic Configuration

```bash
# Ubuntu 22.04+ — install from official PPA.
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# RHEL 9 / Rocky Linux.
dnf install epel-release
dnf install suricata

# Verify installation.
suricata --build-info | grep "Suricata version"
```

```yaml
# /etc/suricata/suricata.yaml — core configuration.

vars:
  # Define your internal network ranges.
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "[10.0.0.53,10.0.0.54]"

# Capture interface.
af-packet:
  - interface: eth0
    threads: 4                # Match CPU cores.
    cluster-id: 99
    cluster-type: cluster_flow  # Per-flow affinity for reassembly.
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

# Logging.
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes          # Include packet payload (base64).
            payload-buffer-size: 4kb
            metadata: yes
        - http:
            extended: yes         # Full HTTP headers.
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes         # JA3/JA3S fingerprints.
        - flow

# Performance.
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [0]
    - worker-cpu-set:
        cpu: ["1-3"]              # Workers on dedicated cores.

# Memory.
stream:
  memcap: 512mb
  checksum-validation: yes
  inline: no                      # IDS mode. Set yes for IPS (nfqueue).
```

### Step 2: Rule Management with suricata-update

```bash
# Install suricata-update.
pip3 install suricata-update

# Update default rule sources.
suricata-update update-sources
suricata-update enable-source et/open          # Emerging Threats Open (free).
# suricata-update enable-source et/pro         # Emerging Threats Pro (paid; better coverage).

# Apply updates.
suricata-update

# Reload rules without restarting Suricata.
suricatasc -c reload-rules

# Automate daily updates.
cat > /etc/cron.daily/suricata-update << 'EOF'
#!/bin/bash
/usr/bin/suricata-update && /usr/bin/suricatasc -c reload-rules
EOF
chmod +x /etc/cron.daily/suricata-update
```

Rule tuning — disable noisy rules before they cause alert fatigue:

```yaml
# /etc/suricata/disable.conf — rules to disable.
# Format: rule ID or GID:SID.

# Disable overly broad HTTP rules that fire on legitimate traffic.
2013504   # ET WEB_SERVER Possible SQL Injection Blind - Too broad for dev environments.
2027758   # ET HUNTING SUSPICIOUS Fixit or similar scanners used internally.

# Disable rules for services not in your environment.
# (If you don't use SMB internally, these are all false positives.)
# 2000419-2000430  # SMB rules.
```

```yaml
# /etc/suricata/threshold.conf — suppress repetitive alerts.
# Suppress after 10 alerts from same source in 60 seconds.
suppress gen_id 1, sig_id 2010935, track by_src, ip 10.0.0.0/8

# Threshold: alert only once per hour from same src/dst pair.
threshold gen_id 1, sig_id 2001219, type both, track by_rule, count 1, seconds 3600
```

### Step 3: IPS Mode with NFQUEUE

In IPS mode, Suricata receives packets from the kernel via NFQUEUE, drops or accepts them, and rules with `drop` action block traffic:

```yaml
# /etc/suricata/suricata.yaml — IPS mode.
# Change capture mode from af-packet to nfqueue.

nfq:
  mode: repeat                # Re-inject to same queue after decision.
  batchcount: 20
  fail-open: yes              # On Suricata crash, default to ACCEPT (fail-open).

stream:
  inline: yes                 # Enable inline/IPS mode.
```

```bash
# iptables rules to redirect traffic through Suricata.
# Forward traffic to NFQUEUE.
iptables -I INPUT -j NFQUEUE --queue-num 0
iptables -I OUTPUT -j NFQUEUE --queue-num 0
iptables -I FORWARD -j NFQUEUE --queue-num 0

# Start Suricata with nfqueue.
suricata -c /etc/suricata/suricata.yaml -q 0

# Persist via systemd (suricata.service should use -q 0 flag).
systemctl restart suricata
```

For gradual IPS rollout — start with `alert` action rules, switch to `drop` selectively:

```bash
# Rules start as alert. Promote specific high-confidence rules to drop.
# /etc/suricata/modify.conf — change action for specific rules.
2008983 "alert" "drop"    # SQL injection pattern — high confidence, drop.
2010935 "alert" "drop"    # Known CVE exploit — high confidence, drop.

# Apply modifications.
suricata-update --modify-conf /etc/suricata/modify.conf
```

### Step 4: Container Network Inspection

For Kubernetes, inspect traffic on the container bridge interface:

```yaml
# /etc/suricata/suricata.yaml — add container bridge interface.
af-packet:
  - interface: eth0          # Host external interface.
    threads: 4
    cluster-id: 99
    cluster-type: cluster_flow

  - interface: cni0          # Container bridge (flannel/kubenet default).
    threads: 2
    cluster-id: 98
    cluster-type: cluster_flow
    copy-mode: ips           # IPS mode on container traffic.

  # For Cilium/Calico with VXLAN:
  - interface: vxlan.calico
    threads: 2
    cluster-id: 97
    cluster-type: cluster_flow
```

For Kubernetes DaemonSet deployment:

```yaml
# kubernetes/suricata-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: suricata
  namespace: security
spec:
  selector:
    matchLabels:
      app: suricata
  template:
    metadata:
      labels:
        app: suricata
    spec:
      hostNetwork: true      # Required to inspect host interfaces.
      hostPID: true
      containers:
        - name: suricata
          image: jasonish/suricata:7.0
          args: ["-c", "/etc/suricata/suricata.yaml", "--af-packet"]
          securityContext:
            capabilities:
              add: ["NET_ADMIN", "SYS_NICE"]  # Required for AF_PACKET.
          volumeMounts:
            - name: config
              mountPath: /etc/suricata
            - name: logs
              mountPath: /var/log/suricata
            - name: rules
              mountPath: /var/lib/suricata/rules
      volumes:
        - name: config
          configMap:
            name: suricata-config
        - name: logs
          hostPath:
            path: /var/log/suricata
        - name: rules
          hostPath:
            path: /var/lib/suricata/rules
```

### Step 5: EVE JSON Log Ingestion

Suricata's EVE JSON output ships to Elasticsearch or Loki for analysis:

```yaml
# /etc/filebeat/filebeat.yml — ship Suricata EVE to Elasticsearch.
filebeat.inputs:
  - type: log
    paths:
      - /var/log/suricata/eve.json
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_type: suricata

output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  index: "suricata-%{+yyyy.MM.dd}"
  ssl:
    certificate_authorities: ["/etc/ssl/certs/es-ca.crt"]
```

For Grafana/Loki:

```yaml
# /etc/promtail/config.yml
scrape_configs:
  - job_name: suricata
    static_configs:
      - targets: [localhost]
        labels:
          job: suricata
          host: __hostname__
          __path__: /var/log/suricata/eve.json
    pipeline_stages:
      - json:
          expressions:
            event_type: event_type
            alert_signature: alert.signature
            alert_severity: alert.severity
            src_ip: src_ip
            dest_ip: dest_ip
      - labels:
          event_type:
          alert_severity:
```

### Step 6: Custom Rules for Environment-Specific Detection

Write rules for your environment's specific threat patterns:

```
# /etc/suricata/rules/local.rules

# Detect access to Kubernetes API server from non-cluster IPs.
alert tcp !10.0.0.0/8 any -> $KUBERNETES_API 6443 (msg:"External access to Kubernetes API server"; classtype:policy-violation; sid:9000001; rev:1;)

# Detect base64-encoded commands in HTTP POST bodies (common in webshells).
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"Possible webshell base64 command"; flow:established,to_server; http.request_body; content:"base64_decode"; nocase; classtype:web-application-attack; sid:9000002; rev:1;)

# Detect DNS queries for known C2 domain patterns (long random subdomain).
alert dns any any -> any 53 (msg:"Possible DNS tunnelling - long subdomain"; dns.query; pcre:"/^[a-f0-9]{32,}\./i"; classtype:trojan-activity; sid:9000003; rev:1;)

# Detect crypto mining pool connections.
alert tcp $HOME_NET any -> any [3333,4444,5555,7777,9999,14444,45700] (msg:"Possible crypto mining pool connection"; classtype:policy-violation; sid:9000004; rev:1;)

# Detect kubectl exec from unexpected sources.
alert http any any -> $KUBERNETES_API 6443 (msg:"kubectl exec API call"; http.uri; content:"/exec?"; classtype:policy-violation; sid:9000005; rev:1;)
```

### Step 7: Telemetry

```
suricata_alerts_total{signature, severity, src_ip, dest_ip}    counter
suricata_drops_total{signature}                                 counter
suricata_flow_bypass_total{}                                    counter
suricata_capture_kernel_drops{interface}                        counter
suricata_decoder_pkts_total{interface}                          counter
suricata_uptime_seconds{}                                       gauge
```

Alert on:

- `suricata_alerts_total{severity="1"}` — severity 1 (critical) alerts require immediate investigation.
- `suricata_capture_kernel_drops` non-zero — Suricata cannot process packets fast enough; dropping traffic uninspected. Increase CPU allocation or ring buffer size.
- `suricata_uptime_seconds` resets — Suricata restarted unexpectedly; review for crashes. In IPS mode, a crash causes fail-open (all traffic passes).
- High `suricata_alerts_total` from a single `src_ip` — potential scanning or automated exploit; consider blocking at firewall level.

## Expected Behaviour

| Signal | No IDS | Suricata IDS/IPS |
|--------|--------|-----------------|
| Known CVE exploit sent to service | Request reaches application | Alert fired; in IPS mode, packet dropped |
| C2 beacon from compromised host | Undetected outbound connection | Signature match; alert on beacon pattern; C2 IP/domain blocked in IPS mode |
| DNS tunnelling exfiltration | Data leaves via DNS | DNS anomaly rule fires on long subdomain pattern |
| Container-to-container lateral movement | Uninspected on bridge interface | Bridge interface inspected; SMB/RDP anomaly rules fire |
| SQL injection in HTTP request | Reaches application | Alert on injection pattern; dropped in IPS mode |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| IPS mode (inline) | Blocks known exploits in real time | Risk of false positive blocking legitimate traffic | Start in IDS; promote rules to drop incrementally; test on staging |
| Emerging Threats Pro | Broader coverage, faster updates, IP reputation | Cost (~$600/year) | Free ET Open covers the most critical patterns; evaluate Pro for high-risk environments |
| Container bridge inspection | East-west visibility | Additional CPU for bridge traffic | Profile traffic volume; use sampling if CPU-constrained |
| Custom local rules | Environment-specific detection | Maintenance burden; risk of false positives | Test rules on replay captures before production; review quarterly |
| `fail-open: yes` in IPS | Service continuity on Suricata crash | Traffic bypasses inspection during crash | Monitor uptime metric; use redundant Suricata instances |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Kernel packet drops | Suricata misses packets; gaps in detection | `suricata_capture_kernel_drops` metric | Increase `ring-size` in af-packet config; add CPU capacity |
| Rule update breaks detection | Suricata fails to reload rules after update | Reload error in suricata.log; zero alerts after reload | Validate rules with `suricata --test-config`; roll back to previous rule set |
| IPS false positive blocks service | Legitimate traffic dropped; application unreachable | Application error rate spikes; alert on traffic drop | Add `suppress` or `threshold` for the offending rule; or change action back to `alert` |
| EVE log disk fills | Log rotation fails; suricata stops writing alerts | Disk usage alert; missing EVE entries | Compress and archive logs; set `limit` in EVE output config; ship to remote storage |
| Suricata crash in IPS mode | All traffic passes uninspected (fail-open) | `suricata_uptime_seconds` resets; uptime monitoring | Investigate core dump; restart service; page on-call |

## Related Articles

- [Network Flow Analysis with eBPF and NetFlow](/articles/observability/network-flow-analysis/)
- [eBPF XDP for DDoS Mitigation](/articles/network/ebpf-xdp-ddos/)
- [DNS RPZ and Threat Intelligence Feeds](/articles/network/dns-rpz-threat-intelligence/)
- [eBPF Tetragon for Runtime Security](/articles/observability/ebpf-tetragon/)
- [Detection Rules and Sigma](/articles/observability/detection-rules/)
