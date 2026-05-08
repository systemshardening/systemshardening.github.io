---
title: "Network Forensics and Secure Packet Capture"
description: "Capturing packets is the most direct way to confirm lateral movement, reconstruct attack sequences, and preserve evidence of data exfiltration. Done wrong, it creates privacy and legal risk, exposes captured data, and runs as root indefinitely. This guide covers privilege-separated capture, PCAP storage security, forensic analysis workflows, and long-term network recording."
slug: network-forensics-packet-capture
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - network-forensics
  - packet-capture
  - tcpdump
  - wireshark
  - incident-response
personas:
  - security-engineer
  - incident-responder
article_number: 505
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/network-forensics-packet-capture/
---

# Network Forensics and Secure Packet Capture

## The Problem

Flow records tell you that a workstation sent 4 GB to an external IP at 2 a.m. Firewall logs confirm the connection was permitted. But neither source answers the question forensic investigators actually need answered: *what was in that traffic?* Was it a large legitimate backup job, or was it a staged archive of customer records moving to an attacker-controlled endpoint?

Packet capture (PCAP) is the definitive answer. It preserves the content of every frame crossing an interface — the actual HTTP request bodies, the DNS queries, the SMB handshakes, the TLS ClientHello fingerprints, and, when session keys are available, the decrypted application payloads. When lateral movement is suspected, PCAP lets you reconstruct exactly which credentials were sprayed, which internal services were probed, and which ones responded.

Despite this, most organisations treat PCAP as an afterthought:

- **Capture runs as root.** The default `sudo tcpdump` pattern grants full root access to an interactive process writing untrusted data from the network. A crafted packet triggering a tcpdump parser bug can escalate to root.
- **Captures are stored unencrypted in `/tmp`.** The PCAP is written to a world-readable temp directory and forgotten. Anyone with shell access reads it.
- **No legal review.** Capturing employee traffic, including credentials and personal communications, may require written authorisation, documented purpose, and retention limits under GDPR, CCPA, and sector-specific regulations.
- **No chain of custody.** A PCAP handed to legal without a hash, timestamp, and access log is inadmissible as evidence and useless for forensic reconstruction.
- **Captures are too broad.** Capturing full traffic on a busy interface for an hour produces gigabytes of data containing traffic entirely unrelated to the incident. Signal is buried in noise, and the privacy exposure is maximised.

This article addresses all of these failure modes.

---

## When and Why to Capture Packets

Packet capture is high-value in three specific scenarios:

**Confirming suspected lateral movement.** Network flow anomalies — a workstation connecting to internal hosts it has never reached before — can be lateral movement or a legitimate software deployment. PCAP confirms which: you see the actual SMB authentication, the RPC calls, the WMI queries. If the connection carries `PsExec` service installation payloads, the question is settled.

**Preserving evidence of data exfiltration.** Once an attacker is evicted from an environment, the evidence is gone unless you captured it. A targeted capture triggered on high-volume outbound connections to unusual destinations preserves the exfil payload, the file names extracted from HTTP multipart uploads or DNS tunnelling queries, and the timing for correlation with access logs.

**Reconstructing attack sequences post-incident.** A continuous ring-buffer capture running at low bandwidth (headers only, or sampled) on critical segments provides a retrospective view. When the SOC alarm fires three days after the initial compromise, the PCAP ring buffer may contain the original foothold — the initial C2 connection, the first credential theft, the first internal scan.

---

## Running tcpdump Securely

The standard advice — `sudo tcpdump` — grants root for the duration of the capture. A safer model assigns only the `CAP_NET_RAW` capability to the binary:

```bash
# Grant CAP_NET_RAW to the tcpdump binary
sudo setcap cap_net_raw+ep /usr/bin/tcpdump

# Verify the capability is set
getcap /usr/bin/tcpdump
# /usr/bin/tcpdump cap_net_raw=ep

# Create a dedicated capture user with no home directory, no shell
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netcap
```

With this configuration, a user in a `netcap` group can run tcpdump without `sudo`. The process has precisely the privilege needed to open a raw socket and nothing else. A parser vulnerability in tcpdump cannot escalate to full root.

Use the `-Z` flag to drop privileges to a non-privileged user immediately after the interface is opened:

```bash
# Open eth0 (requires CAP_NET_RAW), then drop to uid 'netcap'
tcpdump -i eth0 -Z netcap -w /secure/captures/capture-$(date +%Y%m%dT%H%M%S).pcap
```

The `-Z` flag requires that the target user exists and that the output directory is writable by that user. Structure your capture directory accordingly:

```bash
sudo mkdir -p /secure/captures
sudo chown netcap:netcap /secure/captures
sudo chmod 750 /secure/captures
```

---

## Privilege-Separated Capture with dumpcap

`dumpcap` is the capture engine that ships with Wireshark. It is explicitly designed for privilege-separated operation: a small binary with `CAP_NET_RAW` and `CAP_NET_ADMIN` does only capture; analysis happens in a separate unprivileged process.

```bash
# Install dumpcap from the Wireshark package
sudo apt install wireshark-common

# Set capabilities on dumpcap rather than the full wireshark binary
sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/dumpcap

# Add analysts to the wireshark group (created by the package)
sudo usermod -aG wireshark analyst-user

# Capture with dumpcap: ring buffer, 100 MB per file, 10 files max
dumpcap -i eth0 -b filesize:102400 -b files:10 \
  -w /secure/captures/ring.pcapng
```

`dumpcap` writes pcapng format by default, which embeds interface metadata and capture comments — useful for chain-of-custody documentation.

---

## Targeted Capture Filters

Broad captures create evidence management problems and privacy exposure. Berkeley Packet Filter (BPF) expressions at capture time limit collected data to traffic relevant to the investigation. BPF filtering happens in the kernel before data is copied to userspace, which also reduces CPU overhead significantly on high-traffic interfaces.

```bash
# Capture only traffic to/from a specific suspect host
tcpdump -i eth0 -n -w /secure/captures/suspect.pcap \
  'host 10.4.22.45'

# Capture SMB lateral movement indicators (ports 445 and 139)
tcpdump -i eth0 -n -w /secure/captures/smb.pcap \
  'tcp port 445 or tcp port 139'

# Capture DNS for exfiltration detection (long labels, high query rate)
tcpdump -i eth0 -n -w /secure/captures/dns.pcap \
  'udp port 53 or tcp port 53'

# Capture outbound connections on non-standard ports (common C2 pattern)
tcpdump -i eth0 -n -w /secure/captures/nonstd.pcap \
  'tcp and not (port 80 or port 443 or port 22 or port 25) and src net 10.0.0.0/8'

# Headers only (no payload): for long-running captures where content is not needed
tcpdump -i eth0 -n -s 96 -w /secure/captures/headers.pcap
```

The `-s 96` flag sets the snap length to 96 bytes — enough to capture Ethernet, IP, and TCP/UDP headers without any payload. For reconstruction you need full packets (`-s 0`), but for connection metadata without payload privacy exposure, header-only capture is the correct default for continuous recording.

---

## Privacy and Legal Considerations

Packet capture on a corporate network intercepts communications that may include personal data: employee emails, authentication credentials, instant messages, browsing history. Before deploying any capture infrastructure, verify:

1. **Written authorisation.** A documented incident response authorisation signed by legal, HR, and the CISO covers you in most jurisdictions. A verbal go-ahead from the SOC manager does not.
2. **Acceptable use policy coverage.** Employees must have been informed that network traffic is subject to monitoring for security purposes. This is typically in the employment contract or an IT acceptable-use policy. If it is not, legal review is required before capture begins.
3. **Minimisation.** Capture only the traffic types, source hosts, and destination hosts relevant to the investigation. A BPF filter scoped to the suspect host prevents the capture from becoming a general surveillance record.
4. **Retention limits.** Define a maximum retention period for PCAP files before capture begins. Many organisations use 30 days for ring-buffer captures and 90 days for incident-specific captures. Files older than the retention limit must be securely deleted.
5. **Cross-border transfer.** If the capture infrastructure is in one jurisdiction and the investigation team is in another, transfer of PCAP data containing personal communications may require legal basis under GDPR or equivalent legislation.

---

## PCAP File Security: Encryption, Access Control, Chain of Custody

A PCAP file is a direct recording of network credentials, personal data, and proprietary communications. It must be treated as a high-sensitivity asset.

**Encrypt at rest with `age` or GPG:**

```bash
# Encrypt with age (preferred: simpler key management than GPG)
# Install: apt install age
age -r $(cat /etc/netcap/pubkey.txt) \
  -o /secure/captures/suspect.pcap.age \
  /secure/captures/suspect.pcap

# Securely delete the plaintext capture
shred -u /secure/captures/suspect.pcap

# Decrypt for analysis
age -d -i /etc/netcap/privkey.txt \
  -o /tmp/suspect-analysis.pcap \
  /secure/captures/suspect.pcap.age
```

**Document chain of custody.** For any capture that may become legal evidence, generate a cryptographic hash at capture time and record it in an append-only log:

```bash
# Hash the capture immediately after closing the file
sha256sum /secure/captures/suspect.pcap | tee -a /secure/captures/custody.log

# Record metadata: who captured it, when, what interface, what filter
cat >> /secure/captures/custody.log <<EOF
Captured by: $(whoami) at $(date -u +%Y-%m-%dT%H:%M:%SZ)
Interface: eth0
Filter: host 10.4.22.45
Purpose: Incident IR-2026-0412 — suspected exfiltration from workstation
EOF
```

**Access control.** PCAP files should be readable only by the investigator and the IR lead. Group ownership on the captures directory with `chmod 750` and audited with `auditd` rules on file access:

```bash
# Audit all reads of PCAP files
auditctl -w /secure/captures -p r -k pcap-access
```

---

## Live Capture Tools: tcpdump, tshark, gopacket

`tshark` (Wireshark's CLI frontend) applies the same dissectors as the GUI, making it useful for quick protocol-aware filtering that BPF cannot express:

```bash
# Show HTTP requests live, with method and URI
tshark -i eth0 -Y 'http.request' \
  -T fields -e http.host -e http.request.uri -e http.request.method

# Show DNS responses with TTL and answer
tshark -i eth0 -Y 'dns.flags.response == 1' \
  -T fields -e dns.qry.name -e dns.resp.ttl -e dns.a

# Capture and display TLS SNI values without decryption
tshark -i eth0 -Y 'tls.handshake.extensions_server_name' \
  -T fields -e tls.handshake.extensions_server_name
```

For custom capture tooling, the Go `gopacket` library (wrapping `libpcap`) allows building purpose-specific sensors:

```bash
# Example: capture and print all DNS queries with timestamps
go run github.com/google/gopacket/examples/... \
  -i eth0 -filter 'udp port 53'
```

`gopacket`-based tools are commonly used for building inline sensors that feed events to a SIEM in real time without writing full PCAP to disk.

---

## Offline Analysis: Wireshark, tshark, and Object Extraction

Once a PCAP is in hand, the analysis workflow depends on the question being answered.

**Interactive protocol analysis:** Open in Wireshark. Use `Statistics > Conversations` to identify top talkers. Apply the `tcp.stream` display filter to follow individual TCP sessions. Use `File > Export Objects > HTTP` to extract all HTTP-transferred files in a single operation.

**Scripted extraction with tshark:**

```bash
# Count connections by destination IP
tshark -r suspect.pcap -T fields -e ip.dst \
  | sort | uniq -c | sort -rn | head -20

# Extract all URIs from HTTP traffic
tshark -r suspect.pcap -Y 'http.request' \
  -T fields -e http.host -e http.request.uri

# Follow a specific TCP stream and dump the raw payload
tshark -r suspect.pcap -z follow,tcp,raw,0 -q

# Extract files transferred over HTTP using tcpflow
tcpflow -r suspect.pcap -o /tmp/extracted/
```

**Detecting beacon patterns.** C2 beacons produce packets at regular intervals — every 30 seconds, every 5 minutes. To identify beaconing in a PCAP:

```bash
# Extract timestamps and destination IPs, compute inter-arrival time variance
tshark -r suspect.pcap -T fields -e frame.time_epoch -e ip.dst \
  | awk '{print $2, $1}' \
  | sort | awk '
    seen[$1] { print $1, $2 - prev[$1] }
    { seen[$1]=1; prev[$1]=$2 }
  ' | sort -k2 -n | head -40
```

Low-variance inter-arrival times on a single destination IP are a strong beacon indicator.

---

## TLS Session Key Logging for Forensic Decryption

When a TLS session key log is available, Wireshark can decrypt TLS traffic in a PCAP without the private key. This works for traffic generated by Firefox, Chrome, and `curl` when the `SSLKEYLOGFILE` environment variable is set.

```bash
# Start curl with key logging for testing your own infrastructure
SSLKEYLOGFILE=/tmp/tls-keys.log curl https://internal.example.com/api/data

# Start a browser with key logging (Firefox/Chrome)
SSLKEYLOGFILE=/tmp/browser-keys.log firefox &
```

In Wireshark: `Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename`, point to the key log file, and TLS streams decrypt automatically.

**Legal and ethical scope.** Session key logging is legitimate for:
- Analysing your own service's traffic in a test or staging environment
- Forensic analysis of traffic generated by a system you own and have legal authority to inspect
- Debugging TLS issues in your own infrastructure

It is not legitimate for decrypting traffic from users or systems you do not own, and the key log file itself must be treated with the same sensitivity as a private key — it can be used to decrypt any session captured while the log was active.

---

## Long-Term Network Recording: Ring Buffers, Stenographer, Security Onion

For continuous recording with retrospective access, `tcpdump` ring buffers provide a simple on-host solution:

```bash
# Ring buffer: 100 MB per file, keep last 20 files (~2 GB total), rotate on size
tcpdump -i eth0 -n -s 96 -Z netcap \
  -w /secure/captures/ring.pcap \
  -W 20 -C 100

# Ring buffer with time-based rotation (new file every 5 minutes)
tcpdump -i eth0 -n -s 96 -Z netcap \
  -w /secure/captures/ring_%Y%m%d%H%M%S.pcap \
  -W 288 -G 300
```

`-W 288` combined with `-G 300` (5-minute files) yields 24 hours of ring-buffer coverage. Adjust snap length to `-s 0` on segments where full-payload capture is operationally justified.

**Stenographer** (by Google) extends this model with indexed, queryable storage. Stenographer writes compressed PCAP to disk and maintains an index of connections, allowing you to retrieve all packets matching a specific IP, port, or time range in seconds rather than scanning gigabytes of sequential PCAP files:

```bash
# Query Stenographer for all traffic to 10.4.22.45 in the last 2 hours
stenographer-client query \
  'host 10.4.22.45 and after 2h ago' \
  > /tmp/suspect-steno.pcap
```

**Security Onion** combines Suricata, Zeek, and either Stenographer or Arkime (formerly Moloch) into a pre-integrated platform. Zeek generates structured logs (conn.log, dns.log, http.log, ssl.log) with session identifiers that link directly to the corresponding PCAP in Stenographer. When an alert fires in Suricata, the Zeek session ID retrieves the exact packets from Stenographer without manually searching PCAP files.

For environments that need longer retention at lower cost, Arkime stores indexed PCAP in a distributed Elasticsearch backend, enabling multi-month queryable PCAP at scale that Stenographer's local-disk model cannot support.

---

## Operational Checklist

Before starting a capture in an incident response context:

- [ ] Written authorisation obtained and logged
- [ ] BPF filter scoped to suspect hosts and protocols only
- [ ] Capture running under `netcap` user or `dumpcap`, not root
- [ ] Output directory accessible only to IR team (`chmod 750`)
- [ ] Capture file encrypted or moved to encrypted storage before leaving the host
- [ ] SHA-256 hash recorded immediately after capture closes
- [ ] Chain of custody log entry created with operator, timestamp, scope, purpose
- [ ] Retention period documented and deletion scheduled
- [ ] SSLKEYLOGFILE key log (if used) stored with same access controls as PCAP

Packet capture is the most powerful tool in the incident responder's toolkit. The constraints above are not bureaucratic overhead — they are the conditions under which the evidence is trustworthy, legally defensible, and not itself a liability.
