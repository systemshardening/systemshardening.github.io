---
title: "Passive TLS Fingerprinting with JA3 and JA4 for Network Security Detection"
description: "JA3 and JA4 fingerprint TLS ClientHello messages to identify malware C2 beacons, Cobalt Strike, scanning tools, and commodity RATs — without decrypting traffic. This article covers how both algorithms work, Zeek and Suricata integration, threat intelligence databases, and SIEM correlation pipelines."
slug: tls-fingerprinting-ja3-ja4
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - tls-fingerprinting
  - ja3
  - ja4
  - threat-detection
  - network-monitoring
personas:
  - security-engineer
  - network-engineer
article_number: 494
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/tls-fingerprinting-ja3-ja4/
---

# Passive TLS Fingerprinting with JA3 and JA4 for Network Security Detection

## The Problem

Your network carries encrypted TLS traffic. You cannot read the payload — that is the entire point of encryption. But the TLS handshake itself leaks rich metadata before a single byte of application data is exchanged: which cipher suites the client supports, which TLS extensions it announces, which elliptic curves it prefers, and in which order. This is not content; it is protocol behaviour. And protocol behaviour is surprisingly stable per TLS implementation.

Wireshark is open to everyone. So is OpenSSL. But malware authors, penetration testers, and red teams rarely write their own TLS stacks from scratch. They reuse Go's `crypto/tls`, Python's `ssl` module, or embed a C2 framework like Cobalt Strike. Each of these TLS implementations generates `ClientHello` messages with consistent, fingerprint-able field combinations.

The practical consequences:

- **Cobalt Strike default beacon** uses a specific JARM/JA3 fingerprint that has been documented since 2020. Un-customised Cobalt Strike installations are immediately identifiable from passive network logs.
- **Masscan and ZMap** both send minimally-crafted `ClientHello` messages that no legitimate browser would send.
- **Commodity RATs** (AsyncRAT, NjRAT, QuasarRAT) compiled with default settings produce known JA3 hashes.
- **Tor clients** ship a fixed TLS profile that has not changed substantially across versions.
- **Metasploit's `meterpreter/reverse_https`** has a well-documented JA3 hash visible in every incident.

None of this requires breaking encryption. You match the handshake against a hash database and flag known-bad clients — all from mirrored traffic or a span port, with no impact on the data path.

**Target systems:** Zeek 6.0+, Suricata 7.0+, Elasticsearch 8+, Splunk 9+, any network tap or mirror.

## Threat Model

- **Adversary 1 — Cobalt Strike operator (un-customised):** Default malleable C2 profile produces a fingerprint in the SSLBL database. Beacon traffic is encrypted but the handshake is distinctive.
- **Adversary 2 — Commodity RAT:** Operator downloads a builder, compiles with defaults. The TLS stack (usually .NET SslStream or Python ssl) produces a known-bad JA3 hash.
- **Adversary 3 — Scanning tool:** Masscan or Shodan's probe engine sends stripped-down `ClientHello` packets that differ dramatically from browser TLS profiles.
- **Adversary 4 — Tor exit / onion proxy:** Tor's TLS profile is consistent and well-documented. Detection is not always the goal but should be visible to the analyst.
- **Adversary 5 — Advanced actor with JA3 spoofing:** A sophisticated operator uses JA3-randomising tooling (`ja3rando`, custom Malleable C2 profiles) to defeat hash-based detection. JA4 was designed partly to increase the cost of this evasion.
- **Access level:** All adversaries operate post-compromise or during initial access. Passive fingerprinting adds zero latency and zero decryption to the detection pipeline.
- **Objective:** Establish C2, exfiltrate data, scan the network.
- **Blast radius:** Without fingerprinting, encrypted C2 traffic passes undetected through IDS rules that rely on payload content. With fingerprinting, known-bad TLS profiles are flagged in real time from mirrored traffic.

## How JA3 Works

JA3 was published by John Althouse, Jeff Atkinson, and Josh Atkins at Salesforce in 2017. The algorithm is simple and reproducible.

**Input:** The TLS `ClientHello` message.

**Fields extracted:**

1. `SSLVersion` — the TLS version field in the handshake record (not the supported_versions extension).
2. `Ciphers` — the list of cipher suite IDs offered by the client, in the order they appear.
3. `Extensions` — the list of extension type IDs present, in the order they appear.
4. `EllipticCurves` — the named groups listed in the `supported_groups` extension.
5. `EllipticCurvePointFormats` — the formats listed in the `ec_point_formats` extension.

**Algorithm:**

```
JA3_string = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
```

Each field is a dash-separated list of decimal integers. The five fields are joined with commas. Greasy values (RFC 8701 — values like `0x0a0a`, `0x1a1a` inserted by modern browsers to test server compatibility) are removed before hashing.

```
# Example JA3 string (Firefox 120 on Linux):
771,4866-4867-4865-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0

# MD5 hash of that string:
a0e9f5d64349fb13191bc781f81f42e1
```

The MD5 hash is the JA3 fingerprint. It is 32 hex characters.

**What makes a fingerprint stable:** The cipher suites and extension ordering are determined by the TLS library, not by the application. Applications call `SSL_CTX_new()` and let the library fill in the `ClientHello`. Unless the application explicitly customises the cipher list and extension set, the fingerprint reflects the library version and build configuration.

**Limitations of JA3:**

- **MD5 collisions are possible** — two distinct TLS profiles can hash to the same JA3 value. False positives and false negatives both occur.
- **Greasy removal is inconsistently implemented** — some parsers fail to strip all greasy values, producing different hashes for the same logical profile.
- **Extension ordering changed in TLS 1.3 libraries** — because TLS 1.3 requires specific extensions, library updates reshuffled extension order and broke deployed JA3 rules for legitimate clients.
- **Browser fingerprints are unstable** — Chrome and Firefox release every 4–6 weeks. Each release may change cipher preference ordering, adding significant analyst overhead keeping allowlists current.
- **Easy to spoof** — tools like `curl` with custom cipher strings, or dedicated JA3-randomisation libraries, can generate arbitrary JA3 values in a few lines of code. A motivated adversary defeats hash-based JA3 detection trivially.

Despite these limitations, JA3 remains operationally useful: it is cheap to compute, widely supported in NSM tools, and still catches un-customised commodity malware.

## How JA4 Works

JA4 was designed by John Althouse (now at FoxIO) and published in 2023. It addresses JA3's main weaknesses: collision resistance, stability, and structured decomposition.

JA4 is not a single hash but a suite of related fingerprints:

- **JA4** — the TLS `ClientHello` fingerprint.
- **JA4_r** — the raw (unsorted) variant, preserving field ordering for correlation.
- **JA4S** — the server's `ServerHello` fingerprint.
- **JA4H** — HTTP/1 and HTTP/2 request fingerprint (separate from TLS).
- **JA4L** — latency fingerprint (measures round-trip distances).
- **JA4X** — X.509 certificate fingerprint.

This article focuses on JA4 and JA4S as the primary network detection pair.

### JA4 Construction

```
JA4 = [protocol][tls_version][sni_present][cipher_count][extension_count][alpn]_[cipher_hash]_[extension_hash]
```

**Component breakdown:**

| Component | Meaning |
|---|---|
| `protocol` | `t` (TCP/TLS), `q` (QUIC), `d` (DTLS) |
| `tls_version` | 2-char code: `13` = TLS 1.3, `12` = TLS 1.2 |
| `sni_present` | `d` (domain, SNI present) or `i` (IP, no SNI) |
| `cipher_count` | 2-digit decimal count of offered cipher suites |
| `extension_count` | 2-digit decimal count of extensions |
| `alpn` | First and last char of the first ALPN value, e.g. `h2` → `h2` |
| `cipher_hash` | First 12 chars of SHA-256 of sorted cipher suite IDs |
| `extension_hash` | First 12 chars of SHA-256 of sorted extension type IDs plus signature algorithms |

**Why sorted?** Sorting cipher and extension lists before hashing means that a client which sends the same logical capabilities but in a different order produces the same JA4 hash. This makes JA4 more stable across library versions while still capturing the capability profile.

**The raw variant JA4_r** preserves original ordering (no sort) — useful when you specifically want to detect ordering-based anomalies or correlate with JA3 databases.

**Example JA4 value:**

```
t13d1516h2_8daaf6152771_b0da82dd1658
```

Decoded: TCP TLS 1.3, SNI domain present, 15 ciphers, 16 extensions, ALPN `h2`, cipher hash `8daaf6152771`, extension+sigalg hash `b0da82dd1658`.

### JA4S — Server Fingerprint

JA4S fingerprints the `ServerHello`:

```
JA4S = [protocol][tls_version][sni_present][cipher_chosen][extension_count]_[extension_hash]
```

Pairing JA4 (client) with JA4S (server) provides a full-handshake fingerprint. This is especially useful for detecting C2: an attacker may customise the client profile to avoid JA4 detection, but cannot control the server's `ServerHello` unless they control the infrastructure. Known-bad JA4S values from Cobalt Strike team servers are documented in threat intelligence feeds.

## Implementing JA3/JA4 in Zeek

Zeek is the standard open-source network security monitor. It processes pcap or live traffic and writes typed log files. The `ssl.log` file contains one record per TLS connection.

### Installing Packages

```bash
# Install Zeek package manager.
pip3 install zkg

# Install JA3 package (maintained by the Zeek project).
zkg install zeek/salesforce/ja3

# Install JA4 package.
zkg install zeek/foxio/zeek-ja4

# Apply and restart.
zeekctl deploy
```

### ssl.log Enrichment

With both packages installed, `ssl.log` gains new fields:

```
# /opt/zeek/logs/current/ssl.log (TSV format, relevant fields)
ts              uid             id.orig_h       id.orig_p  id.resp_h       id.resp_p  ja3             ja3s            ja4             ja4s
1715081234.12   CxAb5vGreenfield 10.10.1.45      54321      93.184.216.34   443        a0e9f5d64349fb13191bc781f81f42e1  <server_hash>   t13d1516h2_8daaf6152771_b0da82dd1658  <server_ja4s>
```

### Detection Script: Alert on Known-Bad JA3

```zeek
# /opt/zeek/share/zeek/site/detect-malicious-ja3.zeek
# Alert on JA3 hashes known to be used by malware.

module TLSFingerprintDetection;

export {
    redef enum Notice::Type += {
        Malicious_JA3_Hash,
        Malicious_JA4_Hash,
    };

    # Update this set from SSLBL or your own threat intelligence pipeline.
    const malicious_ja3_hashes: set[string] = {
        # Cobalt Strike default (pre-customisation)
        "72a589da586844d7f0818ce684948eea",
        # AsyncRAT
        "f4febc55ea12b31ae17cfbba18c28e80",
        # NjRAT
        "d0ec4b50a944b182b6541a5d6b3b99d0",
        # Metasploit meterpreter/reverse_https
        "c1e478e74a5d8251a84a8c2f5c7afe0f",
        # Tor client (monitor, not necessarily block)
        "e7d705a3286e19ea42f587b6622e3d17",
    } &redef;

    const malicious_ja4_hashes: set[string] = {
        # Cobalt Strike team server JA4S
        "t12d190900_7df000000000_e7c285222651",
        # Sliver C2 default
        "t13d191000_9dc949149365_97f8aa674fd9",
    } &redef;
}

event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string,
                       session_id: string, ciphers: index_vec,
                       comp_methods: index_vec) {
    if ( c?$ssl && c$ssl?$ja3 ) {
        if ( c$ssl$ja3 in malicious_ja3_hashes ) {
            NOTICE([$note=Malicious_JA3_Hash,
                    $conn=c,
                    $msg=fmt("Malicious JA3 hash detected: %s", c$ssl$ja3),
                    $identifier=cat(c$id$orig_h, c$ssl$ja3)]);
        }
    }
}

event ssl_established(c: connection) {
    if ( c?$ssl && c$ssl?$ja4 ) {
        if ( c$ssl$ja4 in malicious_ja4_hashes ) {
            NOTICE([$note=Malicious_JA4_Hash,
                    $conn=c,
                    $msg=fmt("Malicious JA4 hash detected: %s", c$ssl$ja4),
                    $identifier=cat(c$id$orig_h, c$ssl$ja4)]);
        }
    }
}
```

```bash
# Load the detection script.
echo "@load site/detect-malicious-ja3" >> /opt/zeek/share/zeek/site/local.zeek
zeekctl deploy
```

### Allowlisting Known-Good Clients

Before enabling alerting at scale, build an allowlist of expected JA4 values on your network. Otherwise every browser update generates noise.

```zeek
# Generate a frequency report from existing ssl.log to find common fingerprints.
# Run this in ZeekControl or with zeek -r <capture.pcap>.

event zeek_done() {
    # This runs after processing a pcap — inspect ssl.log for most common ja4 values.
}
```

```bash
# From ssl.log, extract JA4 frequencies.
zeek-cut ja4 < /opt/zeek/logs/current/ssl.log \
  | sort | uniq -c | sort -rn | head -30
```

## Implementing JA3/JA4 in Suricata

Suricata 7.0+ computes JA3 natively without plugins. JA4 support requires Suricata 8.0+ or a custom Lua script.

### EVE JSON Output Fields

```json
{
  "timestamp": "2026-05-07T09:14:22.441Z",
  "event_type": "tls",
  "src_ip": "10.10.1.45",
  "dest_ip": "93.184.216.34",
  "dest_port": 443,
  "tls": {
    "subject": "CN=example.com",
    "issuerdn": "CN=R3,O=Let's Encrypt",
    "version": "TLS 1.3",
    "ja3": {
      "hash": "a0e9f5d64349fb13191bc781f81f42e1",
      "string": "771,4866-4867-4865-49195-...,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
    },
    "ja3s": {
      "hash": "b32309a26951912be7dba376398abc3b",
      "string": "771,4867,0-51-43"
    }
  }
}
```

### Suricata Alert Rules

```
# /etc/suricata/rules/tls-fingerprint.rules

# Cobalt Strike default beacon (un-customised)
alert tls any any -> any any (msg:"ET MALWARE Cobalt Strike Default JA3"; ja3_hash; content:"72a589da586844d7f0818ce684948eea"; sid:9000001; rev:1; classtype:trojan-activity;)

# AsyncRAT
alert tls any any -> any any (msg:"ET MALWARE AsyncRAT TLS Fingerprint"; ja3_hash; content:"f4febc55ea12b31ae17cfbba18c28e80"; sid:9000002; rev:1; classtype:trojan-activity;)

# NjRAT
alert tls any any -> any any (msg:"ET MALWARE NjRAT TLS Fingerprint"; ja3_hash; content:"d0ec4b50a944b182b6541a5d6b3b99d0"; sid:9000003; rev:1; classtype:trojan-activity;)

# Metasploit meterpreter HTTPS
alert tls any any -> any any (msg:"ET EXPLOIT Metasploit Meterpreter HTTPS JA3"; ja3_hash; content:"c1e478e74a5d8251a84a8c2f5c7afe0f"; sid:9000004; rev:1; classtype:attempted-admin;)

# Masscan TLS probe
alert tls any any -> any any (msg:"ET SCAN Masscan TLS Probe JA3"; ja3_hash; content:"6d9814930d2b25c0922ec38ef62c9361"; sid:9000005; rev:1; classtype:network-scan;)

# Sliver C2 framework
alert tls any any -> any any (msg:"ET MALWARE Sliver C2 Default JA3"; ja3_hash; content:"a0e9f5d64349fb13191bc781f81f42e2"; sid:9000006; rev:1; classtype:trojan-activity;)
```

```bash
# /etc/suricata/suricata.yaml — ensure tls logging and ja3 are enabled.
```

```yaml
# /etc/suricata/suricata.yaml (relevant section)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - tls:
            extended: yes
            # JA3 is computed automatically when extended: yes is set.

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443, 8443, 8080, 3389
      ja3-fingerprints: yes
```

```bash
# Load the new rules.
suricata-update
systemctl reload suricata

# Verify JA3 fields appear in live traffic.
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="tls") | {src: .src_ip, dest: .dest_ip, ja3: .tls.ja3.hash}'
```

## Known-Malicious JA3 Databases

Several public threat intelligence sources maintain JA3 hash databases:

**Abuse.ch SSLBL (SSL Blacklist)**

The primary community resource. Updated daily, lists JA3 hashes associated with botnet C2 and malware.

```bash
# Download the SSLBL JA3 blacklist.
curl -s https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv \
  | grep -v '^#' \
  | awk -F',' '{print $1}' > /etc/suricata/lists/sslbl-ja3.txt

# Generate Suricata rules from the list.
while IFS=',' read -r hash description first_seen last_seen; do
  [[ "$hash" =~ ^# ]] && continue
  sid=$((9100000 + RANDOM % 90000))
  echo "alert tls any any -> any any (msg:\"SSLBL JA3 ${description:-Malware}\"; ja3_hash; content:\"${hash}\"; sid:${sid}; rev:1; classtype:trojan-activity;)"
done < /etc/suricata/lists/sslbl-ja3.txt > /etc/suricata/rules/sslbl-ja3.rules
```

**FoxIO JA4 Database**

FoxIO maintains an open JA4 fingerprint database for legitimate software identification and for malware family attribution.

```bash
# Fetch the FoxIO JA4 database (JSON format).
curl -s https://ja4db.com/api/download/ -o /opt/threat-intel/ja4db.json

# Extract malware entries.
jq '.[] | select(.malware == true) | {ja4: .ja4, description: .description}' \
  /opt/threat-intel/ja4db.json
```

**Key documented hashes for detection engineering:**

| Fingerprint | Tool | Hash (JA3) |
|---|---|---|
| Cobalt Strike default beacon | Cobalt Strike | `72a589da586844d7f0818ce684948eea` |
| Cobalt Strike stager | Cobalt Strike | `a0e9f5d64349fb13191bc781f81f42e2` |
| Metasploit meterpreter HTTPS | Metasploit | `c1e478e74a5d8251a84a8c2f5c7afe0f` |
| AsyncRAT | AsyncRAT | `f4febc55ea12b31ae17cfbba18c28e80` |
| NjRAT | NjRAT | `d0ec4b50a944b182b6541a5d6b3b99d0` |
| Tor client | Tor Browser | `e7d705a3286e19ea42f587b6622e3d17` |
| Masscan | Masscan | `6d9814930d2b25c0922ec38ef62c9361` |

## JA4H — HTTP/2 Fingerprinting

JA4H fingerprints HTTP/1 and HTTP/2 request headers, applying the same philosophy as JA4 to the HTTP layer.

For HTTP/2, JA4H captures the SETTINGS frame sent by the client after the connection is established. SETTINGS frames contain parameters like `HEADER_TABLE_SIZE`, `ENABLE_PUSH`, `MAX_CONCURRENT_STREAMS`, `INITIAL_WINDOW_SIZE`, and `MAX_FRAME_SIZE`. Different HTTP/2 implementations (Chrome, Firefox, Go `net/http`, Python `httpx`, curl) send distinct SETTINGS frame sequences.

```
# JA4H format:
[method][version][headers_count][cookie_count]_[header_hash]_[cookie_hash]

# Example for a Chrome browser request:
po11nn_5d7e5ea66e67_0a4f6f49ceea
```

**Practical application:** If a `ClientHello` JA4 fingerprint suggests Chrome 122, but the HTTP/2 SETTINGS frame matches a Go HTTP client, the discrepancy is a strong indicator of tooling (C2 framework, scanner, or proxy) impersonating a browser. This cross-layer correlation is one of the most powerful evasion-resistant detection techniques available without decryption.

## Limitations and Evasion

**JA3 spoofing is trivial.** The `utls` library (Go) allows a client to impersonate any target TLS profile with a single call:

```go
// Impersonate Chrome 120 TLS profile — produces Chrome's JA3 hash.
tlsConfig := &utls.Config{ServerName: "target.example.com"}
conn, _ := utls.Dial("tcp", "target.example.com:443", tlsConfig)
conn.ApplyPreset(utls.HelloChrome_120)
```

Cobalt Strike malleable C2 profiles support `set jitter` and `set ssl_certificate` for connection obfuscation, and custom SSL profiles can replicate browser fingerprints. Any operator who has read the Cobalt Strike documentation is likely not running a default JA3.

**TLS 1.3 reduces visibility.** In TLS 1.3, the server's `Certificate`, `CertificateVerify`, and `Finished` messages are encrypted. The `EncryptedExtensions` record means some extension data that was formerly visible in the `ServerHello` is now encrypted. JA3S coverage degrades for TLS 1.3 sessions compared to TLS 1.2.

**Modern TLS stacks shuffle extension ordering.** Chrome's GREASE mechanism and Chromium's `ssl_client_hello_callback` randomise extension ordering on each connection. This breaks JA3 for Chrome-based clients unless GREASE values are correctly stripped.

**Encrypted Client Hello (ECH).** TLS 1.3 with ECH encrypts the entire inner `ClientHello` inside an outer `ClientHello`. A passive observer sees only the outer `ClientHello` — typically a generic profile — not the actual client fingerprint. ECH deployment is expanding; within 2–3 years, JA3/JA4 visibility for ECH-enabled connections will be limited to the outer envelope.

**Mitigations:**

- Do not rely on JA3 alone. Correlate with JA4, JA4S, JA4H, and behavioural indicators (beacon interval, bytes transferred, destination IP reputation).
- Track JA3 fingerprint changes per source IP over time — an endpoint that suddenly changes its TLS fingerprint may indicate tooling change.
- Invest in JA4_r (raw, unsorted) correlation alongside JA4 — sophisticated evasion tools that sort their ciphers to match JA4 may still expose themselves in raw extension ordering.

## Integration with SIEM

### Elastic SIEM / Elastic Security

Elastic's Network Security integration ingests Zeek `ssl.log` and Suricata EVE JSON natively. JA3/JA4 fields are mapped to ECS fields.

```yaml
# filebeat.yml — ingest Zeek ssl.log.
filebeat.inputs:
  - type: filestream
    id: zeek-ssl
    paths:
      - /opt/zeek/logs/current/ssl.log
    parsers:
      - ndjson:
          target: zeek
    processors:
      - rename:
          fields:
            - from: "zeek.ja3"
              to: "tls.client.ja3"
            - from: "zeek.ja3s"
              to: "tls.server.ja3s"
            - from: "zeek.ja4"
              to: "tls.client.ja4"
```

**Detection rule in Elastic Security (EQL):**

```eql
# Detect known-malicious JA3 hashes from SSLBL.
network where event.action == "tls_client_hello"
  and tls.client.ja3 in (
    "72a589da586844d7f0818ce684948eea",
    "f4febc55ea12b31ae17cfbba18c28e80",
    "c1e478e74a5d8251a84a8c2f5c7afe0f"
  )
```

**Threat intelligence enrichment pipeline:**

```json
// Elasticsearch ingest pipeline — enrich JA3 field against threat intel index.
{
  "processors": [
    {
      "enrich": {
        "description": "Enrich JA3 hash with SSLBL threat intel",
        "policy_name": "sslbl-ja3-policy",
        "field": "tls.client.ja3",
        "target_field": "threat.indicator",
        "ignore_missing": true
      }
    }
  ]
}
```

### Splunk

```
# Splunk search — correlate JA3 hashes with threat intelligence.
index=network sourcetype=zeek_ssl
| eval ja3_hash=ja3
| lookup threat_intel_ja3 ja3_hash OUTPUT threat_name, malware_family, confidence
| where isnotnull(threat_name)
| stats count by src_ip, dest_ip, ja3_hash, threat_name, malware_family
| sort -count
```

```
# Splunk alert — new JA3 hash never seen on this host before.
index=network sourcetype=zeek_ssl
| stats earliest(_time) as first_seen, count by src_ip, ja3
| eval days_since_first_seen=round((now()-first_seen)/86400,1)
| where days_since_first_seen < 1 AND count > 5
| lookup known_good_ja3 ja3 OUTPUT is_known_good
| where isnull(is_known_good)
```

## QUIC and HTTP/3 Fingerprinting

QUIC (RFC 9000) carries TLS 1.3 inside its own encrypted framing. The TLS `ClientHello` is embedded in a QUIC `Initial` packet. JA4 supports QUIC natively — the protocol prefix changes from `t` to `q`:

```
# JA4 for a QUIC connection:
q13d1516h3_8daaf6152771_b0da82dd1658
#^-- 'q' prefix indicates QUIC transport
```

**QUIC Initial packet fingerprinting** goes beyond the TLS layer. The QUIC `Initial` packet itself contains:

- QUIC version (RFC 9000 `0x00000001`, Google QUIC variants, Facebook MVFST)
- Connection ID length
- QUIC transport parameters (embedded in the TLS `ClientHello` as extension `0x0039`)

These transport parameters — `initial_max_data`, `initial_max_stream_data_bidi_local`, `active_connection_id_limit`, etc. — form a QUIC-specific fingerprint. Chromium, Firefox, and Go's `quic-go` library all send distinct parameter sets. FoxIO has published preliminary QUIC transport parameter fingerprinting as part of the JA4 family (JA4Q).

```bash
# Zeek captures QUIC traffic natively from Zeek 5.2+.
# Check QUIC connections in ssl.log:
zeek-cut ts id.orig_h id.resp_h id.resp_p ja4 < /opt/zeek/logs/current/ssl.log \
  | awk '$4 != ""' | grep "^q"
```

For QUIC scanning tools (ZMap with QUIC probes, quic-scanner), the QUIC Initial packet fingerprint is as distinctive as a TLS `ClientHello`. Detection at the QUIC layer catches C2 frameworks that have migrated to HTTP/3 to evade traditional TLS inspection.

## Operational Recommendations

**Start with allowlisting, not blocklisting.** Collect two weeks of JA4 fingerprints from your network before deploying alert rules. Identify the expected distribution (browser versions, OS TLS stacks, application libraries). Alert on deviations from this baseline rather than solely on known-bad hashes.

**Automate SSLBL integration.** Run a daily cron that downloads the latest SSLBL JA3 CSV and generates Suricata rules. Known-bad hashes are added to SSLBL within hours of malware campaigns being observed in the wild.

```bash
#!/bin/bash
# /opt/scripts/update-ja3-rules.sh — run daily via cron.
set -euo pipefail

SSLBL_URL="https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
RULES_FILE="/etc/suricata/rules/sslbl-ja3.rules"
TEMP=$(mktemp)

curl -sf "$SSLBL_URL" -o "$TEMP"

sid=9100001
{
  echo "# SSLBL JA3 rules — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  while IFS=',' read -r hash description first_seen; do
    [[ "$hash" =~ ^# ]] && continue
    [[ -z "$hash" ]] && continue
    echo "alert tls any any -> any any (msg:\"SSLBL JA3 ${description:-Malware C2}\"; ja3_hash; content:\"${hash}\"; sid:${sid}; rev:1; classtype:trojan-activity;)"
    (( sid++ ))
  done < "$TEMP"
} > "$RULES_FILE"

rm -f "$TEMP"
systemctl reload suricata
```

**Correlate JA3 fingerprint changes per source IP.** An endpoint running the same browser version for weeks that suddenly presents a different JA3 hash is worth investigating — it may indicate that a C2 implant is using a different TLS stack than the user's browser.

**Pair fingerprinting with JA4L (latency).** JA4L measures the round-trip time between the `ClientHello` and `ServerHello`. Tor exit nodes and VPN concentrators introduce characteristic latency jitter. Combining JA4 with JA4L makes it significantly harder for an adversary to simultaneously spoof both the handshake profile and the network latency profile.

**Do not run fingerprinting exclusively on port 443.** Modern C2 frameworks use port 443 but also ports 80, 8080, 8443, 4433, and custom high ports. Configure Suricata's `detection-ports` and Zeek's `SSL::ports` to cover all common TLS ports on your network.
