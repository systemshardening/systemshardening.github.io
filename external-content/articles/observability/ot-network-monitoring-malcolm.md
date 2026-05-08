---
title: "OT Network Monitoring with CISA Malcolm: Visibility for ICS/SCADA"
description: "CISA's OT Zero Trust guidance recommends Malcolm for OT network traffic analysis. Deploy Zeek-based passive monitoring with Modbus and DNP3 parsers, build behavioral baselines, and implement specification-based detection for process variable anomalies."
slug: ot-network-monitoring-malcolm
date: 2026-05-03
lastmod: 2026-05-03
category: observability
tags:
  - ot-security
  - malcolm
  - zeek
  - ics
  - anomaly-detection
personas:
  - security-engineer
  - platform-engineer
article_number: 403
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/ot-network-monitoring-malcolm/
---

# OT Network Monitoring with CISA Malcolm: Visibility for ICS/SCADA

## The Problem

Most OT networks have zero network visibility: Modbus, DNP3, and PROFINET traffic flows between PLCs, RTUs, and HMIs with no logging, no packet capture, and no anomaly detection. When CISA investigated Volt Typhoon intrusions — where nation-state actors pre-positioned themselves inside U.S. critical infrastructure networks — OT network forensics were impossible at many sites because no traffic history existed at all. The attacker could enumerate PLC I/O mappings, modify ladder logic, and issue control commands, and no record of any of it survived.

CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" addresses this directly with two specific recommendations. First: passive monitoring via a SPAN port — no inline appliances that could disrupt safety-critical control loops. Second: CISA Malcolm as the open-source network traffic analysis platform with built-in OT protocol parsers.

The passive monitoring requirement is not optional in OT. Inline security appliances — even those marketed specifically for ICS environments — add deterministic or variable latency to the control path. A PLC polling an RTU every 100ms over Modbus/TCP has no tolerance for an inline device that adds 2-5ms of processing latency per transaction. A SPAN port on a managed switch copies traffic to the Malcolm capture interface at wire speed, with zero impact on the control path. The mirrored traffic is read-only; Malcolm cannot inject packets onto the OT network segment.

Malcolm is a free, open-source network traffic analysis suite released and maintained by CISA. It bundles Zeek (for protocol-aware log extraction), Arkime (formerly Moloch, for full-packet capture and search), OpenSearch, and OpenSearch Dashboards — all deployed together on a standard Linux server. Malcolm requires no OT-specific hardware, no licensing, and no reconfiguration of PLC firmware. The only OT network change required is enabling a SPAN port on one managed switch.

What Malcolm provides that a generic SIEM does not is the Zeek OT protocol parsers. A standard Zeek installation understands TCP, UDP, HTTP, DNS, TLS, and common enterprise protocols. Malcolm's Zeek configuration extends this with scripts that parse the application layer of Modbus/TCP (function codes, register addresses, and values), DNP3 (application layer objects, function codes, internal indication bits), EtherNet/IP (object classes, service codes, connection parameters), BACnet (service types, object identifiers, property values), and PROFINET (DCP device discovery, alarm messages, configuration records). These parsers produce structured log files — one row per transaction — that can be queried in OpenSearch with full field-level filtering. Without these parsers, a generic SIEM sees only TCP sessions on port 502 or 20000; with them, it sees that register address 40001 was written with value 215 by source IP 192.168.10.50 at 14:32:07.

## Threat Model

**Volt Typhoon-style nation-state persistence.** Attackers gain a foothold on the IT network and pivot to the OT DMZ or directly to the OT flat network. Without any OT network monitoring, they can conduct reconnaissance over weeks — mapping PLC addresses, reading register configurations, learning the communication schedule — with no possibility of detection. The Volt Typhoon playbook relies precisely on this visibility gap.

**Protocol-layer reconnaissance via Modbus READ commands.** An attacker who reaches the OT network can send valid Modbus READ HOLDING REGISTERS requests to any PLC that accepts unauthenticated connections — which is most of them, because Modbus has no authentication. A sequence of READ commands across function codes and register ranges will enumerate the PLC's I/O configuration, variable mapping, and operating setpoints. This traffic is syntactically legitimate and will pass any protocol-aware firewall; only content-aware inspection of who is issuing READ commands, from which source IP, and at what frequency can detect it.

**Rogue device on the OT network.** A contractor laptop, a misconfigured engineering workstation, or an attacker-planted device connecting to an OT network switch creates a new MAC and IP address on the segment. Without an asset inventory built from observed traffic, there is no baseline to compare against and no alert to trigger.

**Living-off-the-land with legitimate vendor software.** An attacker who has compromised an engineering workstation can use Rockwell Studio 5000, Siemens TIA Portal, or Schneider EcoStruxure to modify PLC logic or configuration. This traffic looks identical to legitimate engineering activity from a protocol perspective. Detection requires knowing which engineering workstations are allowed to initiate write operations to which PLCs, and alerting on any deviation from that matrix.

**Out-of-range setpoint injection.** An attacker sends a Modbus WRITE SINGLE REGISTER command to a PLC holding register that controls a process setpoint — a temperature, a pump speed, a valve position. The value written is within the valid range of a 16-bit register (0–65535) and may even be within the normal operating range of the PLC, so no protocol-level error occurs. But the value falls outside the safe operating range for the physical process: a temperature setpoint of 235°C where the safe range is 180–220°C will eventually cause a failure. Detecting this requires specification-based detection — knowledge of the safe value ranges encoded as detection rules.

## Hardening Configuration

### 1. Malcolm Deployment

Malcolm requires a dedicated Linux server. CISA's recommended minimums for a mid-sized OT network (100–500 devices) are 8 CPU cores, 32 GB RAM, and 4 TB storage (sufficient for approximately 90 days of full-packet capture at typical OT traffic volumes). Rocky Linux 9 is the recommended base OS.

```bash
sudo dnf update -y
sudo dnf install -y git python3

git clone https://github.com/cisagov/Malcolm.git /opt/malcolm
cd /opt/malcolm

sudo python3 malcolm_installer.py
```

The installer prompts for interface assignments. Assign the management interface (for the Malcolm web UI) and the capture interface (connected to the SPAN port) separately. After installation, configure HTTPS for the web interface:

```bash
cd /opt/malcolm
./scripts/auth_setup
```

The `auth_setup` script generates a self-signed certificate and prompts for an admin username and password. For production, replace the self-signed certificate with one issued by your internal CA by placing the certificate and key in `/opt/malcolm/nginx/certs/`.

Start Malcolm:

```bash
cd /opt/malcolm
./scripts/start
```

The Malcolm web interface will be available at `https://<server-ip>` after all containers initialise (typically 2–3 minutes).

### 2. SPAN Port Configuration

On the managed switch that aggregates OT device connections, configure a SPAN session to mirror all OT port traffic to the port connected to Malcolm's capture interface. The following example uses Cisco IOS syntax:

```conf
monitor session 1 source interface GigabitEthernet0/1 - 0/24
monitor session 1 destination interface GigabitEthernet0/25
```

`GigabitEthernet0/1` through `0/24` are the OT device ports (PLCs, RTUs, HMIs, engineering workstations). `GigabitEthernet0/25` is the uplink to Malcolm's capture NIC. The SPAN destination port receives copies of all ingress and egress frames from the source ports. The OT devices are not aware of the mirroring, and the SPAN copy cannot inject traffic back onto the OT segment.

Verify the SPAN session is active and confirm Malcolm begins receiving traffic:

```bash
cd /opt/malcolm
./scripts/logs zeek | grep -E "modbus|dnp3|enip|bacnet"
```

### 3. Zeek OT Protocol Parsers

Malcolm includes Zeek scripts for Modbus, DNP3, EtherNet/IP, BACnet, and PROFINET by default. Verify the parsers are loaded:

```bash
docker exec malcolm-zeek-1 zeek -N | grep -iE "modbus|dnp3|enip|bacnet|profinet"
```

Expected output will list the loaded Zeek packages. A healthy installation shows entries such as `ICSNPP::Modbus`, `ICSNPP::DNP3`, `ICSNPP::ENIP`, `ICSNPP::BACnet`, and `ICSNPP::PROFINET`.

Zeek produces a structured log for each Modbus transaction. A `modbus.log` entry for a READ HOLDING REGISTERS request looks like this:

```json
{
  "ts": "2026-05-03T14:32:07.142Z",
  "uid": "CkDe3z1Abc2XyZ",
  "id.orig_h": "192.168.10.50",
  "id.orig_p": 51234,
  "id.resp_h": "192.168.10.10",
  "id.resp_p": 502,
  "func": "READ_HOLDING_REGISTERS",
  "request": {
    "start_address": 40001,
    "quantity": 10
  },
  "response": {
    "registers": [215, 0, 1023, 0, 0, 0, 0, 0, 0, 0]
  }
}
```

Every field — source IP, destination IP, Modbus function code, register address, register values — is indexed in OpenSearch and queryable from the Malcolm dashboards.

### 4. Passive Asset Discovery

Malcolm's Arkime packet capture and Zeek log pipeline together provide the data needed to build a passive asset inventory. In the Malcolm OpenSearch Dashboards, navigate to the "Assets" view to see automatically enumerated unique MAC addresses, IP addresses, hostnames (from DNS queries observed in traffic), and protocol types.

To export the current asset inventory as a JSON document for review:

```bash
curl -s -k -u admin:password \
  "https://localhost/mapi/agg/source.ip" \
  | python3 -m json.tool > /tmp/ot-asset-inventory.json
```

Compare this output against your known device inventory (from procurement records or vendor documentation). Any IP or MAC address not in the known inventory is a rogue or unmanaged asset and should be investigated immediately.

Filter the asset view by protocol to see only devices that have communicated using Modbus:

```json
{
  "query": {
    "term": { "network.protocol": "modbus" }
  },
  "aggs": {
    "sources": { "terms": { "field": "source.ip", "size": 1000 } },
    "destinations": { "terms": { "field": "destination.ip", "size": 1000 } }
  }
}
```

Run this query against the `malcolm_zeek_*` index pattern in OpenSearch to enumerate all source and destination IPs that have appeared in Modbus transactions. This list is your Modbus communication matrix — the ground truth of who talks to whom on port 502.

### 5. Baseline-Based Detection

CISA recommends a two-week baseline period to enumerate all normal source-destination IP pairs and protocols. During this period, Malcolm collects all OT network traffic passively. After two weeks, you have a complete picture of which devices communicate with which other devices, on which protocols, at what frequency.

Implement a baseline alert in OpenSearch Alerting that fires when a source IP communicates on Modbus port 502 and has not appeared in the communication matrix from the baseline period. Create an OpenSearch alerting monitor with the following query against the `malcolm_zeek_*` index:

```json
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "destination.port": 502 } },
        { "range": { "@timestamp": { "gte": "now-1m" } } }
      ],
      "must_not": [
        {
          "terms": {
            "source.ip": [
              "192.168.10.50",
              "192.168.10.51",
              "192.168.10.100"
            ]
          }
        }
      ]
    }
  }
}
```

Replace the IP list with the complete set of source IPs from your baseline. Set the monitor schedule to run every 60 seconds. Any hit means an IP not seen during baseline is now communicating on Modbus — a high-confidence signal for rogue device, compromised host, or attacker reconnaissance.

### 6. Specification-Based Detection

Specification-based detection goes beyond communication matrix baselines to check whether the values being written to PLC registers fall within the safe operating ranges for the physical process. This requires OT engineer input: the security team must obtain from operations the valid value ranges for each monitored register.

The following Zeek script illustrates the pattern. It is provided as a reference implementation and should be reviewed by someone familiar with Zeek scripting before use in production:

```zeek
module OT_Spec;

export {
    redef enum Notice::Type += { Setpoint_Out_Of_Range };
}

type SetpointSpec: record {
    register_addr: count;
    min_val:       count;
    max_val:       count;
    description:   string;
};

global setpoint_specs: vector of SetpointSpec = vector(
    SetpointSpec($register_addr=40001, $min_val=180, $max_val=220,
                 $description="Reactor temperature setpoint (deg C)"),
    SetpointSpec($register_addr=40005, $min_val=0,   $max_val=100,
                 $description="Feed pump speed setpoint (pct)")
);

event modbus_write_single_register_request(
    c: connection, headers: ModbusHeaders,
    register_address: count, register_value: count)
{
    for (i in setpoint_specs)
    {
        local spec = setpoint_specs[i];
        if (register_address == spec$register_addr &&
            (register_value < spec$min_val || register_value > spec$max_val))
        {
            NOTICE([$note=Setpoint_Out_Of_Range,
                    $conn=c,
                    $msg=fmt("Modbus WRITE to register %d: value %d outside safe range [%d, %d] (%s)",
                             register_address, register_value,
                             spec$min_val, spec$max_val, spec$description)]);
        }
    }
}
```

Place this script in `/opt/malcolm/zeek/custom/ot_spec_detection.zeek`. Malcolm mounts the `zeek/custom/` directory into the Zeek container and loads all `.zeek` files found there automatically. After saving the script, restart Malcolm's Zeek container:

```bash
cd /opt/malcolm
docker compose restart zeek
```

When a Modbus WRITE SINGLE REGISTER command sets register 40001 to a value outside 180–220, the script logs a `Notice::Setpoint_Out_Of_Range` entry to `notice.log`, which Malcolm indexes in OpenSearch and which can trigger an OpenSearch alerting monitor.

## Expected Behaviour After Hardening

After Malcolm deployment and SPAN port configuration, the Malcolm OpenSearch Dashboards display a live feed of all Modbus, DNP3, EtherNet/IP, BACnet, and PROFINET transactions across the OT network. The "OT Overview" dashboard shows per-protocol transaction counts, active device pairs, and function code distribution — giving the SOC a real-time view of OT network activity that previously did not exist.

After the baseline alert is configured, any IP address that was not observed communicating on Modbus during the two-week baseline period will trigger an OpenSearch alert within 60 seconds of its first packet reaching the capture interface. A penetration tester connecting a laptop to the OT switch will appear as a new source IP in the Malcolm asset inventory and trigger the baseline alert before they can complete any meaningful Modbus reconnaissance.

After specification-based detection is deployed, a Modbus WRITE SINGLE REGISTER command setting register 40001 to 235 — above the configured maximum of 220 — generates a Zeek `Notice::Setpoint_Out_Of_Range` log entry within milliseconds. Malcolm indexes this entry in OpenSearch, and the associated alerting monitor notifies the SOC within the configured check interval. The PLC executes the command (Malcolm is passive and cannot block it), but the SOC has an actionable alert to investigate before the out-of-range setpoint causes a physical process deviation.

## Trade-offs and Operational Considerations

**Storage planning.** Full-packet capture (Arkime) generates significantly more data than Zeek logs alone. At typical OT network traffic volumes (50–200 Mbps for a medium-sized facility), 4 TB of storage provides approximately 90 days of packet retention. If storage is constrained, configure Arkime to retain 30 days of raw packets while retaining Zeek structured logs for 90 days. Zeek logs are far smaller — typically 1–5 GB per day for a medium OT network — and are the primary data source for detection queries.

**Encrypted OT traffic.** The passive SPAN approach cannot inspect the payload of encrypted OT sessions. Modbus/TCP and most DNP3 deployments are unencrypted today; however, OPC-UA with security mode `SignAndEncrypt` is increasingly deployed in modern ICS installations. Malcolm can still detect encrypted OPC-UA sessions (by observing the TLS handshake and session metadata), but cannot parse application-layer content. Document this limitation explicitly when scoping Malcolm's detection coverage to OT stakeholders.

**Baseline contamination.** The two-week baseline period must exclude known maintenance windows, scheduled firmware updates, and engineering workstation activity that does not represent normal operations. A maintenance window where every PLC is polled by an engineering workstation will permanently add those sessions to the baseline, causing the alert to miss future attacker activity that mimics maintenance traffic. Coordinate with OT operations to identify and exclude atypical periods before beginning the baseline collection window.

**OT engineer involvement for specification-based detection.** Security teams cannot write specification-based detection rules without knowledge of the actual safe operating ranges for process variables. The register address, minimum value, and maximum value for each monitored setpoint must come from OT engineers or process control documentation. Plan a structured elicitation session with OT operations before attempting to configure `ot_spec_detection.zeek`. An incorrectly configured range (too narrow) will produce false positives that erode SOC trust; a range that is too wide will miss genuine out-of-range attacks.

**Malcolm server placement.** Malcolm must be placed in the OT DMZ, not on the OT network segment itself. A Malcolm server on the OT segment creates an attack surface: if Malcolm is compromised, the attacker has a Linux server with full access to all OT device IP addresses. Malcolm should sit in a network zone that has receive-only access to OT traffic (via SPAN) and outbound access to the enterprise SOC or SIEM. Firewall rules should allow inbound SPAN traffic only; block all inbound connections from OT devices to Malcolm.

## Failure Modes

**SPAN port not receiving traffic.** Malcolm is deployed and running, but the OpenSearch Dashboards show zero Modbus or DNP3 events. The most common cause is SPAN misconfiguration on the switch: the SPAN session source ports do not include the OT device ports, or the SPAN destination port is incorrectly assigned. Verify with `show monitor session 1` on the switch and confirm that Malcolm's capture interface is receiving packets via `tcpdump -i eth1 -c 100` on the Malcolm server.

**Baseline built during a maintenance period.** Operations scheduled a firmware update cycle during the chosen baseline window. Every PLC communicated with the engineering workstations, and every engineering workstation IP is now in the baseline. The resulting baseline alert will not fire for future attacker activity that uses the engineering workstation IP range. Discard the baseline and restart the collection window after coordinating a two-week period with no scheduled maintenance.

**SOC analysts without OT context.** Malcolm generates alerts, but the SOC analysts receiving them have no understanding of what Modbus function code 6 (WRITE SINGLE REGISTER) means for a reactor temperature setpoint. Alerts go uninvestigated or are closed as false positives. Address this with OT-specific alert documentation: for each alert type, include the protocol, what the event means in physical process terms, and the escalation path to OT operations.

**Malcolm server on the OT network segment.** A Malcolm server placed directly on the OT VLAN — rather than in the OT DMZ — is reachable from every PLC, RTU, and HMI on that segment. A compromised Malcolm server then has adjacency to every safety-critical device. This is a common deployment mistake when teams prioritise network simplicity over segmentation. Malcolm should always be in an isolated monitoring zone with one-way receive access to OT traffic.

## Related Articles

- [OT Network Segmentation Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
- [Network Flow Analysis](/articles/observability/network-flow-analysis/)
- [Detection Engineering Metrics](/articles/observability/detection-engineering-metrics/)
- [Suricata IDS/IPS](/articles/network/suricata-ids-ips/)
