---
title: "OT Incident Response and Forensics: CISA's ICS Evidence Guidance"
description: "CISA's OT Zero Trust guidance covers pre-crisis decision matrices and MITRE ATT&CK for ICS playbooks. Learn what to preserve from PLCs and HMIs before power cycling, how to structure OT IR playbooks, and how to build forensic readiness into air-gapped OT networks."
slug: ot-incident-response-forensics
date: 2026-05-03
lastmod: 2026-05-03
category: observability
tags:
  - ot-security
  - incident-response
  - forensics
  - ics
  - mitre-attack
personas:
  - security-engineer
  - platform-engineer
article_number: 411
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/ot-incident-response-forensics/
---

# OT Incident Response and Forensics: CISA's ICS Evidence Guidance

## The Problem

When CISA investigated Volt Typhoon intrusions into OT networks, forensic reconstruction was severely hampered by the absence of evidence: no packet captures, no process logs from PLCs, no historian records of anomalous setpoint changes, and HMI workstations that had been rebooted, destroying volatile memory. OT incident response is fundamentally different from IT IR in ways that make standard IR doctrine dangerous to apply without modification.

The core conflict is between two competing first principles. IT IR follows "preserve evidence first, remediate second" — you image the compromised host before you touch it, you pull packet captures before you kill the connection, you let the malware run in an isolated environment while you study it. OT operations follow "restore safety first" — when a PLC controlling a safety interlock shows anomalous behaviour, the right response may be to trigger a safe-state shutdown immediately, which destroys volatile evidence but prevents a physical harm event. These two principles are irreconcilable in the moment. The only way to navigate the conflict is to resolve it before the incident happens.

Isolating a PLC during an active incident may stop a production line or disable a safety interlock that depends on the PLC's outputs. Imaging a Siemens S7-1500's firmware requires Siemens TIA Portal and a licensed engineering workstation — tools not present in most IR team loadouts. Air-gapped OT networks mean that evidence which was never forwarded to a SIEM, never captured on a network tap, and never backed up to an off-segment store will simply not exist when the IR team arrives. The "acquire the evidence" step has a precondition: evidence must have been collected in the first place.

CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" introduces two concepts that address this directly. Pre-crisis decision matrices are structured tables, developed ahead of time with input from OT operations, safety engineering, and cybersecurity, that define the recommended containment action for each suspected-compromise scenario, who is authorised to approve it, and which safety interlocks it affects. Soft segmentation is the technique of isolating a suspected zone at the network layer while deliberately preserving the safety-critical control paths that traverse it — in contrast to hard isolation, which cuts all connectivity to and from the zone. Both concepts exist to ensure that IR teams are not making these decisions for the first time under pressure during an active incident.

## Threat Model

**Nation-state actor with multi-year OT dwell time.** Volt Typhoon was documented at five years of pre-positioned access inside U.S. critical infrastructure. At that timescale, timeline reconstruction becomes nearly impossible without continuous long-term network captures. A 90-day PCAP rolling window — the standard recommendation for OT forensic TAPs — covers less than 5% of the attacker's dwell time. Evidence for the initial intrusion and early lateral movement will be gone regardless of what the IR team does during the incident response.

**Attacker who modifies PLC logic or historian records before triggering a safety event.** The most dangerous OT attack sequence is not the safety event itself — it is the period before it, during which the attacker modifies PLC ladder logic or function blocks, adjusts historian records to conceal the modification, and then triggers the event. The historian record corruption is the primary forensic challenge: if the historian has been modified to show normal setpoint values during the period when the attacker was writing out-of-range values to a PLC, the ground truth of what the process was actually doing is gone.

**IR team that isolates the wrong network segment.** A containment action applied to the wrong segment — one that carries safety interlock communications that the team did not know about — can cause a cascading safety failure. The risk is not hypothetical: in complex OT networks, safety interlock communications frequently traverse general-purpose OT segments because the plant was built incrementally and the safety system was retrofitted without dedicated cabling.

**Evidence destruction during remediation.** The most common form of OT evidence destruction is not attacker action — it is well-intentioned remediation. An OT technician who reboots an HMI workstation to "clean it" before the IR team arrives loses all volatile memory artefacts: the attacker's process tree, open network connections, injected DLLs that have not been written to disk, and any in-memory credentials. This happens not because the technician is careless but because "reboot to fix it" is the standard OT troubleshooting response and no one told them not to.

**No SIEM ingestion from OT network.** Air-gapped or semi-isolated OT networks that have never forwarded logs to a SIEM mean that all evidence is local to devices that may be offline, powered down, or physically inaccessible when the IR team arrives. There is no remote evidence; collection must happen on-site, with physical access to each device.

## Hardening Configuration

### 1. Pre-Crisis Decision Matrix

The decision matrix is a documented table — approved and signed off before any incident — that defines what to do for each suspected-compromise scenario. During an incident, the IR team consults the matrix rather than convening a multi-stakeholder discussion while a safety event unfolds. The matrix is the output of a structured workshop involving OT operations, process safety engineering, and cybersecurity.

```yaml
decision_matrix:
  version: "1.0"
  approved_by:
    - role: OT Operations Manager
      name: "[Name]"
      date: "2026-04-01"
    - role: Safety Engineer
      name: "[Name]"
      date: "2026-04-01"
    - role: CISO
      name: "[Name]"
      date: "2026-04-01"

  scenarios:
    - id: SCENARIO-01
      description: "HMI workstation showing anomalous outbound connections or unexpected process activity"
      containment_options:
        - action: soft_isolation
          description: "Block HMI network port at managed switch; preserve HMI power and PLC communication"
          safety_interlock_impact: "None — HMI is display only; PLC continues executing ladder logic"
          authorisation: "Cybersecurity lead"
        - action: hard_isolation
          description: "Disconnect HMI from all network segments"
          safety_interlock_impact: "None — confirm no safety interlock passes through HMI"
          authorisation: "Cybersecurity lead + OT Operations Manager"
        - action: no_action_collect_evidence
          description: "Take volatile memory snapshot and network connection list before any isolation"
          safety_interlock_impact: "None"
          authorisation: "Cybersecurity lead"
      default_action: soft_isolation
      evidence_to_collect_before_action:
        - "Running process list (tasklist /v or ps aux)"
        - "Active network connections (netstat -ano or ss -tulpn)"
        - "HMI application event log export"

    - id: SCENARIO-02
      description: "Historian server showing unexpected write activity or modified time-series records"
      containment_options:
        - action: soft_isolation
          description: "Block historian server inbound connections from non-PLC sources at firewall"
          safety_interlock_impact: "None — historian is read-only from safety perspective"
          authorisation: "Cybersecurity lead"
        - action: hard_isolation
          description: "Take historian offline"
          safety_interlock_impact: "Operations loses real-time data visibility; PLCs unaffected"
          authorisation: "Cybersecurity lead + OT Operations Manager"
      default_action: soft_isolation
      evidence_to_collect_before_action:
        - "Export time-series data for 72-hour window preceding anomaly"
        - "Database query log"
        - "Running process list"

    - id: SCENARIO-03
      description: "PLC communication anomaly — unexpected source IP issuing Modbus writes, or PLC not responding to polling"
      containment_options:
        - action: safe_state_trigger
          description: "Command PLC to safe state via engineering workstation before isolating"
          safety_interlock_impact: "Process enters defined safe state — coordinate with operations"
          authorisation: "Safety Engineer + OT Operations Manager"
        - action: soft_isolation
          description: "Block all non-authorised source IPs at OT firewall from reaching PLC subnet"
          safety_interlock_impact: "Verify no safety communication traverses the blocked paths"
          authorisation: "Safety Engineer + Cybersecurity lead"
        - action: no_action_monitor
          description: "Increase monitoring and capture; do not isolate if PLC controls active safety interlock"
          safety_interlock_impact: "None"
          authorisation: "Cybersecurity lead"
      default_action: no_action_monitor
      evidence_to_collect_before_action:
        - "PLC project backup via engineering software"
        - "72-hour PCAP from forensic TAP on PLC subnet conduit"
        - "Engineering workstation connection logs"
```

### 2. MITRE ATT&CK for ICS Playbook Structure

CISA's recommended playbook structure maps directly to ATT&CK for ICS tactics. Each tactic becomes a section of the playbook, with specific technique IDs driving the triage questions and containment actions.

```yaml
ot_ir_playbook:
  name: "OT Intrusion Response — ICS Environment"
  version: "1.0"
  reference: "MITRE ATT&CK for ICS v14"

  phases:
    - tactic: "Initial Access"
      attck_techniques:
        - id: T0817
          name: "Drive-by Compromise"
          triage_questions:
            - "Which engineering workstation was used by a technician who visited an external site recently?"
            - "Is there browser history or DNS evidence of a watering-hole visit?"
          ioc_sources: ["DNS logs", "Proxy logs", "EDR on engineering workstations"]
        - id: T0866
          name: "Exploitation of Remote Services"
          triage_questions:
            - "Which remote access paths exist into the OT network (VPN, jump server, vendor access)?"
            - "Are there authentication failures or unusual login times on jump servers?"
          ioc_sources: ["Jump server auth logs", "VPN authentication logs"]

    - tactic: "Execution"
      attck_techniques:
        - id: T0807
          name: "Command-Line Interface"
          triage_questions:
            - "What processes were spawned from the engineering software (TIA Portal, Studio 5000)?"
            - "Are there cmd.exe or powershell.exe invocations from OT application processes?"
          ioc_sources: ["EDR process tree", "Windows Event 4688", "Sysmon"]
        - id: T0871
          name: "Execution through API"
          triage_questions:
            - "Was the vendor API (DCOM, OPC-DA/UA) used from an unexpected source IP?"
          ioc_sources: ["OPC server logs", "Malcolm Zeek logs for EtherNet/IP"]

    - tactic: "Persistence"
      attck_techniques:
        - id: T0839
          name: "Module Firmware"
          triage_questions:
            - "Does the current PLC firmware hash match the signed baseline?"
            - "Was a firmware download initiated from an unexpected engineering workstation?"
          ioc_sources: ["PLC project baseline comparison", "Malcolm Zeek logs for S7comm/Modbus"]
        - id: T0859
          name: "Valid Accounts"
          triage_questions:
            - "Are engineering software accounts being used outside of business hours?"
            - "Have any vendor accounts remained active after a maintenance window closed?"
          ioc_sources: ["Engineering software audit log", "Active Directory logs"]

    - tactic: "Lateral Movement"
      attck_techniques:
        - id: T0812
          name: "Default Credentials"
          triage_questions:
            - "Which PLCs or RTUs still have factory default credentials?"
            - "Is there Modbus or S7comm traffic from a source IP that is not an authorised engineering workstation?"
          ioc_sources: ["Malcolm baseline deviation alerts", "Modbus source IP matrix"]
        - id: T0886
          name: "Remote Services"
          triage_questions:
            - "Is there RDP or SSH traffic between OT segments that does not match the authorised communication matrix?"
          ioc_sources: ["Malcolm Zeek conn.log", "Firewall logs"]

    - tactic: "Collection"
      attck_techniques:
        - id: T0802
          name: "Automated Collection"
          triage_questions:
            - "Is there a high-frequency polling pattern from a source IP reading PLC registers across a wide address range?"
          ioc_sources: ["Malcolm Modbus log — query frequency analysis"]
        - id: T0811
          name: "Data from Information Repositories"
          triage_questions:
            - "Has the historian database been queried from an unexpected IP or application?"
          ioc_sources: ["Historian access logs", "Database audit log"]

    - tactic: "Impact"
      attck_techniques:
        - id: T0831
          name: "Manipulation of Control"
          triage_questions:
            - "Does the PLC project file exported post-incident differ from the signed baseline?"
            - "Were setpoint writes issued outside of authorised maintenance windows?"
          ioc_sources: ["PLC baseline diff", "Malcolm Modbus write log"]
        - id: T0826
          name: "Loss of Availability"
          triage_questions:
            - "Is the PLC failing to respond to control polls from the SCADA server?"
            - "Are safety interlock status bits in an unexpected state?"
          ioc_sources: ["SCADA server alarms", "Malcolm Modbus exception log"]
```

### 3. OT Evidence Collection Checklist

Before any power cycling, isolation, or remediation action on an HMI or engineering workstation, collect volatile evidence. The following script automates the critical collection steps on a Linux-based HMI:

```bash
#!/usr/bin/env bash
CASE_ID="${1:?Usage: $0 <case-id>}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
OUTPUT_DIR="/mnt/evidence-usb/${CASE_ID}/${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"

date -u > "${OUTPUT_DIR}/collection_timestamp.txt"
uname -a >> "${OUTPUT_DIR}/collection_timestamp.txt"

ps auxwwf > "${OUTPUT_DIR}/process_list.txt"

ss -tulpn > "${OUTPUT_DIR}/network_connections.txt"
ss -anp >> "${OUTPUT_DIR}/network_connections.txt"

ip addr show > "${OUTPUT_DIR}/network_interfaces.txt"
ip route show >> "${OUTPUT_DIR}/network_interfaces.txt"
arp -n >> "${OUTPUT_DIR}/network_interfaces.txt"

last -F > "${OUTPUT_DIR}/login_history.txt"
lastb -F >> "${OUTPUT_DIR}/login_history.txt"

find /tmp /var/tmp /dev/shm -type f -ls > "${OUTPUT_DIR}/temp_files.txt" 2>/dev/null

journalctl --since "72 hours ago" --output=json > "${OUTPUT_DIR}/systemd_journal_72h.json"

cp /var/log/auth.log "${OUTPUT_DIR}/auth.log" 2>/dev/null
cp /var/log/syslog "${OUTPUT_DIR}/syslog" 2>/dev/null

cat /proc/meminfo > "${OUTPUT_DIR}/meminfo.txt"
cat /proc/net/tcp > "${OUTPUT_DIR}/proc_net_tcp.txt"
cat /proc/net/tcp6 > "${OUTPUT_DIR}/proc_net_tcp6.txt"

find /etc /home /root -name "*.bash_history" -exec cp --parents {} "${OUTPUT_DIR}/" \; 2>/dev/null

sha256sum "${OUTPUT_DIR}"/* > "${OUTPUT_DIR}/sha256sums.txt"

echo "Evidence collection complete: ${OUTPUT_DIR}"
echo "SHA256 manifest written to ${OUTPUT_DIR}/sha256sums.txt"
```

For a Windows-based HMI, collect the equivalent data before any reboot:

```bash
wmic process list full > evidence\process_list.txt
netstat -ano > evidence\network_connections.txt
arp -a > evidence\arp_cache.txt
ipconfig /all > evidence\network_config.txt
wevtutil epl Security evidence\security_eventlog.evtx
wevtutil epl System evidence\system_eventlog.evtx
wevtutil epl Application evidence\application_eventlog.evtx
```

For historian evidence, export the time-series data for the 72-hour window preceding the anomaly before any database changes:

```bash
HISTORIAN_HOST="192.168.20.10"
HISTORIAN_DB="ProcessHistorian"
START_TIME="2026-05-01T00:00:00Z"
END_TIME="2026-05-03T12:00:00Z"

sqlcmd -S "${HISTORIAN_HOST}" -d "${HISTORIAN_DB}" \
  -Q "SELECT * FROM dbo.ProcessData WHERE Timestamp BETWEEN '${START_TIME}' AND '${END_TIME}'" \
  -o "evidence/historian_export_72h.csv" -s "," -W
```

### 4. PLC Configuration Backup Baseline

Maintain a cryptographically signed baseline of each PLC's project file — ladder logic, function blocks, I/O configuration, and safety program. After any incident, export the current project and compare against the signed baseline to detect logic modification.

The baseline workflow uses GPG signing to create a tamper-evident record:

```bash
PLC_ID="PLC-REACTOR-01"
VENDOR="siemens"
EXPORT_DIR="/opt/plc-baselines/${PLC_ID}"
mkdir -p "${EXPORT_DIR}"

BASELINE_DATE=$(date -u +"%Y%m%d")
BASELINE_FILE="${EXPORT_DIR}/${PLC_ID}_${BASELINE_DATE}.ap16"

sha256sum "${BASELINE_FILE}" > "${BASELINE_FILE}.sha256"

gpg --batch --yes \
    --local-user "ot-security@example.com" \
    --sign --armor \
    --output "${BASELINE_FILE}.sig" \
    "${BASELINE_FILE}"

echo "${PLC_ID} ${BASELINE_DATE} $(cat ${BASELINE_FILE}.sha256 | awk '{print $1}')" \
  >> "${EXPORT_DIR}/baseline_manifest.txt"
```

After an incident, export the current PLC project and compare against the signed baseline:

```bash
INCIDENT_EXPORT="${EXPORT_DIR}/${PLC_ID}_incident_$(date -u +%Y%m%dT%H%M%SZ).ap16"

gpg --verify "${EXPORT_DIR}/${PLC_ID}_${BASELINE_DATE}.ap16.sig" \
              "${EXPORT_DIR}/${PLC_ID}_${BASELINE_DATE}.ap16"

diff <(sha256sum "${EXPORT_DIR}/${PLC_ID}_${BASELINE_DATE}.ap16") \
     <(sha256sum "${INCIDENT_EXPORT}")

python3 /opt/tools/compare_plc_project.py \
  --baseline "${EXPORT_DIR}/${PLC_ID}_${BASELINE_DATE}.ap16" \
  --current "${INCIDENT_EXPORT}" \
  --output "evidence/plc_diff_report.txt"
```

The PLC project comparison tool (`compare_plc_project.py`) must be written against the vendor's project file format. For Siemens TIA Portal `.ap16` files, CISA's SCADAfence and Claroty integrations provide diff tooling; for Rockwell Studio 5000 `.ACD` files, the `acd-toolkit` open-source parser provides block-level diffing. The output should list each modified rung, function block, or I/O binding by name and line number.

### 5. Forensic Network TAP Deployment

Deploy passive hardware TAPs at each critical OT segment conduit — the IT-to-OT boundary, vendor access paths, and connections between safety-critical PLC subnets. A hardware TAP is not a SPAN port: it is a physical device inserted inline in the cable that passively copies all traffic to a monitoring port. It cannot be disabled via software, does not respond to network traffic, and introduces no latency into the control path.

```yaml
tap_deployment:
  tap_01:
    location: "IT/OT Boundary — Firewall to OT DMZ switch"
    tap_model: "Garland Technology P1GCCAS"
    capture_appliance: "Malcolm server — eth1"
    pcap_retention_days: 90
    estimated_daily_volume_gb: 2.1
    estimated_90day_storage_gb: 189

  tap_02:
    location: "OT DMZ to PLC subnet — Aggregation switch to PLC ring"
    tap_model: "Garland Technology P1GCCAS"
    capture_appliance: "Malcolm server — eth2"
    pcap_retention_days: 90
    estimated_daily_volume_gb: 0.8
    estimated_90day_storage_gb: 72

  tap_03:
    location: "Vendor remote access — Vendor jump server egress"
    tap_model: "Garland Technology P1GCCAS"
    capture_appliance: "Malcolm server — eth3"
    pcap_retention_days: 90
    estimated_daily_volume_gb: 0.3
    estimated_90day_storage_gb: 27

  capture_appliance:
    hostname: "malcolm-capture-01"
    location: "OT DMZ — isolated monitoring VLAN"
    storage_total_tb: 4
    zeek_retention_days: 180
    pcap_retention_days: 90
    network_access: "receive-only from TAP mirror ports; outbound to SOC SIEM only"
```

Configure the Malcolm capture appliance to rotate PCAP on a 90-day rolling basis:

```bash
CAPTURE_IFACE="eth1"
PCAP_DIR="/data/pcap"
RETENTION_DAYS=90

tcpdump -i "${CAPTURE_IFACE}" \
  -w "${PCAP_DIR}/capture_%Y%m%d_%H%M%S.pcap" \
  -G 3600 \
  -z /opt/scripts/compress_and_rotate.sh \
  -Z pcap

find "${PCAP_DIR}" -name "*.pcap.gz" -mtime "+${RETENTION_DAYS}" -delete
```

In production, Malcolm manages PCAP capture and rotation natively through Arkime. The above `tcpdump` example illustrates the retention principle for environments that use standalone capture instead of the full Malcolm stack.

### 6. Chain of Custody for OT Evidence

Every piece of evidence collected during an OT incident must have a documented chain of custody before it can be used in legal proceedings or insurance claims. Digital evidence requires hash verification; physical media (USB drives, HMI disk images) requires evidence bags and write-blockers.

```yaml
chain_of_custody:
  case_id: "OT-INC-2026-001"
  incident_description: "Suspected PLC logic modification on Reactor Line 2"
  ir_lead: "Jane Smith, OT Security Engineer"
  opened: "2026-05-03T09:00:00Z"

  evidence_items:
    - item_id: "E001"
      description: "HMI-REACTOR-02 volatile memory collection (bash script output)"
      collected_by: "Jane Smith"
      collected_at: "2026-05-03T09:22:00Z"
      collection_method: "Bash script run from evidence USB; output written to USB"
      storage_location: "Evidence USB drive — serial EV-2026-001"
      sha256: "a3b4c5d6e7f8..."
      write_blocked: true
      notes: "HMI powered on and running at time of collection; not rebooted before collection"

    - item_id: "E002"
      description: "PLC-REACTOR-01 TIA Portal project export (post-incident)"
      collected_by: "Mark Jones, OT Technician"
      collected_at: "2026-05-03T10:45:00Z"
      collection_method: "TIA Portal project export via licensed engineering workstation EWS-02"
      storage_location: "Evidence USB drive — serial EV-2026-001"
      sha256: "b4c5d6e7f8a1..."
      write_blocked: true
      notes: "Exported before any remediation; GPG signature verified against 2026-04-01 baseline"

    - item_id: "E003"
      description: "Malcolm PCAP export — TAP-01 — 72 hours preceding incident"
      collected_by: "Jane Smith"
      collected_at: "2026-05-03T11:00:00Z"
      collection_method: "Arkime PCAP export via Malcolm API; downloaded to evidence server"
      storage_location: "Evidence server \\evidence-srv\cases\OT-INC-2026-001\pcap"
      sha256: "c5d6e7f8a1b2..."
      write_blocked: true
      notes: "PCAP covers 2026-04-30T11:00:00Z through 2026-05-03T11:00:00Z"

  access_log:
    - actor: "Jane Smith"
      timestamp: "2026-05-03T09:00:00Z"
      action: "Case opened; evidence collection begun"
    - actor: "Jane Smith"
      timestamp: "2026-05-03T11:30:00Z"
      action: "Evidence transferred to evidence server; SHA256 hashes verified"
    - actor: "External IR Firm"
      timestamp: "2026-05-03T14:00:00Z"
      action: "Read-only access granted to evidence copies; originals remain write-protected"
```

Verify hash integrity of every evidence item before transferring to external analysts:

```bash
sha256sum -c evidence_sha256sums.txt
```

For physical HMI disk images, use a hardware write-blocker before connecting the drive to any analysis workstation:

```bash
EVIDENCE_DEVICE="/dev/sdb"
IMAGE_FILE="evidence/HMI-REACTOR-02_$(date -u +%Y%m%dT%H%M%SZ).dd"

dcfldd if="${EVIDENCE_DEVICE}" of="${IMAGE_FILE}" \
  bs=4096 \
  hash=sha256 \
  hashlog="${IMAGE_FILE}.sha256" \
  statusinterval=256

sha256sum "${IMAGE_FILE}" >> evidence/sha256sums.txt
```

`dcfldd` (a forensic `dd` variant) produces a hash of the image as it is created, which is the accepted method for establishing hash integrity for legal proceedings.

## Expected Behaviour After Hardening

With a pre-crisis decision matrix in place: during a simulated incident exercise — an HMI workstation on the reactor line showing unexpected outbound connections — the IR team opens the decision matrix, confirms the scenario matches SCENARIO-01, and initiates soft isolation of the HMI's switch port within 12 minutes of initial detection. The safety engineer confirms that no safety interlock paths traverse the HMI's network connection. The PLC continues executing ladder logic without interruption. The entire decision is made by consulting a pre-approved document rather than convening an emergency stakeholder call.

With PLC project baseline in place: a post-incident export of PLC-REACTOR-01's TIA Portal project is compared against the GPG-signed baseline from 2026-04-01. The comparison tool identifies a modified rung in Network 7 of the Safety Program function block — a contact element has been changed from normally-closed to normally-open, which would have caused a safety interlock to fail to respond on high-temperature alarm. This modification was not visible in any alarm log or historian record; it was only detectable by comparing the project file directly against the signed baseline.

With forensic TAPs deployed: when the IR team arrives and determines that no SIEM was receiving OT logs and the historian records have been modified, the 90-day PCAP from TAP-01 (IT/OT boundary) and TAP-02 (OT DMZ to PLC subnet) provides a complete record of every network transaction involving PLC-REACTOR-01 for the preceding 72 hours. Zeek Modbus logs from Malcolm show the exact timestamp, source IP, Modbus function code, register address, and register value for the anomalous write that modified the safety setpoint.

## Trade-offs and Operational Considerations

Hardware TAPs add cost per segment — budget approximately $800–$2,000 per TAP depending on port speed and form factor. Prioritise the IT-to-OT boundary and vendor access paths first; these are the most common initial access and lateral movement paths and provide the highest forensic value per dollar. Extend to intra-OT segment conduits as budget allows.

The pre-crisis decision matrix requires genuine involvement from OT operations, safety engineering, and cybersecurity — three groups with different vocabularies, different risk tolerances, and different reporting lines. Budget two to three months to develop the initial matrix, including time for safety engineering to review each containment option against the safety interlock dependency map. A matrix developed only by the cybersecurity team, without operations and safety input, will be wrong in ways that are not apparent until an incident, when the consequences of applying the wrong containment action are severe.

PCAP retention at 90 days requires storage proportional to OT traffic volume. OT networks are typically much lower bandwidth than IT networks — a medium-sized facility may generate 50–200 Mbps across all OT segments combined, and Zeek structured logs compress to a fraction of raw PCAP. A 4 TB capture appliance with PCAP for 90 days is achievable for most small-to-medium OT networks. Calculate the actual OT traffic volume from a Malcolm deployment before sizing storage, rather than applying IT-network storage assumptions.

PLC project file backup requires vendor engineering software licenses and a technician capable of operating the software. A Siemens S7-1500 project export requires TIA Portal; a Rockwell ControlLogix project export requires Studio 5000. These are not standard IT skills and not standard IT tools — plan for this in the IR team's toolkit procurement and training. The baseline export workflow should be tested quarterly to confirm that the process works, the licenses are current, and the technician who will perform it during an incident has done it before.

## Failure Modes

A decision matrix that has been developed but never tested in a tabletop exercise reverts to an improvised decision during an actual incident. Tabletop exercises must include the scenario of a stakeholder who was not in the room when the matrix was written — the night-shift OT supervisor, the safety engineer on call who was not part of the original working group. If the matrix cannot be applied without the specific people who wrote it, it will fail when those people are unavailable at 2 AM.

HMI volatile memory not collected before reboot is the most common and most consequential forensic failure in OT incidents. Evidence of attacker presence — process trees, open network connections, injected code — survives only in volatile memory and is destroyed by any reboot. The collection script must be accessible on an evidence USB drive that is physically stored in the OT control room, so that any OT technician can run it without waiting for the IR team to arrive on-site. The USB drive location, the script name, and the step-by-step instructions must be laminated and posted in the control room.

A PLC baseline that is not updated after legitimate engineering changes generates false positives on every post-incident comparison. If operations deploys a modified safety program to PLC-REACTOR-01 in February and the baseline is not re-signed until the next quarterly review in April, the February change will appear as a suspicious modification in every comparison until the baseline is updated. This erodes trust in the baseline comparison process — teams begin to dismiss comparison findings as "another stale baseline alert" — precisely the failure mode that allows a real attacker modification to go undetected. Baseline update must be a required step in the engineering change management workflow, not an afterthought.

A forensic TAP that has been installed but whose PCAP retention was not configured will overwrite captures within hours or days. Hardware TAPs capture at wire speed; without a configured retention policy and a storage system sized for 90 days, the capture appliance disk fills and the oldest PCAPs are overwritten. Verify PCAP retention configuration and available storage monthly, and alert when free space on the capture appliance drops below a threshold that indicates fewer than 30 days of remaining capacity.

## Related Articles

- [OT Network Monitoring Malcolm](/articles/observability/ot-network-monitoring-malcolm/)
- [Forensic Readiness](/articles/observability/forensic-readiness/)
- [Incident Response Runbooks](/articles/observability/incident-response-runbooks/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
- [OT Network Segmentation Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)
