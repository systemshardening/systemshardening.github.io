---
title: "OT Data Integrity: Signing Process Data and PLC Configurations"
description: "CISA prioritises integrity over confidentiality in OT. Implement HMAC-signed historian records, digitally signed PLC project exports, file integrity monitoring on HMI workstations, and OPC-UA Sign mode for latency-sensitive control loops."
slug: ot-data-integrity-signing
date: 2026-05-03
lastmod: 2026-05-03
category: cross-cutting
tags:
  - ot-security
  - data-integrity
  - digital-signing
  - ics
  - opc-ua
personas:
  - security-engineer
  - platform-engineer
article_number: 413
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/ot-data-integrity-signing/
---

# OT Data Integrity: Signing Process Data and PLC Configurations

## The Problem

A power plant historian stores 10 years of process data. If an attacker modifies historical records — slightly adjusting turbine temperature readings to conceal a gradual deterioration they caused — the falsified data influences maintenance schedules, safety audits, and regulatory compliance reporting. The data was never encrypted, but that is not the primary problem: it was also never signed.

CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" explicitly states that for most OT systems, data authentication — proving who wrote a value and that it has not been modified — is more important than confidentiality, which prevents others from reading it. Process values like temperatures, pressures, and flow rates are not typically secret. They are often regulatory-required public records, shared with safety auditors, grid operators, or environmental agencies as a matter of law. But their integrity — the assurance that the value recorded is the value that was actually measured — is safety-critical. A falsified temperature trend tells a maintenance engineer that equipment is healthy when it is degrading. A forged setpoint write command tells a PLC to drive a pump beyond its safe operating limit.

Encryption is the wrong primary control for this threat. Adding TLS to Modbus or OPC-UA communication adds 2–5 ms of processing latency per transaction. A PLC executing a 10 ms control loop has no slack to absorb this. The real-time determinism that keeps physical processes safe is violated before any security benefit is realised. A cryptographic HMAC appended to each historian record adds microseconds — processing time measured at the SCADA server or historian ingestion layer, not at the field device — and provides a complete audit trail of every record's origin and integrity. Signing operates at the data layer, not the transport layer, so it imposes no constraint on existing Modbus or serial communication.

This is not a theoretical distinction. Several publicly documented OT incidents involved manipulation of historian data to conceal operational problems from management or regulators. The data transport was often unencrypted, but encryption would not have prevented the manipulation: the attacker had authenticated access to the historian database directly. A signing scheme enforced at the ingestion layer and verified at the query layer would have made the modification detectable.

This article covers four concrete controls: HMAC signing at the historian ingestion point, OPC-UA security mode configuration for Sign-only operation on latency-sensitive control loops, GPG signing of PLC project exports before backup storage, and file integrity monitoring on HMI engineering workstations. Each control is independently deployable; none requires changes to field devices or PLC firmware.

## Threat Model

- **Historian record modification** — an attacker with read/write access to the historian database (via a compromised SCADA server credential, a vendor remote access session, or a database management tool left accessible on the historian server) alters historical process values to conceal an attack, pass a safety audit, or manipulate a regulatory filing. The modification may be subtle: a single degree of temperature offset sustained over months, or a pressure exceedance that is retroactively edited out of the record. Without integrity signatures on individual records, database audit logs are the only detection mechanism, and those logs are often stored in the same database being modified.

- **PLC project file modification** — an attacker modifies a backup copy of PLC ladder logic stored on a shared drive or engineering workstation. The modified project file is then restored during a firmware recovery event — a planned or unplanned scenario that bypasses normal change management review. The operational impact ranges from subtle logic changes that introduce instability under specific process conditions, to safety interlock bypasses that become active only when a particular setpoint is reached.

- **Forged OPC-UA WRITE command** — an attacker on the OT network sends an OPC-UA WRITE request to a PLC or controller using a spoofed or replayed session. Without message-level authentication (OPC-UA `SecurityMode=None`), the OPC-UA server cannot distinguish a legitimate setpoint change from an attacker's command. The attacker does not need to compromise the SCADA server; they need only a network path to the OPC-UA server port (typically TCP 4840) and knowledge of the target NodeID, both of which are discoverable through passive OT network enumeration.

- **HMI configuration tampering** — an attacker modifies SCADA screen configuration files on an HMI engineering workstation: hiding alarm indicators, adjusting display scaling so that out-of-range values appear normal, or removing operator notification for specific tag conditions. The modification is persistent across HMI reboots and may go undetected until an operator notices that expected alarms are not appearing during a process upset.

- **OPC-UA replay attack** — an attacker captures a valid OPC-UA WRITE message containing a legitimate setpoint change and replays it at a later time. Without sequence number validation and nonce enforcement on the OPC-UA session, the replayed message is indistinguishable from a new legitimate command. This allows an attacker to trigger a control action — a valve open, a pump start, a heater enable — by replaying a command that was legitimately issued at a different time under different process conditions.

## Hardening Configuration

### 1. HMAC-Signed Historian Records

Implement an HMAC-SHA256 signing layer at the historian ingestion point. Each record — consisting of the timestamp, tag name, value, and quality code — is signed before it is committed to the historian. The HMAC key is a shared secret held by the SCADA server (or the process that writes to the historian) and the historian integrity verification service. Field devices never touch the key; it lives only in the SCADA server's secret store and in the verification tooling.

The following Python module wraps an InfluxDB 2.x write client. The same pattern applies to any historian with a programmable ingestion API (OSIsoft PI via PI Web API, Honeywell PHD via the PHD SDK, or any TSDB with a REST or socket interface).

```python
import hmac
import hashlib
import json
import time
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

HMAC_KEY = b"replace-with-32-byte-secret-from-vault"

def _canonical_record(tag: str, value: float, quality: int, ts_ns: int) -> bytes:
    return json.dumps(
        {"tag": tag, "value": value, "quality": quality, "ts": ts_ns},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

def sign_record(tag: str, value: float, quality: int, ts_ns: int) -> str:
    payload = _canonical_record(tag, value, quality, ts_ns)
    return hmac.new(HMAC_KEY, payload, hashlib.sha256).hexdigest()

def verify_record(tag: str, value: float, quality: int, ts_ns: int, signature: str) -> bool:
    expected = sign_record(tag, value, quality, ts_ns)
    return hmac.compare_digest(expected, signature)

def write_signed(client: InfluxDBClient, bucket: str, org: str,
                 tag: str, value: float, quality: int = 192) -> None:
    ts_ns = time.time_ns()
    sig = sign_record(tag, value, quality, ts_ns)
    point = (
        Point("process_data")
        .tag("tag_name", tag)
        .field("value", value)
        .field("quality", quality)
        .field("hmac_sha256", sig)
        .time(ts_ns, WritePrecision.NANOSECONDS)
    )
    write_api = client.write_api(write_options=SYNCHRONOUS)
    write_api.write(bucket=bucket, org=org, record=point)

def audit_records(client: InfluxDBClient, bucket: str, org: str,
                  tag: str, start: str = "-1h") -> list[dict]:
    query_api = client.query_api()
    query = f'''
    from(bucket: "{bucket}")
      |> range(start: {start})
      |> filter(fn: (r) => r["tag_name"] == "{tag}")
      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
    '''
    failures = []
    for table in query_api.query(query, org=org):
        for record in table.records:
            ts_ns = int(record.get_time().timestamp() * 1e9)
            ok = verify_record(
                tag=record.values["tag_name"],
                value=record.values["value"],
                quality=record.values["quality"],
                ts_ns=ts_ns,
                signature=record.values["hmac_sha256"],
            )
            if not ok:
                failures.append({
                    "tag": record.values["tag_name"],
                    "ts": record.get_time().isoformat(),
                    "value": record.values["value"],
                })
    return failures
```

Run `audit_records` on a schedule — hourly for high-criticality tags, daily for archive tags — and ship failures to the OT SIEM as integrity violation events. A modified record will produce a different HMAC than the stored signature, because the attacker cannot compute a valid HMAC without knowing the key.

Store the HMAC key in the OT secrets manager (Vault instance in the OT DMZ or an HSM-backed key store). Rotate the key on a defined schedule — annually is acceptable for HMAC keys used solely for integrity verification, not encryption. After rotation, re-sign recent records using the new key and archive the old signature alongside the record for audit trail continuity.

### 2. OPC-UA Security Mode: Sign

Configure all OPC-UA clients and servers to use `SecurityMode=Sign` with the `Basic256Sha256` security policy. This enforces message-level authentication: every OPC-UA message is signed with the sender's certificate private key, and the receiver verifies the signature before processing the message. A forged or tampered OPC-UA message — including a WRITE command from an attacker on the OT network — is rejected by the OPC-UA server before the command is applied to the controller.

`Sign` mode, not `SignAndEncrypt`. Encryption doubles the per-message processing overhead and adds symmetric cipher operations to every publish cycle. For a SCADA server polling 500 tags at 100 ms intervals, the overhead is measurable on the OT network and on constrained OPC-UA server implementations in PLCs. `Sign` mode adds only asymmetric signature verification — a one-time cost during session establishment and a lightweight HMAC verification on each message body thereafter.

Reserve `SignAndEncrypt` for the historian-to-IT replication path, where records leave the OT DMZ and cross into the enterprise network. On that path, latency is not a hard real-time constraint and confidentiality of aggregated process data from the OT segment may be a compliance requirement.

OPC-UA server endpoint configuration (UA server configuration XML, Unified Automation UaGateway format):

```xml
<UaServerConfig>
  <Endpoints>
    <Endpoint>
      <Url>opc.tcp://scada-server.ot.example.internal:4840</Url>
      <SecurityPolicies>
        <SecurityPolicy>
          <Uri>http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256</Uri>
          <SecurityModes>
            <SecurityMode>Sign</SecurityMode>
          </SecurityModes>
        </SecurityPolicy>
      </SecurityPolicies>
      <UserTokenPolicies>
        <UserTokenPolicy>
          <TokenType>Certificate</TokenType>
        </UserTokenPolicy>
      </UserTokenPolicies>
    </Endpoint>
  </Endpoints>
  <SecurityConfiguration>
    <ApplicationCertificate>
      <StoreType>Directory</StoreType>
      <StorePath>/etc/opcua/pki/own</StorePath>
      <SubjectName>CN=SCADA OPC-UA Server,O=Example Corp OT</SubjectName>
    </ApplicationCertificate>
    <TrustedCertificateStore>
      <StoreType>Directory</StoreType>
      <StorePath>/etc/opcua/pki/trusted</StorePath>
    </TrustedCertificateStore>
    <RejectedCertificateStore>
      <StoreType>Directory</StoreType>
      <StorePath>/etc/opcua/pki/rejected</StorePath>
    </RejectedCertificateStore>
    <RejectSHA1SignedCertificates>true</RejectSHA1SignedCertificates>
    <MinimumCertificateKeySize>2048</MinimumCertificateKeySize>
  </SecurityConfiguration>
</UaServerConfig>
```

Remove any endpoint configured with `SecurityMode=None`. An OPC-UA server that advertises a `None` security endpoint will be used by any client that does not have a certificate configured — which includes most default OPC-UA client installations. Removing the `None` endpoint forces all clients to present a certificate and negotiate a signed session; clients that cannot do so cannot connect.

OPC-UA client certificates must be issued by the OT PKI (described in the OT NPE Identity PKI article). Add each OPC-UA client's certificate to the server's trusted certificate store at `/etc/opcua/pki/trusted`. Certificates in the rejected store are logged and blocked.

### 3. OPC-UA Replay Protection

Enable sequence number validation and session nonce enforcement. Replay protection is part of the OPC-UA specification's `Basic256Sha256` security policy but requires explicit verification that the OPC-UA server implementation enforces it. Check the server audit log after enabling Sign mode to confirm that replayed messages are rejected.

An OPC-UA server configured correctly with `Basic256Sha256` and `Sign` mode will log replayed message rejections:

```conf
[2026-05-03T14:22:11.443Z] [WARN] [SecurityChannel] MessageSequenceNumber out of order:
  ChannelId=42 TokenId=7 Expected=1192 Received=1101 Action=Reject
[2026-05-03T14:22:11.443Z] [WARN] [SecurityChannel] RequestNonce already used in session:
  SessionId=session-8a4f2c ChannelId=42 Action=Reject
```

If the server log shows replayed messages being accepted (no reject action, or no sequence number validation log entry), the server implementation does not enforce replay protection despite the security policy being set. In that case, implement replay detection at the SCADA application layer: maintain a sliding window of the last 200 sequence numbers per channel and reject duplicates before passing WRITE commands to the control application.

Verify replay protection is active after configuration change:

```bash
# Use the open62541 OPC-UA toolkit's ua-cli to send a replayed message
# and confirm the server rejects it.

# First, capture a valid WRITE request during a legitimate setpoint change.
# Then attempt to replay it:
ua-cli write \
  --endpoint opc.tcp://scada-server.ot.example.internal:4840 \
  --security-mode Sign \
  --security-policy Basic256Sha256 \
  --certificate /etc/opcua/pki/own/client.crt \
  --private-key /etc/opcua/pki/own/client.key \
  --node-id "ns=2;s=Boiler.Setpoint.Temperature" \
  --value 85.0 \
  --replay-sequence-number 1101

# Expected: server returns BadSequenceNumberInvalid (0x80560000)
# If the server returns Good (0x00000000), replay protection is not enforced.
echo "Exit code $? — 0 indicates server accepted the replayed message (fail)"
```

### 4. PLC Project File Signing

Establish a signing workflow for all PLC project exports. After every project modification — whether a scheduled logic change or an emergency fix — the engineer exports the project file and GPG-signs it before committing the backup. The signature file travels with the project file in every backup location: the Git-backed OT configuration repository, the removable media backup, and any historian snapshot that includes controller configuration.

Each OT engineer who is authorised to modify PLC programs holds an OT signing key. These keys are stored on a hardware security token (YubiKey or similar FIDO2/OpenPGP device). The key never exists unprotected on a workstation filesystem.

```bash
# Export a project from the PLC engineering software (vendor-specific export command).
# The exported file is a binary or XML archive — example: line-a-boiler-plc.L5X (Allen-Bradley).

# Sign the project file with the engineer's OT signing key.
gpg --armor \
    --detach-sign \
    --local-user "engineer-alice@ot.example.internal" \
    --output line-a-boiler-plc.L5X.sig \
    line-a-boiler-plc.L5X

# Commit both the project file and the signature to the OT Git repo.
git -C /opt/ot-configs add line-a-boiler-plc.L5X line-a-boiler-plc.L5X.asc
git -C /opt/ot-configs commit -m "Update boiler PLC setpoint limits — Alice"

# Verify the signature before any restore operation.
gpg --verify line-a-boiler-plc.L5X.sig line-a-boiler-plc.L5X
```

The OT signing keyring — a GPG public keyring containing the public keys of all engineers authorised to sign PLC projects — is stored on the historian server and replicated to the OT SIEM. Verification uses this keyring; a project file signed by a key not in the keyring is treated as unsigned.

Export engineer public keys to the OT keyring:

```bash
# On the engineer's workstation: export the public key for distribution.
gpg --armor --export "engineer-alice@ot.example.internal" > alice-ot-signing.pub

# On the historian server (OT keyring administrator): import and sign to establish trust.
gpg --import alice-ot-signing.pub
gpg --sign-key "engineer-alice@ot.example.internal"

# List the OT signing keyring to confirm all authorised keys are present.
gpg --list-keys --keyid-format LONG
```

### 5. Integrity Verification at Restore

Before restoring any PLC project backup during incident response, maintenance, or firmware recovery, verify the GPG signature. This check is a required step in the OT incident response forensics checklist, not an optional courtesy. An unsigned backup should never be restored to a production PLC without explicit written authorisation and a documented reason.

```bash
#!/usr/bin/env bash

BACKUP_FILE="${1:?Usage: verify-restore.sh <plc-backup-file>}"
SIG_FILE="${BACKUP_FILE}.sig"
OT_KEYRING="/etc/ot-pki/ot-signing-keyring.gpg"
AUDIT_LOG="/var/log/ot-integrity/restore-audit.log"

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "${AUDIT_LOG}"
}

if [[ ! -f "${SIG_FILE}" ]]; then
  log "FAIL no-signature file=${BACKUP_FILE}"
  echo "Restore blocked: no signature file found for ${BACKUP_FILE}" >&2
  exit 1
fi

gpg --no-default-keyring \
    --keyring "${OT_KEYRING}" \
    --verify "${SIG_FILE}" "${BACKUP_FILE}" 2>/tmp/gpg-verify.out

if [[ $? -ne 0 ]]; then
  log "FAIL bad-signature file=${BACKUP_FILE} gpg_output=$(cat /tmp/gpg-verify.out)"
  echo "Restore blocked: signature verification failed for ${BACKUP_FILE}" >&2
  exit 1
fi

SIGNER=$(gpg --no-default-keyring --keyring "${OT_KEYRING}" \
             --verify "${SIG_FILE}" "${BACKUP_FILE}" 2>&1 \
             | grep "Good signature" | sed 's/.*from "\(.*\)".*/\1/')

log "OK signature-verified file=${BACKUP_FILE} signer=${SIGNER}"
echo "Signature verified. Signed by: ${SIGNER}"
echo "Restore may proceed."
exit 0
```

Deploy this script at `/usr/local/bin/verify-restore.sh` on all OT engineering workstations and the historian server. Document in the OT runbooks that no PLC project restore may begin without running this script and confirming an exit code of 0. Add the exit code and the signer identity to the incident ticket before the restore proceeds.

### 6. File Integrity Monitoring on HMI Workstations

Deploy AIDE (Advanced Intrusion Detection Environment) on Linux HMI workstations to monitor SCADA application configuration directories, screen layout files, and alarm configuration files. Any modification outside a defined maintenance window generates an alert within 60 seconds.

AIDE configuration for a generic Linux SCADA installation:

```conf
# /etc/aide/aide.conf — HMI workstation file integrity configuration

database_in=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
database_new=file:/var/lib/aide/aide.db.new
gzip_dbout=yes
report_url=file:/var/log/aide/aide.log
report_url=stdout

# Define the attribute set for SCADA configuration files.
# p=permissions, i=inode, n=link count, u=uid, g=gid, s=size,
# S=growing size check, m=mtime, c=ctime, md5=MD5 hash, sha256=SHA256 hash
SCADA_CONFIG = p+i+n+u+g+s+m+c+sha256+md5

# SCADA application installation and configuration directories.
# Adjust paths to match the specific SCADA vendor's installation layout.
/opt/scada/project                SCADA_CONFIG
/opt/scada/screens                SCADA_CONFIG
/opt/scada/alarms                 SCADA_CONFIG
/opt/scada/scripts                SCADA_CONFIG
/opt/scada/tags                   SCADA_CONFIG
/etc/scada                        SCADA_CONFIG

# HMI display configuration.
/home/hmi-operator/.config/scada  SCADA_CONFIG

# Exclude runtime state files that change legitimately during operation.
!/opt/scada/logs
!/opt/scada/cache
!/opt/scada/tmp
```

Initialise the AIDE database after a verified clean installation:

```bash
aide --init --config /etc/aide/aide.conf
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

Run AIDE checks on a 60-second systemd timer:

```bash
# /etc/systemd/system/aide-check.service
[Unit]
Description=AIDE file integrity check
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/aide --check --config /etc/aide/aide.conf
StandardOutput=append:/var/log/aide/aide.log
StandardError=append:/var/log/aide/aide.log
```

```bash
# /etc/systemd/system/aide-check.timer
[Unit]
Description=Run AIDE integrity check every 60 seconds

[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now aide-check.timer
```

Forward AIDE log output to the OT SIEM via the local Wazuh agent or syslog forwarder. Configure the SIEM to suppress alerts generated within a defined maintenance window (a scheduled time window communicated to the SIEM before any planned SCADA update). Outside maintenance windows, any AIDE-detected change to a monitored path generates a high-severity alert.

For Windows HMI workstations, deploy Wazuh FIM (File Integrity Monitoring) agent with equivalent directory monitoring rules. Wazuh FIM achieves the same 60-second detection target on Windows and ships alerts to the same OT SIEM without a separate log pipeline.

## Expected Behaviour After Hardening

After HMAC historian signing: a modified historian record produces a different HMAC than the stored signature. The hourly `audit_records` sweep detects the mismatch and emits an integrity violation event to the OT SIEM. The event includes the tag name, timestamp, and the stored value, giving incident responders the exact record that was modified. The attacker cannot forge a valid HMAC without the key. Direct database modification — bypassing the SCADA API — is detected because the signing layer signs at ingestion time; any record written directly to the database has no signature or a signature computed without the current key.

After OPC-UA Sign mode: a forged OPC-UA WRITE command without a valid message signature is rejected by the OPC-UA server with `BadSecurityChecksFailed`. The server logs the rejection, including the channel ID and the source endpoint. A client presenting a certificate that is not in the server's trusted store is rejected with `BadCertificateUntrusted` during session establishment and cannot issue any commands. An attacker on the OT network who does not have a valid OPC-UA client certificate cannot interact with any OPC-UA server on the segment.

After PLC project signing: a project file that has been modified after signing produces a GPG verification failure — `gpg: BAD signature`. The verify-restore script exits with code 1, logs the failure to the restore audit log, and blocks the restore. An unsigned project file — one without a `.sig` file — is also blocked. The engineer must produce a valid signed export from the current PLC program before any restore proceeds.

After FIM: a modification to the SCADA alarm configuration file at `/opt/scada/alarms/` outside a maintenance window generates an AIDE mismatch entry within 60 seconds of the next timer firing. The OT SIEM receives the event and creates a high-severity alert within 90 seconds of the modification. An attacker who modifies alarm display configuration to hide process upset indicators is detected before the next operator shift handover.

## Trade-offs and Operational Considerations

HMAC-signed historian records require changes to the SCADA data ingestion pipeline. The signing wrapper sits between the SCADA output and the historian write API; any SCADA vendor-provided historian agent or PI connector that writes directly to the historian database bypasses the wrapper. Coordinate with the SCADA vendor before deploying the signing layer to ensure it does not violate the support agreement and that the vendor's historian agents can be configured to write through the signing wrapper rather than directly to the database.

OPC-UA Sign mode requires certificate management for every OPC-UA client and server on the OT segment. This is a meaningful operational commitment: each PLC with an OPC-UA server, each SCADA client, and each historian OPC-UA collector needs a certificate from the OT PKI, must have that certificate renewed annually, and must have the OT PKI root in its trust store. Establish the OT PKI infrastructure — described in the OT NPE Identity PKI article — before enabling OPC-UA security mode. Attempting to enable Sign mode without a working PKI results in a segment-wide connectivity outage as all OPC-UA sessions fail certificate validation.

PLC project signing requires engineers to manage OT signing keys as a new operational requirement. Keys must be stored on hardware tokens — a YubiKey configured for OpenPGP signing, not a software key on the workstation filesystem. Establish a key ceremony process for issuing and registering new engineer signing keys, and a revocation process for engineers who leave the team. The OT signing keyring on the historian server must be updated when keys are issued or revoked; a revoked key should not be able to verify new restores, but its historical signatures on archived project files remain valid records of who signed what at the time.

AIDE and Wazuh FIM generate high-volume change events during legitimate SCADA software updates. A version upgrade that touches hundreds of files in the monitored directories will produce hundreds of alerts if FIM is running during the update. Configure maintenance window suppression in the OT SIEM — a time-bounded alert suppression rule that is explicitly created and closed by a change ticket, not a permanent suppression. After the maintenance window closes, re-initialise the AIDE database from the newly installed state: `aide --init`, verify the new baseline is correct, and move it into place before re-enabling the timer.

Key rotation for the historian HMAC key affects all previous records: records signed with the previous key cannot be verified with the new key unless the old key is retained for verification. Maintain a key archive: each retired key is kept (access-controlled, not deleted) and identified by a key version tag stored alongside each record. When verifying a record, use the key version tag to select the correct key for verification. This adds one field to the historian schema but prevents the entire historical record from becoming unverifiable after a key rotation.

## Failure Modes

HMAC signing implemented at the historian REST API but not at the database ingest layer — direct database connections bypass signature verification entirely. If the historian database is accessible via a SQL client, a vendor management tool, or a direct database connection from the SCADA server, records written through those paths are unsigned. Enumerate all write paths to the historian database and either route them through the signing layer or block them at the database firewall. The signing wrapper is ineffective if unsigned records can be written directly to the database alongside signed records.

OPC-UA security mode set to Sign but the `None` security endpoint is left in place alongside it. Many OPC-UA server implementations advertise all configured endpoints in the discovery response; a client that does not have a certificate configured will automatically negotiate the `None` endpoint rather than failing. The `None` endpoint must be removed from the server configuration, not merely deprioritised. Verify by running a UA discovery scan and confirming that no endpoint with `SecurityMode=None` is advertised.

OPC-UA Sign mode active but certificate revocation not implemented. A compromised OPC-UA client certificate — from a stolen engineer workstation, a compromised vendor laptop, or an expired certificate that was not rotated — continues to produce valid message signatures indefinitely if there is no revocation mechanism. Deploy an OT OCSP responder or CRL distribution point as part of the OT PKI before enabling OPC-UA security mode. Configure the OPC-UA server to check certificate revocation status on session establishment.

PLC project signing workflow skipped for an emergency change. An operator or engineer bypasses the signing step during an incident to restore a configuration quickly. The unsigned backup is restored to the PLC. During post-incident forensics, the restored project file cannot be verified, and it is unclear whether the backup was from a trusted source or was modified. Prevent this by enforcing the verify-restore script as a hard gate in the restoration procedure, not a recommendation. If the emergency genuinely requires bypassing the gate, the bypass must be documented in the incident ticket with a named approver before the restore proceeds, not as a post-hoc note.

AIDE alerts forwarded to a log aggregator running on the same HMI workstation being monitored. An attacker who has compromised the HMI workstation can suppress local syslog forwarding before modifying SCADA configuration files, preventing the AIDE alert from reaching the OT SIEM. The log forwarder must send to a remote OT SIEM over a one-way data path or a network connection that cannot be blocked from the HMI workstation's operating system. Alternatively, run AIDE checks from a separate monitoring host that reads the HMI filesystem over a read-only network share — the monitoring host is outside the attacker's control even if the HMI is compromised.

## Related Articles

- [OT NPE Identity PKI](/articles/cross-cutting/ot-npe-identity-pki/)
- [Log Integrity](/articles/observability/log-integrity/)
- [Linux IMA EVM](/articles/linux/linux-ima-evm/)
- [HSM Key Management](/articles/cross-cutting/hsm-key-management/)
- [OT Incident Response Forensics](/articles/observability/ot-incident-response-forensics/)
