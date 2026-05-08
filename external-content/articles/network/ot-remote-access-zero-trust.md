---
title: "OT Remote Access Zero Trust: Replacing Persistent Vendor VPNs"
description: "CISA identifies always-on vendor VPN access as a critical OT vulnerability. Replace it with time-limited ZTNA sessions through a DMZ jump host — with MFA, session recording, automatic expiry, and an out-of-band approval workflow."
slug: ot-remote-access-zero-trust
date: 2026-05-03
lastmod: 2026-05-03
category: network
tags:
  - ot-security
  - remote-access
  - zero-trust
  - vendor-access
  - ics
personas:
  - platform-engineer
  - security-engineer
article_number: 409
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/network/ot-remote-access-zero-trust/
---

# OT Remote Access Zero Trust: Replacing Persistent Vendor VPNs

## The Problem

Volt Typhoon's documented attack path into critical infrastructure repeatedly exploits the same entry point: a vendor VPN account created during equipment commissioning, granted broad OT network access, and never revoked. The vendor finishes the job, the credential stays active, and years later an attacker who obtained it through phishing or a third-party breach walks straight into the OT network with no further authentication challenge.

CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" names persistent vendor VPN access as one of the highest-priority remote access risks in OT environments. The documented failure pattern is consistent across critical infrastructure sectors: the VPN account lands the vendor directly in the OT network, typically with an IP address in the same range as engineering workstations. There is no MFA requirement. Sessions are not recorded. The credential does not expire between maintenance windows. Access is not scoped to the equipment the vendor actually supports — a vendor brought in to service a single PLC can reach the entire OT subnet.

The Zero Trust replacement model is explicit in CISA's guidance: no remote access should terminate directly in the OT network. All remote access terminates in the IT/OT DMZ. From the DMZ, a session-proxied connection to specific OT assets is granted only after identity verification, out-of-band approval, and for a time-limited window. Every session is recorded. Every session expires automatically.

A common objection to this model is that adding MFA to the existing VPN solves the problem. It does not. MFA on a persistent VPN authenticates the initial session, but it does not limit what the vendor can reach once connected. It does not record what the vendor does during the session. It does not expire the credential between maintenance windows — a vendor who connects every three months has active credentials for the 89 days between visits. And if the VPN account exists in an Active Directory domain that has even nominal IT/OT trust relationships, a compromised IT credential may already have lateral movement paths into the same network segment the vendor reaches. MFA on a bad architecture reduces one risk while leaving the others intact.

The architecture described in this article addresses each failure mode individually: network termination point (DMZ only), credential lifetime (time-limited certificates, automatic expiry), access scope (per-vendor firewall rules), identity verification (MFA at jump host), session visibility (full recording to write-once storage), and approval workflow (out-of-band human gate before credentials are issued).

## Threat Model

**Stolen vendor VPN credentials via phishing or third-party breach.** The vendor's employee receives a credential-harvesting phish. The attacker obtains valid VPN credentials that connect directly into the OT network. Because the credential is persistent, the attacker can connect at any time. Because there is no scope restriction, they can reach any OT asset on the vendor's VPN subnet.

**Vendor employee with active credentials who has left the company.** The vendor finishes a site engagement. The employee who held the VPN credentials leaves the vendor's company three months later. The vendor's IT team does not notify the asset owner. The credential remains active, discoverable in a password manager, and usable by anyone who obtains access to the departed employee's accounts.

**Overprivileged vendor account reaching equipment the vendor does not support.** A building automation vendor is given VPN access to service an HVAC controller. The VPN subnet routes to the full OT flat network, including PLCs, historian servers, and the DCS. The vendor's access scope is defined by nothing more than a verbal understanding that they will only touch what they are there to service.

**Insider threat: vendor technician accessing OT outside a maintenance window.** A vendor technician with persistent VPN access logs in at 02:00 on a Sunday. No maintenance window is scheduled. Without session recording and automatic expiry, this access is indistinguishable from a routine visit. Detection depends entirely on someone reviewing VPN connection logs — which are often not reviewed unless an incident has already been detected.

**No session recording makes post-incident attribution impossible.** After an anomaly is detected in an OT process, the incident response team discovers a vendor was connected during the relevant window for what the vendor describes as "routine diagnostics." There is no session recording. There is no way to determine whether the vendor's session was legitimate, whether credentials were shared with a third party during that session, or whether any configuration changes were made.

## Hardening Configuration

### 1. Vendor Access Architecture

The three-tier model separates the vendor's network path from the OT network by two controlled chokepoints.

**Tier 1 — VPN gateway in the DMZ.** The vendor's VPN client connects to a VPN concentrator or ZTNA gateway whose tunnel terminates in the IT/OT DMZ, not the corporate IT network and not the OT network. The DMZ has no default routing to either. The vendor's traffic arrives and stops at the DMZ boundary.

**Tier 2 — Authenticated jump host in the DMZ.** From the DMZ network, the vendor SSHes to a dedicated jump host. This is the identity enforcement point: the jump host requires MFA, maps the authenticated identity to a specific access scope, and records the session. The vendor does not get a shell with network access to OT directly — they get a proxied session to a specific asset.

**Tier 3 — Per-vendor firewall rules from jump host to OT.** The jump host has outbound firewall rules that allow it to reach specific OT asset IPs on specific ports, and only those. Each vendor's access is encoded as a named nftables chain. A vendor supporting a single PLC gateway can reach that PLC gateway's management port and nothing else. The jump host itself cannot initiate connections to OT assets outside the approved ruleset.

In prose: the vendor's laptop → internet → vendor VPN gateway (DMZ) → jump host (DMZ, MFA required, session recorded) → specific OT asset (OT network, TCP port restricted). At no point does the vendor's machine have an IP route into the OT network. The connection is session-proxied by the jump host acting as a bastion.

This architecture also separates two concerns that a single VPN conflates: network access and identity-verified session access. The vendor's VPN terminates their network path in the DMZ. The jump host resolves their identity and scopes their OT access. These are independent controls, each of which can fail or be strengthened without affecting the other.

### 2. Time-Limited Credential Issuance

HashiCorp Vault's SSH Secrets Engine issues time-limited SSH certificates that are valid for a fixed TTL and cannot be renewed without going back through the approval workflow. When the TTL expires, the certificate becomes cryptographically invalid regardless of whether the vendor's session has ended.

Initialize the SSH Secrets Engine and configure a signing key:

```bash
vault secrets enable ssh

vault write ssh/config/ca \
    generate_signing_key=true

vault read -field=public_key ssh/config/ca \
    > /etc/ssh/trusted-vendor-ca.pub
```

On the jump host, configure `sshd` to trust certificates signed by the Vault CA:

```conf
# /etc/ssh/sshd_config — vendor certificate trust
TrustedUserCAKeys /etc/ssh/trusted-vendor-ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

Create a Vault role for vendor access. The TTL is set to 4 hours — sufficient for a planned maintenance window, short enough to expire before a long-term intrusion becomes established:

```hcl
vault write ssh/roles/ot-vendor \
    key_type=ca \
    ttl=4h \
    max_ttl=4h \
    allowed_users="*" \
    allowed_extensions="permit-pty" \
    default_extensions='{"permit-pty":""}' \
    allow_user_certificates=true
```

When a vendor access request is approved (see the approval workflow below), the automation layer calls Vault to issue a certificate for the vendor's public key:

```bash
vault write ssh/sign/ot-vendor \
    public_key=@/tmp/vendor_id_ed25519.pub \
    valid_principals="vendor-acme-plc" \
    ttl=4h
```

The issued certificate is delivered to the vendor. The jump host `authorized_principals` file for the `vendor-acme-plc` account contains a single line mapping the principal to the allowed user:

```conf
# /etc/ssh/auth_principals/vendor-acme-plc
vendor-acme-plc
```

Vault's lease management automatically tracks the certificate's TTL. The `max_ttl` setting prevents any renewal — a new approval request and a new certificate are required for every maintenance window.

### 3. Out-of-Band Approval Workflow

No credentials are issued without an explicit approval from an internal OT engineer. The workflow is intentionally out-of-band from the vendor's own systems — the approval gate is inside the asset owner's control, not delegated to the vendor.

**Standard workflow:**

1. Vendor submits a maintenance request through the asset owner's service management system (ServiceNow, Jira Service Management, or equivalent). The request includes: vendor name, technician name, equipment to be accessed, maintenance window start and end time, and reason for access.
2. The request is routed to the on-call OT engineer responsible for the relevant equipment. The engineer validates the request against the maintenance schedule, confirms no production process will be affected, and approves or rejects the ticket.
3. On approval, an automation script (triggered by ticket status change to "Approved") calls the Vault API to issue a time-limited certificate for the vendor's pre-registered public key. The certificate TTL is set to the duration of the maintenance window, with a hard maximum of 4 hours.
4. The certificate is delivered to the vendor's designated technical contact via a secure channel (encrypted email, or the service portal's secure file transfer). The Vault lease ID is recorded in the ticket.
5. The vendor connects during the window. The session is recorded automatically (see section 4).
6. At TTL expiry, the certificate becomes invalid. If the vendor requires additional time, they submit a new request from the beginning. No self-service extension is possible.

**Emergency break-glass procedure:**

When OT access is needed immediately due to a process emergency and the normal approval workflow cannot be completed within the required time:

```bash
vault write ssh/sign/ot-vendor-emergency \
    public_key=@/tmp/vendor_id_ed25519.pub \
    valid_principals="vendor-acme-plc" \
    ttl=1h
```

The emergency role has a 1-hour TTL. Its use requires a phone call to the OT security lead for verbal authorization, and the ticket is filed retrospectively within 2 hours. All emergency certificate issuances are logged to a dedicated Vault audit path and trigger a SIEM alert for review:

```hcl
vault audit enable file \
    file_path=/var/log/vault/audit.log \
    log_raw=false
```

The SIEM alert rule fires on any `ssh/sign/ot-vendor-emergency` write operation and pages the OT security lead regardless of time.

### 4. Session Recording on the Jump Host

Session recording is configured via `tlog`, which integrates with PAM and begins recording before the user's shell prompt appears. The vendor cannot disable or bypass recording — it is enforced at the PAM layer, not at the shell.

Install `tlog` and configure PAM to invoke the recorder for all vendor accounts:

```bash
dnf install tlog
```

```conf
# /etc/pam.d/sshd — session section additions for vendor accounts
session    optional     pam_exec.so /usr/bin/tlog-rec-session
```

For vendor accounts specifically (matched by group membership in `ot-vendors`), enforce recording unconditionally via a systemd override on the SSH service that wraps the session in the recorder:

```conf
# /etc/systemd/system/sshd.service.d/vendor-recording.conf
[Service]
ExecStartPre=/usr/bin/bash -c \
  'usermod -s /usr/bin/tlog-rec-session $(getent group ot-vendors | cut -d: -f4 | tr , " ") 2>/dev/null || true'
```

Configure `tlog` to write to both the local journal and a remote syslog endpoint simultaneously:

```conf
# /etc/tlog/tlog-rec-session.conf
{
    "writer": "journal",
    "limit-rate": 16384,
    "latency": 5,
    "payload": 2048
}
```

Forward `tlog` records to write-once object storage. For S3 with Object Lock:

```bash
aws s3api create-bucket \
    --bucket ot-session-recordings \
    --region us-east-1

aws s3api put-object-lock-configuration \
    --bucket ot-session-recordings \
    --object-lock-configuration \
      '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":90}}}'
```

Configure `rsyslog` to forward `tlog` journal entries to an S3-backed relay over TLS. The relay is write-only from the jump host's perspective:

```conf
# /etc/rsyslog.d/90-tlog-remote.conf
if $programname == 'tlog-rec-session' then {
    action(
        type="omfwd"
        Target="siem-relay.ot-mgmt.internal"
        Port="6514"
        Protocol="tcp"
        StreamDriver="gtls"
        StreamDriverMode="1"
        StreamDriverAuthMode="x509/name"
        StreamDriverPermittedPeers="siem-relay.ot-mgmt.internal"
    )
}
```

Session recordings stored on the jump host's local disk are insufficient — a compromised jump host can delete local files before detection. The recording must leave the jump host in real time, over a write-only channel, before any attacker with jump host access can reach it.

### 5. Firewall Rules Scoped per Vendor

Each vendor is assigned a named nftables chain on the jump host. The chain allows outbound connections only to the specific OT asset IPs and ports that vendor is authorized to access. Connections to any IP outside the vendor's approved scope are logged and dropped.

The jump host `sshd_config` uses `Match` blocks to assign vendors to named Unix groups. The firewall rules use those group names as the rule selector via uid-based matching in nftables:

```conf
# /etc/nftables.conf — vendor-scoped output chains

table inet vendor_access {

    chain output {
        type filter hook output priority 0; policy drop;

        ct state established,related accept
        iif lo accept

        ct state invalid drop

        meta skuid vendor-acme-plc jump vendor_acme_plc
        meta skuid vendor-siemens-hmi jump vendor_siemens_hmi

        log prefix "vendor-output-unmatched: " flags all limit rate 10/second
        drop
    }

    chain vendor_acme_plc {
        ip daddr 10.0.50.21 tcp dport 502 ct state new \
            log prefix "vendor-acme-plc-allow: " accept
        ip daddr 10.0.50.22 tcp dport 502 ct state new \
            log prefix "vendor-acme-plc-allow: " accept
        log prefix "vendor-acme-plc-drop: " flags all limit rate 10/second
        drop
    }

    chain vendor_siemens_hmi {
        ip daddr 10.0.50.30 tcp dport 102 ct state new \
            log prefix "vendor-siemens-hmi-allow: " accept
        ip daddr 10.0.50.30 tcp dport 4840 ct state new \
            log prefix "vendor-siemens-hmi-allow: " accept
        log prefix "vendor-siemens-hmi-drop: " flags all limit rate 10/second
        drop
    }

    chain vendor_dns_allow {
        ip daddr 192.168.1.53 udp dport 53 ct state new accept
        ip daddr 192.168.1.53 tcp dport 53 ct state new accept
    }
}
```

Apply and persist:

```bash
nft -f /etc/nftables.conf
systemctl enable --now nftables
```

When a new vendor is onboarded or an existing vendor's equipment scope changes, the change requires a formal change request. The nftables ruleset update is version-controlled in git, reviewed by the OT security engineer, and applied through a change management pipeline — not edited directly on the jump host.

### 6. Vendor Access Audit

The monthly audit compares active Vault leases against the vendor register to identify dormant credentials, inactive accounts, and scope drift.

```bash
#!/usr/bin/env bash
VAULT_ADDR="https://vault.ot-mgmt.internal:8200"
VENDOR_REGISTER="/etc/ot-access/vendor-register.csv"
DORMANT_THRESHOLD_DAYS=90

vault_leases=$(vault list -format=json sys/leases/lookup/ssh/creds/ot-vendor 2>/dev/null \
    | jq -r '.[]')

while IFS=',' read -r vendor_id vendor_name contact equipment_scope; do
    last_access=$(vault read -format=json \
        "sys/internal/counters/activity/monthly" 2>/dev/null \
        | jq -r --arg vid "$vendor_id" \
          '.data.by_namespace[] | select(.namespace_id == $vid) | .last_activity_date // "never"')

    if [[ "$last_access" == "never" ]]; then
        echo "DORMANT: $vendor_name ($vendor_id) — no access recorded"
        continue
    fi

    last_ts=$(date -d "$last_access" +%s 2>/dev/null || echo 0)
    now_ts=$(date +%s)
    days_inactive=$(( (now_ts - last_ts) / 86400 ))

    if (( days_inactive > DORMANT_THRESHOLD_DAYS )); then
        echo "DORMANT: $vendor_name ($vendor_id) — last access ${days_inactive} days ago"
    fi
done < <(grep -v '^#' "$VENDOR_REGISTER")

echo "Active leases:"
for lease in $vault_leases; do
    vault read -format=json "sys/leases/lookup/$lease" \
        | jq -r '"  Lease: \(.data.id)  Expires: \(.data.expire_time)  TTL: \(.data.ttl)"'
done
```

The vendor register is a CSV file maintained by the OT security team:

```conf
# /etc/ot-access/vendor-register.csv
# vendor_id,vendor_name,technical_contact,equipment_scope
vendor-acme-plc,Acme Automation,j.smith@acme.example,PLC-BOILER-01,PLC-BOILER-02
vendor-siemens-hmi,Siemens Field Services,ops@siemens.example,HMI-CTRL-01
vendor-johnson-hvac,Johnson Controls,remote@jci.example,HVAC-BAS-01
```

Any account with no access in 90 days is flagged for immediate revocation. The script is scheduled monthly; flagged accounts are reviewed within 5 business days and either reconfirmed with updated justification or revoked. Revocation deletes the Vault policy binding, removes the `authorized_principals` file entry, and disables the Unix account on the jump host.

## Expected Behaviour After Hardening

**After time-limited certificate issuance:** The vendor receives a certificate with a 4-hour TTL at 09:00. At 14:01, they attempt to reconnect. The SSH handshake completes key exchange, then the server rejects the certificate: `Permission denied (publickey). Certificate has expired.` The expired certificate cannot be renewed by the vendor — a new approval request is required. The rejection is logged to the jump host's auth log and forwarded to the SIEM.

**After per-vendor firewall scoping:** The vendor for the boiler PLC finishes their authorized work and, out of curiosity, attempts to SSH to an HMI workstation at `10.0.50.30`. The connection attempt exits the jump host and hits the `vendor_acme_plc` chain. The destination IP is not `10.0.50.21` or `10.0.50.22`. The chain's default rule matches: the attempt is logged with prefix `vendor-acme-plc-drop:` and dropped. The SIEM receives the log line within seconds. The vendor gets a connection timeout — no banner, no error message indicating the host exists.

**After the approval workflow:** A vendor submits an out-of-hours access request at 23:30 without a corresponding ticket in the service management system. The automation layer checks for an approved ticket in "In Progress" state before calling the Vault sign endpoint. No matching ticket exists. No certificate is issued. The vendor's public key is never signed. Any SSH attempt to the jump host with an unsigned key returns `Permission denied (publickey)` without reaching the OT network.

## Trade-offs and Operational Considerations

**Approval workflow adds lead time.** The minimum latency from vendor request to credential issuance is however long it takes an OT engineer to review and approve the ticket. Establish a 4-hour SLA for standard access requests during business hours. For emergency access, define a fast-track path: phone call to on-call OT engineer, verbal approval logged in the ticket, automated certificate issuance with a 1-hour TTL. Document the fast-track procedure in the vendor access runbook so it is not invented under pressure during an actual emergency.

**Vault SSH certificate infrastructure requires PKI setup and ongoing maintenance.** Vault's SSH Secrets Engine requires a dedicated Vault cluster, TLS certificates for the Vault API, backup and recovery procedures, and trained operators who understand the lease and policy model. If Vault complexity is prohibitive for a small OT team, a PAM appliance (CyberArk, BeyondTrust, Delinea) provides comparable time-limited access controls with a more managed operational model. The architectural principle — time-limited, recorded, scoped access — applies regardless of the specific tooling.

**Session recording storage costs scale with access frequency.** A busy vendor support team connecting for 4-hour windows three times a week generates substantial session recording data. Implement a 90-day retention policy on the S3 bucket with lifecycle rules that automatically delete recordings after the retention period. Recording storage should be sized at a minimum 3× the expected volume to absorb peaks. Do not reduce the retention period below 90 days: OT process anomalies are often not detected immediately, and 90 days provides sufficient lookback for most incident investigations.

**Proprietary vendor remote access tools may not support SSH certificate authentication.** Some OT vendors use proprietary remote access clients — HMI vendor portals, PLC programming software with built-in remote access, or legacy serial-over-IP tools — that cannot be configured to use SSH certificates. Document each exception explicitly. Compensating controls for non-SSH vendor tools: manual TOTP token enforced at the VPN gateway for that vendor's account, stricter firewall scope limited to a single asset IP and port, and mandatory session recording via a screen capture tool on a dedicated vendor workstation in the DMZ rather than on the vendor's own laptop. Each exception must be reviewed annually and eliminated in the next vendor contract renewal where possible.

## Failure Modes

**VPN gateway terminates in the corporate IT network instead of the DMZ.** The vendor connects to a VPN concentrator that assigns them an address in the corporate IT VLAN. From there, implicit IT→OT routing or an existing IT/OT trust relationship gives them direct access to OT assets without touching the jump host. The entire ZTNA architecture is bypassed at the first step. Verify termination points: run `traceroute` from a vendor test account to an OT asset IP and confirm the path traverses the jump host. Any path that reaches OT without appearing in the jump host's authentication logs indicates a bypass.

**Jump host firewall rules use vendor username as the selector, but the vendor logs in with a shared account.** The nftables `meta skuid` matcher works when each vendor has a dedicated Unix account on the jump host. If multiple vendors share a single `ot-vendor` account — a common shortcut — the per-vendor chain mapping fails. All vendors in the shared account get the union of all vendor scopes, or the rules do not match at all. Each vendor must have a dedicated Unix account. Enforce this at onboarding: the automation that issues credentials creates the account if it does not exist.

**Session recordings stored on the jump host's local disk.** If `rsyslog` forwarding fails silently and recordings accumulate only in local files, a vendor (or attacker) with jump host access can truncate or delete them. Monitor the SIEM for gaps in `tlog-rec-session` log volume. Alert on any window longer than 5 minutes with no `tlog` records from a jump host that has active SSH sessions. Test the forwarding path monthly by issuing a test session and confirming the recording appears in object storage.

**Vault TTL set to 30 days "to reduce vendor friction."** A 30-day TTL provides no practical difference from a persistent credential — a stolen certificate is valid for up to 30 days with no mechanism to revoke it short of rotating the CA key and re-issuing all vendor certificates. The TTL must match the maintenance window duration plus a small buffer. 4 hours for standard access; 1 hour for emergency access. If vendors consistently exceed maintenance windows and request TTL increases, the correct response is to improve the approval workflow speed, not increase the TTL.

## Related Articles

- [Linux OT Jump Host Hardening](/articles/linux/linux-ot-jump-host-hardening/)
- [OT Network Segmentation Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)
- [SSH Bastion Hardening](/articles/network/ssh-bastion-hardening/)
- [Production Access Management](/articles/cross-cutting/production-access-management/)
- [JIT CI Access](/articles/cicd/jit-ci-access/)
