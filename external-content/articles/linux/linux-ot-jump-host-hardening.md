---
title: "Linux OT Jump Host Hardening: Zero Trust at the IT/OT Boundary"
description: "CISA's OT Zero Trust guidance places Linux jump hosts as the primary enforcement point between IT and OT networks. Learn how to harden them with MFA, application allowlisting, LOTL defences, and session recording."
slug: linux-ot-jump-host-hardening
date: 2026-05-03
lastmod: 2026-05-03
category: linux
tags:
  - ot-security
  - jump-host
  - ics
  - zero-trust
  - application-control
personas:
  - platform-engineer
  - security-engineer
article_number: 399
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-ot-jump-host-hardening/
---

# Linux OT Jump Host Hardening: Zero Trust at the IT/OT Boundary

## The Problem

CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" documents a failure pattern found repeatedly across critical infrastructure audits: IT and OT networks are nominally segmented but share identity infrastructure, have implicit trust relationships, and funnel remote access through a single shared VPN that treats network presence as sufficient authentication. When Volt Typhoon or a comparable nation-state actor compromises an IT workstation, they pivot into OT in minutes. The jump host that should have been a choke point validates only network connectivity — it confirms the user can reach TCP port 22, then allows the session through without confirming who the user is, what they are allowed to run, or what they actually did.

CISA's remedy is explicit: the Linux jump host must enforce MFA at the session boundary, allowlist the applications permitted to run on that host, and record every terminal session in tamper-evident storage. The rationale is architectural. PLCs, RTUs, and DCS controllers — the devices that actually control physical processes — cannot run security agents. They are resource-constrained, real-time, and often run firmware that predates the concept of an agent-based EDR. The jump host is the last layer where identity can be verified and behaviour can be inspected before traffic reaches those devices.

Linux is the correct choice for this role for several concrete reasons. PAM (Pluggable Authentication Modules) provides a mature, well-audited framework for enforcing MFA on SSH logins without modifying the SSH daemon itself. `sshd_config` directives like `AllowUsers`, `AllowGroups`, `PermitRootLogin`, and `PermitTunnel` give administrators fine-grained control over who can connect and what the session is permitted to do. `fapolicyd` on RHEL and Rocky Linux, or AppArmor in strict allowlist mode on Ubuntu and Debian, can block any binary not explicitly permitted — including the interpreted languages and download utilities that attackers use in Living Off The Land attacks. And unlike Windows, the Linux jump host has no GUI, no browser, no document rendering engine, and no COM infrastructure: the attack surface is structurally smaller.

This article maps directly to CISA's five control families for OT Zero Trust as applied to the jump host layer: identity verification, device trust, least-privilege access, application control, and continuous monitoring.

**Target systems:** RHEL 9 / Rocky Linux 9 (primary examples), Ubuntu 24.04 LTS (AppArmor path noted where it differs). All examples assume OpenSSH 9.x.

## Threat Model

- **Volt Typhoon and nation-state lateral movement:** CISA's advisory documents Volt Typhoon maintaining persistent, undetected access to OT environments for up to five years. The entry path in each documented case was an IT network compromise followed by pivot across an insufficiently enforced IT/OT boundary. The jump host was either absent, unpatched, or enforced only network-layer controls.
- **Living Off The Land (LOTL) attacks:** Attackers do not bring their own tools to an OT-adjacent jump host because novel binaries trigger EDR alerts. Instead they abuse tools already present: `bash` for enumeration, `python3` for payload execution, `curl` or `wget` for staging, vendor engineering software (Schneider EcoStruxure, Siemens TIA Portal remote tools) for OT-protocol commands. LOTL on a jump host is indistinguishable from legitimate operator activity if application execution is not controlled and sessions are not recorded.
- **Compromised vendor credentials during maintenance windows:** Vendors routinely authenticate to OT jump hosts using shared accounts or long-lived SSH keys that are not rotated between engagements. A single phished vendor technician provides authenticated access that bypasses all network-layer controls.
- **Over-permissioned OT engineer accounts:** Engineers who need read access to historian data regularly have the same jump host accounts used for control system modifications. Lateral movement within the OT network is trivial once the jump host is accessed.
- **Insider threat:** Session recording is the primary control. Without keystroke-level records stored off the jump host, there is no forensic basis for distinguishing an insider action from a legitimate engineering change.
- **Physical console bypass:** If MFA is enforced on SSH but the local console login uses only a password, an attacker with physical access to the jump host bypasses Zero Trust entirely. This failure mode is called out explicitly in the Failure Modes section.

## Hardening Configuration

### 1. MFA Enforcement via PAM

CISA requires MFA at every OT-bound session boundary. For SSH, this is enforced through PAM so that even if `sshd` is replaced or misconfigured, the MFA requirement persists as a separate gate.

Install `pam_oath` for TOTP-based MFA (hardware tokens such as YubiKey in OTP mode also work through `pam_u2f`):

```bash
dnf install pam_oath oathtool
```

Create the OATH users file. Each line contains the username, the TOTP secret (hex), and the time-step:

```conf
# /etc/users.oath
HOTP/T30 alice - <hex-secret>
HOTP/T30 bob   - <hex-secret>
```

```bash
chmod 600 /etc/users.oath
chown root:root /etc/users.oath
```

Configure PAM to require both TOTP and SSH key (or password) — order matters, both must succeed:

```conf
# /etc/pam.d/sshd
auth       required     pam_oath.so usersfile=/etc/users.oath window=1
auth       required     pam_unix.so nullok
account    required     pam_nologin.so
account    include      system-account
session    include      system-session
```

Enable keyboard-interactive authentication in `sshd_config` so PAM challenges are presented to the connecting user:

```conf
# /etc/ssh/sshd_config — MFA-relevant directives
KbdInteractiveAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
UsePAM yes
```

With `AuthenticationMethods publickey,keyboard-interactive`, a user must present a valid public key and then complete the PAM TOTP challenge before the session is opened. Neither factor alone is sufficient.

For hardware FIDO2 token support instead of TOTP, install `pam_u2f` from the `pam-u2f` package and enroll tokens with `pamu2fcfg`. The PAM stack structure is identical; replace the `pam_oath.so` line with `pam_u2f.so`.

### 2. SSH Restriction

The SSH daemon is the primary ingress point. Every default-permissive setting is a potential pivot:

```conf
# /etc/ssh/sshd_config
Protocol 2
Port 22

AllowUsers alice@192.168.10.0/24 bob@192.168.10.0/24
AllowGroups ot-operators

PermitRootLogin no
PermitEmptyPasswords no
MaxSessions 2
MaxAuthTries 3

ClientAliveInterval 300
ClientAliveCountMax 2

PermitTunnel no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
GatewayPorts no

AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes

LogLevel VERBOSE
```

`AllowUsers` restricts logins to named accounts and, optionally, the source IP range. `MaxSessions 2` prevents a single compromised account from opening unlimited parallel sessions for lateral movement. `PermitTunnel no` and `AllowTcpForwarding no` are critical: without these, an attacker can establish an SSH tunnel through the jump host directly into the OT network, bypassing every firewall rule at the OT boundary.

Reload without restarting to preserve existing sessions:

```bash
sshd -t && systemctl reload sshd
```

### 3. Application Allowlisting

LOTL attacks depend on the availability of general-purpose tooling on the jump host. `fapolicyd` enforces an application execution policy: if a binary, script interpreter, or shared library is not on the allowlist, the kernel blocks its execution before the process starts.

Install and enable `fapolicyd`:

```bash
dnf install fapolicyd
systemctl enable --now fapolicyd
```

Configure the policy in `/etc/fapolicyd/rules.d/`. The default policy ships in permissive trust mode; replace it with an explicit allowlist:

```conf
# /etc/fapolicyd/rules.d/90-ot-jumphost.rules

# Allow the SSH daemon
allow perm=execute exe=/usr/sbin/sshd : all

# Allow PAM helpers
allow perm=execute exe=/usr/sbin/unix_chkpwd : all
allow perm=execute exe=/usr/bin/oathtool : all

# Allow session recording (tlog)
allow perm=execute exe=/usr/bin/tlog-rec-session : all

# Allow vendor engineering tools (explicit paths only)
allow perm=execute exe=/opt/vendor/engineeringtool : all
allow perm=execute exe=/opt/vendor/plcconnect : all

# Allow SSH client for OT host connections
allow perm=execute exe=/usr/bin/ssh : all

# Allow basic system utilities required for session establishment
allow perm=execute exe=/usr/bin/bash : all
allow perm=execute exe=/usr/bin/id : all
allow perm=execute exe=/usr/bin/env : all

# Deny everything else — this must be the last rule
deny perm=execute all : all
```

After updating rules, rebuild the trust database and reload:

```bash
fapolicyd-cli --update
systemctl restart fapolicyd
```

Test that blocked binaries fail immediately:

```bash
curl https://example.com
```

The result is `curl: (23) Failed writing body` or an `Operation not permitted` error from the kernel, depending on the libc version. The binary never executes.

For Ubuntu/Debian, the AppArmor equivalent uses a deny-by-default profile applied to the shell:

```
# /etc/apparmor.d/ot-jumphost-shell
#include <tunables/global>

/usr/bin/bash {
  #include <abstractions/base>
  /usr/bin/ssh Px,
  /opt/vendor/engineeringtool Px,
  /opt/vendor/plcconnect Px,
  /usr/bin/tlog-rec-session Px,
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /usr/bin/python3 x,
  deny /usr/bin/nc x,
}
```

Load and enforce:

```bash
apparmor_parser -r /etc/apparmor.d/ot-jumphost-shell
aa-enforce /etc/apparmor.d/ot-jumphost-shell
```

Establish a change-control process for adding new binaries to the allowlist. Every vendor tool installation requires a planned change request, a test in a staging environment, and a rule update reviewed by a second engineer before production deployment.

### 4. Session Recording

CISA's OT Zero Trust guidance requires that all privileged sessions be recorded at keystroke granularity. `tlog` is the RHEL-native solution; it integrates with PAM so recording starts before the user's shell prompt appears and cannot be disabled by the user.

```bash
dnf install tlog
```

Configure `tlog-rec-session` as the default session recorder via PAM:

```conf
# /etc/pam.d/sshd — append to the session section
session    required     pam_exec.so /usr/bin/tlog-rec-session
```

Configure `tlog` to write to the system journal and simultaneously to a file:

```conf
# /etc/tlog/tlog-rec-session.conf
{
    "writer": "journal",
    "limit-rate": 16384,
    "latency": 10,
    "payload": 2048
}
```

Session data lands in the journal under `TLOG_USER` metadata and can be replayed with:

```bash
tlog-play -r journal -M TLOG_USER=alice
```

For off-host storage, configure `rsyslog` to forward journal entries containing `tlog` records to a remote SIEM relay over TLS. The relay must be configured read-only from the jump host's perspective — the jump host can send, not modify:

```conf
# /etc/rsyslog.d/90-tlog-remote.conf
if $programname == 'tlog-rec-session' then {
    action(
        type="omfwd"
        Target="siem-relay.ot-management.internal"
        Port="6514"
        Protocol="tcp"
        StreamDriver="gtls"
        StreamDriverMode="1"
        StreamDriverAuthMode="x509/name"
        StreamDriverPermittedPeers="siem-relay.ot-management.internal"
    )
}
```

On Ubuntu without `tlog`, use `script` piped to syslog via a wrapper placed in `/etc/profile.d/`:

```bash
# /etc/profile.d/session-record.sh
if [ -n "$SSH_TTY" ] && [ "$TERM" != "dumb" ]; then
    exec script -q -f \
        >(logger -t session-record -p local6.info) \
        /dev/null
fi
```

### 5. Jump Host Network Segmentation

The jump host belongs in a dedicated DMZ, not in the IT network or the OT network. Two firewall boundaries protect it: one between the IT network and the DMZ, one between the DMZ and the OT network. The jump host can receive SSH from approved IT source IPs and can initiate connections to specific OT endpoints on specific ports. Nothing else.

```conf
# /etc/nftables.conf — OT jump host ruleset

table inet filter {

    chain input {
        type filter hook input priority 0; policy drop;

        iif lo accept

        ct state established,related accept
        ct state invalid drop

        # Accept SSH only from IT management VLAN
        ip saddr 192.168.10.0/24 tcp dport 22 ct state new accept

        # Log and drop everything else
        log prefix "JH-INPUT-DROP: " flags all limit rate 5/second
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy drop;

        iif lo accept

        ct state established,related accept

        # Allow SSH to specific OT HMI stations only
        ip daddr { 10.0.50.10, 10.0.50.11, 10.0.50.12 } tcp dport 22 ct state new accept

        # Allow Modbus/TCP to PLC gateway (read-only historian path)
        ip daddr 10.0.50.100 tcp dport 502 ct state new accept

        # Allow DNS to internal resolver only
        ip daddr 192.168.1.53 udp dport 53 ct state new accept

        # Allow NTP
        ip daddr 192.168.1.123 udp dport 123 ct state new accept

        # Allow rsyslog TLS to SIEM relay
        ip daddr 192.168.20.50 tcp dport 6514 ct state new accept

        # Log and drop everything else
        log prefix "JH-OUTPUT-DROP: " flags all limit rate 5/second
        drop
    }
}
```

Apply and persist:

```bash
nft -f /etc/nftables.conf
systemctl enable --now nftables
```

The output chain is the critical control. An attacker who compromises the jump host and attempts to reach an unapproved OT device, or to beacon to an external C2 host, is blocked at the output chain and the attempt is logged.

### 6. Audit and Accounting

`auditd` captures the syscall-level record that session recording does not: process tree relationships, file opens, and network socket creation. These records establish forensic causality — which process spawned which child, which file was opened before a network connection was made.

```conf
# /etc/audit/rules.d/90-ot-jumphost.rules

# Process execution — all users
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k ot_exec

# File opens — flag access to engineering configuration files
-a always,exit -F arch=b64 -S openat -F dir=/opt/vendor -F perm=r -k vendor_file_access
-a always,exit -F arch=b64 -S openat -F path=/etc/passwd -F perm=r -k passwd_read
-a always,exit -F arch=b64 -S openat -F path=/etc/shadow -F perm=r -k shadow_read

# Network socket creation
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket_ipv4
-a always,exit -F arch=b64 -S socket -F a0=10 -k network_socket_ipv6
-a always,exit -F arch=b64 -S connect -k network_connect

# Privilege changes
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_change

# SSH authorized_keys modifications
-w /root/.ssh -p rwa -k root_ssh_keys
-w /home -p rwa -k user_ssh_keys

# fapolicyd configuration changes (detect allowlist tampering)
-w /etc/fapolicyd -p rwa -k fapolicyd_config

# Audit configuration itself (tamper detection)
-w /etc/audit -p rwa -k audit_config
-w /etc/audit/rules.d -p rwa -k audit_rules

# Make rules immutable after loading
-e 2
```

Load rules:

```bash
augenrules --load
auditctl -s
```

`-e 2` makes rules immutable until reboot. An attacker cannot disable audit logging at runtime; a reboot to remove the rules is itself a detectable event via SIEM availability monitoring.

Ship audit logs off-host via `audisp-remote` or the same `rsyslog` TLS pipeline used for `tlog` records.

## Expected Behaviour After Hardening

After MFA is configured: an SSH connection attempt without a valid TOTP token returns `Permission denied (publickey,keyboard-interactive)` and the session is not opened. The PAM failure is logged to `/var/log/secure`.

After `fapolicyd` is in enforce mode: running `curl https://example.com` on the jump host returns an error immediately — the binary is blocked before any network connection is attempted. The block event appears in `/var/log/fapolicyd/fapolicyd.log` with the executable path and the denying rule.

After session recording is active: every keystroke typed in an SSH session is written to the journal and forwarded to the SIEM relay within the configured latency window (default 10 seconds). Replaying the session with `tlog-play` shows the exact terminal output, including timing information.

After the nftables ruleset is applied: a connection attempt from an IP outside the `192.168.10.0/24` range to port 22 is dropped at the input chain and logged with the `JH-INPUT-DROP:` prefix. An outbound connection attempt from the jump host to any IP not in the explicit output allowlist is dropped and logged with `JH-OUTPUT-DROP:`.

## Trade-offs and Operational Considerations

**TOTP/hardware token requirement breaks automated vendor scripts.** Vendor remote access tools that script SSH sessions (polling scripts, automated firmware deployment, configuration backup tools) cannot complete the TOTP challenge. The exception process: create a time-limited service account with a long-lived SSH key, no MFA requirement, restricted to a specific source IP and a specific destination in the OT network, with a hard expiry date enforced by `account` PAM directives. The account must be created and closed through a formal change ticket. Break-glass access outside this process requires a change request reviewed by two engineers.

**`fapolicyd` blocks newly installed vendor tools.** Every new vendor binary installed on the jump host is blocked until its path is added to the allowlist and the trust database is rebuilt. This is a feature, not a bug, but it requires a documented change-control process. The operational risk of deploying a vendor update without a change request is that engineers arrive for a planned maintenance window and find their tools do not work. Test allowlist changes in a staging environment before production deployment.

**Session recording adds latency to terminal output.** `tlog` buffers terminal data before writing to the journal. The default 10-second latency is imperceptible for interactive engineering work — operators are not typing at 16KB/s. The latency is configurable down to 1 second at the cost of increased journal write frequency. Document the recording overhead in the jump host operational runbook so that engineers do not attempt to disable it when they notice it.

**Break-glass emergency OT access.** At least one break-glass account must exist for emergency access to OT systems when normal authentication infrastructure is unavailable (identity provider outage, MFA infrastructure failure). The break-glass account credentials must be stored in a physical safe in the OT control room, not in a password manager. The account must be tested quarterly: confirm the credentials work, confirm the session is recorded, then immediately change the credentials and re-seal them. Document every break-glass use in the incident log.

## Failure Modes

**MFA enforced on SSH but not on the local console login.** An attacker with physical access to the jump host — or access to the out-of-band management network (IPMI, iDRAC, iLO) — can access the console with only a password. Enforce MFA on the console by applying the same `pam_oath` configuration to `/etc/pam.d/login`. Also restrict IPMI/BMC access to a separate management network with its own MFA enforcement.

**Jump host in the same VLAN as the OT network.** A jump host without firewall isolation between itself and the OT devices it connects to provides no meaningful segmentation. If the jump host is compromised, the attacker has unmediated network access to every OT device in the same VLAN. The jump host must be in a dedicated DMZ subnet with stateful firewall rules on both boundaries. "Segmented by VLAN" without firewall policy enforcement is nominal, not actual, segmentation.

**`fapolicyd` in permissive mode that was never switched to enforce.** The default `fapolicyd` installation starts in permissive mode for policy development. Teams that never transition to enforce mode have a false sense of protection — `fapolicyd` logs violations but does not block them. Check the mode with `fapolicyd-cli --list` and confirm `enforce = 1` in `/etc/fapolicyd/fapolicyd.conf`. Include a check for enforce mode in the quarterly security review.

**Session logs stored locally on the jump host.** If `tlog` is configured to write only to local files — or if rsyslog is not forwarding to the SIEM relay — an attacker who compromises the jump host can delete or truncate the session records before forensic review. All session logs must stream to a remote, write-only destination as they are generated, not as a batch export. Confirm the SIEM relay is receiving records in real time; alert on gaps of more than five minutes with no tlog records from an active jump host.

## Related Articles

- [SSH Hardening](/articles/linux/ssh-hardening/)
- [PAM Hardening](/articles/linux/pam-hardening/)
- [AppArmor](/articles/linux/apparmor/)
- [Auditd Deep Dive](/articles/linux/auditd-deep-dive/)
- [Systemd Unit Hardening](/articles/linux/systemd-unit-hardening/)
