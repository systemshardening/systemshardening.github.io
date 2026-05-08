---
title: "Linux Hardening for PCI DSS Cardholder Data Environments"
description: "Cardholder data environments require Linux hardening that maps directly to PCI DSS Requirements 2, 6, 8, and 10. Generic OS hardening isn't enough — this guide maps specific sysctl settings, filesystem controls, service minimisation, and audit configuration to the PCI DSS v4.0 requirements that assessors actually check."
slug: linux-pci-dss-cde-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - pci-dss
  - cde-hardening
  - compliance
  - linux-hardening
  - audit-logging
personas:
  - security-engineer
  - compliance-engineer
article_number: 625
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/linux/linux-pci-dss-cde-hardening/
---

# Linux Hardening for PCI DSS Cardholder Data Environments

## Problem

A general-purpose hardened Linux server and a PCI DSS cardholder data environment (CDE) server share many of the same controls — but the CDE variant carries a compliance burden the general server does not. When a Qualified Security Assessor (QSA) arrives, they are not performing an abstract security review. They are working through a specific checklist tied to numbered requirements in the PCI DSS standard, and they need to see documentary evidence that each control exists, is configured correctly, and has been in place continuously, not just switched on the week before the assessment.

The distinction matters because it changes how you implement controls. Disabling unnecessary services is good practice on any server; on a CDE server it must be documented in a system configuration standard, verified against a baseline image, and demonstrated via a running-services check that the QSA can reproduce. The implementation is the same. The evidence chain is not.

**PCI DSS v4.0 requirements that directly govern Linux OS configuration:**

- **Requirement 2.2** — System components are configured and managed securely. Sub-requirements cover changing vendor defaults, removing unnecessary functionality, and documenting approved services, protocols, and daemons.
- **Requirement 6.3** — Security vulnerabilities are identified and addressed. This requires a patching process with defined timelines: critical vulnerabilities within one month, and a risk-based approach for lower severities.
- **Requirement 8.6** — System and application accounts are managed and controlled. Every account on a CDE system must have a defined owner, follow password complexity requirements, and be reviewed periodically.
- **Requirements 10.2 and 10.3** — Audit logs capture specific event types and are protected from modification and unauthorized access.

**Common CDE Linux failures in QSA assessments:**

- `/etc/passwd` is world-readable with accounts whose shells indicate interactive access but have no documented owner (nobody, games, lp, uucp, news). The QSA sees these and asks who owns them.
- `netstat -tlnp` or `ss -tlnp` shows services listening that have no documented business justification: postfix on port 25, CUPS on port 631, avahi-daemon on mDNS.
- `auditd` is either not installed or installed but running with no rules — the service is up, but the audit log contains no CDE-relevant events.
- Service accounts (postgres, www-data, tomcat) have `/bin/bash` as their shell, meaning if an attacker or insider escalates to that user they get a fully functional interactive session.
- SSH allows root login or has no `AllowUsers` restriction, meaning any account with a valid credential can attempt access.

## Threat Model

**External attacker via compromised payment application.** An attacker who exploits a web application vulnerability in a payment processor running in the CDE has code execution as the application user (e.g., `tomcat` or `www-data`). Their next steps are to read PAN data from the database, escalate privileges, and pivot to other CDE hosts. Linux controls that limit what an application user can read, restrict the commands they can run, and log every attempt directly address this path.

**Insider threat — operations staff accessing PANs outside their job function.** An operator with SSH access to a CDE server can, on an under-hardened system, read payment files, copy data to removable media or a network share, and cover their tracks by clearing shell history. Auditd, immutable log forwarding, and filesystem permissions with mandatory access controls remove the ability to cover tracks and make the access visible in the SIEM within seconds.

**Malware pivoting from a DMZ host.** Malware on a DMZ host that has network connectivity to the CDE will attempt to reach internal services, perform reconnaissance via ICMP and port scans, and exploit trust relationships (SSH keys, service accounts shared across zones). Network stack sysctl hardening, SSH key hygiene, and service minimisation reduce the attack surface. Auditd rules that fire on new outbound connection attempts from CDE hosts make the pivot visible before data exfiltration begins.

## Configuration

### Req 2.2 — Vendor Defaults and Secure Configuration

#### Remove Default Accounts

Default Linux accounts that have no business purpose on a CDE server should be removed or locked. The presence of accounts like `games`, `lp`, `news`, and `uucp` in `/etc/passwd` is a finding in assessments because they represent unreviewed access paths.

```bash
# List accounts with interactive shells that are not needed
awk -F: '$7 !~ /nologin|false|sync|halt|shutdown/ {print $1}' /etc/passwd

# Remove unnecessary default accounts (adjust to your distribution)
for USER in games lp news uucp proxy list irc gnats; do
    if id "$USER" &>/dev/null; then
        userdel "$USER"
    fi
done

# Lock accounts that cannot be deleted (some are required by system packages)
# but have no business purpose in the CDE
usermod -L -s /usr/sbin/nologin sync
usermod -L -s /usr/sbin/nologin halt
```

After cleanup, document the remaining accounts in your system configuration standard. The QSA will compare the running system against that document.

#### Disable Unnecessary Services

On a CDE application server, the approved services list is narrow. Everything else should be masked (not just disabled — masked prevents accidental re-enablement):

```bash
# Services with no place in a CDE
for SVC in cups avahi-daemon bluetooth postfix rpcbind nfs-server \
           rpc-statd autofs nis; do
    systemctl stop "$SVC" 2>/dev/null
    systemctl disable "$SVC" 2>/dev/null
    systemctl mask "$SVC" 2>/dev/null
done

# Verify nothing unexpected is listening
ss -tlnp
```

The output of `ss -tlnp` becomes evidence in your assessment. Document the expected listening ports in your configuration standard and be prepared to justify each one.

#### sysctl Hardening for CDE

The following `/etc/sysctl.d/99-pci-cde.conf` addresses the network-layer threats most relevant to CDE environments — particularly the DMZ pivot scenario — as well as kernel information leaks that aid privilege escalation:

```ini
# /etc/sysctl.d/99-pci-cde.conf
# PCI DSS CDE sysctl configuration
# Apply with: sysctl --system

# --- Network: prevent packet routing manipulation ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source routing — an attacker cannot specify a packet path to bypass firewalls
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# Do not send ICMP redirects (this host is not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore ICMP broadcasts (Smurf attack mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable IP forwarding (CDE hosts should not route traffic)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# --- Kernel: reduce information leakage ---
# ASLR — full randomisation
kernel.randomize_va_space = 2

# Restrict dmesg to root only
kernel.dmesg_restrict = 1

# Hide kernel pointers from unprivileged users
kernel.kptr_restrict = 2

# Restrict perf events to root (side-channel attack mitigation)
kernel.perf_event_paranoid = 3

# Restrict ptrace to parent processes only
kernel.yama.ptrace_scope = 1

# Restrict unprivileged user namespaces (reduces container escape surface)
kernel.unprivileged_userns_clone = 0

# --- Filesystem ---
# Prevent symlink following exploits in world-writable directories
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# Restrict core dumps
fs.suid_dumpable = 0
kernel.core_pattern = /dev/null
```

Apply and verify:

```bash
sysctl --system
sysctl -a | grep -E 'randomize_va_space|dmesg_restrict|kptr_restrict|ip_forward'
```

#### SSH Configuration for CDE

```bash
# /etc/ssh/sshd_config — CDE hardened configuration
Protocol 2
Port 22

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Restrict to named users only — anyone not on this list cannot SSH in
AllowUsers operator1 operator2 svc-deploy

# Ciphers, MACs, and KEX — exclude CBC ciphers and MD5/SHA-1 MACs
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Session hardening
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 4

# Disable dangerous features
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
Banner /etc/issue.net

# Log authentication at VERBOSE level for auditd correlation
LogLevel VERBOSE
```

```bash
# Test configuration before reloading
sshd -t && systemctl reload sshd
```

---

### Req 6.3 — Vulnerability Management

Unpatched critical vulnerabilities in CDE hosts are a direct finding. PCI DSS v4.0 Requirement 6.3.3 requires all system components to be protected from known vulnerabilities by installing applicable security patches, with critical patches applied within one month.

**On Debian/Ubuntu — unattended security updates:**

```bash
apt install unattended-upgrades apt-listchanges -y

# /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Mail "security-team@example.com";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";  # Coordinate CDE reboots
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
```

**On RHEL/Rocky — dnf-automatic for security patches:**

```bash
dnf install dnf-automatic -y

# /etc/dnf/automatic.conf
[commands]
upgrade_type = security
apply_updates = yes

# Enable the timer
systemctl enable --now dnf-automatic.timer
```

**Assessor verification commands:**

```bash
# Debian/Ubuntu — show installed kernel versions and dates
dpkg -l | grep linux-image

# RHEL/Rocky — show installed kernels
rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE} %{INSTALLTIME:date}\n' | grep kernel | sort

# Check for available security updates (run before assessment)
apt list --upgradable 2>/dev/null | grep -i security   # Debian/Ubuntu
dnf check-update --security                             # RHEL/Rocky
```

---

### Req 8.6 — System and Application Accounts

Every account on a CDE system must have a documented owner and a defined purpose. Service accounts must not have interactive shell access.

#### Disable Interactive Login for Service Accounts

```bash
# List service accounts that still have interactive shells
awk -F: '$3 >= 100 && $3 < 65534 && $7 !~ /nologin|false/ {print $1, $7}' /etc/passwd

# Lock interactive login for service accounts
for USER in postgres www-data tomcat nginx redis elasticsearch; do
    if id "$USER" &>/dev/null; then
        usermod -s /usr/sbin/nologin -L "$USER"
    fi
done
```

#### PAM Password Quality (pam_pwquality)

For human accounts (operators, administrators), enforce complexity via `pam_pwquality`:

```bash
# /etc/security/pwquality.conf
minlen = 12
minclass = 4
maxrepeat = 3
maxclassrepeat = 4
lcredit = -1
ucredit = -1
dcredit = -1
ocredit = -1
difok = 6
gecoscheck = 1
dictcheck = 1
```

```bash
# /etc/pam.d/common-password (Debian/Ubuntu)
password requisite pam_pwquality.so retry=3
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass sha512 shadow remember=12
```

#### Account Aging with chage

PCI DSS Requirement 8.3.9 requires passwords for interactive users to be changed at least every 90 days where passwords are used as authentication factors:

```bash
# Set aging for all human accounts
for USER in operator1 operator2 admin-user; do
    chage -M 90 -m 1 -W 14 -I 30 "$USER"
done

# Verify aging settings
chage -l operator1

# Lock accounts inactive for 30 days
useradd -D -f 30
```

#### No Shared Accounts

The QSA will ask how you know which individual performed a privileged action on a CDE host. Shared accounts make this impossible to answer. Document each account, its owner, and its purpose. Use `sudo` with individual accounts and `NOPASSWD` only where operationally unavoidable — and log every sudo invocation (covered in the audit section below).

---

### Req 10.2 / 10.3 — Audit Logging

This is where most CDE failures occur. Requirement 10.2.1 specifies the exact event types that must be logged. Requirement 10.3 requires that audit logs are protected from modification, that access to logs is logged, and that logs are sent to a centralized log server that CDE staff cannot modify.

#### Complete auditd Rules for PCI DSS CDE

```bash
# /etc/audit/rules.d/pci-dss-cde.rules
# PCI DSS v4.0 CDE audit rules
# Load with: augenrules --load && service auditd restart

# === Performance: exclude high-volume low-value events first ===
-a always,exclude -F msgtype=CWD
-a always,exclude -F msgtype=EOE

# === Req 10.2.1.1 — All individual user access to cardholder data ===
# Adjust paths to match your actual PAN storage locations
-w /var/lib/postgresql/cde_payments/ -p rwa -k pci_pan_access
-w /opt/payment-app/data/ -p rwa -k pci_pan_access
-w /etc/ssl/private/ -p rwa -k pci_key_access

# === Req 10.2.1.2 — All actions by root or any privileged user ===
-a always,exit -F euid=0 -F arch=b64 -S execve -k pci_root_exec
-a always,exit -F euid=0 -F arch=b32 -S execve -k pci_root_exec

# === Req 10.2.1.3 — Access to audit trails themselves ===
-w /var/log/audit/ -p rwa -k pci_audit_log_access
-w /etc/audit/ -p rwa -k pci_audit_config
-w /etc/rsyslog.conf -p rwa -k pci_syslog_config
-w /etc/rsyslog.d/ -p rwa -k pci_syslog_config

# === Req 10.2.1.4 — Invalid logical access attempts ===
# Failed logins captured by PAM/sshd and written to auth.log/secure
# auditd supplements with syscall-level failed auth
-a always,exit -F arch=b64 -S open -F exit=-EACCES -k pci_access_denied
-a always,exit -F arch=b64 -S open -F exit=-EPERM -k pci_access_denied

# === Req 10.2.1.5 — Use of and changes to identification/authentication mechanisms ===
-w /etc/passwd -p rwa -k pci_passwd_change
-w /etc/shadow -p rwa -k pci_shadow_change
-w /etc/group -p rwa -k pci_group_change
-w /etc/gshadow -p rwa -k pci_gshadow_change
-w /etc/sudoers -p rwa -k pci_sudoers_change
-w /etc/sudoers.d/ -p rwa -k pci_sudoers_change
-w /etc/pam.d/ -p rwa -k pci_pam_change

# Privileged commands that must be individually logged
-a always,exit -F path=/usr/bin/sudo -F perm=x -k pci_sudo_exec
-a always,exit -F path=/usr/bin/su -F perm=x -k pci_su_exec
-a always,exit -F path=/usr/bin/passwd -F perm=x -k pci_passwd_exec
-a always,exit -F path=/usr/sbin/useradd -F perm=x -k pci_user_mgmt
-a always,exit -F path=/usr/sbin/usermod -F perm=x -k pci_user_mgmt
-a always,exit -F path=/usr/sbin/userdel -F perm=x -k pci_user_mgmt
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -k pci_user_mgmt
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -k pci_user_mgmt
-a always,exit -F path=/usr/sbin/groupdel -F pci_user_mgmt

# === Req 10.2.1.6 — Initialisation, stopping, or pausing of audit logs ===
# These events are captured automatically by auditd itself (SERVICE_STOP, SERVICE_START)
# Ensure the auditd service is monitored externally

# === Req 10.2.1.7 — Creation and deletion of system-level objects ===
-a always,exit -F arch=b64 -S mknod -S mknodat -k pci_mknod
-a always,exit -F arch=b64 -S delete_module -S init_module -k pci_kernel_module
-w /sbin/insmod -p x -k pci_kernel_module
-w /sbin/rmmod -p x -k pci_kernel_module
-w /sbin/modprobe -p x -k pci_kernel_module

# === Network activity from CDE hosts (pivot detection) ===
-a always,exit -F arch=b64 -S connect -k pci_outbound_connect
-a always,exit -F arch=b64 -S bind -k pci_port_bind

# === Time change detection (Req 10.6 — time synchronisation) ===
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k pci_time_change
-w /etc/localtime -p wa -k pci_time_change

# === IMMUTABLE MODE — rules cannot be changed without a reboot ===
# Put this LAST. Once set, auditctl -l shows "enabled 2" and no rule changes are accepted.
-e 2
```

Load the rules:

```bash
augenrules --load
auditctl -l     # Verify rules are loaded
auditctl -s     # Should show enabled=2 (immutable)
```

#### Log Protection and Forwarding (Req 10.3)

Immutable auditd mode (the `-e 2` at the end of the rules file) prevents rule changes or auditd from being stopped without a reboot. But the log files themselves are still on the local filesystem. Forwarding to a centralised SIEM that CDE staff cannot modify is mandatory:

```bash
# /etc/rsyslog.d/50-pci-cde.conf
# Forward audit events to immutable SIEM
# Use TLS to prevent in-transit tampering

module(load="imfile" PollingInterval="10")

input(type="imfile"
      File="/var/log/audit/audit.log"
      Tag="auditd"
      Facility="local6"
      Severity="info")

# Forward to SIEM over TLS (adjust IP/port/cert paths)
action(type="omfwd"
       Target="siem.internal.example.com"
       Port="6514"
       Protocol="tcp"
       StreamDriver="gtls"
       StreamDriverMode="1"
       StreamDriverAuthMode="x509/name"
       StreamDriverPermittedPeers="siem.internal.example.com")
```

Configure `auditd.conf` to handle disk pressure without silently dropping events:

```ini
# /etc/audit/auditd.conf (CDE-relevant settings)
log_file = /var/log/audit/audit.log
log_format = ENRICHED
max_log_file = 100
max_log_file_action = ROTATE
num_logs = 10
space_left = 500
space_left_action = EMAIL
admin_space_left = 100
admin_space_left_action = HALT
disk_full_action = HALT
disk_error_action = HALT
```

Setting `disk_full_action = HALT` and `admin_space_left_action = HALT` means the system halts rather than dropping audit events. This is the correct PCI DSS posture — audit continuity is more important than availability.

## Expected Behaviour

The following table maps each PCI DSS requirement to the verification command a QSA would run. Run these commands before your assessment and document the output:

| PCI Requirement | Control | Verification Command |
|---|---|---|
| 2.2.1 — Approved services only | Services disabled and masked | `systemctl list-units --state=active --type=service` and `ss -tlnp` |
| 2.2.2 — Vendor defaults changed | Default accounts removed | `awk -F: '$7 !~ /nologin|false/' /etc/passwd` |
| 2.2.7 — Non-console admin encrypted | SSH with strong ciphers | `sshd -T \| grep -E 'ciphers|macs|kexalgorithms'` |
| 6.3.3 — Patches applied | Kernel patch currency | `uname -r` and `rpm -qa \| grep kernel` or `dpkg -l \| grep linux-image` |
| 8.3.9 — Password max age | chage settings | `chage -l <username>` for all human accounts |
| 8.6.1 — Service account shells | No interactive shells for services | `awk -F: '$3>=100 && $7~/bash\|sh/' /etc/passwd` |
| 8.6.1 — No shared accounts | Individual accounts per user | Account inventory document + `last` output |
| 10.2.1.1 — CDE data access logged | auditd rules on PAN paths | `auditctl -l \| grep pci_pan_access` |
| 10.2.1.2 — Root actions logged | auditd execve for euid=0 | `auditctl -l \| grep pci_root_exec` |
| 10.2.1.5 — Auth mechanism changes | /etc/passwd, /etc/shadow watched | `auditctl -l \| grep pci_passwd_change` |
| 10.3.2 — Audit log modification prevented | Immutable auditd mode | `auditctl -s \| grep enabled` (should show `enabled 2`) |
| 10.3.3 — Audit logs backed up promptly | SIEM forwarding active | `ss -tnp \| grep 6514` and SIEM receipt confirmation |
| 10.7.1 — Audit log failures detected | auditd disk-full action | `grep 'disk_full_action' /etc/audit/auditd.conf` |

## Trade-offs

**Audit log volume.** The PCI DSS ruleset above — particularly the `connect` syscall rule and PAN path watches — generates substantial log volume. A payment server processing thousands of transactions per minute will produce tens of thousands of audit events per minute. Storage and SIEM ingestion costs are real. Consider filtering at the shipper layer (keeping all events in the local audit log for local compliance, forwarding only non-routine events to the SIEM for alerting), but only after validating that filtered events still meet the QSA's evidence requirements for Req 10.3.

**`disk_full_action = HALT`.** Halting the system when audit disk space is exhausted is the PCI DSS-correct posture, but it means a storage misconfiguration takes down a production payment system. This is why `space_left_action = EMAIL` fires early (at 500 MB remaining in the example above). Monitor audit disk usage in your alerting platform, not just the SIEM. Some organisations use `space_left_action = SYSLOG` and `admin_space_left_action = SUSPEND` as a middle ground, keeping the system running while suspending new audit events — but this approach requires a compensating control and QSA agreement.

**Immutable auditd (`-e 2`).** Once rules are loaded with `-e 2`, you cannot change audit rules without rebooting. This prevents an attacker from disabling logging, but it also means your change window for audit rule updates requires a service interruption. On systems with kernel live patching, pair immutable auditd with a controlled reboot schedule for rule updates.

**`AllowUsers` in sshd_config.** Whitelisting individual usernames in SSH is correct for a stable operations team. It becomes operationally painful during on-call rotations, team growth, or incident response when a new engineer needs access. Build the process for updating `AllowUsers` (change request, approval, Ansible push, reload) before you need to use it at 2am.

**PAM pwquality and existing passwords.** Enabling `pam_pwquality` with strong minimums does not retroactively invalidate existing passwords. Users with weak passwords will not be prompted to change until their next password change event. Force a password reset on all human accounts after deploying pwquality settings if you cannot verify existing password complexity.

## Failure Modes

**Auditd running with no rules.** `systemctl status auditd` shows the service as active, but `auditctl -l` returns `No rules`. This is the most common failure — the package is installed but configuration was never applied, or rules failed to load silently. Check `/var/log/audit/audit.log` for `type=CONFIG_CHANGE` events at startup. Always verify with `auditctl -l` and `auditctl -s`, not just the service status.

**SSH root login not actually disabled.** `sshd_config` shows `PermitRootLogin no`, but `sshd -T | grep permitrootlogin` shows `permitrootlogin prohibit-password` — a file in `/etc/ssh/sshd_config.d/` is overriding the base config. Always use `sshd -T` (the effective configuration test) rather than reading `sshd_config` directly.

**Service account with a shell after a package update.** Package updates for services like `postgresql`, `nginx`, or `elasticsearch` occasionally reset the shell for their service user. Add a post-update check to your patch process: `awk -F: '$3>=100 && $7~/bash|sh/' /etc/passwd`.

**sysctl settings not persisting across reboots.** `sysctl net.ipv4.ip_forward` shows `0` on the running system, but a reboot reveals the setting was applied with `sysctl -w` rather than written to `/etc/sysctl.d/`. Always use a file in `/etc/sysctl.d/` and verify with `sysctl --system` to ensure all drop-in files are loaded correctly.

**Log forwarding silently failing.** rsyslog is running and the SIEM shows events from yesterday, but a TLS certificate rotation broke the connection overnight. The local audit log is intact, but the SIEM has a gap. Instrument log forwarding at the SIEM side with an alert for hosts that stop sending events. A CDE host that goes silent is either compromised or broken — both require immediate investigation.

**`/etc/passwd` world-readable after all that.** It is — and it should be. `/etc/passwd` is world-readable by design; programs need to resolve UIDs to usernames. The QSA finding is not that the file is readable, but that it contains accounts with interactive shells that have no business owner documented in your configuration standard. The control is account management, not file permissions.

## QSA Evidence Checklist

Run this checklist in the two weeks before an assessment to identify gaps before the QSA does:

```bash
#!/bin/bash
# pre-assessment-check.sh — PCI DSS CDE Linux evidence collection

echo "=== 1. Listening services (Req 2.2.1) ==="
ss -tlnp

echo "=== 2. Accounts with interactive shells (Req 2.2.2 / 8.6.1) ==="
awk -F: '$7 !~ /nologin|false|sync|halt|shutdown/ {print $1, $3, $7}' /etc/passwd

echo "=== 3. SSH effective configuration (Req 2.2.7 / 8.6) ==="
sshd -T | grep -E 'permitrootlogin|passwordauthentication|allowusers|ciphers|macs'

echo "=== 4. Kernel patch level (Req 6.3.3) ==="
uname -r
dpkg -l 'linux-image*' 2>/dev/null || rpm -qa | grep kernel

echo "=== 5. Password aging for human accounts (Req 8.3.9) ==="
for USER in $(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd); do
    echo "--- $USER ---"
    chage -l "$USER"
done

echo "=== 6. auditd status and rule count (Req 10.2) ==="
auditctl -s
auditctl -l | wc -l
auditctl -l | grep pci_

echo "=== 7. auditd immutable mode (Req 10.3.2) ==="
auditctl -s | grep enabled

echo "=== 8. SIEM log forwarding active (Req 10.3.3) ==="
ss -tnp | grep 6514
systemctl status rsyslog

echo "=== 9. sysctl CDE settings (Req 2.2) ==="
sysctl net.ipv4.ip_forward kernel.randomize_va_space kernel.dmesg_restrict \
       net.ipv4.conf.all.accept_redirects kernel.kptr_restrict

echo "=== 10. auditd disk-full action (Req 10.7.1) ==="
grep -E 'disk_full_action|admin_space_left_action' /etc/audit/auditd.conf
df -h /var/log/audit/
```

Save the output from this script as a dated file and attach it to your assessment evidence package. The QSA can reproduce the checks live — having pre-run output demonstrates continuous control operation rather than a configuration applied just before the visit.

The gap between a general hardened Linux server and a QSA-ready CDE host is not primarily a technical gap. Most of the controls are the same. The gap is the evidence chain: documented configuration standards, verification commands with expected outputs, continuous log forwarding, and a process that keeps the configuration in its documented state between assessments. Build the documentation and the verification process alongside the technical controls, not after them.
