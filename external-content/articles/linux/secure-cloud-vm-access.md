---
title: "Secure Cloud VM Access: SSH Key Authentication, Two-Factor Login, VPN, and Audit Logging"
description: "Cloud VMs exposed to the internet with password-only SSH are compromised within hours. This article covers the complete secure access stack: SSH key authentication, TOTP two-factor login, WireGuard VPN as a network-layer gate, and audit logging to track who did what and when."
slug: "secure-cloud-vm-access"
date: 2026-04-23
lastmod: 2026-04-23
category: "linux"
tags: ["ssh", "2fa", "totp", "wireguard", "vpn", "audit-logging", "cloud", "authentication", "google-authenticator"]
personas: ["systems-engineer", "security-engineer", "devops-engineer"]
article_number: 155
difficulty: "intermediate"
estimated_reading_time: 24
provider_bridges:
  - name: "Tailscale"
    id: 40
    category: "identity"
  - name: "Teleport"
    id: 41
    category: "identity"
  - name: "JumpCloud"
    id: 42
    category: "identity"
premium_pack: "secure-vm-access-templates"
published: true
layout: article.njk
permalink: "/articles/linux/secure-cloud-vm-access/index.html"
---

# Secure Cloud VM Access: SSH Key Authentication, Two-Factor Login, VPN, and Audit Logging

## Problem

A cloud VM with SSH exposed on port 22 to the public internet receives thousands of brute-force login attempts per day. Password-only authentication on a public-facing VM is not a question of "if" but "when." Automated scanners discover new cloud instances within minutes of provisioning. Default configurations from most cloud providers leave SSH open to `0.0.0.0/0` with password authentication enabled.

Single-factor authentication (SSH key or password alone) is insufficient for production infrastructure. A stolen laptop contains an SSH private key. A compromised developer machine gives an attacker the key and the known hosts. An SSH key with no passphrase, which is common, gives instant access.

The defensive architecture requires three layers:

1. **SSH key authentication** eliminates passwords entirely and ensures only holders of the correct private key can initiate an SSH handshake.
2. **Two-factor authentication (TOTP)** ensures that a stolen SSH key alone is not enough. The attacker must also possess the time-based one-time password generator.
3. **VPN (WireGuard)** ensures that the SSH port is never exposed to the public internet. Only devices connected to the VPN can reach the SSH daemon. Attackers who do not have VPN credentials cannot even begin an SSH handshake.

A fourth element, **audit logging**, answers the question every security incident requires: who accessed this system, when, from where, and what did they do?

This article implements all four layers on a cloud VM running Ubuntu 24.04 LTS. The same approach works on Debian 12, RHEL 9, and Rocky Linux 9 with minor package name differences.

**Target systems:** Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9 cloud VMs on AWS, GCP, Azure, or any VPS provider.

## Threat Model

- **Adversary:** External attacker performing automated SSH brute force, credential stuffing from leaked password databases, or targeted attack using a stolen SSH private key. Also: insider with legitimate credentials performing unauthorised actions.
- **Access level:** Network access to the VM's public IP (external attacker) or possession of a valid SSH private key (stolen credential scenario).
- **Objective:** Initial access to the VM, privilege escalation, data exfiltration, persistence (adding attacker's key or user), lateral movement to other systems the VM can reach.
- **Blast radius:** Without layered defence: single key compromise gives persistent access. With VPN + SSH key + TOTP: attacker needs VPN credentials AND the SSH key AND the TOTP seed, which requires compromising three independent systems.

**The key shift:** Each layer independently blocks an attack class. VPN blocks network-level scanners. SSH keys block brute-force password attacks. TOTP blocks stolen-key attacks. Audit logging ensures that even successful authorised access is traceable.

## Configuration

### Layer 1: SSH Key Authentication

Disable password authentication entirely. Only SSH key holders can connect.

**Generate an Ed25519 SSH key pair on your local machine:**

```bash
# Generate a key pair with a strong passphrase.
# Ed25519 is faster and more secure than RSA.
# The passphrase protects the key if your local machine is compromised.
ssh-keygen -t ed25519 -C "your-email@example.com" -f ~/.ssh/id_ed25519_cloud
```

**Copy the public key to the cloud VM:**

```bash
# Option 1: Using ssh-copy-id (if password auth is currently enabled)
ssh-copy-id -i ~/.ssh/id_ed25519_cloud.pub user@vm-public-ip

# Option 2: Manual copy (if using cloud provider's console or metadata)
cat ~/.ssh/id_ed25519_cloud.pub
# Copy the output and paste into the VM's ~/.ssh/authorized_keys

# Option 3: Cloud provider metadata (at VM creation time)
# AWS: --key-name parameter or user-data
# GCP: project or instance metadata ssh-keys
# Azure: --ssh-key-values parameter
```

**Harden sshd_config on the VM:**

```bash
# /etc/ssh/sshd_config.d/hardening.conf
# Using a drop-in file to avoid modifying the main config.

# Disable password authentication entirely
PasswordAuthentication no
KbdInteractiveAuthentication no

# Disable root login
PermitRootLogin no

# Only allow specific users (replace with your username)
AllowUsers deployer

# Use only SSH protocol 2
Protocol 2

# Restrict key exchange and cipher algorithms to modern options
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com

# Connection rate limiting
MaxStartups 10:30:60
LoginGraceTime 20
MaxAuthTries 3

# Disable all forwarding (enable selectively if needed)
AllowTcpForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no

# Idle session timeout (10 minutes)
ClientAliveInterval 300
ClientAliveCountMax 2

# Log level for audit trail
LogLevel VERBOSE
```

```bash
# Validate the configuration before restarting
sudo sshd -t

# Restart sshd
sudo systemctl restart sshd
```

**Verify key-only authentication is working before closing your current session:**

```bash
# Open a NEW terminal and test SSH key login
ssh -i ~/.ssh/id_ed25519_cloud deployer@vm-public-ip

# Verify password auth is rejected
ssh -o PubkeyAuthentication=no deployer@vm-public-ip
# Expected: Permission denied (publickey).
```

### Layer 2: Two-Factor Authentication with TOTP

SSH key authentication proves you have the key. TOTP proves you also have the authenticator device. Even if an attacker steals the SSH private key, they cannot log in without the TOTP code.

**Install Google Authenticator PAM module on the VM:**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install libpam-google-authenticator

# RHEL/Rocky
sudo dnf install epel-release
sudo dnf install google-authenticator
```

**Configure TOTP for each user:**

```bash
# Run as the user who will log in (not as root)
google-authenticator

# Answer the prompts:
# Do you want authentication tokens to be time-based? y
# [QR code will be displayed - scan with authenticator app]
# Do you want me to update your ~/.google_authenticator file? y
# Do you want to disallow multiple uses of the same token? y
# Do you want to increase the time skew window? n
# Do you want to enable rate-limiting? y
```

**Save the emergency scratch codes** displayed during setup. Store them securely (password manager or printed in a safe). These are the recovery codes if you lose your authenticator device.

**Configure PAM to require TOTP after SSH key auth:**

```bash
# /etc/pam.d/sshd
# Add the following line at the end of the file.
# 'nullok' allows users who have not yet set up TOTP to log in
# (remove 'nullok' after all users have configured TOTP).
auth required pam_google_authenticator.so nullok
```

**Configure SSH to require both key and TOTP:**

```bash
# /etc/ssh/sshd_config.d/2fa.conf

# Enable challenge-response authentication (needed for TOTP prompt)
KbdInteractiveAuthentication yes

# Require both publickey AND keyboard-interactive (TOTP)
AuthenticationMethods publickey,keyboard-interactive
```

```bash
# Validate and restart sshd
sudo sshd -t
sudo systemctl restart sshd
```

**Test two-factor login (from a new terminal, keep current session open):**

```bash
ssh -i ~/.ssh/id_ed25519_cloud deployer@vm-public-ip
# Expected flow:
# 1. SSH key accepted automatically
# 2. Prompted: "Verification code: "
# 3. Enter the 6-digit code from your authenticator app
# 4. Login successful

# Test with wrong TOTP code:
# Expected: Connection closed after incorrect code
```

**Remove the `nullok` option** after all users have configured TOTP:

```bash
# /etc/pam.d/sshd
# Change:
#   auth required pam_google_authenticator.so nullok
# To:
auth required pam_google_authenticator.so
```

### Layer 3: WireGuard VPN

WireGuard ensures that SSH is never exposed to the public internet. Only VPN-connected devices can reach the SSH port. This eliminates the entire class of internet-facing SSH attacks: brute force, zero-day exploits against sshd, and pre-authentication vulnerabilities.

**Install WireGuard on the VM (VPN server):**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install wireguard

# RHEL/Rocky
sudo dnf install epel-release
sudo dnf install wireguard-tools
```

**Generate server keys:**

```bash
# Generate private and public keys for the server
wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key

# Restrict permissions on the private key
sudo chmod 600 /etc/wireguard/server_private.key
```

**Generate client keys (on your local machine):**

```bash
# Generate keys for the client
wg genkey | tee client_private.key | wg pubkey | tee client_public.key
chmod 600 client_private.key
```

**Configure the WireGuard server:**

```ini
# /etc/wireguard/wg0.conf
[Interface]
# Server's VPN IP address
Address = 10.100.0.1/24
# WireGuard listen port (UDP)
ListenPort = 51820
# Server's private key
PrivateKey = <contents of /etc/wireguard/server_private.key>
# Save configuration on shutdown and load on startup
SaveConfig = false

# Enable IP forwarding for VPN traffic (optional, needed if routing between clients)
PostUp = sysctl -w net.ipv4.ip_forward=1
PostDown = sysctl -w net.ipv4.ip_forward=0

[Peer]
# Client 1: your workstation
PublicKey = <contents of client_public.key>
# Client's VPN IP address
AllowedIPs = 10.100.0.2/32
```

```bash
# Enable and start WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Verify the interface is up
sudo wg show
```

**Configure the WireGuard client (your local machine):**

```ini
# /etc/wireguard/wg0.conf (Linux)
# or import into WireGuard app (macOS, Windows, iOS, Android)

[Interface]
# Client's VPN IP address
Address = 10.100.0.2/24
# Client's private key
PrivateKey = <contents of client_private.key>
# DNS server (optional, use the VM's DNS or a public resolver)
DNS = 1.1.1.1

[Peer]
# Server's public key
PublicKey = <contents of server_public.key>
# Server's public IP and WireGuard port
Endpoint = vm-public-ip:51820
# Route only the VPN subnet through the tunnel (split tunnelling)
AllowedIPs = 10.100.0.0/24
# Keep the connection alive (important for NAT traversal)
PersistentKeepalive = 25
```

```bash
# Start the VPN connection
sudo wg-quick up wg0

# Verify connectivity
ping 10.100.0.1
```

**Restrict SSH to listen only on the VPN interface:**

```bash
# /etc/ssh/sshd_config.d/vpn-only.conf
# SSH listens only on the WireGuard VPN IP, not on the public IP.
ListenAddress 10.100.0.1
```

```bash
# Validate and restart sshd
sudo sshd -t
sudo systemctl restart sshd
```

**Configure the firewall to enforce VPN-only SSH access:**

```bash
# Using nftables: allow SSH only from the WireGuard subnet.
# Allow WireGuard UDP port from anywhere (needed to establish the VPN).
# Block SSH from the public internet.

sudo tee /etc/nftables.conf << 'NFTEOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established and related connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow WireGuard UDP port from anywhere (VPN establishment)
        udp dport 51820 accept

        # Allow SSH only from the WireGuard VPN subnet
        iif wg0 tcp dport 22 accept

        # Allow ICMP (ping) from VPN only
        iif wg0 icmp type echo-request accept
        iif wg0 icmpv6 type echo-request accept

        # Drop everything else (implicit, but explicit for clarity)
        counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
NFTEOF

# Apply the firewall rules
sudo nft -f /etc/nftables.conf

# Enable nftables on boot
sudo systemctl enable nftables
```

**Verify SSH is unreachable from the public internet:**

```bash
# From an external machine (not connected to VPN):
ssh -o ConnectTimeout=5 deployer@vm-public-ip
# Expected: Connection timed out (port is not reachable)

# From VPN-connected machine:
ssh -i ~/.ssh/id_ed25519_cloud deployer@10.100.0.1
# Expected: Prompted for TOTP code, then login succeeds
```

**Update your SSH config for VPN-based access:**

```
# ~/.ssh/config on your local machine
Host cloud-vm
    HostName 10.100.0.1
    User deployer
    IdentityFile ~/.ssh/id_ed25519_cloud
    # Ensure VPN is up before connecting
```

### Layer 4: Audit Logging

Track every access event: who connected, when, from where, what they did, and when they disconnected. This is essential for incident investigation, compliance, and accountability.

**Configure auditd for comprehensive access logging:**

```bash
# Install auditd (usually pre-installed)
# Ubuntu/Debian:
sudo apt install auditd

# RHEL/Rocky:
sudo dnf install audit
```

```bash
# /etc/audit/rules.d/access-audit.rules
# These rules track SSH access events, privilege escalation,
# user/group modifications, and command execution by administrators.

# Delete all existing rules and set buffer
-D
-b 8192

# Track all authentication events
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/secure -p wa -k auth_log

# Track SSH configuration changes
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Track user and group modifications
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Track privilege escalation
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privilege_escalation

# Track all sudo usage
-w /usr/bin/sudo -p x -k sudo_usage
-w /usr/bin/su -p x -k su_usage

# Track SSH key modifications
-w /home/ -p wa -k ssh_key_change -F path=*/.ssh/authorized_keys

# Track WireGuard configuration changes
-w /etc/wireguard/ -p wa -k wireguard_config

# Track PAM configuration changes
-w /etc/pam.d/ -p wa -k pam_config

# Track firewall configuration changes
-w /etc/nftables.conf -p wa -k firewall_config

# Track login/logout events
-w /var/log/wtmp -p wa -k login_events
-w /var/log/btmp -p wa -k failed_logins
-w /var/log/lastlog -p wa -k last_login

# Make the configuration immutable until next reboot
# (prevents attacker from disabling audit logging)
-e 2
```

```bash
# Load the audit rules
sudo augenrules --load

# Verify rules are active
sudo auditctl -l
```

**Configure structured logging for SSH events:**

```bash
# /etc/ssh/sshd_config.d/logging.conf
# Verbose logging captures key fingerprint, username, source IP,
# and authentication method for every connection.
LogLevel VERBOSE
```

**Query audit logs to answer "who did what when":**

```bash
# Who logged in today?
sudo ausearch -m USER_LOGIN --start today -i

# Who used sudo in the last 24 hours?
sudo ausearch -k sudo_usage --start recent -i

# What commands did a specific user run as root?
sudo ausearch -k privilege_escalation -ui 1001 --start today -i

# Who modified SSH configuration?
sudo ausearch -k sshd_config --start today -i

# Who modified firewall rules?
sudo ausearch -k firewall_config --start today -i

# Who added or modified an SSH authorized_keys file?
sudo ausearch -k ssh_key_change --start today -i

# Failed login attempts
sudo ausearch -m USER_LOGIN --success no --start today -i
```

**Generate an access report:**

```bash
#!/bin/bash
# scripts/access-report.sh
# Generate a daily access report for compliance and review.

REPORT_DATE="${1:-today}"
REPORT_FILE="/var/log/access-report-$(date +%Y-%m-%d).txt"

echo "=== Access Report: $(date +%Y-%m-%d) ===" > "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "--- Successful Logins ---" >> "${REPORT_FILE}"
sudo ausearch -m USER_LOGIN --success yes --start "${REPORT_DATE}" -i 2>/dev/null \
  | grep -E "^type=USER_LOGIN" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "--- Failed Login Attempts ---" >> "${REPORT_FILE}"
sudo ausearch -m USER_LOGIN --success no --start "${REPORT_DATE}" -i 2>/dev/null \
  | grep -E "^type=USER_LOGIN" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "--- Sudo Usage ---" >> "${REPORT_FILE}"
sudo ausearch -k sudo_usage --start "${REPORT_DATE}" -i 2>/dev/null \
  | grep -E "^type=SYSCALL" >> "${REPORT_FILE}"
echo "" >> "${REPORT_FILE}"

echo "--- Configuration Changes ---" >> "${REPORT_FILE}"
for key in sshd_config wireguard_config pam_config firewall_config identity sudoers; do
  changes=$(sudo ausearch -k "${key}" --start "${REPORT_DATE}" -i 2>/dev/null | grep -c "^type=SYSCALL")
  if [ "${changes}" -gt 0 ]; then
    echo "${key}: ${changes} changes" >> "${REPORT_FILE}"
    sudo ausearch -k "${key}" --start "${REPORT_DATE}" -i 2>/dev/null \
      | grep -E "^type=SYSCALL" >> "${REPORT_FILE}"
  fi
done
echo "" >> "${REPORT_FILE}"

echo "--- VPN Connection Log ---" >> "${REPORT_FILE}"
sudo journalctl -u wg-quick@wg0 --since "${REPORT_DATE}" --no-pager >> "${REPORT_FILE}" 2>/dev/null
echo "" >> "${REPORT_FILE}"

echo "Report written to ${REPORT_FILE}"
cat "${REPORT_FILE}"
```

```bash
# Run the daily report
chmod +x scripts/access-report.sh
sudo ./scripts/access-report.sh today
```

**Automate daily report generation with a cron job:**

```bash
# /etc/cron.d/access-report
# Generate access report at 23:55 every day
55 23 * * * root /opt/scripts/access-report.sh today >> /var/log/access-report-cron.log 2>&1
```

**Ship audit logs to a remote syslog server** (prevents an attacker from deleting logs on the compromised VM):

```bash
# /etc/audit/auditd.conf
# Add remote logging plugin
log_format = ENRICHED
name_format = HOSTNAME

# /etc/audit/plugins.d/syslog.conf
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_LOCAL6
format = string
```

```bash
# Configure rsyslog to forward audit logs to a remote server
# /etc/rsyslog.d/50-audit-remote.conf
local6.* @@syslog.example.com:514
```

```bash
# Restart auditd and rsyslog
sudo systemctl restart auditd
sudo systemctl restart rsyslog
```

## Expected Behaviour

After implementing all four layers:

- **SSH key only:** Password authentication is disabled. Only Ed25519 key holders can initiate an SSH connection. Connections from unknown keys are rejected immediately.
- **Two-factor TOTP:** After SSH key verification, the user is prompted for a 6-digit TOTP code. Incorrect codes terminate the connection. Each code is valid for 30 seconds and can only be used once.
- **VPN gate:** SSH port (22) is not reachable from the public internet. Only WireGuard VPN clients on the `10.100.0.0/24` subnet can reach SSH. The WireGuard UDP port (51820) is the only port exposed to the internet.
- **Audit logging:** Every login (successful and failed), sudo usage, configuration change, and privilege escalation is logged. Logs are shipped to a remote syslog server to prevent tampering. Daily access reports are generated automatically.

**Complete connection flow:**

```
1. Connect to WireGuard VPN        → VPN tunnel established
2. SSH to 10.100.0.1               → SSH key verified
3. Enter TOTP code                  → Second factor verified
4. Session established              → Audit log: USER_LOGIN success
5. Run commands                     → Audit log: privilege_escalation (if sudo)
6. Disconnect                       → Audit log: USER_LOGOUT
```

**Verification commands:**

```bash
# Verify SSH is only listening on VPN interface
sudo ss -tlnp | grep sshd
# Expected: 10.100.0.1:22 only (not 0.0.0.0:22)

# Verify password auth is disabled
ssh -o PubkeyAuthentication=no deployer@10.100.0.1
# Expected: Permission denied (publickey,keyboard-interactive)

# Verify TOTP is required
ssh -o KbdInteractiveAuthentication=no -i ~/.ssh/id_ed25519_cloud deployer@10.100.0.1
# Expected: Connection fails (keyboard-interactive required but disabled)

# Verify audit rules are loaded
sudo auditctl -l | wc -l
# Expected: 15+ rules

# Verify audit logging is working
sudo ausearch -m USER_LOGIN --start today -i | tail -5
# Expected: Shows your current login event

# Verify WireGuard is running
sudo wg show
# Expected: Shows interface wg0 with peer information
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| SSH key only (no password) | Cannot log in if SSH key is lost or corrupted | Locked out of VM entirely | Store a backup key in a password manager. Cloud providers offer console access as a break-glass option (AWS SSM, GCP serial console, Azure serial console). |
| TOTP two-factor | Extra step on every login. Cannot log in if authenticator device is lost. | Lost phone = locked out | Save emergency scratch codes during setup. Store in a password manager or printed in a physical safe. Register TOTP on two devices. |
| WireGuard VPN | Must connect to VPN before SSH. Adds a dependency on VPN availability. | WireGuard service down = no SSH access | Cloud provider console access as break-glass. Monitor WireGuard service health. Keep WireGuard configuration simple (fewer failure modes). |
| SSH on VPN-only interface | SSH completely invisible to internet scanners | Misconfigured ListenAddress can lock you out | Test from a new terminal before closing existing session. Keep cloud console access available. |
| Auditd with immutable rules (`-e 2`) | Rules cannot be changed without reboot. Attacker cannot disable logging. | Legitimate rule changes require reboot | Plan audit rules carefully before enabling immutable mode. Test rules thoroughly in non-immutable mode first. |
| Remote syslog shipping | Logs survive even if VM is compromised and local logs deleted | Network dependency; logs lost if syslog server unreachable | Buffer logs locally if remote server is down. Use TLS for syslog transport. Monitor syslog delivery. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SSH key lost or corrupted | "Permission denied (publickey)" when connecting | User reports inability to log in | Use cloud provider console access (AWS SSM Session Manager, GCP serial console, Azure serial console). Add a new SSH key via console. |
| Authenticator device lost | SSH key accepted but TOTP prompt fails | User cannot provide valid TOTP code | Use one of the five emergency scratch codes generated during setup. Set up TOTP on a new device. Generate new scratch codes. |
| WireGuard server process crashes | VPN connection drops; SSH unreachable | Monitoring detects WireGuard service down; users report inability to connect | Cloud provider console access. Restart WireGuard: `sudo systemctl restart wg-quick@wg0`. Investigate cause in journal: `journalctl -u wg-quick@wg0`. |
| nftables misconfiguration locks out SSH | Cannot establish SSH even over VPN | All users report inability to connect | Cloud provider console access. Fix nftables rules. Always test firewall changes from a second session. |
| Auditd buffer overflow | Audit events dropped under heavy load | `aureport --summary` shows lost events; auditd logs "audit backlog limit exceeded" | Increase buffer size (`-b 16384` in rules). If events are still lost: increase `backlog_wait_time` in `/etc/audit/auditd.conf`. |
| Remote syslog server unreachable | Audit logs accumulate locally but are not shipped | Monitoring detects syslog delivery failure; local disk fills up | Fix network connectivity to syslog server. Increase local log retention. Logs will ship once connectivity is restored (rsyslog queues by default). |
| PAM misconfiguration locks all users out | All SSH logins fail at PAM stage | No users can authenticate; cloud console access still works | Access via cloud provider console. Fix `/etc/pam.d/sshd`. Test PAM changes with `pamtester` before applying in production. |
| Time drift breaks TOTP | TOTP codes rejected despite correct code on authenticator | User reports valid codes being rejected | Check system time: `timedatectl`. Enable NTP: `sudo timedatectl set-ntp true`. TOTP tolerates up to 30 seconds of drift by default. |

## When to Consider a Managed Alternative

**Transition point:** When your team exceeds 5 users, managing SSH keys, TOTP enrolment, VPN peer configuration, and audit log review becomes a recurring operational burden. Adding a new team member requires: generating VPN keys, adding a WireGuard peer, setting up TOTP, distributing SSH access. Removing a team member requires: removing the WireGuard peer, revoking SSH keys, and verifying removal across all VMs.

**Recommended providers:**

- **[Tailscale](https://tailscale.com):** Replaces the WireGuard VPN layer entirely. Mesh VPN built on WireGuard with automatic key distribution, SSO integration (Okta, Google, Microsoft), and ACLs. Eliminates manual WireGuard peer management. SSH over Tailscale means zero public-internet exposure with zero VPN configuration per machine. Free for up to 100 devices.

- **[Teleport](https://goteleport.com):** Replaces SSH keys, TOTP, and audit logging in a single platform. Certificate-based SSH with SSO integration (no SSH keys to manage), session recording (full audit trail of commands), and RBAC. Eliminates TOTP setup per user by integrating with your identity provider's MFA. Free Community Edition available.

- **[JumpCloud](https://jumpcloud.com):** Cloud directory that manages SSH access, MFA, and device trust centrally. Push SSH keys, enforce MFA, and manage group-based access from a single dashboard. Useful if you also need to manage macOS and Windows devices alongside Linux VMs.

**What you still control:** sshd_config hardening (algorithms, forwarding, rate limiting) applies regardless of how you manage access. Auditd rules are your configuration. Firewall rules are your responsibility. The managed solutions handle identity and access lifecycle; the OS-level hardening remains yours.

**Premium content pack:** Secure cloud VM access templates. Ansible playbook for automated deployment of all four layers across a fleet of VMs. WireGuard peer management scripts. Auditd rule sets for compliance (SOC 2, ISO 27001, PCI DSS). Daily access report templates with alerting on anomalous patterns.

## Related Articles

- [SSH Hardening Beyond the Basics: Certificate Authentication, Jump Hosts, and Logging](/articles/linux/ssh-hardening/)
- [PAM Configuration Hardening: Password Policies, Login Controls, and MFA Integration](/articles/linux/pam-hardening/)
- [Linux Audit Framework Deep Dive: auditd Rules, auditctl, and ausearch for Security Monitoring](/articles/linux/auditd-deep-dive/)
- [Linux Firewall Hardening with nftables: Replacing iptables in Production](/articles/linux/nftables/)
- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
