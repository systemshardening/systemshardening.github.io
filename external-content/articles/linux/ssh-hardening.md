---
title: "SSH Hardening Beyond the Basics: Certificate Authentication, Jump Hosts, and Logging"
description: "Every SSH hardening guide starts and ends with the same three changes: disable root login, require key-based authentication, change the default port."
slug: "ssh-hardening"
date: 2026-04-16
lastmod: 2026-04-16
category: "linux"
tags: ["ssh", "certificates", "hardening", "bastion", "session-recording", "authentication"]
personas: ["systems-engineer", "security-engineer"]
article_number: 7
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Teleport"
    id: 41
    category: "identity"
  - name: "Smallstep"
    id: 43
    category: "identity"
  - name: "Tailscale"
    id: 40
    category: "identity"
premium_pack: "ssh-ca-automation"
published: true
layout: article.njk
permalink: "/articles/linux/ssh-hardening/index.html"
---

# SSH Hardening Beyond the Basics: Certificate Authentication, Jump Hosts, and Logging

## Problem

Every SSH hardening guide starts and ends with the same three changes: disable root login, require key-based authentication, change the default port. These are necessary but insufficient. Production SSH infrastructure faces problems these basics do not address:

- **Key sprawl.** Every engineer has an SSH key pair. Every server has an `authorized_keys` file. When an engineer leaves, you must remove their key from every server, and you will miss some. There is no expiry, no revocation, and no central visibility into who has access to what.
- **No session logging.** SSH provides encrypted transport but no audit trail of what happened during a session. After an incident, you cannot answer "what commands did this user run on this host?"
- **Direct exposure.** Every server running `sshd` on a public or semi-public network is a target for brute force, credential stuffing, and zero-day exploits against the SSH daemon itself.
- **Overly permissive configuration.** Default `sshd_config` allows TCP forwarding, X11 forwarding, stream local forwarding, and agent forwarding, features that attackers use for pivoting and data exfiltration, and that most engineers never need.
- **Connection exhaustion.** Default `MaxStartups` allows unlimited pre-authentication connections, enabling a simple denial-of-service against the SSH daemon.

This article moves past the basics into certificate-based authentication (eliminating key sprawl), jump host architecture (reducing exposed surface), session recording (audit compliance), and the `sshd_config` settings that most guides miss.

**Target systems:** OpenSSH 8.2+ on Ubuntu 24.04 LTS, Debian 12, RHEL 9 / Rocky Linux 9.

## Threat Model

- **Adversary:** External attacker brute-forcing SSH (automated scanning), compromised SSH key (stolen laptop, leaked key in Git), or insider/compromised account abusing SSH access for lateral movement or data exfiltration.
- **Access level:** Network access to SSH port (external attack), or valid SSH credentials (compromised key, insider).
- **Objective:** Initial access to hosts, lateral movement between hosts, persistent backdoor (add attacker's key to `authorized_keys`), data exfiltration via SSH tunnels.
- **Blast radius:** Without hardening, single key compromise gives persistent access to every server the key is authorised on. With certificate auth, compromised certificate expires within hours, and revocation is immediate.

## Configuration

### SSH Certificate Authority

SSH certificates solve key sprawl. Instead of distributing individual public keys to every server, you create a Certificate Authority (CA) that signs user certificates with an expiry time. Servers trust the CA, any certificate signed by the CA is accepted, and expired certificates are rejected automatically.

**Create the CA (do this once, store securely):**

```bash
# Generate the CA key pair. This key signs all user certificates.
# Protect this key like a root CA - it grants access to every server
# that trusts it. Store offline or in a hardware security module.
ssh-keygen -t ed25519 -f /etc/ssh/ca_user_key -C "SSH User CA"

# No passphrase for automated signing (use a passphrase if signing manually).
# For production: use Vault (#65) or Smallstep (#43) as the CA backend.
```

**Configure servers to trust the CA:**

```bash
# Copy the CA public key to every server:
sudo cp ca_user_key.pub /etc/ssh/ca_user_key.pub

# Add to sshd_config:
echo "TrustedUserCAKeys /etc/ssh/ca_user_key.pub" | sudo tee -a /etc/ssh/sshd_config

# Restart sshd:
sudo systemctl restart sshd
```

**Sign a user certificate:**

```bash
# Sign the user's existing public key with the CA.
# -I = certificate identity (usually the username)
# -n = principals (usernames allowed to use this certificate)
# -V = validity period (8 hours from now)
# -z = serial number (for revocation tracking)

ssh-keygen -s /etc/ssh/ca_user_key \
  -I "alice@company.com" \
  -n alice,deploy \
  -V +8h \
  -z $(date +%s) \
  /home/alice/.ssh/id_ed25519.pub

# This creates /home/alice/.ssh/id_ed25519-cert.pub
# The certificate is valid for 8 hours and allows login as 'alice' or 'deploy'.
```

**Verify the certificate:**

```bash
ssh-keygen -L -f /home/alice/.ssh/id_ed25519-cert.pub
# Output shows:
#   Type: ssh-ed25519-cert-v01@openssh.com user certificate
#   Serial: 1713830400
#   Valid: from 2026-04-22T10:00:00 to 2026-04-22T18:00:00
#   Principals: alice, deploy
#   Critical Options: (none)
#   Extensions: permit-pty
```

**User connects with the certificate:**

```bash
# The user connects normally - OpenSSH automatically uses the certificate
# if it exists alongside the private key.
ssh alice@server.example.com

# No authorized_keys entry needed on the server. The server validates
# the certificate against the trusted CA key.
```

**Certificate revocation:**

```bash
# Create a revocation list (KRL) to revoke specific certificates:
ssh-keygen -k -f /etc/ssh/revoked_keys -s /etc/ssh/ca_user_key.pub \
  /home/alice/.ssh/id_ed25519-cert.pub

# Add to sshd_config:
echo "RevokedKeys /etc/ssh/revoked_keys" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart sshd

# Now Alice's certificate is immediately rejected, even if it hasn't expired.
```

### Jump Host Architecture

A jump host (bastion) reduces your exposed SSH surface to a single hardened entry point.

```
Internet → [Jump Host] → [Internal Servers]
              |
         Only SSH exposed to internet.
         All internal servers: SSH only from jump host CIDR.
```

**Client configuration (`~/.ssh/config`):**

```
# ~/.ssh/config
# Connect to internal servers via the jump host.
# The user never connects directly to internal servers.

Host jump
    HostName bastion.example.com
    User alice
    Port 22
    IdentityFile ~/.ssh/id_ed25519

Host internal-*
    ProxyJump jump
    User alice
    IdentityFile ~/.ssh/id_ed25519

Host internal-web
    HostName 10.0.1.10

Host internal-db
    HostName 10.0.1.20
```

```bash
# Connect to an internal server (transparently proxied through jump):
ssh internal-web
# This connects to bastion.example.com first, then to 10.0.1.10.
```

**Hardening the jump host itself:**

```bash
# On the jump host, restrict what users can do:
# /etc/ssh/sshd_config on the jump host

# No interactive shell on the jump host - only forwarding:
Match User *,!admin
    ForceCommand /usr/sbin/nologin
    AllowTcpForwarding yes
    X11Forwarding no
    AllowStreamLocalForwarding no
    AllowAgentForwarding no
    PermitTTY no

# Admin users (for jump host maintenance only):
Match User admin
    AllowTcpForwarding no
    X11Forwarding no
```

**Firewall rules for internal servers:**

```bash
# Internal servers: only accept SSH from the jump host's IP.
# nftables rule:
nft add rule inet filter input ip saddr 10.0.0.5 tcp dport 22 accept
nft add rule inet filter input tcp dport 22 drop
```

### Session Recording

For audit compliance and incident investigation, record all SSH sessions.

**Using `tlog` (recommended for [systemd](https://systemd.io)-based systems):**

```bash
# Install tlog
# Ubuntu/Debian:
sudo apt install tlog

# RHEL/Rocky:
sudo dnf install tlog

# Configure tlog as the login shell for recorded users:
sudo usermod -s /usr/bin/tlog-rec-session alice

# Configure tlog to log to the journal:
# /etc/tlog/tlog-rec-session.conf
{
    "writer": "journal",
    "log": {
        "input": true
    }
}
```

```bash
# View recorded sessions:
tlog-play -r journal -M TLOG_REC_SESSION=1

# Search for specific commands in recorded sessions:
journalctl -t tlog-rec-session --grep="rm -rf"
```

**Storage requirements:** Session recordings consume 50-200MB per hour per active session, depending on output volume. For 5 engineers with 4 hours of SSH per day, expect 1-4GB per day. Ship to external storage for retention beyond 30 days.

### Advanced sshd_config Settings

These settings address connection exhaustion, forwarding abuse, and information leakage:

```bash
# /etc/ssh/sshd_config - additions beyond the basics

# --- Connection rate limiting ---
# MaxStartups rate-limits pre-authentication connections.
# Format: start:rate:full
# 10:30:60 = accept 10 connections, then drop 30% of new connections,
# drop 100% at 60 pending connections.
# Prevents SSH daemon exhaustion from mass connection attempts.
MaxStartups 10:30:60

# Time allowed to authenticate after connecting. Default is 120s.
# Reduce to prevent connections held open for scanning.
LoginGraceTime 20

# Maximum authentication attempts per connection.
MaxAuthTries 3

# Maximum concurrent sessions per connection.
MaxSessions 3

# --- Disable unused forwarding ---
# TCP forwarding allows SSH tunnels for data exfiltration and pivoting.
# Disable unless specific users need it.
AllowTcpForwarding no

# Stream local (Unix socket) forwarding - used for Docker socket access
# and other local pivoting. Disable.
AllowStreamLocalForwarding no

# X11 forwarding - rarely needed, potential information leak.
X11Forwarding no

# Agent forwarding - allows the server to use the client's SSH agent.
# Enables pivoting if the server is compromised.
AllowAgentForwarding no

# SSH tunnelling (VPN-like). Almost never needed.
PermitTunnel no

# --- Algorithm selection ---
# Only allow modern key exchange and cipher algorithms.
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com

# --- Idle timeout ---
# Disconnect idle sessions after 5 minutes (300 seconds).
ClientAliveInterval 300
ClientAliveCountMax 2
```

**Selective forwarding for specific users:**

```bash
# If specific users need TCP forwarding (e.g., for database access):
Match User db-admin
    AllowTcpForwarding local
    PermitOpen 10.0.1.20:5432
    # Only allow forwarding to the specific database host and port.
```

## Expected Behaviour

After applying all changes:

- Users authenticate with short-lived certificates (8-hour expiry). No `authorized_keys` files on servers.
- Expired certificates are automatically rejected. Revoked certificates are immediately rejected via KRL.
- All SSH connections to internal servers are proxied through the jump host. Internal servers do not accept SSH from any other source.
- All sessions are recorded by tlog and searchable in the systemd journal.
- `MaxStartups 10:30:60` prevents SSH connection exhaustion.
- TCP forwarding, X11 forwarding, stream local forwarding, and agent forwarding are disabled globally (enabled per-user where needed).
- Only modern cryptographic algorithms are accepted.

```bash
# Verify certificate auth is working:
ssh -v alice@server.example.com 2>&1 | grep "Server accepts key"
# Expected: "Server accepts key: /home/alice/.ssh/id_ed25519 ED25519-CERT SHA256:..."

# Verify forwarding is disabled:
ssh -L 8080:localhost:80 alice@server.example.com
# Expected: "administratively prohibited: open failed" (or connection refused)

# Verify session recording:
journalctl -t tlog-rec-session --since "10 minutes ago" | head
# Expected: JSON log entries showing session input/output
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Certificate auth (8h expiry) | Users must re-authenticate daily; requires CA infrastructure | CA outage = no SSH access for anyone | Keep one emergency static key per host in a break-glass safe. Automate certificate signing. |
| Jump host architecture | Adds latency to SSH connections (one extra hop) | Jump host is a single point of failure and high-value target | Run the jump host with maximum hardening. HA with two jump hosts in different AZs. |
| Session recording (tlog) | 50-200MB/hour storage per active session; 1-3% CPU overhead | Privacy considerations for developer environments; may record credentials typed in terminal | Inform users sessions are recorded (policy + banner). Filter known credential patterns from recordings. |
| Disable TCP forwarding | Breaks SSH tunnels used for database access, internal web UIs | Engineers who rely on tunnels lose access | Enable forwarding per-user with `Match` blocks and `PermitOpen` to restrict to specific destinations. |
| `MaxStartups 10:30:60` | Legitimate connections may be dropped during high concurrent access | Deployment scripts opening many SSH connections simultaneously may fail | Increase values if your deployment tooling opens >10 simultaneous connections. |
| Modern algorithm restriction | Rejects connections from very old SSH clients | Legacy systems (old RHEL 6, some embedded devices) cannot connect | Add legacy algorithms in a `Match` block for specific source IPs if required. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| CA key compromised | Attacker can sign certificates for any user | No detection without monitoring certificate usage; unexpected logins in auth log | Rotate CA key. Generate new `ca_user_key`. Update `TrustedUserCAKeys` on all servers. Revoke all existing certificates. |
| CA signing service unavailable | No new certificates can be issued; users with expired certs lose access | Users report "Permission denied"; signing service health check fails | Emergency: use break-glass static keys. Long-term: HA signing service or manual signing with the CA key. |
| Jump host down | No SSH access to any internal server | Monitoring detects jump host down; users report connection refused | Failover to second jump host (configure both in `~/.ssh/config` with `ProxyJump jump1,jump2`). |
| `MaxStartups` too aggressive | Legitimate connections rejected during busy periods | Users or automation report "Connection refused"; SSH metrics show rejected connections | Increase `MaxStartups` values. Stagger deployment scripts to avoid connection bursts. |
| Session recording fills disk | Recording host runs out of storage; tlog starts failing | Disk usage alerts on the journal partition; tlog logs errors | Ship recordings to external storage (Backblaze #161, Wasabi #162). Implement journal size limits (`SystemMaxUse` in `journald.conf`). |
| Certificate used after employee departure | Former employee's certificate is still valid until expiry | Auth log shows login by departed user; certificate was not revoked | Add the certificate to the KRL immediately upon departure. Short expiry (8h) limits the window. Automate offboarding to include KRL update. |

## When to Consider a Managed Alternative

**Transition point:** When your team exceeds 5 regular SSH users and managing the CA, signing workflow, session recording storage, and KRL becomes operational overhead exceeding 4 hours per month.

**Recommended providers:**

- **[Teleport](https://goteleport.com):** Free OSS Community Edition provides SSH CA, session recording, audit logging, and RBAC in one tool. Manages the entire certificate lifecycle including automatic short-lived certificate issuance integrated with SSO. Enterprise edition adds FedRAMP compliance and enhanced session recording. This is the most complete SSH security platform.

- **[Smallstep](https://smallstep.com):** Free `step-ca` provides a lightweight SSH CA that issues short-lived certificates. Integrates with existing identity providers (OIDC, LDAP). Smallstep managed CA removes the operational burden of running and backing up the CA. Better for teams that want SSH certificates without adopting a full platform.

- **[Tailscale](https://tailscale.com):** Mesh VPN with SSO/MFA-integrated SSH that can replace bastion architecture entirely. Every host gets a stable WireGuard address within your Tailscale network. SSH over Tailscale means no jump host needed and no SSH exposed to the public internet. Free for personal use (100 devices), paid for teams.

**What you still control:** sshd_config hardening (algorithm selection, forwarding restrictions, connection limits) applies regardless of whether you use a managed CA or self-managed. The managed solutions handle certificate lifecycle; the sshd configuration remains your responsibility.

**Architecture decision:** Teleport/Smallstep for certificate-based SSH with session recording. Tailscale for eliminating public SSH exposure entirely. These are complementary. Tailscale provides the network layer, Teleport provides the access layer.


## Related Articles

- [PAM Configuration Hardening: Password Policies, Login Controls, and MFA Integration](/articles/linux/pam-hardening/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [SELinux in Production: Writing Custom Policies Without Losing Your Mind](/articles/linux/selinux/)
- [AppArmor Profiles for Custom Applications: From Complain Mode to Enforce](/articles/linux/apparmor/)
