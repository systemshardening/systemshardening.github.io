---
title: "SSH Bastion Host and Jump Server Hardening"
description: "A bastion host is the single SSH entry point to your fleet. Hardening it — session recording, certificate auth, MFA, strict forwarding controls — contains the blast radius of a stolen SSH key."
slug: "ssh-bastion-hardening"
date: 2026-04-30
lastmod: 2026-04-30
category: "network"
tags: ["ssh", "bastion", "jump-server", "session-recording", "mfa"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 257
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/network/ssh-bastion-hardening/index.html"
---

# SSH Bastion Host and Jump Server Hardening

## Problem

Direct SSH access to production servers from developer laptops creates a sprawling attack surface: every developer's SSH key is a potential credential to every server they can reach. When a laptop is compromised, all accessible servers are at risk. When an employee leaves, key rotation across hundreds of servers is error-prone.

A bastion host centralises SSH access: all connections to production pass through a single hardened host. This concentrates the attack surface at a point you can harden thoroughly, monitor completely, and rotate credentials from a single place.

Most bastion deployments are superficial: an EC2 instance with port 22 open and SSH key auth — essentially a jump host with no additional controls. A well-hardened bastion provides:

- **Session recording:** Every keystroke and output is recorded centrally; an attacker or insider cannot cover their tracks.
- **Certificate-based authentication:** Short-lived SSH certificates replace long-lived authorized_keys; a stolen key expires within hours.
- **MFA enforcement:** Even with a valid certificate, authentication requires a second factor.
- **Strict forwarding controls:** Port forwarding, X11 forwarding, and agent forwarding are disabled by default on targets reachable from the bastion.
- **Zero trust per session:** Each connection is authorized separately; past access doesn't imply future access.

Specific gaps in unmanaged bastions:

- Direct SSH to target servers remains possible (bastion is bypass-able; not the sole path).
- Long-lived `authorized_keys` on all target servers; certificate rotation never happens.
- No session recording; incident forensics requires log correlation across many systems.
- Bastion itself is reachable from the public internet with no rate limiting or geo-filtering.
- Agent forwarding enabled on the bastion; a compromise of the bastion steals all agents.

**Target systems:** OpenSSH 8.9+ on the bastion and targets; HashiCorp Vault SSH Secrets Engine or Teleport 14+ for certificate issuance; Google Authenticator PAM module or Duo Security for MFA; sshaudit 3.3+ for configuration validation.

## Threat Model

- **Adversary 1 — Stolen developer SSH key:** An attacker exfiltrates a developer's private key from their laptop. With long-lived `authorized_keys`, this provides indefinite SSH access to all servers the developer can reach. SSH certificates with 8-hour validity limit the window dramatically.
- **Adversary 2 — Compromised bastion host:** An attacker gains code execution on the bastion. If agent forwarding is enabled, they harvest all forwarded SSH agents and can reach all target servers silently. Disabling agent forwarding and using certificate auth means the bastion compromise doesn't provide target server credentials.
- **Adversary 3 — Bastion bypass:** An attacker who has obtained a server's private IP accesses it directly because the server's firewall allows SSH from `0.0.0.0/0`. The bastion is only useful if target servers only allow SSH from the bastion's IP.
- **Adversary 4 — Insider session manipulation:** A privileged insider uses their bastion access to perform unauthorized actions on production servers. Without session recording, there is no audit trail. With recording, every command is logged and tamper-evident.
- **Adversary 5 — Credential replay after certificate expiry:** An attacker captures an SSH certificate in transit. Certificates have a validity window (e.g., 8 hours); replaying an expired certificate fails.
- **Access level:** Adversary 1 has the developer's private key file. Adversary 2 has code execution on the bastion. Adversary 3 has network access to internal server IPs. Adversary 4 is a legitimate bastion user.
- **Objective:** Access production servers, move laterally, exfiltrate data, cover tracks.
- **Blast radius:** Without a bastion: stolen key = access to all servers with that authorized key. With hardened bastion + short-lived certs: stolen key is expired, and even a compromised bastion doesn't yield target credentials.

## Configuration

### Step 1: Bastion sshd_config Hardening

```
# /etc/ssh/sshd_config on the bastion host

# === Authentication ===
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile none          # Use certificate auth only; no authorized_keys.
TrustedUserCAKeys /etc/ssh/trusted_user_ca.pub   # Certificates signed by the CA are trusted.

PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30

# === MFA (requires PAM configuration below) ===
AuthenticationMethods publickey,keyboard-interactive
UsePAM yes
ChallengeResponseAuthentication yes

# === Forwarding — disabled on the bastion itself ===
AllowAgentForwarding no          # CRITICAL: prevents bastion compromise from stealing agents.
AllowTcpForwarding no            # Disable arbitrary port forwarding from the bastion.
X11Forwarding no
PermitTunnel no
GatewayPorts no

# === Only allow jump-through, not local shell work ===
# Optionally restrict bastion users to ProxyJump only:
# Match Group bastion-users
#   ForceCommand /bin/false       # Prevents interactive sessions; allow only proxyjump.
#   AllowTcpForwarding yes        # Enable only what ProxyJump needs.
# Match All

# === Logging ===
SyslogFacility AUTH
LogLevel VERBOSE                  # Logs fingerprint on every auth.

# === Connection limits ===
MaxSessions 10
MaxStartups 10:30:100             # Rate limiting: 10 unauthenticated, drop 30% at 30 pending.
ClientAliveInterval 300
ClientAliveCountMax 2             # Kill idle sessions after 10 minutes.

# === Host keys — modern algorithms only ===
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# === Ciphers and KEX — modern only ===
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512

# === Allowlist of users who can connect ===
AllowGroups ssh-bastion-users
```

### Step 2: Certificate-Based Authentication with Vault SSH Secrets Engine

Vault issues short-lived SSH certificates signed by a CA that target servers trust:

```bash
# On Vault: enable the SSH secrets engine.
vault secrets enable -path=ssh ssh

# Configure Vault as a CA for signing user certificates.
vault write ssh/config/ca generate_signing_key=true

# Get the public key (publish this on all target servers as TrustedUserCAKeys).
vault read -field=public_key ssh/config/ca > /etc/ssh/trusted_user_ca.pub

# Create a role for bastion users.
vault write ssh/roles/prod-access \
  key_type=ca \
  ttl=8h \
  max_ttl=8h \
  allowed_users="*" \
  allow_user_certificates=true \
  default_extensions='{"permit-pty":""}'

# Users request a certificate with their public key.
vault write ssh/sign/prod-access \
  public_key=@~/.ssh/id_ed25519.pub \
  valid_principals=$(whoami)
# Returns: signed_key (the certificate, valid for 8 hours)
```

Developer workflow:

```bash
# 1. Authenticate to Vault (with MFA/OIDC).
vault login -method=oidc

# 2. Sign your SSH public key.
vault write -field=signed_key ssh/sign/prod-access \
  public_key=@~/.ssh/id_ed25519.pub \
  valid_principals=$(vault token lookup -format=json | jq -r .data.display_name) \
  > ~/.ssh/id_ed25519-cert.pub

# 3. SSH to the bastion (presents the certificate automatically alongside the private key).
ssh -i ~/.ssh/id_ed25519 -i ~/.ssh/id_ed25519-cert.pub bastion.internal

# Or wrap in a helper script that renews the cert on each use.
```

On every target server, add the Vault CA public key:

```
# /etc/ssh/sshd_config on target servers
TrustedUserCAKeys /etc/ssh/trusted_user_ca.pub
AuthorizedKeysFile none          # Disable static keys entirely.
PasswordAuthentication no

# Only allow connections from the bastion IP.
AllowUsers *@10.0.1.5             # Bastion's internal IP only.
```

### Step 3: MFA on the Bastion with Google Authenticator PAM

```bash
# Install the PAM module.
apt install libpam-google-authenticator

# Configure users to set up TOTP (run as each user).
google-authenticator --time-based --disallow-reuse --force --rate-limit=3 --rate-time=30 --window-size=3

# /etc/pam.d/sshd
# Comment out the default auth line and add:
auth required pam_google_authenticator.so nullok    # nullok allows users who haven't set up TOTP yet; remove after rollout.
# auth required pam_google_authenticator.so        # Strict: no TOTP setup = no login.
```

With `AuthenticationMethods publickey,keyboard-interactive` in sshd_config:

1. User presents their SSH certificate (public key phase).
2. User is prompted for TOTP code (keyboard-interactive phase).
3. Both must succeed; either alone is insufficient.

For hardware key MFA (FIDO2/WebAuthn):

```bash
# Users generate a resident key on their hardware token.
ssh-keygen -t ecdsa-sk -O resident -O verify-required -f ~/.ssh/id_ecdsa_sk
```

```
# sshd_config: require hardware key verification for each connection.
PubkeyAuthOptions verify-required   # Requires user presence (touch) on hardware key.
AuthenticationMethods publickey     # Hardware key already provides MFA via presence check.
```

### Step 4: Session Recording with tlog or asciinema

Record every session on the bastion:

```bash
# Install tlog (Red Hat's session recorder; structured JSON output).
dnf install tlog

# Configure tlog in PAM to wrap every SSH session.
# /etc/pam.d/sshd — add before session close:
session required pam_exec.so /usr/libexec/tlog/tlog-rec-session

# Or use ForceCommand in sshd_config to wrap the shell:
# /etc/ssh/sshd_config
# ForceCommand tlog-rec-session
```

tlog records input, output, and timing to a JSON log:

```bash
# Replay a session.
tlog-play --file /var/log/tlog/session-alice-20260430T120000.json
```

For simpler setups, use script-based recording:

```bash
# In /etc/profile.d/session-record.sh (runs for every login shell):
SESSION_LOG="/var/log/sessions/$(date +%Y%m%d_%H%M%S)-${USER}-$$.log"
if [ -z "$ALREADY_RECORDING" ]; then
  export ALREADY_RECORDING=1
  exec script -qf "$SESSION_LOG" -c "${SHELL:-/bin/bash}"
fi
```

Forward session logs to your SIEM:

```bash
# filebeat config to ship tlog JSON logs.
filebeat.inputs:
  - type: log
    paths: ["/var/log/tlog/*.json"]
    json.keys_under_root: true
    json.add_error_key: true
output.elasticsearch:
  hosts: ["siem.internal:9200"]
```

### Step 5: Network Controls — Bastion as the Only SSH Path

Lock target servers to accept SSH only from the bastion:

```bash
# AWS: security group for target servers.
aws ec2 authorize-security-group-ingress \
  --group-id sg-target-servers \
  --protocol tcp \
  --port 22 \
  --source-group sg-bastion   # Only the bastion's security group.

# AWS: remove any 0.0.0.0/0 rule on port 22 from target servers.
aws ec2 revoke-security-group-ingress \
  --group-id sg-target-servers \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# nftables on target servers.
nft add rule inet filter input tcp dport 22 ip saddr 10.0.1.5 accept
nft add rule inet filter input tcp dport 22 drop
```

The bastion itself should only accept SSH from known IP ranges:

```bash
# Bastion security group: allow only corporate IP ranges + VPN.
aws ec2 authorize-security-group-ingress \
  --group-id sg-bastion \
  --protocol tcp \
  --port 22 \
  --cidr 203.0.113.0/24   # Corporate IP range.
```

### Step 6: ProxyJump Configuration

Users connect through the bastion transparently using `ProxyJump`:

```
# ~/.ssh/config on developer workstations
Host bastion
  HostName bastion.internal
  User %r
  IdentityFile ~/.ssh/id_ed25519
  CertificateFile ~/.ssh/id_ed25519-cert.pub
  ServerAliveInterval 60

Host prod-*
  User %r
  ProxyJump bastion
  IdentityFile ~/.ssh/id_ed25519
  CertificateFile ~/.ssh/id_ed25519-cert.pub

Host prod-app-1
  HostName 10.0.10.11

Host prod-db-1
  HostName 10.0.10.21
```

Connection:

```bash
ssh prod-app-1
# Transparently connects bastion -> prod-app-1 in one command.
# MFA prompt appears for the bastion authentication.
# The bastion does NOT forward the SSH agent; target servers trust the certificate.
```

### Step 7: Audit and Alerting

```bash
# Monitor failed auth attempts on the bastion.
journalctl -u ssh --since "1 hour ago" | grep "Failed\|Invalid\|Disconnected"

# Count login attempts per source IP.
grep "sshd" /var/log/auth.log | grep "Failed" | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
```

```
ssh_auth_attempt_total{result, user, src_ip}       counter
ssh_session_start_total{user}                      counter
ssh_session_duration_seconds{user}                 histogram
ssh_cert_issued_total{user, ttl}                   counter
ssh_cert_expired_attempt_total                     counter
mfa_failure_total{user}                            counter
```

Alert on:

- `mfa_failure_total` > 5 from the same user in 10 minutes — possible brute force on MFA.
- `ssh_cert_expired_attempt_total` non-zero — someone attempting to use an expired certificate.
- `ssh_auth_attempt_total` from unexpected source IPs — access from outside known ranges.
- Session recording gaps — any session without a corresponding tlog record.

## Expected Behaviour

| Signal | Unmanaged bastion | Hardened bastion |
|--------|------------------|-----------------|
| Stolen SSH private key validity | Indefinite (authorized_keys) | ≤8h (certificate TTL) |
| Bastion compromise yields target creds | Yes (agent forwarding) | No (agent forwarding disabled; certs expire) |
| Session forensics | Log correlation across servers | Centrally recorded; replayable from bastion |
| Target servers reachable directly | Yes (0.0.0.0/0 on port 22) | No (only bastion IP allowed) |
| Authentication factor count | 1 (SSH key) | 2 (SSH cert + TOTP/hardware key) |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Certificate auth (8h TTL) | Stolen key expires quickly | Users must re-sign key after 8h | Wrap in a script; Vault login + cert renewal takes <5s. |
| Session recording | Complete audit trail | Disk space for recordings; minor latency | Compress and ship to SIEM; retain locally for 7 days, SIEM for 90+. |
| Agent forwarding disabled | Bastion compromise doesn't cascade | Users must carry their cert to connect forward | ProxyJump with cert is the correct pattern; no agent forwarding needed. |
| Bastion as sole SSH path | Centralised control; single point to harden | Single point of failure | Bastion HA: two bastions in separate AZs; both behind a NLB. |
| MFA on bastion | Blocks stolen-key-only attacks | Additional step for every session | Acceptable for production access; TOTP takes 3s. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vault CA unavailable | SSH cert signing fails; users locked out | Vault health check fails; cert requests timeout | Vault HA; bastion emergency access via OOB console (AWS SSM, GCP serial). |
| Bastion host down | All SSH access to production blocked | Monitoring alert; engineers report login failures | HA bastion pair; or use cloud provider's OOB console for emergency. |
| MFA app lost (user) | User cannot authenticate | User reports; zero successful logins for that user | OOB recovery: provision scratch codes at setup; admin reset of TOTP secret. |
| Session recording fills disk | New sessions cannot start | `df` alert on bastion; SSH login errors | Archive old recordings to S3/GCS; increase disk or reduce local retention. |
| Target server SSH key mismatch after rotation | Connection refused; host key verification fails | SSH error: `REMOTE HOST IDENTIFICATION HAS CHANGED` | Update `~/.ssh/known_hosts`; use cert-based host auth to avoid this entirely. |
| Certificate expired mid-session | Session continues; next connection fails | Login error: `Permission denied (publickey)` | Re-sign the certificate; existing sessions are unaffected by expiry. |

## Related Articles

- [SSH Hardening](/articles/linux/ssh-hardening/)
- [FIDO2 SSH Authentication](/articles/linux/fido2-ssh/)
- [Production Access Management with Teleport and Boundary](/articles/cross-cutting/production-access-management/)
- [Kubernetes OIDC Authentication and kubectl Access Control](/articles/kubernetes/kubernetes-oidc-authentication/)
- [Zero-Trust Networking](/articles/cross-cutting/zero-trust-networking/)
