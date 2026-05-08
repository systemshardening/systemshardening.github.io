---
title: "SSH Certificate Authority: Short-Lived User Certificates and Host Verification"
description: "SSH key sprawl — hundreds of authorized_keys entries, no revocation — is eliminated by an SSH CA. The CA signs short-lived user certificates and host certificates, centralising trust and enabling instant revocation without touching individual servers."
slug: "ssh-certificate-authority"
date: 2026-05-01
lastmod: 2026-05-01
category: "linux"
tags: ["ssh", "certificate-authority", "pki", "short-lived-certificates", "access-control"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 295
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/linux/ssh-certificate-authority/index.html"
---

# SSH Certificate Authority: Short-Lived User Certificates and Host Verification

## Problem

Traditional SSH key management does not scale securely. The `authorized_keys` model distributes trust across every server: each host maintains its own list of permitted public keys. Adding access requires touching every server the user needs. Revoking access requires removing the key from every `authorized_keys` file — a process that is slow, error-prone, and frequently incomplete.

The real-world consequence: employees who have left the organisation still have working SSH keys on servers nobody audited. Keys issued for a one-off task years ago are still valid because nobody tracked them. There is no central view of who has SSH access to what.

SSH Certificate Authorities solve this by centralising trust. Instead of distributing keys to `authorized_keys`, servers trust a CA public key. Users authenticate with certificates signed by that CA. Revoking a user's access means revoking their certificate — no changes to individual servers required.

Short-lived certificates (4–24 hour validity) are the strongest form: even if a certificate is stolen, it expires quickly. There is no revocation infrastructure needed when certificates expire before an attacker can use them for more than a day.

Additional problems SSH CAs solve:

- **Host impersonation.** Users who blindly accept host key prompts are vulnerable to MITM. Host certificates eliminate the prompt — clients verify the host's certificate against the trusted CA, the same way HTTPS works.
- **Key rotation.** Rotating long-lived SSH keys requires pushing new public keys to all servers. Certificate renewal happens at the CA; servers need no changes.
- **Audit trail.** Certificate issuance is logged at the CA. Who requested a certificate, for what principal, at what time — all recorded centrally.

**Target systems:** OpenSSH 7.3+ (certificate principals, host certificates, revocation via `TrustedUserCAKeys`); HashiCorp Vault SSH Secrets Engine; Smallstep `step-ca` for automated issuance; AWS EC2 Instance Connect (managed SSH CA).

## Threat Model

- **Adversary 1 — Stale key from departed employee:** An employee leaves. Their SSH public key remains in `authorized_keys` on 40 servers. Three months later, after their laptop is sold and their private key is extracted, an attacker uses it.
- **Adversary 2 — Stolen long-lived certificate:** An attacker compromises a developer's workstation and steals their SSH private key. With no expiry on the key, the attacker has permanent SSH access to all servers the key authorises.
- **Adversary 3 — Host impersonation MITM:** An attacker redirects SSH traffic from a developer to an attacker-controlled host. The developer accepts the unknown host key fingerprint. The attacker captures credentials and proxies the session.
- **Adversary 4 — Insider privilege escalation via key addition:** A developer adds their own public key to `authorized_keys` on a production server they should not have access to. Without centralised authorisation, this goes undetected.
- **Adversary 5 — Certificate principal bypass:** A certificate is issued with an overly broad principal list. An attacker who obtains the certificate uses it to log in as `root` on systems that trust the CA.
- **Access level:** Adversaries 1 and 2 have a valid private key. Adversary 3 is on-path. Adversary 4 has non-root write access. Adversary 5 obtains a certificate with excessive principals.
- **Objective:** Persistent SSH access to infrastructure; lateral movement; credential exfiltration.
- **Blast radius:** SSH access to a production server with stale keys or broad principals provides a foothold for lateral movement across all servers accessible from that host.

## Configuration

### Step 1: Generate the SSH CA Key Pair

```bash
# Generate the CA key pair. Store the private key in an HSM or secrets manager.
# This key signs all user and host certificates — protect it accordingly.

# User CA — signs user certificates.
ssh-keygen -t ed25519 -f /etc/ssh/ca/user_ca -C "user-ca@example.com" -N ""
# Private key: /etc/ssh/ca/user_ca  (KEEP OFFLINE or in HSM)
# Public key:  /etc/ssh/ca/user_ca.pub (distribute to all SSH servers)

# Host CA — signs host certificates.
ssh-keygen -t ed25519 -f /etc/ssh/ca/host_ca -C "host-ca@example.com" -N ""
# Private key: /etc/ssh/ca/host_ca  (KEEP OFFLINE or in HSM)
# Public key:  /etc/ssh/ca/host_ca.pub (distribute to all SSH clients via known_hosts)

# Store private keys in Vault (never leave them on a general-purpose server).
vault write sys/policies/acl/ssh-ca-policy \
  policy='path "secret/ssh-ca/*" { capabilities = ["read"] }'

vault kv put secret/ssh-ca/user_ca \
  private_key=@/etc/ssh/ca/user_ca

# Shred local copies after loading into Vault.
shred -u /etc/ssh/ca/user_ca
```

### Step 2: Configure SSH Servers to Trust the CA

```bash
# On every SSH server — add to sshd_config.
cat >> /etc/ssh/sshd_config << 'EOF'

# Trust user certificates signed by this CA.
TrustedUserCAKeys /etc/ssh/user_ca.pub

# Certificate principals are the SSH login username.
# Certificates must contain a principal matching the login user.
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u

# Disable authorized_keys entirely (enforce CA-only auth).
AuthorizedKeysFile none

# Host certificate — server presents this to clients.
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
EOF

# Distribute the user CA public key to all servers.
# (Done once; not per-user — this is the CA's power.)
cp /etc/ssh/ca/user_ca.pub /etc/ssh/user_ca.pub
chmod 644 /etc/ssh/user_ca.pub

systemctl restart sshd
```

### Step 3: Define Principals per Server

Principals control which certificate principals are accepted on each host. Restrict tightly:

```bash
# /etc/ssh/auth_principals/ubuntu   (for login as 'ubuntu')
# List of valid certificate principals that may log in as 'ubuntu'.
mkdir -p /etc/ssh/auth_principals
echo "production-engineer" > /etc/ssh/auth_principals/ubuntu
echo "sre-oncall"         >> /etc/ssh/auth_principals/ubuntu

# /etc/ssh/auth_principals/root
# Nobody should log in as root via SSH. Keep this file empty or absent.
# If needed for break-glass:
echo "emergency-root-access" > /etc/ssh/auth_principals/root
```

Use configuration management to maintain principals consistently:

```yaml
# Ansible task: deploy principal files from central inventory.
- name: Deploy SSH principals
  copy:
    content: "{{ item.principals | join('\n') }}\n"
    dest: "/etc/ssh/auth_principals/{{ item.user }}"
    mode: "0644"
  loop:
    - user: ubuntu
      principals: ["production-engineer", "sre-oncall"]
    - user: deploy
      principals: ["ci-deploy"]
```

### Step 4: Issue Short-Lived User Certificates

```bash
# Issue a certificate valid for 8 hours, with a specific principal.
# Run at the CA or via Vault SSH Secrets Engine.

issue_user_cert() {
  local USERNAME=$1
  local PRINCIPAL=$2
  local PUBKEY=$3
  local VALIDITY="8h"

  ssh-keygen -s /etc/ssh/ca/user_ca \
    -I "cert-${USERNAME}-$(date +%Y%m%d-%H%M%S)" \  # Certificate identity (logged).
    -n "$PRINCIPAL" \                                  # SSH principal (must match server).
    -V "+${VALIDITY}" \                               # Validity: 8 hours from now.
    -O no-agent-forwarding \                          # Disable agent forwarding.
    -O no-port-forwarding \                           # Disable port forwarding.
    -O no-x11-forwarding \                            # Disable X11 forwarding.
    "$PUBKEY"

  # Log the issuance.
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) issued cert to $USERNAME (principal=$PRINCIPAL, validity=$VALIDITY)" \
    >> /var/log/ssh-ca/issuance.log
}

# Example: issue cert for alice.
issue_user_cert alice production-engineer /tmp/alice_ed25519.pub
# Produces: /tmp/alice_ed25519-cert.pub
```

### Step 5: HashiCorp Vault SSH Secrets Engine (Automated Issuance)

Vault automates certificate issuance with authentication and audit:

```bash
# Enable the SSH secrets engine.
vault secrets enable -path=ssh-user ssh

# Configure the CA (using the CA key stored in Vault).
vault write ssh-user/config/ca \
  private_key=@/etc/ssh/ca/user_ca \
  public_key=@/etc/ssh/ca/user_ca.pub

# Define a role for production engineers.
vault write ssh-user/roles/production-engineer \
  key_type=ca \
  allowed_users="ubuntu" \
  default_user="ubuntu" \
  allowed_extensions="permit-pty" \
  default_extensions='{"permit-pty": ""}' \
  ttl=8h \
  max_ttl=24h \
  allowed_critical_options="" \
  allow_user_certificates=true

# Policy: allow production-engineers to request certs.
vault policy write ssh-production-engineer - << 'EOF'
path "ssh-user/sign/production-engineer" {
  capabilities = ["create", "update"]
}
EOF

# Assign policy to an OIDC group.
vault write auth/oidc/role/production-engineer \
  groups_claim="groups" \
  bound_audiences="vault" \
  allowed_redirect_uris="https://vault.internal/ui/vault/auth/oidc/oidc/callback" \
  token_policies="ssh-production-engineer"
```

```bash
# Developer workflow: request a certificate via Vault.
# Authenticate to Vault (via SSO).
vault login -method=oidc

# Sign the public key.
vault write -field=signed_key ssh-user/sign/production-engineer \
  public_key=@~/.ssh/id_ed25519.pub \
  > ~/.ssh/id_ed25519-cert.pub

# Verify the certificate.
ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub

# Connect — certificate used automatically.
ssh ubuntu@prod-server-01.example.com
```

### Step 6: Host Certificates (Eliminate Host Key Prompts)

```bash
# Sign host public keys with the host CA.
# Run for every SSH server.

sign_host_cert() {
  local HOSTNAME=$1
  local HOST_PUBKEY=$2

  ssh-keygen -s /etc/ssh/ca/host_ca \
    -I "host-${HOSTNAME}" \
    -h \                       # -h: this is a host certificate.
    -n "$HOSTNAME,$(dig +short $HOSTNAME)" \  # Principals: hostname and IP.
    -V "+52w" \                # Host certs: 1-year validity (longer than user certs).
    "$HOST_PUBKEY"
}

# On each server: sign the host key.
sign_host_cert prod-server-01.example.com /etc/ssh/ssh_host_ed25519_key.pub
# Produces: /etc/ssh/ssh_host_ed25519_key-cert.pub

# Add HostCertificate to sshd_config (done in Step 2).
```

```bash
# On SSH clients: trust the host CA (once, for all hosts).
# ~/.ssh/known_hosts
# Add this line — @cert-authority means trust certificates signed by this key.
echo "@cert-authority *.example.com $(cat /etc/ssh/ca/host_ca.pub)" \
  >> ~/.ssh/known_hosts

# Now connecting to any *.example.com host presents a host certificate.
# Client verifies the certificate against the CA — no fingerprint prompt.
ssh prod-server-01.example.com   # No "authenticity of host" prompt.
```

### Step 7: Certificate Revocation

Short-lived certs reduce the need for revocation, but for immediate action:

```bash
# Create a Key Revocation List (KRL) for compromised certificates.
ssh-keygen -k \
  -f /etc/ssh/revoked_keys \
  -s /etc/ssh/ca/user_ca.pub \
  /tmp/compromised-cert.pub   # The specific cert to revoke.

# Add to sshd_config on all servers.
echo "RevokedKeys /etc/ssh/revoked_keys" >> /etc/ssh/sshd_config

# Distribute the updated KRL to all servers.
ansible all -m copy \
  -a "src=/etc/ssh/revoked_keys dest=/etc/ssh/revoked_keys mode=0644" \
  --become

# Alternatively: via Vault, revoke the lease that issued the certificate.
vault lease revoke <lease_id>
# Next cert request from that user requires re-authentication.
```

### Step 8: Telemetry

```
ssh_ca_certificates_issued_total{principal, issuer, validity}    counter
ssh_ca_issuance_failures_total{reason}                           counter
ssh_cert_auth_total{server, principal, result}                   counter
ssh_key_auth_total{server, result}                               counter  # Should be 0 if AuthorizedKeysFile=none
ssh_ca_cert_age_seconds{server, host}                            gauge
ssh_revoked_certs_total{}                                        gauge
```

Alert on:

- `ssh_key_auth_total` non-zero — a server is accepting key-based auth despite policy; `authorized_keys` may not be disabled on all servers.
- `ssh_ca_cert_age_seconds` > 86400 for host certificates — host cert expired; clients will see verification failure on next connection.
- `ssh_ca_issuance_failures_total` spike — CA signing failures; check Vault or CA key availability.
- `ssh_cert_auth_total{result="rejected"}` spike from a single `principal` — possible stolen certificate attempt or principal misconfiguration.

## Expected Behaviour

| Signal | authorized_keys model | SSH CA model |
|--------|----------------------|--------------|
| Employee offboarding | Must remove key from every server | Revoke certificate or let 8h TTL expire; zero server changes |
| Host impersonation | User accepts unknown fingerprint | Host certificate verified against CA; no prompt |
| Key from 2 years ago | Still valid, likely forgotten | Certificate expired after 8h; never persists |
| Access audit | No central view | CA issuance log shows who got access to what |
| New server added | Push all authorised keys | Add `TrustedUserCAKeys`; inherits all CA trust |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Short-lived certs (8h TTL) | Stolen cert expires quickly; no revocation needed | Users must re-issue cert each day | Vault + OIDC SSO makes re-issuance a single command |
| `AuthorizedKeysFile none` | Eliminates stale key risk entirely | Emergency access requires break-glass | Keep one emergency key on a bastion; document break-glass procedure |
| Host certificates | Eliminates fingerprint-prompt TOFU | Host CA must be maintained and distributed | Single `known_hosts` CA entry covers all hosts; low maintenance |
| Centralised issuance (Vault) | Full audit trail; policy enforcement | Vault is a dependency for SSH access | Vault HA; break-glass via direct CA access from jump host |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vault unavailable | Users cannot get new certificates; connections fail after cert expiry | Vault health check; `ssh_ca_issuance_failures_total` | Vault HA; extend cert TTL to 24h as temporary workaround |
| Host cert expired | SSH clients reject connection; "Host key verification failed" | `ssh_ca_cert_age_seconds` alert | Re-sign host certificate; distribute to server; reload sshd |
| Principal misconfiguration | User cert issued with wrong principal; login rejected | Auth failure log; `ssh_cert_auth_total{result="rejected"}` | Reissue certificate with correct principal matching server's auth_principals |
| CA private key compromise | Attacker can issue arbitrary certificates | Security event | Rotate CA key pair; re-sign all host certs; update `TrustedUserCAKeys` on all servers |

## Related Articles

- [SSH Hardening](/articles/linux/ssh-hardening/)
- [FIDO2 for SSH Authentication](/articles/linux/fido2-ssh/)
- [SSH Bastion Hardening](/articles/network/ssh-bastion-hardening/)
- [PAM Hardening](/articles/linux/pam-hardening/)
- [Production Access Management](/articles/cross-cutting/production-access-management/)
