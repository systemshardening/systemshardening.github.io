---
title: "FIDO2 SSH with sk-* Keys: Hardware-Backed Authentication for Production Hosts"
description: "ed25519-sk and ecdsa-sk bind SSH keys to a hardware token. Phishing-resistant, exfiltration-proof, increasingly the default. Two short commands to switch."
slug: "fido2-ssh"
date: 2026-04-27
lastmod: 2026-04-27
category: "linux"
tags: ["ssh", "fido2", "yubikey", "passkey", "openssh", "linux"]
personas: ["systems-engineer", "security-engineer", "platform-engineer"]
article_number: 199
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/linux/fido2-ssh/index.html"
---

# FIDO2 SSH with sk-* Keys: Hardware-Backed Authentication for Production Hosts

## Problem

Standard SSH keys live on disk. The private key is a file: `~/.ssh/id_ed25519`. Anything that can read that file (a backup tool, a misconfigured Slack share, a developer laptop compromise, an `rsync` mistake) can copy the key. Once copied, the key is indistinguishable from the original — every host that trusts the public key trusts the copy.

Mitigations exist (encrypted private keys with passphrases, ssh-agent forwarding) but each has gaps. A passphrase protects against passive theft of the file but does not stop a compromised process that captures the passphrase from the user's terminal. Agent forwarding is a known phishing vector and effectively trusts every intermediate hop.

OpenSSH 8.2+ (February 2020) added `sk-*` key types — Security Key SSH keys — that bind the private key to a hardware token (YubiKey, SoloKey, Token2, Nitrokey, Google Titan, or any FIDO2/U2F device). The private key never exists in unprotected memory or on disk. Each authentication requires the user to physically touch the token, which a remote attacker cannot satisfy.

By 2026 the toolchain is universal:

- OpenSSH 9.x default-supports both `ed25519-sk` and `ecdsa-sk` (NIST P-256).
- Most major Linux distros (Ubuntu 22.04+, RHEL 9+, Debian 12+) ship with `libfido2` and the helpers needed.
- Hardware tokens are available for $25-$70.
- Cloud providers' bastion hosts (AWS Session Manager, GCP IAP, Azure Bastion) interoperate with `sk-*` keys via standard OpenSSH on the user side.

Despite the maturity, a substantial fraction of production fleets still allow plain `ed25519` keys. The migration is mechanically trivial: generate a new `sk-*` key, add to `authorized_keys`, deprecate the old key. The friction is operational discipline, not technical.

This article covers `sk-*` key generation, server-side configuration to require hardware-backed keys, multi-token enrollment patterns, integration with SSH certificate authorities, and the failure modes (token loss, FIDO2 firmware bugs, host compatibility).

**Target systems:** OpenSSH 9.x server and client, FIDO2-capable hardware tokens (YubiKey 5+, SoloKey 2+, Token2, Nitrokey 3+, Google Titan), Linux 5.4+ with libfido2 support, macOS 13+, Windows 11 + WSL.

## Threat Model

- **Adversary 1 — Filesystem theft of private key:** attacker exfiltrates `~/.ssh/id_ed25519` from a compromised laptop, a leaked backup, an open share. Wants to authenticate as the user.
- **Adversary 2 — Memory scraping:** malware running as the user reads ssh-agent's in-memory key material (or future fork via `ptrace`).
- **Adversary 3 — Phishing-style remote attack:** attacker compromises a host the user has agent-forwarded to. The forwarded socket allows the attacker to authenticate elsewhere as the user.
- **Adversary 4 — Coerced sign:** attacker has physical access to the user's machine. Wants to sign with the user's key.
- **Adversary 5 — Server-side key trust drift:** an old, unrotated key remains in `authorized_keys` on legacy hosts long after the key was compromised.
- **Access level:** Adversaries 1-3 are remote / software-only. Adversary 4 has physical access. Adversary 5 is the result of poor key lifecycle.
- **Objective:** Authenticate as the user against any host that trusts the user's public key.
- **Blast radius:** With on-disk keys: every host trusting the key is reachable. With `sk-*` keys: zero — without the hardware token, the private key is unrecoverable.

## Configuration

### Step 1: Generate `sk-*` Keys

```bash
# ed25519-sk requires a FIDO2 token. Insert it before running.
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -O application=ssh:production \
  -C "you@laptop, 2026-04-27"
# Tap the token when it blinks.
# Generates ~/.ssh/id_ed25519_sk and ~/.ssh/id_ed25519_sk.pub
```

Key options:

- `-O resident` — store the key handle on the token itself (rather than only on disk). This lets you recover the credential on a fresh laptop by enumerating the token. Without `resident`, losing the on-disk key handle means losing access.
- `-O verify-required` — require user verification (PIN entry, fingerprint) on every authentication. Without this, just a touch is required. For high-trust hosts, require verification.
- `-O application=ssh:production` — namespace the credential. Different `application` strings produce different keys on the same hardware token.

The public key file looks like:

```
sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t... you@laptop, 2026-04-27
```

The `sk-` prefix and `@openssh.com` suffix are the markers that tell the server "this key is hardware-backed."

### Step 2: Enroll on Production Hosts

Standard `authorized_keys` workflow:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519_sk.pub user@host.example.com
```

Or via your existing key-distribution mechanism (Ansible, Puppet, Vault SSH CA, Teleport).

### Step 3: Server-Side: Require Hardware-Backed Keys

OpenSSH server can refuse non-`sk-*` keys via `PubkeyAcceptedAlgorithms`:

```
# /etc/ssh/sshd_config.d/60-fido2-only.conf
PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com
```

Reload sshd and verify:

```bash
sudo sshd -T | grep pubkeyacceptedalgorithms
# pubkeyacceptedalgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com
sudo systemctl reload ssh
```

Existing on-disk keys now fail to authenticate; only hardware-backed keys are accepted.

For phased rollout (allow both during migration):

```
PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ssh-ed25519
```

After migration deadline, remove `ssh-ed25519` and reload.

### Step 4: Require User Verification (PIN / Biometric)

The client `verify-required` option on key generation can be enforced server-side: the server can demand `verify-required` keys via `PubkeyAuthOptions`:

```
# /etc/ssh/sshd_config.d/60-fido2-verify.conf
PubkeyAuthOptions verify-required
```

A key generated without `-O verify-required` will fail authentication against this server. Use for production hosts holding sensitive data; user-verification adds 1-2 seconds of friction per authentication, which is fine for production access but expensive for high-frequency CI use.

### Step 5: Enroll Multiple Tokens (Backup)

A single token is a single point of failure. Enroll at least one backup token; some teams enroll three (primary, backup-laptop, recovery-vault).

```bash
# Repeat key generation with the second token.
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -O application=ssh:production-backup \
  -f ~/.ssh/id_ed25519_sk_backup \
  -C "you@laptop-backup, 2026-04-27"

# Append both public keys to authorized_keys on every host.
cat ~/.ssh/id_ed25519_sk.pub ~/.ssh/id_ed25519_sk_backup.pub | \
  ssh-copy-id -f -i /dev/stdin user@host
```

Update each host's `authorized_keys` to trust both. Lose one token, the other still authenticates.

### Step 6: Integrate with SSH Certificate Authority

For fleets larger than a handful of hosts, individual `authorized_keys` distribution is unmanageable. Use an SSH CA: a central authority signs short-lived certificates derived from the user's `sk-*` key.

```bash
# CA signs the user's sk-* public key.
ssh-keygen -s ca_key -I "user-cert-2026-04-27" \
  -n alice -V +24h \
  -O verify-required \
  ~/.ssh/id_ed25519_sk.pub
# Produces ~/.ssh/id_ed25519_sk-cert.pub
```

Hosts trust the CA's public key (one entry in `/etc/ssh/sshd_config`):

```
TrustedUserCAKeys /etc/ssh/ca_user.pub
```

Now any user with a valid certificate signed by the CA authenticates — regardless of whether the host has the user's individual key on file. The certificate's `verify-required` option propagates to the server, which enforces hardware verification.

For automation, integrate with HashiCorp Vault's SSH secrets engine or Teleport's CA, both of which support certificate-based hardware-backed SSH out of the box.

### Step 7: Remove Legacy Keys

After migration, audit and purge old keys:

```bash
# On each host, list non-sk keys still trusted.
for host in $(cat hosts.txt); do
  ssh "$host" "awk '!/sk-ssh-ed25519|sk-ecdsa-sha2-nistp256/{print FILENAME, NR, \$1}' \
    /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null"
done

# After confirming only legitimate operator keys remain, replace the file:
echo "operator-1-public-key sk-ssh-ed25519..." | ssh "$host" "tee ~/.ssh/authorized_keys"
```

Keep the old key trust window short (1-2 weeks). The longer it lingers, the more likely a stolen key gets used.

## Expected Behaviour

| Signal | On-disk keys | `sk-*` keys |
|--------|--------------|-------------|
| Backup containing the key | Authenticatable by anyone with the backup | Useless without the hardware token |
| Phishing / malicious script reads key | Succeeds | Fails (no key on disk to read) |
| User authentication | Type passphrase | Tap or PIN-and-tap on hardware |
| Authentication latency | <100ms | 200-500ms (touch + verify) |
| Key rotation requirement | Periodic | Tied to token replacement (rare) |
| Forwarded agent risk | Compromised hop authenticates as user | Compromised hop cannot generate fresh signature without token |

Verify the protection holds:

```bash
# Server log on successful authentication.
sudo journalctl -u ssh | grep "Accepted publickey" | tail -1
# Apr 27 10:00:00 server sshd[1234]: Accepted publickey for alice from 1.2.3.4 port 56789 ssh2:
#   ED25519-SK SHA256:AbCdE...

# Negative test: try a stolen-key scenario.
# Copy ~/.ssh/id_ed25519_sk to a different machine.
# Without the original token, ssh attempts fail at signing time:
ssh user@host
# (no token detected) sign_and_send_pubkey: signing failed for ED25519-SK from agent: agent refused operation
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Hardware-backed keys | Defeats key-theft attacks | Token cost ($25-$70 per device); user must carry it | Issue tokens as part of hardware onboarding; bulk-purchase. |
| `verify-required` | Defeats stolen-token attacks (PIN required) | 1-2 second friction per authentication | Apply to production / sensitive hosts; allow touch-only for low-risk hosts. |
| Multi-token enrollment | Survives token loss | Extra setup per user | Document the recovery flow; second token kept in secure off-laptop location. |
| SSH CA + certificates | Centralized trust; short-lived authority | CA infrastructure to operate | Use Vault, Teleport, or smallstep — managed CA tooling. |
| Strict server-side `PubkeyAcceptedAlgorithms` | Eliminates legacy key paths | Migration window required for users without tokens yet | Phase rollout: warning logs, then dual-allow, then strict. |
| Audit and purge legacy keys | Closes the trust-drift gap | Operational work to track keys | Use SSH key inventory tools (ssh-audit, ansible facts) to enumerate. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Token lost or broken | User cannot authenticate to anything | User reports inability to access systems | Use the backup token. Generate new credentials with the new token, distribute. The lost token is effectively useless to a finder (still requires PIN). |
| Token firmware bug | Authentication fails or hangs at the touch step | OS logs show `libfido2` errors | Update token firmware via vendor tooling. Keep a backup token of a different vendor / model to mitigate model-specific bugs. |
| Resident key collision | Multiple credentials with same `application` namespace get confused | Wrong credential selected on auth attempt | Use distinct `application` strings (`ssh:prod`, `ssh:staging`); token enumerates by application name. |
| Host doesn't support sk-* (pre-OpenSSH-8.2) | sk-* keys cannot authenticate to legacy hosts | Auth log shows "no matching algorithm" | Upgrade OpenSSH; for hosts that cannot upgrade (vendor appliances), maintain a separate, restricted-use legacy key path with strict access controls. |
| `verify-required` not enforced | Host accepts touch-only authentication when PIN was expected | Audit log shows authentications without UV flag | Use `PubkeyAuthOptions verify-required` server-side; log and alert on any authentication without UV. |
| User stuck without backup token | Single-point-of-failure during outage | User unable to access hosts during incident | Always enroll at least one backup. For high-availability accounts (on-call SRE), three tokens distributed across home/laptop/safe. |
| OS doesn't have libfido2 | Client cannot use sk-* keys | Client-side error: "could not load library libfido2.so" | Install libfido2 (`apt install libfido2-1` on Debian / Ubuntu); for older systems, build from source or use a different client machine. |

## Related Articles

- [SSH Hardening for Production Servers](/articles/linux/ssh-hardening/)
- [Secure Cloud VM Access Patterns](/articles/linux/secure-cloud-vm-access/)
- [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/)
- [Hardening the Linux Kernel Attack Surface with sysctl](/articles/linux/sysctl-kernel-hardening/)
- [PAM Hardening for Production Linux](/articles/linux/pam-hardening/)
