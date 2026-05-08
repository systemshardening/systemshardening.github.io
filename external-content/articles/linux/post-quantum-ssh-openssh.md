---
title: "Post-Quantum SSH: Hybrid ML-KEM Key Exchange and ML-DSA Host Keys with OpenSSH 9.0+"
description: "OpenSSH 9.0 shipped sntrup761x25519 hybrid key exchange, and OpenSSH 9.9 adds ML-KEM-768 support. Harvest-now-decrypt-later attacks make upgrading SSH key exchange urgent for long-lived sensitive sessions. This guide migrates SSH infrastructure to hybrid PQC key exchange, updates host key algorithms, and deploys client configuration for organisations managing hundreds of servers."
slug: post-quantum-ssh-openssh
date: 2026-05-08
lastmod: 2026-05-08
category: linux
tags:
  - post-quantum
  - ssh
  - openssh
  - ml-kem
  - hybrid-cryptography
personas:
  - security-engineer
  - platform-engineer
article_number: 633
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/linux/post-quantum-ssh-openssh/
---

# Post-Quantum SSH: Hybrid ML-KEM Key Exchange and ML-DSA Host Keys with OpenSSH 9.0+

## Problem

SSH secures the control plane for virtually every serious infrastructure deployment. When you log into a production server, push a configuration change via Ansible, or pull secrets from Vault over a bastion, SSH is the channel carrying that trust. Today, all of that is protected by classical cryptography: ECDH P-256 or Curve25519 for key exchange, RSA or Ed25519 for host and user keys.

Classical asymmetric cryptography — ECDH, RSA, ECDSA — is broken by Shor's algorithm running on a cryptographically relevant quantum computer (CRQC). No CRQC exists at scale yet, but the timeline is compressing. NIST completed its first post-quantum cryptography standardisation round in 2024, producing FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). The existence of these standards signals that planning for quantum-capable adversaries is an engineering requirement, not a thought experiment.

The specific threat is **harvest-now-decrypt-later (HNDL)**. A nation-state adversary does not need a CRQC today to benefit from post-quantum cryptography failing. They need only to record encrypted traffic now and store it until a CRQC is available. Long-lived sensitive sessions — SSH connections to production infrastructure, secrets management systems, or financial core systems — are the highest-priority targets because the information they carried is often still sensitive years later. A session transcript from today that is decrypted in 2032 may still contain usable credentials, configuration details, or strategic information.

HNDL is not theoretical. Intelligence agencies with the budget and mandate to protect national secrets have operated bulk traffic collection infrastructure for decades. SSH sessions to government, financial, and critical infrastructure targets are obvious collection priorities.

SSH has three cryptographic components that need PQC hardening:

1. **Key exchange (KEX)** — the most urgent. This is where the shared session key is established at connection setup. If the key exchange is captured today and broken with a CRQC later, the entire session can be decrypted retroactively. A single passive recording is sufficient for an HNDL attack.

2. **Host key algorithms** — server authentication. The host presents a signed certificate or public key to prove its identity. A future quantum attacker who can break ECDSA or Ed25519 could forge host authentication, enabling active man-in-the-middle attacks. This is a concern for traffic captured today only if the connection negotiation itself is recorded; for active attacks, a CRQC is needed in real time.

3. **User authentication keys** — client identity. If a stored user private key is later broken by a CRQC, the attacker gains the ability to authenticate as that user. Less immediately urgent than KEX (requires recovering the private key, not just captured traffic), but part of a complete PQC migration.

**OpenSSH PQC timeline:**

- OpenSSH 8.5 (March 2021): introduced `sntrup761x25519-sha512@openssh.com`, a hybrid of NTRU Prime sntrup761 and X25519
- OpenSSH 9.0 (April 2022): made `sntrup761x25519-sha512@openssh.com` the **default** first-preference KEX algorithm, making it the most widely deployed post-quantum SSH algorithm in the world
- OpenSSH 9.9 (October 2024): added `mlkem768x25519-sha256`, the NIST-standardised ML-KEM-768 hybrid

The distinction between `sntrup761` and `mlkem768x25519` matters for compliance-sensitive environments. `sntrup761` (NTRU Prime) is not a NIST-standardised algorithm. It provides quantum resistance, but it is not covered by FIPS 203. For any environment subject to FIPS compliance, FedRAMP, or equivalent frameworks that require NIST-approved algorithms, `mlkem768x25519-sha256` is the correct choice, not `sntrup761x25519-sha512`.

For environments without strict algorithm compliance requirements, `sntrup761x25519-sha512` is already widely deployed and provides meaningful quantum resistance today. The practical recommendation is to prefer `mlkem768x25519-sha256` where OpenSSH 9.9+ is available on both client and server, and retain `sntrup761x25519-sha512` as a second preference for clients that have not yet upgraded.

## Threat Model

- **Adversary 1 — Nation-state HNDL collector:** A state intelligence service operates packet capture infrastructure at internet exchange points, peering connections, or via legal interception orders against cloud providers and telcos. It records encrypted SSH sessions to government contractors, financial institutions, or critical infrastructure operators. Today's traffic is stored for future decryption once a CRQC becomes available. This adversary does not need to be present at the time of decryption; bulk storage is sufficient.

- **Adversary 2 — Insider with long-term network tap access:** An insider at a managed service provider, large enterprise, or government agency has access to network recording infrastructure. The insider exfiltrates SSH session recordings targeting specific high-value accounts. The recordings sit on offline storage until quantum capability is acquired or contracted.

- **Adversary 3 — Post-quantum active attacker (future):** In 5-10 years, an adversary gains access to a CRQC (via nation-state development or a future quantum computing service). This adversary can now break all previously recorded ECDH key exchanges retroactively and can also forge classical ECDSA/RSA host key signatures for active MitM attacks in real time. Organisations that have not migrated to PQC key exchange by this point expose all their historical session transcripts.

- **Objective:** Decrypt SSH sessions — specifically to recover command output, credentials passed over SSH tunnels, secret payloads, and lateral movement paths through infrastructure.

- **Blast radius:** An unprotected SSH session to a secrets management bastion could yield API keys, database passwords, or signing keys. An SSH session to a CI/CD controller could yield deployment credentials or code signing keys. Long-lived multiplexed sessions are especially valuable because they carry more data per captured handshake.

- **Mitigations address:** Adversaries 1 and 2 are defeated by PQC key exchange — even if the session is recorded, the session key cannot be recovered by breaking the key exchange algorithm. Adversary 3 is defeated by deploying PQC key exchange now, before the CRQC becomes available.

## Configuration

### Checking Your OpenSSH Version and PQC Support

Before making any configuration changes, verify which OpenSSH version is running and which PQC KEX algorithms it supports:

```bash
ssh -V
# OpenSSH_9.9p1, OpenSSL 3.3.1 4 Jun 2024

# Check which KEX algorithms are available
ssh -Q kex
# Should include:
# sntrup761x25519-sha512@openssh.com
# mlkem768x25519-sha256   (OpenSSH 9.9+)

# Filter for PQC algorithms specifically
ssh -Q kex | grep -E "mlkem|sntrup"
```

On the server side:

```bash
# Check effective server configuration
sudo sshd -T | grep -i kex
# kexalgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,...

# Check OpenSSH server version
sshd -V 2>&1 || ssh -V
```

If `mlkem768x25519-sha256` does not appear in `ssh -Q kex` output, the client or server is running OpenSSH older than 9.9. In that case, `sntrup761x25519-sha512@openssh.com` is the best available PQC option.

### Server-Side sshd_config: PQC Key Exchange

Add a drop-in configuration file to prefer PQC KEX algorithms:

```bash
# /etc/ssh/sshd_config.d/50-pqc-kex.conf

# Prefer ML-KEM-768 hybrid (NIST FIPS 203) first.
# Fall back to sntrup761x25519 for OpenSSH 9.0-9.8 clients.
# Retain classical algorithms for clients that cannot do PQC.
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
```

Algorithm rationale:

| Algorithm | Type | Notes |
|-----------|------|-------|
| `mlkem768x25519-sha256` | PQC hybrid (ML-KEM-768 + X25519) | NIST FIPS 203; requires OpenSSH 9.9+ on both sides |
| `sntrup761x25519-sha512@openssh.com` | PQC hybrid (NTRU Prime + X25519) | Default since OpenSSH 9.0; not NIST-standardised |
| `curve25519-sha256` | Classical | Recommended classical fallback; constant-time |
| `ecdh-sha2-nistp256` | Classical | NIST P-256; retain for HSM/appliance compatibility |
| `diffie-hellman-group-exchange-sha256` | Classical | Legacy fallback only; prefer removing in a second pass |

After modifying the configuration, validate and reload:

```bash
sudo sshd -t && sudo systemctl reload ssh
```

For environments that want to enforce PQC-only connections (removing classical fallback entirely), first confirm that every client in your fleet supports PQC KEX — this is a migration-breaking change:

```bash
# PQC-only — do not deploy until all clients are confirmed compatible
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com
```

### Updating SSH Host Keys

Host keys authenticate the server to the client. Classical RSA and ECDSA host keys are vulnerable to a future quantum attacker performing active MitM (Adversary 3 above). Ed25519 host keys are not quantum-safe either — all elliptic curve discrete log-based algorithms are broken by Shor's algorithm.

The current OpenSSH landscape for host keys:

- **OpenSSH does not yet ship a native ML-DSA host key type.** ML-DSA (FIPS 204, formerly Dilithium) host key support is on the OpenSSH development roadmap but had not been merged into a stable release as of early 2026. Watch the `openssh-unix-dev` mailing list and OpenSSH release notes.
- **Ed25519 host keys are the current best practice for the classical component.** They are more resistant to implementation-level attacks than RSA or ECDSA and are faster. They do not provide PQC security, but they are the right classical choice to pair with PQC key exchange.
- **The most impactful change you can make today is upgrading KEX, not host keys.** HNDL attacks against SSH primarily target the session key established in key exchange. Host key compromise requires an active MitM at connection time, which demands a real-time CRQC — a more demanding capability than a CRQC used offline against stored ciphertexts.

Generate Ed25519 host keys if not already present:

```bash
# Check existing host keys
ls -la /etc/ssh/ssh_host_*

# Generate Ed25519 host key if not present
sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""

# Disable RSA host key if you want to force Ed25519 only
# (keep RSA for now if you have legacy clients)
# In sshd_config.d/50-host-keys.conf:
# HostKey /etc/ssh/ssh_host_ed25519_key
# HostKey /etc/ssh/ssh_host_rsa_key  # Remove once legacy clients are gone
```

Restrict advertised host key types to deprioritise RSA:

```bash
# /etc/ssh/sshd_config.d/50-host-keys.conf
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Restrict host-based auth algorithms to prefer Ed25519
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
```

When ML-DSA host key support lands in a stable OpenSSH release, the migration path will be:

1. Generate ML-DSA host keys alongside existing Ed25519 keys
2. Add ML-DSA host keys to `HostKey` list
3. Distribute the new host key fingerprints (or re-sign server certificates with the ML-DSA CA key)
4. Update client `known_hosts` or SSH CA trust
5. After confirmed client support, remove classical host keys

### SSH Certificate Authority Migration

If your fleet uses SSH certificate authorities (a CA key signs user or host certificates), the CA key itself is also a classical asymmetric key and will need to be migrated when ML-DSA CA keys become available in OpenSSH.

Current best practice for SSH CAs:

```bash
# Generate a new Ed25519 CA key (if migrating from RSA CA)
ssh-keygen -t ed25519 -f /etc/ssh/ca_host_key -C "host-ca-2026"
ssh-keygen -t ed25519 -f /etc/ssh/ca_user_key -C "user-ca-2026"

# Re-sign existing host certificates with the new CA
ssh-keygen -s /etc/ssh/ca_host_key \
  -I "$(hostname)-2026" \
  -h \
  -V +52w \
  /etc/ssh/ssh_host_ed25519_key.pub

# Distribute the new CA public key to all clients
# /etc/ssh/ssh_known_hosts or pushed via Ansible:
# @cert-authority *.example.com <ca_host_key.pub content>
```

When ML-DSA CA key support is available, follow the same pattern: generate a new ML-DSA CA key, re-sign all host certificates, update client trust anchors.

### Client-Side ssh_config

Every connecting client should also prefer PQC KEX algorithms. A server offering PQC KEX only matters if the client negotiates it:

```
# ~/.ssh/config or /etc/ssh/ssh_config.d/50-pqc.conf

# Global default: prefer PQC hybrid algorithms
Host *
    KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
    HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# Legacy servers that don't support PQC KEX (network appliances, old distros)
Host legacy-switch.corp.example.com
    KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
    HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Production jump hosts: use connection multiplexing to amortise PQC KEX overhead
Host jumphost.prod.example.com
    ControlMaster auto
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlPersist 10m
    KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256
```

Connection multiplexing (`ControlMaster`) is particularly valuable with PQC key exchange. ML-KEM key generation involves generating random lattice samples, and while the overhead is small in absolute terms (see Trade-offs below), multiplexing amortises it across multiple connections sharing the same SSH session.

### Fleet Inventory and Staged Rollout with Ansible

For a fleet of servers, use Ansible to audit current KEX support before making changes:

```yaml
# audit-ssh-kex.yml
- name: Audit SSH KEX algorithms across fleet
  hosts: all
  gather_facts: false
  tasks:
    - name: Get current sshd KexAlgorithms
      command: sshd -T
      register: sshd_config
      become: true
      changed_when: false

    - name: Extract KexAlgorithms line
      set_fact:
        kex_line: "{{ sshd_config.stdout | regex_search('kexalgorithms.*') }}"

    - name: Report PQC status
      debug:
        msg: >
          {{ inventory_hostname }}: PQC={{ 'mlkem768' in kex_line or 'sntrup761' in kex_line }},
          ML-KEM={{ 'mlkem768' in kex_line }},
          sntrup={{ 'sntrup761' in kex_line }}
```

Staged rollout procedure:

**Phase 1 — Add PQC algorithms, keep all classical (no disruption):**

```yaml
# phase1-add-pqc.yml
- name: Phase 1 - Enable PQC KEX (additive change)
  hosts: all
  become: true
  tasks:
    - name: Deploy PQC KEX config
      copy:
        dest: /etc/ssh/sshd_config.d/50-pqc-kex.conf
        content: |
          KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
        validate: "sshd -t -f %s"

    - name: Reload sshd
      service:
        name: ssh
        state: reloaded
```

**Phase 2 — Monitor for PQC negotiation success in logs:**

```bash
# Watch for successful PQC KEX in auth.log
grep "kex: algorithm:" /var/log/auth.log | grep -E "mlkem|sntrup" | wc -l

# Watch for any KEX failures (clients that can't negotiate)
grep -E "no matching key exchange method|Unable to negotiate" /var/log/auth.log | tail -20
```

**Phase 3 — Remove legacy DH algorithms after confirmed PQC adoption:**

Once monitoring confirms all clients are using PQC or modern classical KEX, remove weaker algorithms (e.g., `diffie-hellman-group14-sha256` and older).

### known_hosts Management

If host keys change (e.g., migrating from RSA-only to Ed25519, or future ML-DSA addition), clients will encounter `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED` errors. For large fleets, individual `known_hosts` entries are not the right tool.

Preferred approaches at scale:

**CA-based host trust:** Clients trust the CA public key and accept any host certificate signed by it, regardless of whether the individual host key is in `known_hosts`. This completely decouples host key rotation from client `known_hosts` management:

```
# /etc/ssh/ssh_known_hosts (pushed to all clients via Ansible/CM)
@cert-authority *.prod.example.com ssh-ed25519 AAAA... host-ca-2026

# sshd_config on each server
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

**SSHFP DNS records:** Publish SSH host key fingerprints in DNS, and configure clients to verify them:

```
# Zone file:
jumphost.prod.example.com. IN SSHFP 4 2 <sha256-fingerprint-of-ed25519-key>

# Client ssh_config:
VerifyHostKeyDNS yes
```

SSHFP record type 4 is Ed25519; no SSHFP type exists for ML-DSA yet — this will need an IANA update when ML-DSA host keys ship.

**Ansible-managed known_hosts:** For organisations without DNS SSHFP or SSH CAs, use Ansible to distribute a canonical `known_hosts` file:

```yaml
- name: Distribute known_hosts
  copy:
    src: files/ssh_known_hosts
    dest: /etc/ssh/ssh_known_hosts
    owner: root
    mode: '0644'
```

## Expected Behaviour

After deploying PQC KEX configuration, verify the algorithm in use with verbose SSH output:

```bash
ssh -vvv user@server.example.com 2>&1 | grep -E "kex:|KEX"
```

| Scenario | `ssh -vvv` KEX output | Session is PQC-protected |
|----------|----------------------|--------------------------|
| Both client and server OpenSSH 9.9+ | `kex: algorithm: mlkem768x25519-sha256` | Yes — NIST ML-KEM-768 hybrid |
| Server 9.9+, client 9.0-9.8 | `kex: algorithm: sntrup761x25519-sha512@openssh.com` | Yes — NTRU Prime hybrid |
| Server 9.9+, client pre-9.0 | `kex: algorithm: curve25519-sha256` | No — falls back to classical |
| Server pre-9.0, client 9.9+ | `kex: algorithm: sntrup761x25519-sha512@openssh.com` | Yes — server sends sntrup first |
| Both pre-8.5 | `kex: algorithm: ecdh-sha2-nistp256` | No — no PQC support |

Full `ssh -vvv` handshake output showing a successful ML-KEM negotiation:

```
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug2: local client KEXINIT proposal
debug2: KEX algorithms: mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,...
debug2: peer server KEXINIT proposal
debug2: KEX algorithms: mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,...
debug1: kex: algorithm: mlkem768x25519-sha256          # <-- PQC negotiated
debug1: kex: host key algorithm: ssh-ed25519
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
```

The line `kex: algorithm: mlkem768x25519-sha256` is the confirmation that hybrid ML-KEM key exchange was negotiated and the session key was established using a quantum-resistant algorithm.

## Trade-offs

| Dimension | ML-KEM-768 hybrid | sntrup761x25519 hybrid | Classical curve25519 |
|-----------|-------------------|------------------------|----------------------|
| Quantum resistance | Yes (NIST FIPS 203) | Yes (not NIST-standardised) | No |
| FIPS/compliance eligible | Yes | No | Depends on mode |
| Min OpenSSH version (server+client) | 9.9 | 8.5 | All versions |
| Key generation overhead vs ECDH | ~0.2ms additional | ~1.5ms additional | Baseline |
| Handshake latency overhead | Negligible (<1ms on modern hardware) | Low (2-5ms on constrained hardware) | Baseline |
| Client compatibility coverage | Narrower (newer requirement) | Broad (3+ years deployed) | Universal |

The performance difference between ML-KEM-768 and ECDH is negligible for interactive SSH sessions. The ML-KEM key encapsulation is CPU-bound but fast — modern servers handle thousands of ML-KEM operations per second. The latency cost only becomes visible in high-frequency automated SSH session establishment (e.g., Ansible running against hundreds of hosts simultaneously). For those workflows, SSH connection multiplexing (`ControlMaster`) amortises the cost.

`sntrup761x25519-sha512` has slightly higher overhead than `mlkem768x25519-sha256` because NTRU Prime is more computationally expensive than the lattice operations in ML-KEM. This is another reason to prefer `mlkem768x25519-sha256` where available.

For compliance-sensitive environments: if your security policy requires NIST-approved algorithms, the only PQC KEX option today is `mlkem768x25519-sha256`, and it requires OpenSSH 9.9+ on both ends. Environments on older distributions (Ubuntu 22.04 ships OpenSSH 8.9; Ubuntu 24.04 ships OpenSSH 9.6) need to either pin a newer OpenSSH build or accept `sntrup761x25519-sha512` as an interim measure.

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Client doesn't support PQC KEX | `Unable to negotiate a key exchange method` if classical algorithms removed from server | `grep "no matching key exchange" /var/log/auth.log` | Keep classical fallback algorithms in server `KexAlgorithms` during transition; upgrade clients first |
| Old Ansible/Fabric SSH library | Automation fails with KEX negotiation error | Automation logs show `paramiko` or `libssh` KEX errors | Upgrade paramiko (supports sntrup761 from 2.11+, ML-KEM pending); pin legacy KEX for automation hosts using `Match` blocks |
| `known_hosts` mismatch after host key type change | `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` on client | Client-side SSH warning; connection may refuse | Remove stale entry with `ssh-keygen -R hostname`; deploy CA-based trust or updated known_hosts file |
| sshd config syntax error | sshd refuses to reload; new connections fail with `Connection refused` | `sshd -t` returns error before reload; or post-reload connection failure | Always run `sudo sshd -t` before `systemctl reload ssh`; have an out-of-band console access path (AWS SSM, IPMI, cloud console) for recovery |
| Mixed fleet KEX mismatch | Some hosts accept PQC connections, some don't; clients see intermittent failures | Monitoring shows non-deterministic SSH auth failures across fleet; Ansible tasks fail on specific hosts | Audit fleet with `sshd -T | grep kexalgorithms`; use phased Ansible rollout tagging by OpenSSH version |
| OpenSSH 9.9 not available on distribution | `mlkem768x25519-sha256` absent from `ssh -Q kex` | `ssh -Q kex | grep mlkem` returns nothing | Use `sntrup761x25519-sha512@openssh.com` as interim; track distribution OpenSSH package version; consider using the `openssh-portable` PPA or container-based Ansible execution environment with newer OpenSSH |
| PQC KEX breaks a network appliance | Managed switch or firewall rejects SSH connection when PQC algorithms are offered | Device logs show parse error or disconnection at KEXINIT; or no error but connection hangs | Create a `Match Address` block in sshd_config for the appliance's IP, offering only classical KEX; or restrict PQC in the client's `~/.ssh/config` for that host alias |

## Related Articles

- [FIDO2 SSH with sk-* Keys: Hardware-Backed Authentication for Production Hosts](/articles/linux/fido2-ssh/)
- [SSH Hardening for Production Servers](/articles/linux/ssh-hardening/)
- [Secure Cloud VM Access Patterns](/articles/linux/secure-cloud-vm-access/)
- [Kernel Lockdown Mode](/articles/linux/kernel-lockdown/)
- [PAM Hardening for Production Linux](/articles/linux/pam-hardening/)
