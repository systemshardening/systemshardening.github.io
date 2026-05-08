---
title: "GnuPG Key Management: Package Signing, File Integrity, and Git Commit Signing"
description: "Hardened GnuPG setup for production: offline primary keys, subkey architecture, APT/DNF package verification, Git commit signing, YubiKey offload, key rotation, and WKD autodiscovery."
slug: linux-gnupg-key-management
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - gnupg
  - pgp
  - key-management
  - signing
  - package-security
personas:
  - security-engineer
  - sysadmin
article_number: 480
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-gnupg-key-management/
---

# GnuPG Key Management: Package Signing, File Integrity, and Git Commit Signing

## The Problem

GnuPG underpins a surprisingly wide slice of Linux infrastructure trust: APT and DNF verify packages against repository signing keys; Git commit and tag signing chains authorship to a verified identity; signed release artifacts let downstream consumers know the binary came from the claimed publisher without tampering in transit.

The tooling exists and works. The failure mode is not cryptographic; it is operational. Most engineers generate a long-lived primary key, put it in `~/.gnupg`, use it for everything, and never touch it again. That key eventually lives in a laptop backup, a dotfiles repo, a misconfigured S3 bucket, or the memory of a process that was compromised before the engineer noticed. When the key leaks, every signature it ever made is suspect. Revoking it invalidates every signature, breaks package trust chains, and requires coordinating a key transition across every system that ever trusted it.

The correct model is architecturally different: a primary key that stays offline and is used only to certify subkeys, plus separate short-lived subkeys for signing, encryption, and authentication. The subkeys are what appear on the daily-use machine. Compromise a subkey, revoke it, issue a new one; the primary key fingerprint and trust chain are unchanged.

This article covers that architecture end to end: hardened key generation, subkey isolation, package verification, Git signing, hardware token offload, rotation, and WKD autodiscovery.

**Target environment:** GnuPG 2.4+, Ubuntu 22.04+ / RHEL 9+, Git 2.34+, YubiKey 5+ (optional).

## Threat Model

- **Adversary 1 — Laptop compromise:** attacker exfiltrates `~/.gnupg`. Wants to sign packages, commits, or emails as the owner. With a naive single-key setup, full compromise. With an offline primary key and subkey architecture, only current subkeys are exposed.
- **Adversary 2 — Supply chain tampering:** attacker intercepts a package in transit and replaces it. Wants the victim's package manager to install the malicious version silently.
- **Adversary 3 — Git history forgery:** attacker wants to inject commits attributed to a trusted developer. Without commit signing, this is trivially possible on any repo the attacker can push to.
- **Adversary 4 — Repository key substitution:** attacker serves a malicious `InRelease` or `repomd.xml` signed with a key the client hasn't explicitly imported. Wants the package manager to accept it.
- **Blast radius:** a leaked primary key with no subkey architecture invalidates the entire trust hierarchy. Proper subkey hygiene limits blast radius to the current subkey and the period since it was last rotated.

## Key Architecture: Primary Key and Subkeys

A GnuPG keyring organizes keys into a primary key (also called the master or certification key) and zero or more subkeys. The primary key has the **[C]ertify** capability — it can sign other keys and issue certifications. Subkeys carry one capability each: **[S]ign**, **[E]ncrypt**, or **[A]uthenticate**.

The principle: the primary key's job is to certify subkeys. Nothing else. It lives on an encrypted USB drive or air-gapped machine. The subkeys are the working keys. This separation means:

- A stolen laptop exposes current subkeys, not the certification root.
- Revoking a subkey requires the primary key but does not change the primary fingerprint or its web of trust.
- Subkeys can be rotated on a schedule without anyone who trusts your primary fingerprint needing to do anything.

```
Primary key [C] ─── fingerprint is your identity, stays offline
    ├── Signing subkey    [S] ── expires 1 year, on laptop / YubiKey
    ├── Encryption subkey [E] ── expires 1 year, on laptop / YubiKey
    └── Authentication subkey [A] ── expires 1 year, optional (SSH)
```

## Generating a Hardened GnuPG Key

### Algorithm Choice

Use Ed25519 for signing and X25519 (Curve25519) for encryption. Both are fast, short, resistant to known attacks, and supported by GnuPG 2.2+. Avoid RSA-2048 for new keys (short margin) and DSA/ElGamal (implementation history).

### Batch Generation

The interactive `gpg --full-gen-key` workflow is error-prone. Use a batch parameter file instead:

```bash
cat > /tmp/keygen-params << 'EOF'
%echo Generating hardened primary key
Key-Type: EdDSA
Key-Curve: Ed25519
Key-Usage: cert
Name-Real: Alice Engineer
Name-Email: alice@example.com
Name-Comment:
Expire-Date: 0
Passphrase: <STRONG-PASSPHRASE-HERE>
%commit
%echo Primary key done
EOF

gpg --batch --generate-key /tmp/keygen-params
rm /tmp/keygen-params
```

The primary key has **no expiry** — it is your long-term identity anchor. Subkeys will carry their own expiries.

Verify:

```bash
gpg --list-keys --with-subkey-fingerprint alice@example.com
```

### Adding Subkeys

```bash
# Export the fingerprint for scripting.
FPR=$(gpg --list-keys --with-colons alice@example.com \
      | awk -F: '$1=="fpr"{print $10; exit}')

# Add signing subkey (Ed25519, 1 year).
gpg --batch --pinentry-mode loopback --passphrase "<PASSPHRASE>" \
    --quick-add-key "$FPR" ed25519 sign 1y

# Add encryption subkey (cv25519, 1 year).
gpg --batch --pinentry-mode loopback --passphrase "<PASSPHRASE>" \
    --quick-add-key "$FPR" cv25519 encr 1y

# Add authentication subkey (Ed25519, 1 year) — needed for SSH or YubiKey auth.
gpg --batch --pinentry-mode loopback --passphrase "<PASSPHRASE>" \
    --quick-add-key "$FPR" ed25519 auth 1y
```

Verify the three subkeys appear with the correct capabilities:

```bash
gpg --list-keys --with-subkey-fingerprint alice@example.com
# pub   ed25519 2026-05-07 [C]
#       AAAA...PRIMARY_FINGERPRINT...AAAA
# uid           [ultimate] Alice Engineer <alice@example.com>
# sub   ed25519 2026-05-07 [S] [expires: 2027-05-07]
# sub   cv25519 2026-05-07 [E] [expires: 2027-05-07]
# sub   ed25519 2026-05-07 [A] [expires: 2027-05-07]
```

## Offline Primary Key Storage

With the key generated, export everything, store it securely, then remove the primary key from your daily machine, leaving only subkeys.

### Export and Backup

```bash
# Export the full keypair (primary + subkeys) — store this OFFLINE only.
gpg --armor --export-secret-keys alice@example.com > primary-full-backup.asc

# Export the public key — this can go on keyservers and your website.
gpg --armor --export alice@example.com > alice-public.asc

# Export only subkeys (no primary secret key material).
gpg --armor --export-secret-subkeys alice@example.com > subkeys-only.asc
```

Store `primary-full-backup.asc` on two encrypted USB drives in separate physical locations. Use a strong VeraCrypt or LUKS container, or encrypt the file itself with another passphrase:

```bash
gpg --symmetric --cipher-algo AES256 --armor primary-full-backup.asc
# Creates primary-full-backup.asc.asc — the backup is double-encrypted.
```

### Strip the Primary Key from the Daily Keyring

```bash
# Import only the subkeys back after deleting the primary.
gpg --delete-secret-key alice@example.com

# Re-import only subkey secret material (no primary private key).
gpg --import subkeys-only.asc

# Confirm: primary shows '#' (stub), subkeys are present.
gpg --list-secret-keys alice@example.com
# sec#  ed25519 2026-05-07 [C]      ← '#' = primary secret key NOT present
# ssb   ed25519 2026-05-07 [S]
# ssb   cv25519 2026-05-07 [E]
# ssb   ed25519 2026-05-07 [A]
```

The `#` marker means the primary key secret is not on this machine. Signing and decryption still work (via the subkeys). Creating new subkeys or revocation certificates requires fetching the primary from offline storage.

### gpg-agent Configuration

```bash
# ~/.gnupg/gpg-agent.conf
default-cache-ttl 600
max-cache-ttl 7200
pinentry-program /usr/bin/pinentry-curses
```

Keep cache TTLs short on shared or high-risk machines. Reload after changes:

```bash
gpgconf --kill gpg-agent
```

## APT Package Verification

Debian/Ubuntu use signed `InRelease` files and package checksums. Getting this right means not using the deprecated `apt-key add` workflow (which puts keys into the global `/etc/apt/trusted.gpg.d/` store without binding them to a specific repository).

### Importing Repository Keys Securely

```bash
# Fetch the key, verify its fingerprint manually against the project's HTTPS page.
curl -fsSL https://packages.example.com/signing-key.gpg \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/example-archive-keyring.gpg > /dev/null

# Verify the imported fingerprint.
gpg --no-default-keyring \
    --keyring /usr/share/keyrings/example-archive-keyring.gpg \
    --fingerprint
# Confirm the fingerprint matches what the project publishes over HTTPS.
```

### Binding the Key to a Specific Source

```
# /etc/apt/sources.list.d/example.list
deb [arch=amd64 signed-by=/usr/share/keyrings/example-archive-keyring.gpg] \
    https://packages.example.com/apt stable main
```

The `signed-by=` directive means APT will only accept packages from this source if they are signed by exactly this key, not by any other key in the trusted store. A compromised key for a different repository cannot sign packages from this source.

Verify that APT enforces the signature:

```bash
sudo apt-get update 2>&1 | grep -E 'Signature|NO_PUBKEY'
# Clean output means all configured sources have valid signatures.
```

### DNF/RPM Verification

```bash
# Import a key for an RPM repository.
sudo rpm --import https://packages.example.com/RPM-GPG-KEY-example

# List imported keys.
rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n'

# Verify the signature on an installed package.
rpm --verify --checksig package-1.0-1.x86_64.rpm

# Verify all installed packages.
rpm -Va 2>&1 | grep -v "^.$"
# Lines starting with '.' indicate verified; 'S' = size mismatch, 'M' = mode change, etc.
```

For RHEL/Rocky/Alma, the `/etc/yum.repos.d/*.repo` files support `gpgcheck=1` and `repo_gpgcheck=1`. Ensure both are set for production repositories:

```ini
[example]
name=Example Repository
baseurl=https://packages.example.com/rpm/stable/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.example.com/RPM-GPG-KEY-example
```

## Git Commit and Tag Signing

Signed commits and tags give you a cryptographic link between a commit and the GnuPG key of the person who made it. CI systems can verify the entire merge chain before deploying.

### Configure Git to Use Your Signing Key

```bash
# Set the signing key (use the subkey fingerprint, or the primary for selection).
git config --global user.signingkey "$FPR"

# Sign all commits automatically.
git config --global commit.gpgSign true

# Sign all tags automatically.
git config --global tag.gpgSign true

# Optionally, tell git which gpg binary to use.
git config --global gpg.program gpg2
```

### Signing and Verifying Locally

```bash
# Sign a commit (--gpg-sign or -S, redundant if commit.gpgSign is set).
git commit -S -m "Add hardened configuration"

# Verify a commit.
git log --show-signature -1

# Verify a tag.
git tag -v v1.0.0
```

A valid signature shows:

```
gpg: Signature made Thu 07 May 2026 10:00:00 UTC
gpg:                using EDDSA key SSSS...SUBKEY_FPR...SSSS
gpg: Good signature from "Alice Engineer <alice@example.com>" [ultimate]
```

### Verifying Signatures in CI

GitHub Actions, GitLab CI, and Forgejo all support commit signature verification. For a raw `git` verification step in any CI system:

```bash
# Import the authorized signing key(s) from a known-good location.
gpg --import /etc/ci-trusted-keys/alice-public.asc

# Verify all commits in the merge range carry a valid signature.
git verify-commit HEAD

# For a pull request merge range (GitHub Actions example):
git log --pretty=format:"%H" origin/main..HEAD | while read sha; do
  git verify-commit "$sha" || { echo "FAIL: unsigned commit $sha"; exit 1; }
done
```

GitHub's `--verify-signatures` flag on merge via the API and the "Require signed commits" branch protection rule accomplish this without a custom script for GitHub-hosted repositories.

For tag-based release pipelines:

```bash
git verify-tag "$RELEASE_TAG" \
  && echo "Tag signature valid" \
  || { echo "FAIL: invalid or missing tag signature"; exit 1; }
```

## Hardware Keys: Moving Subkeys to a YubiKey

Moving subkeys to a YubiKey (or any OpenPGP card) means the private subkey material never exists in software memory on the daily machine. Authentication, signing, and decryption operations are performed on the card.

### Prerequisites

```bash
sudo apt install scdaemon pcscd yubikey-manager
sudo systemctl enable --now pcscd
```

### Transfer Subkeys to the Card

```bash
# Enter the key editing interface.
gpg --edit-key "$FPR"

# Select the first subkey (signing).
gpg> key 1
# gpg> shows [S] subkey is selected.

gpg> keytocard
# GnuPG asks which slot: 1=Signature, 2=Encryption, 3=Authentication.
# Choose slot 1 for the signing subkey.

# Deselect, select the encryption subkey.
gpg> key 1
gpg> key 2
gpg> keytocard
# Choose slot 2.

# Repeat for the auth subkey.
gpg> key 2
gpg> key 3
gpg> keytocard
# Choose slot 3.

gpg> save
```

After `keytocard`, the local subkey stubs are replaced with card stubs. The private key material now lives only on the YubiKey:

```bash
gpg --list-secret-keys alice@example.com
# sec#  ed25519 2026-05-07 [C]
# ssb>  ed25519 2026-05-07 [S]     ← '>' = key is on a card
# ssb>  cv25519 2026-05-07 [E]
# ssb>  ed25519 2026-05-07 [A]
```

### Daily Use Workflow

Signing, decryption, and authentication now require the YubiKey to be present and the PIN to be entered (default PIN `123456`; change it):

```bash
# Change the default PIN and Admin PIN on the card.
gpg --card-edit
gpg/card> admin
gpg/card> passwd
# Option 1 changes PIN (default 123456).
# Option 3 changes Admin PIN (default 12345678).
gpg/card> quit
```

If the YubiKey is not present, GnuPG operations that require a private key fail with:

```
gpg: signing failed: No secret key
```

This is the expected and correct behavior. The private key cannot be exfiltrated from a machine that never held it.

## Key Expiry and Rotation

### Setting and Extending Subkey Expiry

Short expiry on subkeys limits the window during which a compromised subkey remains valid. One year is a reasonable default for most environments. Extend before expiry without changing the key fingerprint or requiring recipients to re-import anything:

```bash
# Edit the key (primary key must be accessible or a stub with cached agent).
gpg --edit-key "$FPR"

# Select the signing subkey.
gpg> key 1
gpg> expire
# Enter the new expiry: 1y, 2y, or a specific date.
gpg> key 1

# Repeat for encryption and auth subkeys.
gpg> key 2
gpg> expire
gpg> key 2

gpg> save

# Re-publish the updated public key.
gpg --armor --export alice@example.com > alice-public-updated.asc
gpg --send-keys "$FPR"    # if using a keyserver
```

Recipients who previously imported your key see the extended expiry the next time they refresh from a keyserver or WKD.

### Revoking a Compromised Subkey

```bash
gpg --edit-key "$FPR"
gpg> key 1         # select the compromised subkey
gpg> revkey
# Choose reason: 1=No longer used, 2=Superseded, 3=Key compromised
gpg> save

# Distribute the updated key with the revocation embedded.
gpg --send-keys "$FPR"
```

## Web Key Directory (WKD)

WKD allows automatic discovery of your public key based on your email address. Clients (GnuPG 2.2+, Thunderbird, Sequoia, ProtonMail) look up keys at a well-known URL derived from the email's domain, avoiding keyserver trust issues.

### WKD URL Structure

For `alice@example.com`, GnuPG computes:

```
https://example.com/.well-known/openpgpkey/hu/<hash-of-localpart>
```

The `<hash-of-localpart>` is the Z-Base-32 encoding of the SHA-1 hash of the lowercased local part (`alice`).

### Hosting WKD

```bash
# Compute the WKD hash for alice@example.com.
gpg --list-keys --with-wkd-hash alice@example.com
# uid  [ ultimate ] Alice Engineer <alice@example.com>
#                   alice.HASH@example.com  ← the hash appears here

HASH=$(gpg --list-keys --with-wkd-hash alice@example.com \
       | awk '/wkd/{gsub(/@.*/,""); print $NF}')

# Export the key in WKD binary format.
gpg --no-armor --export alice@example.com > /var/www/html/.well-known/openpgpkey/hu/"$HASH"

# Set the correct Content-Type via web server config:
# Content-Type: application/octet-stream
# Access-Control-Allow-Origin: *
```

Verify WKD discovery works:

```bash
gpg --locate-external-key alice@example.com
# gpg: key AAAA...: public key "Alice Engineer <alice@example.com>" imported
```

## Detecting Weak Key Usage

### Key Length and Algorithm Audit

```bash
# List all keys with algorithm info.
gpg --list-keys --with-colons | awk -F: '
  $1=="pub" || $1=="sub" {
    alg=$10; bits=$3; fpr=$5;
    if ($4 != "") print alg, bits, "created:", $6
  }'

# Check for old RSA keys under 3072 bits.
gpg --list-keys --with-colons | awk -F: '$1=="pub" && $4=="1" && $3<3072 {print "WEAK RSA:", $5}'
```

### SHA-1 Signature Warnings

GnuPG 2.4+ by default rejects SHA-1-based signatures with a warning:

```
gpg: WARNING: signature digest algorithm SHA1 is deprecated
```

If you see this on imported keys or old signatures, the signer is using a deprecated digest. Treat these signatures as untrustworthy for new software.

Enforce minimum digest algorithms in `~/.gnupg/gpg.conf`:

```
# ~/.gnupg/gpg.conf
personal-digest-preferences SHA512 SHA384 SHA256
cert-digest-algo SHA512
default-preference-list SHA512 SHA256 AES256 AES ZLIB BZIP2 ZIP Uncompressed
disable-cipher-algo IDEA
weak-digest SHA1
```

### Audit Signatures on Installed Package Keys

```bash
# Verify the RPM database.
rpm --verify --all 2>&1 | grep -v "^.$" | head -50

# For Debian: debsums verifies installed package file checksums.
sudo apt install debsums
sudo debsums --changed
# Lines output = files that have changed from package installation.
```

## Expected Behaviour

| Operation | Naive single-key setup | Subkey architecture |
|-----------|------------------------|---------------------|
| Laptop stolen | Primary and all usage keys compromised | Subkeys exposed; primary offline and safe |
| Subkey compromised | Must revoke primary, rebuild all trust | Revoke and reissue the subkey; primary fingerprint unchanged |
| YubiKey lost | N/A | Revoke card subkeys; issue new subkeys; card is useless without PIN |
| Key rotation | Breaks all trust relationships | Extending or rotating subkeys is transparent to relying parties |
| Package signing | Vulnerable to key theft from build server | Build server holds only the signing subkey; primary is not exposed |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Offline primary key | Primary cannot be stolen from a networked machine | Subkey operations (new subkeys, revocations) require physical access to offline media | Maintain an air-gapped or encrypted-USB workflow with documented runbook |
| Short subkey expiry | Limits validity window of a compromised key | Must remember to extend before expiry | Calendar reminder; automated alerting on upcoming expiry via `gpg --list-keys --with-colons` |
| Hardware token subkeys | Private key never in software | Requires physical token for every sign/decrypt operation | Maintain a backup token with the same subkeys transferred; store securely |
| `signed-by=` in APT sources | Repository key is scoped to one source | Must import each key individually | Automate via configuration management (Ansible, Puppet, Salt) |
| WKD | Keyserver trust not required for discovery | Requires control of the email domain's HTTPS server | Works only for custom domains; fallback to keyservers for generic addresses |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Subkey expired before extension | Signatures rejected; git commits fail CI | `gpg --list-keys` shows `[expired]`; git log shows signature invalid | Fetch offline primary key, extend subkey expiry, redistribute public key |
| Primary key passphrase lost | Cannot certify new subkeys or generate revocation certificate | Attempted operation fails with passphrase error | Use the pre-generated revocation certificate to revoke the key; generate a new key; rebuild trust |
| YubiKey lost without backup | All operations requiring card subkeys fail | All sign/decrypt operations return "No secret key" or card-not-present | Revoke card subkeys via the primary key (offline), issue new subkeys, optionally move to a new card |
| APT `signed-by` mismatch | `apt-get update` fails with signature errors | APT output: `The following signatures were invalid` | Verify the key fingerprint against the project's HTTPS page; re-import the correct key |
| Build server primary key compromise | Attacker signs packages with the primary key | Unexplained signatures; audit log anomalies | Revoke the primary; the entire trust chain for that key is invalidated — no mitigation short of rekeying |
| SHA-1 signatures in CI verification | Git verify-commit emits deprecation warnings or fails | CI output shows `WARNING: signature digest algorithm SHA1` | The signer must regenerate their key with SHA-256+; short-term, update `gpg.conf` `weak-digest` policies |

## Related Articles

- [FIDO2 SSH with sk-* Keys](/articles/linux/fido2-ssh/)
- [dm-verity: Block-Level Integrity for Root Filesystems](/articles/linux/dm-verity/)
- [Auditd Deep Dive](/articles/linux/auditd-deep-dive/)
- [Supply Chain Security for Container Images](/articles/linux/container-base-images/)
- [Kernel Module Hardening](/articles/linux/kernel-module-hardening/)
