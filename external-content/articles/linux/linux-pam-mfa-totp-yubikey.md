---
title: "Linux PAM Multi-Factor Authentication: TOTP and YubiKey"
description: "Password-only PAM is not enough. Add TOTP via libpam-google-authenticator and hardware-bound OTP or U2F via pam_yubico / pam_u2f to SSH and sudo. Stack ordering, break-glass access, and how to test without locking yourself out."
slug: linux-pam-mfa-totp-yubikey
date: 2026-05-07
lastmod: 2026-05-07
category: linux
tags:
  - pam
  - mfa
  - totp
  - yubikey
  - fido2
personas:
  - security-engineer
  - sysadmin
article_number: 471
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/linux-pam-mfa-totp-yubikey/
---

# Linux PAM Multi-Factor Authentication: TOTP and YubiKey

## The Problem

Passwords are a single factor. A single factor has a single failure mode: the secret leaves the user's head through phishing, credential stuffing, password-spray, keyloggers, or leaked breach databases. By 2026 there are over 15 billion credential pairs circulating on criminal markets. Any password your users have ever typed on a non-air-gapped machine has a measurable probability of being in that set.

The threat model for a hardened Linux fleet looks like this:

- **Credential stuffing**: attacker takes a breach database, runs it against your SSH and web-based admin panels. Even a 1-in-10,000 hit rate is catastrophic at scale.
- **Password spray**: slow, low-volume attempts against known usernames. Flies under rate-limit thresholds. Particularly effective against Active Directory-synchronized accounts where the same password appears on your Linux SSH endpoint.
- **Insider threat / lateral movement**: a compromised developer workstation has the user's password in plaintext keychain or browser cache. The attacker moves laterally inside the network — they already know the password.
- **Phishing and social engineering**: sophisticated attackers get credentials through convincing web replicas. The password is correct; the login should be denied anyway.

None of these attacks are stopped by stronger passwords. A 30-character random password that leaks is just as useless as an 8-character one. The fix is a second independent factor: something the user *has*, not something they *know*.

Linux Pluggable Authentication Modules (PAM) sits between every authentication event and the underlying credentials. SSH logins, `su`, `sudo`, `login`, `su -c`, graphical desktop lockscreens — all go through PAM. Correctly stacking two factors in PAM closes the credential stuffing and password spray classes entirely, and significantly raises the bar for every other attack.

This article covers two second-factor mechanisms: TOTP via `libpam-google-authenticator` (software token on a phone, no hardware required) and YubiKey via `pam_u2f` (U2F/FIDO2) and `pam_yubico` (Yubico OTP). Both are production-grade and commonly combined.

## TOTP with libpam-google-authenticator

TOTP (RFC 6238) generates a 6-digit code that changes every 30 seconds from a shared secret. The shared secret is seeded once; after that, the user's phone and the server independently compute the same value from `HMAC-SHA1(secret, floor(unix_epoch / 30))`. No network call required at verification time.

### Installation

```bash
# Debian / Ubuntu
apt-get install libpam-google-authenticator

# RHEL / Fedora / Rocky
dnf install google-authenticator pam_google_authenticator
```

### Per-User Enrollment

Each user runs `google-authenticator` as themselves — the secret is stored in their home directory, not a system-wide database. This is intentional: a root compromise of the secret file does not cascade to all users if each user has a distinct secret.

```bash
$ google-authenticator

Do you want authentication tokens to be time-based (y/n) y

# Outputs QR code and base32 seed — scan with Authy, Google Authenticator,
# 1Password, Bitwarden, etc.

Do you want me to update your "~/.google_authenticator" file? y

Do you want to disallow multiple uses of the same authentication token?
This restricts you to one login about every 30s, but it increases your
chances to notice or even prevent man-in-the-middle attacks (y/n) y

By default, a new token is generated every 30 seconds by the mobile app.
In order to compensate for possible time-skew between the client and the server,
we allow an extra token before and after the current time. This allows for a
time skew of up to 30 seconds between authentication server and client. If you
experience problems with poor time synchronization, you can increase the window
from its default size of 3 permitted codes (one previous code, the current code,
the next code) to 17 permitted codes (the 8 previous codes, the current code,
and the 8 next codes). This will permit for a time skew of up to 4 minutes
between client and server. Do you want to do so? n

If the computer that you are logging into isn't hardened against brute-force
login attempts, you can enable rate-limiting for the authentication module.
By default, this limits attackers to no more than 3 login attempts every 30s.
Do you want to enable rate-limiting? y
```

The resulting `~/.google_authenticator` file:

```
JBSWY3DPEHPK3PXP        ← base32 secret (keep this offline)
" TOTP_AUTH
" DISALLOW_REUSE
" RATE_LIMIT 3 30
63947612                 ← scratch codes (emergency one-time use)
83928746
...
```

**Permissions must be 0600** and owned by the user. The PAM module refuses to read world-readable secret files by default — this is a deliberate security control, not a quirk.

```bash
chmod 0600 ~/.google_authenticator
```

For automated provisioning across a fleet, you can generate the secret programmatically:

```bash
# Generate and write non-interactively (Ansible / cloud-init use case)
google-authenticator --time-based --disallow-reuse --force \
  --rate-limit=3 --rate-time=30 --window-size=3 \
  --secret=/home/${USERNAME}/.google_authenticator
chown ${USERNAME}:${USERNAME} /home/${USERNAME}/.google_authenticator
chmod 0600 /home/${USERNAME}/.google_authenticator
```

The base32 secret from the file can be imported into your secrets manager so it can be recovered and re-enrolled if a phone is lost.

### PAM Stack Configuration for SSH

Edit `/etc/pam.d/sshd`:

```
# /etc/pam.d/sshd

# Standard password auth — keep this or remove based on policy
@include common-auth

# TOTP second factor
auth required pam_google_authenticator.so nullok
```

The `nullok` option allows login for users who have *not* yet enrolled (no `~/.google_authenticator` file). Remove `nullok` once all users are enrolled. During a rollout, leaving `nullok` active prevents lockouts while enrollment completes, but it means unenrolled accounts bypass MFA entirely — plan your rollout window carefully.

Now configure `sshd` itself to ask for both the publickey (or password) and the TOTP code. In `/etc/ssh/sshd_config`:

```
# /etc/ssh/sshd_config

# Require both a public key AND keyboard-interactive (TOTP) to complete auth
AuthenticationMethods publickey,keyboard-interactive

# Allow keyboard-interactive challenges (required for TOTP prompt)
KbdInteractiveAuthentication yes

# If you're using passwords instead of keys as primary factor:
# AuthenticationMethods password,keyboard-interactive

# Disable PAM bypass when using password auth
UsePAM yes
```

With `AuthenticationMethods publickey,keyboard-interactive`, the user must:
1. Present a valid public key (stored in `authorized_keys`)
2. Then complete a keyboard-interactive challenge (the PAM stack, which now includes TOTP)

This is the strongest common combination for SSH: the key proves the user has their private key file, TOTP proves they have their phone. Stealing either one alone is insufficient.

Reload `sshd` — **before closing your current session**:

```bash
systemctl reload sshd
```

### PAM Stack Configuration for sudo

Edit `/etc/pam.d/sudo`:

```
# /etc/pam.d/sudo

# Primary auth: the user's password
@include common-auth

# Second factor: TOTP
auth required pam_google_authenticator.so nullok forward_pass
```

The `forward_pass` option passes the authentication token down the stack so that `common-auth` can also inspect it. Without it, PAM expects separate prompts for password and TOTP, which breaks the typical `sudo` flow where the user types one credential. With it, the user can append the TOTP code directly to their password (`password123456`) and PAM will split them appropriately. Whether you want `forward_pass` depends on your UX preference; separate prompts are more auditable.

**Non-interactive scripts and sudo:** requiring MFA on `sudo` breaks cronjobs and automation that calls `sudo` non-interactively. The standard pattern is to scope MFA only to interactive sessions via the `sudo` configuration:

```
# /etc/sudoers.d/mfa-exceptions
# Service accounts that run non-interactively — skip MFA
Defaults:deploy-svc !requiretty
Defaults:deploy-svc authenticate

# Or, more surgically, use a PAM service file for automation
# and require MFA only in /etc/pam.d/sudo, not /etc/pam.d/sudo-i
```

A cleaner approach is to give automation accounts a dedicated sudoers entry with `NOPASSWD` and no PAM MFA, while keeping MFA on all human accounts:

```
# /etc/sudoers.d/automation
deploy-svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp
```

## YubiKey with pam_u2f

`pam_u2f` provides FIDO2/U2F hardware token authentication. Unlike TOTP, there is no shared secret stored on the server — the YubiKey holds an asymmetric key pair, and authentication is a challenge-response that proves possession of the hardware. A stolen `u2f_keys` file gives an attacker nothing without the physical token.

### Installation

```bash
# Debian / Ubuntu
apt-get install libpam-u2f

# RHEL / Fedora
dnf install pam-u2f
```

Ensure `pcscd` is running if you are using the smart card interface (YubiKey 5 NFC and similar):

```bash
systemctl enable --now pcscd
```

### Registering a YubiKey

Create the per-user key file. The registration command opens a browser-like FIDO2 challenge and writes the public key credential:

```bash
# As the user being enrolled
mkdir -p ~/.config/Yubico
pamu2fcfg > ~/.config/Yubico/u2f_keys
```

You will be prompted to touch the YubiKey. The resulting `u2f_keys` file contains one line per registered credential:

```
username:<KeyHandle>,<UserKey>,<COSE_type>,+presence
```

To register a backup YubiKey (strongly recommended — always register at least two):

```bash
pamu2fcfg -n >> ~/.config/Yubico/u2f_keys
```

For centralized management (shared filesystem, LDAP home directories), point all users to a single directory:

```bash
# Create system-wide keys directory
mkdir -p /etc/security/u2f_keys.d/
pamu2fcfg | sudo tee /etc/security/u2f_keys.d/${USERNAME}
```

Then reference it in the PAM module configuration with `authfile=/etc/security/u2f_keys.d/${USER}` (the `${USER}` is expanded by pam_u2f at runtime to the authenticating user).

### PAM Stack Integration

In `/etc/pam.d/sshd` or `/etc/pam.d/sudo`:

```
# After your primary factor:
auth required pam_u2f.so authfile=/etc/security/u2f_keys.d/${USER} cue
```

The `cue` option prints "Please touch your YubiKey" to the terminal so the user knows to physically interact with the token. Without it, the prompt is silent and users wonder why authentication stalls.

For systemwide default key location (`~/.config/Yubico/u2f_keys`), omit `authfile`:

```
auth required pam_u2f.so cue
```

## YubiKey OTP Mode with pam_yubico

Yubico OTP (the 44-character modhex string `ccccccbcvufebirnfijljngbuhhlgrjhnbtiuhlbtuc`) is a different protocol from U2F. Each key press generates a unique OTP from a symmetric secret stored in the key and registered with Yubico's validation service (or your own `yubikey-val` server). The server validates it, marks it as used, and never accepts it again.

This is slightly weaker than U2F (the symmetric key must be shared with a server) but widely supported and works wherever keyboard input does.

### Installation

```bash
apt-get install libpam-yubico
# RHEL:
dnf install pam_yubico
```

### Online Validation (YubiCloud)

The simplest deployment uses Yubico's public validation API. Get free API credentials from [upgrade.yubico.com/getapikey](https://upgrade.yubico.com/getapikey/).

Map usernames to YubiKey serial IDs in `/etc/yubikey_mappings`:

```
# /etc/yubikey_mappings
# Format: username:YubiKey_ID[:YubiKey_ID...]
alice:ccccccbcvufe
bob:cccccchgrjhn:ccccccabcdef
```

The YubiKey ID is the first 12 characters of any OTP the key generates (the public identifier portion).

PAM stack in `/etc/pam.d/sshd`:

```
auth required pam_yubico.so id=12345 key=APIKEY authfile=/etc/yubikey_mappings
```

Replace `12345` and `APIKEY` with your YubiCloud API credentials.

### Offline / Self-Hosted Validation

For air-gapped environments or compliance regimes that prohibit external calls, deploy a local `yubikey-val` + `yubikey-ksm` stack:

```bash
apt-get install yubikey-val yubikey-ksm

# Point PAM at your local server
auth required pam_yubico.so id=1 \
  url=https://yubikeys.internal/wsapi/2.0/verify?id=%d&otp=%s \
  capath=/etc/ssl/certs \
  authfile=/etc/yubikey_mappings
```

The `yubikey-ksm` (Key Storage Module) holds the AES keys programmed into each YubiKey. Import them after physical programming of tokens:

```bash
ykksm-import --key-id 1234567 --aes-key <hex_aes_key>
```

Offline validation eliminates the network dependency but requires you to maintain the KSM infrastructure securely. A compromised KSM exposes the AES keys for all registered tokens — treat it as a tier-1 secret.

## PAM Stack Ordering: required vs requisite vs sufficient

Getting the PAM control flags wrong is the most common way to accidentally weaken or permanently lock out a system.

| Flag | Meaning |
|------|---------|
| `required` | Must succeed. Failure is recorded, but PAM continues evaluating the stack and fails at the end. The user cannot tell *which* module failed. |
| `requisite` | Must succeed. On failure, PAM **immediately** stops and returns failure. Leaks information about which factor failed, but faster. |
| `sufficient` | If it succeeds *and* nothing above it has failed, authentication succeeds immediately. Stack evaluation stops. |
| `optional` | Result is ignored unless it is the only module in the stack. |

A correct two-factor stack for SSH:

```
# /etc/pam.d/sshd

# Factor 1: password or publickey (handled by sshd before PAM for key auth)
@include common-auth

# Factor 2: TOTP — required, not requisite, to avoid leaking which factor failed
auth required pam_google_authenticator.so nullok
```

**Do not use `sufficient` on a second factor unless you intend to allow that factor to bypass the first.** A common misconfiguration:

```
# WRONG — this lets TOTP alone bypass the password
auth sufficient pam_google_authenticator.so
auth required pam_unix.so
```

Because `sufficient` stops evaluation on success, a valid TOTP code alone completes authentication without checking the password. The PAM module ordering must always put the strongest required factors as `required` and not use `sufficient` unless you fully understand the short-circuit semantics.

**Ordering for combined pam_u2f and TOTP:**

```
# /etc/pam.d/sshd (requiring EITHER TOTP OR YubiKey U2F as second factor)
@include common-auth

# Try U2F first; if it succeeds, skip TOTP
auth sufficient pam_u2f.so cue
# Fall through to TOTP if U2F not configured or token not present
auth required pam_google_authenticator.so nullok
```

This pattern allows users with YubiKeys to use them, and falls back to TOTP for users without hardware tokens. Users with neither enrolled get through if `nullok` is set.

## Break-Glass Emergency Access

Every MFA deployment needs a documented break-glass procedure. Without one, a lost phone or dead YubiKey becomes an outage.

### Scratch Codes (TOTP)

During `google-authenticator` enrollment, five 8-digit scratch codes are generated. Each is single-use. Store them in:
- A hardware password manager (YubiKey's static password slot, a smartcard)
- An offline safe
- A separate secrets manager (Vault, AWS Secrets Manager) with restricted IAM policy

To generate new scratch codes for a user (requires existing access):

```bash
# Regenerate — this invalidates the old set
google-authenticator --force --secret=/home/alice/.google_authenticator
```

### Temporary PAM Bypass (for operators)

When a user is genuinely locked out and scratch codes are exhausted, a root operator can temporarily disable MFA for that user by renaming their authenticator file:

```bash
# Disable TOTP for alice temporarily
mv /home/alice/.google_authenticator /home/alice/.google_authenticator.disabled
# alice can now log in with primary factor only (because nullok is set)

# Re-enable after re-enrollment
mv /home/alice/.google_authenticator.disabled /home/alice/.google_authenticator
```

This is not a permanent backdoor because:
1. `nullok` behaviour is gated on the file being absent, not a persistent config change
2. The action is auditable via `auditd` (file renames in home directories)
3. Re-enrollment is required before the user regains MFA protection

For cases where even root cannot log in (misconfigured PAM, corrupted module), recovery requires console access (physical or out-of-band like IPMI/iDRAC). Boot to single-user mode or use a rescue image to revert `/etc/pam.d/sshd` to the previous known-good version.

**Never put a permanent backdoor in the PAM stack.** A pattern like:

```
# WRONG — permanent backdoor
auth sufficient pam_succeed_if.so user ingroup wheel
```

...looks like "only requires MFA for non-admins" but actually means any compromised wheel account can authenticate anywhere without MFA. Backdoors for convenience become attack surfaces.

## Testing Before Lockout

The single most important practice when modifying PAM is to **never close your existing session before verifying the new configuration works in a separate session**.

### The Second Terminal Procedure

```bash
# Step 1: Open a second SSH session and keep it open.
# This is your recovery session — do not close it until step 5.
ssh -v user@target-host

# Step 2: In your editing session, make PAM changes.
# Then reload sshd WITHOUT disconnecting:
systemctl reload sshd

# Step 3: Open a THIRD terminal and attempt to login with the new config.
ssh user@target-host
# Does it prompt for TOTP? Does it accept a valid code? Does it reject invalid ones?

# Step 4: Verify sudo also works if you modified /etc/pam.d/sudo:
sudo -k; sudo id

# Step 5: Only after step 3 and 4 succeed, close your second terminal.
# If step 3 or 4 fails, use your second terminal to revert:
cp /etc/pam.d/sshd.bak /etc/pam.d/sshd
systemctl reload sshd
```

The `screen` or `tmux` trick is a variant: start a `screen` session before making changes. If you get locked out, the `screen` session persists and you can attach from the console.

### Validating PAM Directly

Test the PAM stack without an SSH round-trip using `pamtester`:

```bash
apt-get install pamtester

# Test the 'sshd' PAM service as user alice
pamtester sshd alice authenticate
```

`pamtester` will walk through the configured stack, including prompting for TOTP codes. It surfaces PAM errors that are otherwise buried in `/var/log/auth.log`.

Always check logs during testing:

```bash
# In a separate terminal, tail auth logs while testing
journalctl -f -u sshd
# or on systems with syslog:
tail -f /var/log/auth.log
```

Common failures:
- `pam_google_authenticator: secret file access failed` — permissions on `~/.google_authenticator` are not 0600
- `pam_u2f: user not found in authfile` — username mismatch or wrong `authfile` path
- `pam_yubico: OTP validation failed` — API credentials wrong, or OTP has already been used
- `Module is unknown` — the PAM module `.so` file is not installed or in the wrong path

## Production Deployment Checklist

Before rolling out fleet-wide:

1. Install and verify the PAM module on a single non-production host.
2. Enroll at least two second factors per user (two TOTP enrollments from the same secret, or two YubiKeys).
3. Document the break-glass procedure and store scratch codes out-of-band.
4. Set `nullok` during rollout, track enrollment with `find /home -name .google_authenticator | wc -l`, remove `nullok` when 100% enrolled.
5. Add auditd rules to detect removal of `~/.google_authenticator` and changes to `/etc/pam.d/`:
   ```
   -w /etc/pam.d/ -p wa -k pam-changes
   -w /home/ -p wa -k home-auth-files
   ```
6. Test TOTP clock skew: if server and phone drift more than 60 seconds, authentication fails. Ensure `chronyd` or `ntpd` is running and synchronized on the server.
7. For `pam_yubico` with YubiCloud, ensure outbound HTTPS to `api.yubico.com` is permitted from your authentication servers. Add it to your firewall allowlist explicitly.

MFA through PAM is not a panacea — it does not protect against compromised sessions after authentication, privilege escalation vulnerabilities, or an attacker who has physical access and time. But it eliminates the entire class of credential stuffing and password spray attacks, and significantly narrows the blast radius of any single stolen password. For a fleet where SSH and sudo are the primary access paths, PAM-level MFA is one of the highest-leverage controls you can deploy.
