---
title: "PAM Configuration Hardening: Password Policies, Login Controls, and MFA Integration"
description: "PAM (Pluggable Authentication Modules) is the authentication foundation on Linux."
slug: "pam-hardening"
date: 2026-02-02
lastmod: 2026-02-02
category: "linux"
tags: ["pam", "authentication", "mfa", "yubikey", "password-policy", "faillock"]
personas: ["systems-engineer", "security-engineer"]
article_number: 6
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Teleport"
    id: 41
    category: "identity"
  - name: "JumpCloud"
    id: 42
    category: "identity"
  - name: "Yubico"
    id: 39
    category: "identity"
premium_pack: "pam-config-templates"
published: true
layout: article.njk
permalink: "/articles/linux/pam-hardening/index.html"
---

# PAM Configuration Hardening: Password Policies, Login Controls, and MFA Integration

## Problem

PAM (Pluggable Authentication Modules) is the authentication foundation on Linux. Default PAM stacks allow unlimited password attempts, accept weak passwords, and have no MFA. A misconfigured PAM stack can lock out all users including root, making PAM changes one of the highest-risk configurations on a Linux system.

## Threat Model

- **Adversary:** Brute force attacker (SSH, local console), credential stuffer (leaked password database), or insider with weak credentials.
- **Blast radius:** Without PAM hardening, unlimited login attempts with weak passwords. With hardening, account lockout after failed attempts, strong password requirements, and hardware MFA.

## Configuration

### Password Quality with pam_pwquality

```bash
# /etc/security/pwquality.conf
minlen = 14          # Minimum password length
dcredit = -1         # At least 1 digit
ucredit = -1         # At least 1 uppercase
lcredit = -1         # At least 1 lowercase
ocredit = -1         # At least 1 special character
maxrepeat = 3        # No more than 3 consecutive identical characters
maxclassrepeat = 4   # No more than 4 consecutive characters from same class
dictcheck = 1        # Check against dictionary
usercheck = 1        # Check if password contains username
enforcing = 1        # Enforce (not just warn)
retry = 3            # Number of retries before PAM returns error
```

### Account Lockout with pam_faillock

```bash
# /etc/security/faillock.conf
deny = 5             # Lock account after 5 failed attempts
unlock_time = 900    # Unlock after 15 minutes (900 seconds)
fail_interval = 900  # Count failures within a 15-minute window
even_deny_root = no  # Do NOT lock root (you'll need console access)
# WARNING: Setting even_deny_root=yes can lock you out permanently
# if you don't have console/BMC access.
audit = yes          # Log lockout events to audit log
```

```bash
# /etc/pam.d/system-auth (RHEL/Rocky) or /etc/pam.d/common-auth (Debian/Ubuntu)
# Add these lines BEFORE pam_unix.so:
auth    required    pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth    sufficient  pam_unix.so try_first_pass
auth    [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900

# In the account section:
account required    pam_faillock.so
```

```bash
# Check lockout status for a user:
faillock --user alice
# Expected: shows failed attempt count and lock status

# Manually unlock a user:
faillock --user alice --reset
```

### YubiKey MFA with pam_u2f

```bash
# Install pam_u2f
# Debian/Ubuntu:
sudo apt install libpam-u2f

# RHEL/Rocky:
sudo dnf install pam-u2f

# Step 1: Register the YubiKey for each user
mkdir -p ~/.config/Yubico
pamu2fcfg > ~/.config/Yubico/u2f_keys
# Touch the YubiKey when it blinks.
# For backup key: pamu2fcfg -n >> ~/.config/Yubico/u2f_keys

# Step 2: Add to PAM stack (after password, before success)
# /etc/pam.d/sshd - add after auth pam_unix.so:
auth    required    pam_u2f.so cue [cue_prompt=Touch your YubiKey]

# This requires BOTH password AND YubiKey touch for SSH login.
```

### Session Controls with pam_limits

```bash
# /etc/security/limits.conf
# Prevent resource exhaustion attacks via login sessions.

# Maximum number of simultaneous logins per user
*    hard    maxlogins    5

# Maximum number of processes per user (prevents fork bombs)
*    hard    nproc        4096

# Maximum open files per user
*    hard    nofile       65536
```

### Testing PAM Changes Safely

**Critical procedure: always keep a second SSH session open when modifying PAM.**

```bash
# Step 1: Open TWO SSH sessions to the host
# Session 1: make changes
# Session 2: keep open as a backup in case Session 1 locks you out

# Step 2: Make PAM changes in Session 1

# Step 3: Test by opening a THIRD session (new SSH connection)
ssh user@host
# If login works: changes are safe
# If login fails: Session 2 is still active - fix the changes from there

# Step 4: Test root login separately
sudo su -
# If this works: PAM changes are safe for root
# If this fails: fix from Session 2

# NEVER make PAM changes with only one active session.
```

## Expected Behaviour

- Passwords must meet complexity requirements (14+ chars, mixed case, digits, special)
- Account locks after 5 failed attempts (auto-unlocks after 15 minutes)
- YubiKey required for SSH login (password + hardware MFA)
- Session limits prevent fork bombs and resource exhaustion
- `faillock --user alice` shows attempt tracking

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| pam_faillock (5 attempts) | Blocks brute force | Denial-of-service by deliberately failing another user's login | `even_deny_root=no` ensures root is never locked. For other accounts: 15-minute auto-unlock. |
| YubiKey MFA | Eliminates phishing; hardware-bound authentication | Key loss = locked out. $25-90 per key. | Register two keys per user (primary + backup). |
| 14-character minimum password | Strong passwords | User friction; longer password entry | Consider certificate-based auth ([SSH Hardening Beyond the Basics: Certificate Authentication, Jump Hosts, and Logging](/articles/linux/ssh-hardening/)) to eliminate passwords entirely. |
| Session limits (maxlogins=5) | Prevents session exhaustion | Breaks legitimate use cases with many sessions (tmux, screen, CI) | Increase limit for service accounts. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| PAM misconfiguration locks all users | Nobody can SSH or sudo | All login attempts fail; only console access works | Use console/BMC/IPMI access. Fix PAM config. Reboot into single-user mode if console unavailable. |
| faillock locks legitimate user | User reports "Account locked" | `faillock --user alice` shows deny count exceeded | `faillock --user alice --reset` to unlock immediately. |
| YubiKey not recognized | MFA fails with "no devices found" | PAM log shows pam_u2f error | Check USB connection. Verify `u2f_keys` file exists. Check udev rules for YubiKey. |
| pam_pwquality too strict | Users cannot set passwords that meet requirements | User reports "password does not meet requirements" after multiple attempts | Review pwquality.conf. Reduce requirements if they prevent users from setting any password. |

## When to Consider a Managed Alternative

PAM management across a fleet with different auth requirements is fragile.

- **[Teleport](https://goteleport.com):** SSH certificate auth replaces PAM-based authentication entirely. Session recording built-in.
- **[Smallstep](https://smallstep.com):** SSH certificates via CA-as-a-service.
- **[JumpCloud](https://jumpcloud.com):** Managed directory with PAM/MFA integration. Centralised user management.
- **[YubiKey](https://www.yubico.com):** Hardware keys for FIDO2/U2F MFA.

**Premium content pack:** PAM configuration templates by use case (web server, database server, jump host, [Kubernetes](https://kubernetes.io) node) with faillock, pwquality, U2F, and session limits pre-configured and tested.


## Related Articles

- [SSH Hardening Beyond the Basics: Certificate Authentication, Jump Hosts, and Logging](/articles/linux/ssh-hardening/)
- [Hardening the Linux Kernel Attack Surface with sysctl and Boot Parameters](/articles/linux/sysctl-kernel-hardening/)
- [systemd Unit Hardening: ProtectSystem, PrivateTmp, and the Full Sandbox Toolkit](/articles/linux/systemd-unit-hardening/)
- [SELinux in Production: Writing Custom Policies Without Losing Your Mind](/articles/linux/selinux/)
- [AppArmor Profiles for Custom Applications: From Complain Mode to Enforce](/articles/linux/apparmor/)
