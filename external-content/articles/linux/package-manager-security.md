---
title: "Linux Package Manager Security: APT/DNF Signature Verification, Mirror Pinning, and Supply Chain Hardening"
description: "Package managers are the primary software supply chain for Linux systems. Weak GPG key configuration, unauthenticated mirrors, and unpinned package versions allow an attacker who controls a mirror or the network path to install arbitrary packages as root."
slug: "package-manager-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "linux"
tags: ["apt", "dnf", "package-manager", "supply-chain", "gpg", "linux-hardening"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 303
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/linux/package-manager-security/index.html"
---

# Linux Package Manager Security: APT/DNF Signature Verification, Mirror Pinning, and Supply Chain Hardening

## Problem

Linux package managers install software as root. They download packages from remote servers, verify signatures, and execute post-install scripts with full system access. A compromised package, a malicious mirror, or a MITM attack on package downloads becomes instant root access on every host that installs the package.

Common weaknesses:

- **HTTP mirrors without TLS.** Many APT sources still use `http://` mirrors. An on-path attacker can serve modified packages or strip the response. While APT checks GPG signatures, a stripped or forged `InRelease` file can downgrade to an unsigned state if `Allow-Insecure-Repositories` is set.
- **Broad GPG key trust.** A single `/etc/apt/trusted.gpg` containing all trusted keys means a key compromise for any trusted repository affects all package verification. APT does not bind keys to specific repositories by default in older configurations.
- **No package version pinning.** Production hosts install "latest" on every `apt-get upgrade`. A malicious package pushed to an upstream repository reaches every host on the next unattended upgrade.
- **Third-party repository keys installed without verification.** Instructions like `curl https://example.com/key.gpg | apt-key add -` install GPG keys without verifying their fingerprint. A compromised CDN serves a different key.
- **Post-install scripts execute arbitrary code.** Debian's `preinst`, `postinst`, `prerm`, and `postrm` scripts run as root. A compromised package in a trusted repository runs arbitrary code on install.
- **Unattended upgrades without testing.** `unattended-upgrades` applies security updates automatically — correct for most security patches — but can break applications if not scoped correctly.

**Target systems:** Ubuntu 22.04+/Debian 12+ (APT); RHEL 9+/Rocky Linux/Alma Linux (DNF); Alpine Linux (apk); Ansible/Puppet/Chef managing packages via configuration management.

## Threat Model

- **Adversary 1 — Compromised upstream package:** An attacker compromises a maintainer account on PyPI, npm, or a Linux distribution's build system. A trojanised package is signed with the legitimate key (or the key is also compromised) and distributed to all users of that repository.
- **Adversary 2 — Mirror MITM for unsigned content:** An attacker intercepts traffic to an HTTP mirror. The host's APT configuration allows unauthenticated packages. The attacker serves a modified package that passes no signature check.
- **Adversary 3 — Malicious third-party repository key:** A developer adds a third-party repository following vendor documentation: `curl http://repo.vendor.com/key.gpg | apt-key add -`. The vendor's CDN is compromised and serves a different key. The attacker's packages are now trusted as if they were from the vendor.
- **Adversary 4 — Dependency confusion attack:** An attacker publishes a package on PyPI/npm/RubyGems with the same name as an internal private package, but a higher version number. Hosts that resolve packages from public repositories before private ones install the attacker's package.
- **Adversary 5 — Post-install script execution:** A legitimate package in a trusted repository is updated to include a malicious `postinst` script. Unattended-upgrades installs it overnight. The script establishes persistence before the next security scan.
- **Access level:** Adversaries 1, 3, and 5 require supply chain access. Adversary 2 is on-path. Adversary 4 requires knowledge of internal package names.
- **Objective:** Install malware, establish persistent access, exfiltrate data — all via a trusted package management channel.
- **Blast radius:** A malicious package installed via a trusted repository runs as root during installation, affecting every host that installs it.

## Configuration

### Step 1: Enforce HTTPS for All APT Sources

```bash
# Audit all APT source lists for HTTP URLs.
grep -r "^deb http://" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null

# Replace all http:// with https:// where available.
# Ubuntu/Debian official mirrors support HTTPS.
sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g' /etc/apt/sources.list
sed -i 's|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list

# Install apt-transport-https if not present (needed for older distros).
apt-get install -y apt-transport-https ca-certificates

# Verify no HTTP sources remain.
grep -r "^deb http://" /etc/apt/sources.list /etc/apt/sources.list.d/
# Output should be empty.
```

### Step 2: Bind GPG Keys to Specific Repositories

Modern APT (1.4+) supports repository-specific key binding via `Signed-By`:

```bash
# DEPRECATED: apt-key add adds keys to global trust.
# DO NOT USE: curl https://example.com/key.gpg | apt-key add -

# CORRECT: bind the key to a specific repository.

# Step 1: Download and verify the key fingerprint.
curl -fsSL https://repo.example.com/gpg-key.pub | gpg --dearmor \
  -o /usr/share/keyrings/example-archive-keyring.gpg

# Verify the fingerprint before trusting.
gpg --show-keys /usr/share/keyrings/example-archive-keyring.gpg
# Compare the fingerprint with the vendor's published fingerprint.
# EXPECTED: ABCD 1234 EFGH 5678 ...
# NEVER trust a key without verifying its fingerprint out-of-band.

# Step 2: Reference the key in the source file with Signed-By.
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/example-archive-keyring.gpg] \
  https://repo.example.com stable main" \
  > /etc/apt/sources.list.d/example.list
# The Signed-By clause means ONLY packages signed by this specific key
# are accepted from this repository. A key compromise elsewhere has no effect.
```

```bash
# Audit existing sources for missing Signed-By.
grep -r "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/ | \
  grep -v "signed-by"
# Any line without signed-by uses the global keyring — should be minimised.

# Remove the deprecated global keyring if all sources use Signed-By.
# ls /etc/apt/trusted.gpg.d/  -- any keys here apply globally.
```

### Step 3: APT Security Configuration

```bash
# /etc/apt/apt.conf.d/99-security-hardening

# Reject unsigned repositories.
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowWeakRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";

# Enforce HTTPS for all downloads.
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";

# Sandboxing: APT uses a dedicated _apt user for downloads.
# Ensure the user exists and has no login shell.
APT::Sandbox::User "_apt";

# Limit parallel downloads to avoid cache file contention.
Acquire::Queue-Mode "host";
Acquire::Retries "3";

# Hash algorithm for package verification.
APT::Hashes::MD5::Weak "yes";   # Mark MD5 as weak (reject MD5-only signed packages).
APT::Hashes::SHA1::Weak "yes";  # Mark SHA1 as weak.
# SHA256 and SHA512 are accepted; MD5 and SHA1 alone are rejected.
```

### Step 4: Package Version Pinning

Pin critical packages to specific versions in production:

```bash
# /etc/apt/preferences.d/pinning — prevent surprise upgrades.

# Pin openssh-server to the currently installed version.
Package: openssh-server
Pin: version 1:9.0p1-1ubuntu8.6
Pin-Priority: 1001

# Pin kernel packages — kernel upgrades require testing and reboot.
Package: linux-image-* linux-headers-* linux-modules-*
Pin: release a=jammy-updates
Pin-Priority: 100  # Do not auto-install from -updates; require explicit upgrade.

# Allow security updates for most packages (default priority 500).
# Override for critical infrastructure packages requiring tested upgrades.
Package: postgresql-14
Pin: version 14.10-*
Pin-Priority: 1001
```

```bash
# DNF/RHEL: version locking.
dnf install dnf-plugin-versionlock

# Lock a package to the current version.
dnf versionlock add openssh-server

# List locked packages.
dnf versionlock list

# Ansible: specify exact version in playbooks.
# Do NOT use: apt: name=openssh-server state=latest
# Use: apt: name=openssh-server=1:9.0p1-1ubuntu8.6 state=present
```

### Step 5: DNF/RHEL Signature Configuration

```bash
# /etc/dnf/dnf.conf
[main]
# Require GPG signature verification for all packages.
gpgcheck=1

# Require repo file to be signed.
repo_gpgcheck=1

# Require HTTPS for all repositories.
sslverify=1

# Do not install from weak repositories.
best=True          # Fail if best version cannot be installed (prevents downgrade).
skip_if_unavailable=False
```

```bash
# Import RPM GPG keys with fingerprint verification.
# Always verify the fingerprint before importing.
rpm --import https://repo.example.com/RPM-GPG-KEY-example

# Verify imported keys.
rpm -qa gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'

# Verify a specific package's signature.
rpm -K package.rpm
# Expected: package.rpm: digests signatures OK
```

### Step 6: Unattended Upgrades — Scoped to Security Only

```bash
# /etc/apt/apt.conf.d/50unattended-upgrades

Unattended-Upgrade::Allowed-Origins {
    # Only apply security updates automatically.
    "${distro_id}:${distro_codename}-security";
    # NOT: "${distro_id}:${distro_codename}-updates" (may contain breaking changes).
};

# Do NOT automatically install new packages (only upgrades).
Unattended-Upgrade::InstallOnShutdown "false";

# Blacklist packages that must not be auto-upgraded.
Unattended-Upgrade::Package-Blacklist {
    "kernel";
    "linux-image";
    "postgresql";
    "nginx";
    "python3";
};

# Automatically remove unused dependencies.
Unattended-Upgrade::Remove-Unused-Dependencies "true";

# Reboot if required, but only during maintenance window.
Unattended-Upgrade::Automatic-Reboot "false";
# Reboot is handled by change management process.

# Mail on failures.
Unattended-Upgrade::Mail "security-alerts@example.com";
Unattended-Upgrade::MailReport "on-change";

# Log to syslog.
Unattended-Upgrade::SyslogEnable "true";
```

### Step 7: Private Mirror Verification

For air-gapped or enterprise environments using private mirrors:

```bash
# Verify the private mirror is a legitimate mirror of the upstream.
# Compare package hashes against upstream Release file.

UPSTREAM_RELEASE_URL="https://archive.ubuntu.com/ubuntu/dists/jammy/Release"
MIRROR_RELEASE_URL="https://internal-mirror.example.com/ubuntu/dists/jammy/Release"

# Download both Release files.
curl -s "$UPSTREAM_RELEASE_URL" > /tmp/upstream-release
curl -s "$MIRROR_RELEASE_URL" > /tmp/mirror-release

# Compare package index checksums.
# The SHA256 checksums for Packages files must match.
diff \
  <(grep "Packages" /tmp/upstream-release | awk '{print $1, $3}') \
  <(grep "Packages" /tmp/mirror-release | awk '{print $1, $3}')
# No output = checksums match = mirror is a legitimate copy.
```

### Step 8: Telemetry

```
package_upgrade_applied_total{package, version, host}        counter
package_upgrade_failed_total{package, reason, host}          counter
package_signature_verification_failed_total{repo, host}      counter
unattended_upgrades_packages_total{result}                    counter
package_unauthenticated_install_attempt_total{package}        counter
package_version_pinning_override_total{package}               counter
```

Alert on:

- `package_signature_verification_failed_total` non-zero — APT/DNF rejected a package due to signature failure; potential supply chain attack or mirror compromise.
- `package_unauthenticated_install_attempt_total` non-zero — someone ran `apt-get --allow-unauthenticated`; immediate investigation.
- Unattended upgrade failed for a security package — the patch was not applied; verify manually.
- New GPG key added to trusted keyring outside change management — possible attacker adding a trusted key.

## Expected Behaviour

| Signal | Default package manager | Hardened configuration |
|--------|------------------------|----------------------|
| HTTP mirror MITM | Modified package served; installed as root | HTTPS enforced; TLS certificate verified |
| Third-party key without fingerprint check | Key trusted without verification | Key fingerprint verified out-of-band before import |
| Unsigned package in repository | May install with warning | `AllowUnauthenticated=false` rejects it |
| Unattended kernel upgrade | Applied automatically; host may be unstable | Kernel blacklisted from auto-upgrade |
| Dependency confusion attack | Public package installs if higher version | Private mirror with strict allowlist; public repos not consulted |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Strict version pinning | No surprise upgrades | Security patches require manual unpinning | Automate pin updates for security patches via Ansible |
| `repo_gpgcheck=1` (DNF) | Repo metadata authenticated | Older repos may not sign metadata | Contact vendor; use repo without `repo_gpgcheck` only if unsigned metadata explicitly accepted |
| Unattended security updates only | Reduces exposure window | Security update may occasionally break something | Test in staging; have rollback procedure for base packages |
| Signed-By per repository | Key compromise scoped to one repo | More keyring files to manage | Automate via Ansible; template generates correct Signed-By |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| GPG key expired | `apt-get update` fails with "EXPKEYSIG" | APT error log; package update failure alert | Download and reimport the new key with fingerprint verification |
| Mirror out of sync | Old package hashes in Release; install fails | Package hash mismatch error | Switch to backup mirror; report sync issue |
| Version pin blocks security update | Security patch not applied | Unattended-upgrades log shows held package | Temporarily remove pin; apply patch; restore pin at new version |
| Private mirror offline | All package operations fail | `apt-get update` connection refused | Failover to secondary mirror; restore primary |

## Related Articles

- [Linux IMA and EVM](/articles/linux/linux-ima-evm/)
- [Rootkit Detection](/articles/linux/rootkit-detection/)
- [Ansible OS Hardening](/articles/linux/ansible-os-hardening/)
- [Software Bill of Materials (SBOM)](/articles/cicd/sbom/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
