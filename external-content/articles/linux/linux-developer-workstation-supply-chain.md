---
title: "Linux Developer Workstation Hardening: Closing the Axios Supply Chain Vector"
description: "The Axios attacker compromised a maintainer's PC to steal an npm token. Harden Linux developer workstations with credential isolation, application allowlisting, and malware detection so a compromised machine cannot pivot to npm publish."
slug: linux-developer-workstation-supply-chain
date: 2026-05-04
lastmod: 2026-05-04
category: linux
tags:
  - supply-chain
  - npm
  - workstation-security
  - credential-protection
  - endpoint
personas:
  - security-engineer
  - platform-engineer
article_number: 423
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/linux/linux-developer-workstation-supply-chain/
---

# Linux Developer Workstation Hardening: Closing the Axios Supply Chain Vector

## The Problem

The Axios supply chain attack did not begin with a compromised server, a malicious pull request, or a CI/CD vulnerability. It began with malware on a developer's workstation. On March 31 2026, the North Korean threat actor Sapphire Sleet compromised the personal computer of the lead Axios maintainer, exfiltrated the npm authentication token stored in `~/.npmrc`, and used that token to publish versions 1.14.1 and 0.30.0 of the Axios package — which receives 100 million weekly downloads — without ever touching GitHub, a CI runner, or any server infrastructure. The attacker had publish access within the lifetime of a single stolen credential file.

npm stores authentication tokens in plaintext in `~/.npmrc`. This is not a security-adjacent configuration file tucked away in a privileged location; it is read by every invocation of `npm install` and sits alongside `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.gitconfig` (which often contains embedded tokens), and browser-stored session cookies. On a developer workstation, the aggregate credential surface is extraordinary: a single malware infection of a machine maintained by a high-value npm publisher is sufficient to compromise the entire downstream dependency graph of every package that maintainer owns.

The social engineering pretext used by Sapphire Sleet against open-source maintainers is documented across multiple incidents: fake job offers from credible-sounding companies, fake security-researcher outreach requesting a look at a proof-of-concept, fake conference invitations containing malicious PDF attachments or shortened links to drive-by download pages. The technical defence at the package registry — npm's two-factor authentication requirement for publishing — was bypassed because the stolen token was an automation token with publish scope, and because TOTP-based two-factor authentication is defeated by a keylogger running on the same machine generating the codes.

The Linux workstation must be hardened under the assumption that a maintainer will eventually click something. Perimeter controls and registry-side protections are insufficient when the authentication material is already on the attacker's machine before the publish request is made.

## Threat Model

- **Malware dropped via phishing, malicious PDF, trojanised development tool, or a fake npm package that runs at install time.** The initial access vector does not require a vulnerability; it requires that a maintainer open an attachment or run a command. Sapphire Sleet has successfully used all four vectors against open-source communities.
- **Credential harvesting from `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/`, and browser credential stores.** These files are world-readable to the user that owns them. Any process running as that user — including malware dropped by a phishing payload — can read them without escalating privileges.
- **Keylogger capturing npm two-factor TOTP codes.** TOTP codes are generated on the same machine that is infected, and a kernel-level or userspace keylogger captures them as they are typed or displayed. Hardware security keys (FIDO2/WebAuthn) are immune to this attack because the private key never leaves the hardware device and the authentication challenge is bound to the origin.
- **Malware establishing persistence via cron, systemd user units, or shell RC file modification.** A `~/.config/systemd/user/` service unit, a line appended to `~/.bashrc`, or a new entry in `crontab -e` all survive a logout and re-login. Persistence on a developer workstation is trivially achieved without root access.
- **Supply chain amplification.** One compromised developer account can publish to every package that account maintains. The Axios maintainer's account had publish rights to Axios specifically; a maintainer who contributes to multiple high-download packages multiplies the blast radius proportionally.

## Hardening Configuration

### 1. Isolate npm Credentials from the Daily Browser Session

The plaintext token in `~/.npmrc` is present on the workstation because the developer ran `npm login` or manually set it. The publish token and the read-only token are the same token unless you explicitly create separate scoped tokens. Read-only tokens cannot publish, so local development and dependency installation should never use the publish token.

Create a read-only token for daily development and keep the publish token out of `~/.npmrc` entirely:

```bash
npm token create --type=readonly
```

Set this read-only token in your user-level `~/.npmrc`:

```bash
npm config set //registry.npmjs.org/:_authToken YOUR_READONLY_TOKEN
```

The publish token lives only in `pass`, the GPG-encrypted password manager, and is injected at publish time without ever being written to disk in plaintext:

```bash
NPM_TOKEN=$(pass show npm/publish-token) npm publish
```

If the workstation is compromised and `~/.npmrc` is read, the attacker obtains a read-only token. Read-only tokens cannot publish. The blast radius of the credential theft is eliminated for the supply chain vector even if the machine is fully owned.

For higher isolation, run publish operations from a dedicated system user account — `npm-publisher` — that does not run a browser, does not have a home directory full of general-purpose credentials, and is only accessed via `su - npm-publisher` for release operations. The daily browser session and its associated credential surface are completely separated from the publish path.

```bash
sudo useradd --create-home --shell /bin/bash npm-publisher
sudo -u npm-publisher pass init GPG_KEY_ID
```

### 2. Replace `~/.npmrc` Plaintext Token with a Credential Helper

Even the read-only token sitting in `~/.npmrc` is plaintext. The GNOME keyring (via `libsecret`) and `secret-tool` provide a userspace-encrypted store that requires the user's login session to unlock. Tokens stored here are not directly readable by inspecting a file.

Store the token using `secret-tool`:

```bash
secret-tool store --label="npm registry token" service npm account registry.npmjs.org
```

Create a credential helper script at `/usr/local/bin/npm-credential-helper`:

```bash
#!/bin/bash
secret-tool lookup service npm account registry.npmjs.org
```

```bash
chmod 755 /usr/local/bin/npm-credential-helper
```

Configure `~/.npmrc` to use the helper rather than a static token:

```ini
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

And source the token in your shell profile from the keyring rather than hardcoding it:

```bash
export NPM_TOKEN=$(secret-tool lookup service npm account registry.npmjs.org)
```

With this configuration, `~/.npmrc` contains no plaintext credential. A process that reads the file gets an environment variable reference that resolves only in the context of a logged-in shell session that has already unlocked the keyring. A malware dropper reading `~/.npmrc` as a static file captures nothing useful.

### 3. Application Allowlisting with `fapolicyd`

`fapolicyd` is a Linux Security Module daemon that enforces an allowlist of permitted executables. In enforce mode, any binary not explicitly listed — including a malware dropper downloaded by a phishing payload, a fake npm binary placed in `/tmp`, or a malicious ELF disguised as a PDF — cannot execute. The execution is blocked at the kernel level before a single instruction of the malicious binary runs.

Install and enable `fapolicyd`:

```bash
sudo dnf install fapolicyd
sudo systemctl enable --now fapolicyd
```

On Debian/Ubuntu, `fapolicyd` is available from the Ubuntu 24.04 repository:

```bash
sudo apt install fapolicyd
```

Create a developer workstation rule set at `/etc/fapolicyd/rules.d/10-developer-workstation.rules`:

```conf
allow perm=execute exe=/usr/bin/node : all
allow perm=execute exe=/usr/bin/npm : all
allow perm=execute exe=/usr/bin/npx : all
allow perm=execute exe=/usr/bin/git : all
allow perm=execute exe=/usr/bin/bash : all
allow perm=execute exe=/usr/bin/sh : all
allow perm=execute exe=/usr/bin/python3 : all
allow perm=execute exe=/usr/bin/pip3 : all
allow perm=execute exe=/usr/bin/gcc : all
allow perm=execute exe=/usr/bin/make : all
allow perm=execute exe=/usr/local/bin/node : all
deny_audit perm=execute all : all
```

The final `deny_audit` rule blocks and logs any execution attempt not matched by the preceding allow rules. A malware dropper that writes an ELF binary to `~/.config/discord/update` and attempts to execute it is blocked with `Operation not permitted` and an audit record is written.

Start in `permissive` mode first to identify gaps:

```bash
sudo sed -i 's/^permissive.*/permissive = 1/' /etc/fapolicyd/fapolicyd.conf
sudo systemctl restart fapolicyd
sudo journalctl -u fapolicyd -f
```

Run your complete development workflow under permissive mode for at least a week. Every blocked execution appears in the journal as a `fapolicyd[<pid>]: rule=deny_audit` entry. Add allow rules for each legitimate binary until the journal shows no unexpected denials, then switch to enforce mode:

```bash
sudo sed -i 's/^permissive.*/permissive = 0/' /etc/fapolicyd/fapolicyd.conf
sudo systemctl restart fapolicyd
```

### 4. Full-Disk Encryption with TPM2 Sealing

LUKS2 full-disk encryption ensures that `~/.npmrc`, `~/.aws/credentials`, `~/.ssh/`, and every other credential file on the workstation cannot be read by an attacker who has physical access to the machine — a scenario that is relevant when a laptop is stolen, seized, or left unattended. Without disk encryption, booting from a USB key provides immediate read access to every file on the drive.

Sealing the LUKS key to the TPM2 chip via `systemd-cryptenroll` adds a second property: the disk cannot be decrypted offline even with the full LUKS header, because the key material is held by the TPM and the TPM will only release it to the correct measured boot environment. A disk removed from the machine and plugged into an attacker's system cannot be opened.

Enroll a TPM2+PIN credential into an existing LUKS2 volume:

```bash
systemd-cryptenroll /dev/sda2 \
  --tpm2-device=auto \
  --tpm2-pcrs="0+2+4+7" \
  --tpm2-with-pin=yes
```

The `--tpm2-with-pin=yes` flag requires a PIN to be entered at boot in addition to the TPM measurement. This defends against an attacker who steals the machine with the disk already unlocked (e.g., a sleeping laptop): the TPM alone cannot unlock the disk without the PIN, so waking from suspend after theft still requires a credential the attacker does not have.

Update `/etc/crypttab` to use the TPM2 token:

```bash
root-crypt    /dev/sda2    none    tpm2-device=auto,tpm2-pcrs=0+2+4+7
```

Regenerate initramfs to include TPM2 tooling:

```bash
sudo apt install tpm2-tools
sudo update-initramfs -u -k all
```

Before enabling TPM2 sealing, generate and store a recovery key in a location that is not on the machine being hardened:

```bash
systemd-cryptenroll /dev/sda2 --recovery-key
```

Print the recovery key and store it in a physical safe or in an offline password manager backup. If the TPM chip fails, the machine is re-provisioned with new hardware, or the PIN is forgotten, the recovery key is the only path to the data.

### 5. Detect Credential-Harvesting Behaviour with auditd

Even with credential isolation and application allowlisting, auditd provides a detection layer that catches malware before it successfully exfiltrates credentials. File-read watches on high-value credential files generate an audit record any time a process opens them. When a process that is not `npm`, `aws`, or `ssh` reads these files, that record is an indicator of compromise.

Add the following to `/etc/audit/rules.d/credential-watch.rules`:

```conf
-w /home/maintainer/.npmrc -p r -k credential_npmrc
-w /home/maintainer/.aws/credentials -p r -k credential_aws
-w /home/maintainer/.aws/config -p r -k credential_aws
-w /home/maintainer/.ssh/id_rsa -p r -k credential_ssh_privkey
-w /home/maintainer/.ssh/id_ed25519 -p r -k credential_ssh_privkey
-w /home/maintainer/.gitconfig -p r -k credential_gitconfig
-w /home/maintainer/.config/gcloud/credentials.db -p r -k credential_gcloud
```

Load the rules:

```bash
sudo augenrules --load
sudo auditctl -l | grep credential
```

Query for reads by unexpected processes:

```bash
sudo ausearch -k credential_npmrc --format text -ts today
```

The output includes the process name, PID, parent PID, and the executable path. A read of `~/.npmrc` by `npm` or `node` is expected. A read by `python3`, `curl`, a process in `/tmp`, or any process whose executable path is outside `/usr/bin` or `/usr/local/bin` is a signal that warrants immediate investigation.

For continuous alerting, forward the auditd output to a SIEM and write an alert rule that fires when `credential_npmrc` or `credential_ssh_privkey` appears with a `comm` field value that does not match the expected allowlist. The alert fires within seconds of the credential read, before the exfiltration connection completes if the malware follows the observed Sapphire Sleet pattern of reading credentials and then opening a network connection.

Extend the watch to detect persistence mechanisms that malware commonly uses on Linux workstations:

```conf
-w /home/maintainer/.bashrc -p wa -k persistence_shellrc
-w /home/maintainer/.bash_profile -p wa -k persistence_shellrc
-w /home/maintainer/.profile -p wa -k persistence_shellrc
-w /home/maintainer/.config/systemd/user -p wa -k persistence_systemd_user
```

A write to `~/.bashrc` or the creation of a new file under `~/.config/systemd/user/` by any process other than the user's own shell or a known configuration management tool is a strong persistence indicator.

## Expected Behaviour After Hardening

After credential isolation, malware executing in the context of the daily browser session reads `~/.npmrc` and finds an environment variable reference that resolves to a read-only token. Even if the malware correctly resolves the token via the shell, the token cannot be used to publish. An attempt to run `npm publish` with the read-only token returns a `403 Forbidden` from the registry. The publish token was never on the compromised machine.

After `fapolicyd` in enforce mode, a malware binary downloaded as part of a phishing PDF's embedded JavaScript or dropped by a malicious npm `postinstall` hook cannot execute. The attempt to run the binary produces `Operation not permitted`, and `fapolicyd` writes an audit record identifying the blocked executable path, the process that attempted to run it, and the timestamp. The malware payload is inert on disk.

After the auditd credential watch, a read of `~/.npmrc` by a process whose `comm` is `python3` — the interpreter used by many credential-stealing scripts — generates an alert tagged `credential_npmrc`. The alert is visible in `ausearch` output within the same second and appears in the SIEM before the exfiltration network connection is attempted. The defender has the process PID in the alert and can kill it immediately.

After TPM2+PIN sealing, a stolen laptop cannot be decrypted by booting from external media or by removing the disk and reading it on another machine. The disk is ciphertext to any environment that does not hold the TPM2 chip in the correct measured boot state with the correct PIN.

## Trade-offs and Operational Considerations

The separate `npm-publisher` account adds friction to the release workflow. A maintainer who previously ran `npm publish` from their daily terminal must now `su - npm-publisher`, navigate to the package directory, and invoke the publish command with the injected token. Document this as a named procedure and implement it as a wrapper script — `~/bin/do-npm-publish` — that handles the `su`, the credential injection from `pass`, and the `npm publish` invocation in a single command. The friction is intentional: it makes the publish step a deliberate act rather than something that can be triggered by malware piggybacking on an existing npm session.

`fapolicyd` allowlist maintenance is an ongoing operational task. Every new development tool, every new compiler or language runtime, and every new binary installed by a package manager requires a rule update. This is not a one-time configuration; it is a process. The payoff — that unknown executables simply cannot run — is only realised if the allowlist is maintained and the daemon is in enforce mode. Start in permissive mode for at least two full work weeks covering the complete development workflow, not just the common path. Include release operations, debugging sessions, and any tools used infrequently. An incomplete allowlist that blocks a critical tool and prompts the operator to disable enforcement to meet a deadline destroys the control entirely.

TPM2 sealing ties the LUKS key to a specific TPM chip and a specific measured boot state. A motherboard replacement or TPM reset requires re-enrolling the key from the recovery passphrase. A firmware update or kernel update that changes the PCRs selected in the sealing policy breaks automatic unlock. Document the re-sealing procedure, test it on a non-production machine before deploying to primary workstations, and automate re-sealing as a post-install hook for kernel package upgrades. Store the recovery key before enabling TPM2 sealing — attempting to add a recovery key after a TPM-related unlock failure requires the old recovery passphrase, which creates a circular dependency if none was set.

## Failure Modes

A credential helper is configured and `~/.npmrc` no longer contains a static token, but the developer ran `npm login` months earlier and a token from that session remains in the user-level npm config at a precedence level higher than the project-level `.npmrc`. npm resolves tokens with a specific priority order: environment variable `NPM_TOKEN` overrides `.npmrc`, which overrides the user-level config. Audit the full token surface with `npm config list --json` and verify that no stale authentication entries remain in `/home/maintainer/.npmrc` or in `$(npm config get userconfig)` after migrating to credential-helper-based storage.

`fapolicyd` is deployed and configured but left in `permissive` mode for longer than the planned evaluation period — typically because the allowlist remains incomplete for an infrequently used tool and no one schedules the time to add the rule and switch modes. Permissive mode generates alerts but does not block execution; malware runs without restriction. Set a calendar-based deadline for the transition to enforce mode and assign ownership. Monitor the `fapolicyd` mode setting as part of a workstation configuration compliance check so that permissive mode on a production workstation is a visible compliance failure.

auditd file-watch rules are applied after hardening but a kernel update resets the running rule set. auditd rules are loaded from `/etc/audit/rules.d/` by `augenrules --load`; the rules persist across reboots if `auditd.service` loads them at startup, but the `augenrules --load` command must have been run after any change to the rules files for them to take effect. Verify that the `ExecStartPost` directive in `auditd.service` includes `augenrules --load` or that the distribution's auditd package runs it at service start. Test rule persistence by rebooting and immediately running `auditctl -l | grep credential`; if the rules are absent, the startup configuration is not loading them.

A hardware security key is used for npm two-factor authentication, eliminating the keylogger threat against TOTP codes. However, the TOTP backup codes generated at hardware key setup are stored in a plaintext file in the user's home directory as a convenience fallback. Backup codes are equivalent to the TOTP secret; if they are stored on the compromised machine, an attacker can use them to bypass the hardware key requirement. TOTP backup codes must be stored offline — printed and physically secured, or stored in a hardware-backed credential store that is not on the workstation — and must never appear in the developer's filesystem.

## Related Articles

- [npm Maintainer Account Security](/articles/cross-cutting/npm-maintainer-account-security/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
- [LUKS TPM2 Sealing](/articles/linux/luks-tpm2-sealing/)
- [Auditd Deep Dive](/articles/linux/auditd-deep-dive/)
- [npm Postinstall Kernel Detection](/articles/linux/npm-postinstall-kernel-detection/)
