---
title: "Privileged Access Workstations: Isolating Administrative Credentials from Everyday Risk"
description: "Admins who check email and browse the web on the same device they use for production access expose privileged credentials to phishing, malware, and browser exploitation. Privileged Access Workstations provide a dedicated, hardened, internet-isolated environment for administrative operations. This guide covers PAW design, hardening, jump server patterns, and cloud-native alternatives."
slug: privileged-access-workstation
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - paw
  - privileged-access
  - admin-security
  - workstation-hardening
  - zero-trust
personas:
  - security-engineer
  - security-analyst
article_number: 607
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/privileged-access-workstation/
---

# Privileged Access Workstations: Isolating Administrative Credentials from Everyday Risk

## Problem

A senior engineer has SSH access to every production server, kubectl cluster-admin on three Kubernetes clusters, and AWS IAM permissions broad enough to spin up or delete anything in the account. They do all of that work from the same MacBook they use to browse the web, check email, join Zoom calls, and install developer tools from the internet.

That laptop is the largest attack surface in the environment.

General-purpose workstations accumulate risk from every direction. A phishing email that installs an infostealer harvests every SSH key, cookie, and stored password on the system. A malicious npm package executed during `npm install` runs with the developer's full permissions and can exfiltrate `~/.aws/credentials`, `~/.kube/config`, and SSH private keys in the background while the build succeeds. A browser zero-day exploited via a compromised ad network drops shellcode that moves laterally using whatever credentials are cached in memory.

The attacks that result are not theoretical:

- **Pass-the-hash / pass-the-ticket:** Credential material captured from memory (via tools like Mimikatz or similar Linux equivalents) is replayed against other systems without knowing the plaintext password. If an admin's NTLM hash or Kerberos ticket is in memory when malware runs, every system that hash grants access to is compromised.
- **Credential dumping:** Tools reading LSASS, `/proc/<pid>/mem`, or kernel memory dump browser saved-password databases, SSH agent sockets, and GNOME keyring contents. A single execution with local admin or root produces a complete credential inventory.
- **Browser session hijacking:** Stolen session cookies bypass MFA entirely. An attacker with the admin console session cookie for AWS or GCP does not need the password or the hardware token.
- **Supply-chain execution:** Malicious packages in npm, PyPI, or brew formulae execute at install time, before any EDR signature update catches them, and run as the developer's user.

The common thread: the general-purpose device is simultaneously trusted (it holds privileged credentials) and exposed (it runs arbitrary internet content). Separating those two roles is the purpose of a Privileged Access Workstation.

## What a PAW Is — and What It Is Not

A Privileged Access Workstation (PAW) is a dedicated computing environment used exclusively for administrative and privileged operations. It is not used for email, web browsing, instant messaging, software development, or any task that involves content originating from the internet or from untrusted parties.

The PAW can take several physical forms:

- **Dedicated physical device:** A separate laptop or desktop used only for admin work. Physically distinct, never connected to the internet directly, locked away when not in use.
- **Hardened VM on a dedicated hypervisor:** A tightly controlled VM on a host that runs nothing else untrusted. The hypervisor itself is treated as privileged infrastructure.
- **Secure enclave laptop with two profiles:** A physical device where a hardened OS is used for all admin work, and a completely separate user profile (or VM) handles daily use. This is weaker than physical separation but practical for organizations that cannot justify two devices per admin.

What a PAW is **not**: a jump server. A jump server is a network hop that centralises inbound connections to an admin network segment. A PAW is the endpoint from which the admin initiates those connections. The two are complementary, not interchangeable, and the distinction matters for the threat model. A jump server compromise exposes everyone who uses it. A PAW compromise is scoped to that admin's sessions.

## PAW Design Principles

**Single purpose.** The PAW runs administrative tools only: SSH client, kubectl, cloud CLI tools, a password manager, the corporate VPN or ZTNA client, and the browser locked to internal admin UIs. Nothing else is installed or permitted. Browser bookmarks point exclusively to internal admin consoles. The admin's personal Slack, personal email, and news feeds are not available on the PAW.

**No internet access.** The PAW firewall blocks all outbound connections except to the admin network segment, identity provider (for authentication), and approved update mirrors. DNS resolution on the PAW resolves only internal names and approved update sources. There is no route to the public internet from the PAW. If an admin needs to look something up, they do it on their daily-use device and type — not paste — the relevant command into the PAW.

**Separate identity.** Admin accounts used from the PAW are distinct accounts from the admin's daily-use identity. The admin's personal Google account, GitHub account, or corporate SSO for productivity tools is never authenticated on the PAW. Admin credentials exist only in the PAW's password manager and are not accessible from any other device.

**Physical and logical separation.** The PAW is either a different physical machine or a VM that cannot share clipboard contents, file system, or network namespace with the daily-use environment. Shared clipboards between a general-purpose VM and a privileged VM are a credential exfiltration channel.

**Minimal software.** Every package installed on the PAW is a potential attack surface. The PAW runs a minimal OS installation — no office productivity suite, no media players, no development frameworks beyond the specific CLI tools required for admin work. The package list is locked and reviewed periodically.

## PAW Hardening

### Disk Encryption

Full-disk encryption is mandatory. If the PAW is a physical device, FileVault (macOS) or LUKS (Linux) with a strong passphrase protects the device at rest. The encryption key must not be stored in the cloud backup for the device. For Windows PAWs, BitLocker with TPM + PIN is the minimum; TPM-only without PIN is insufficient for a high-value target.

### BIOS/UEFI and Secure Boot

Set a BIOS/UEFI administrator password to prevent boot order changes. Secure Boot must be enabled with the default platform keys retained; no unsigned bootloaders. Disable booting from USB and network boot in the BIOS. This prevents an attacker with physical access from booting a live OS to read disk contents offline.

### No Local Administrator for the PAW User

The account the admin uses day-to-day on the PAW is a standard user account. Elevation to administrator requires a separate credential — the PAW's local admin password stored in a privileged password manager, not the same password as the admin account used to connect to production. This limits the blast radius if the PAW session is hijacked: the attacker has network access to admin systems but does not automatically gain the ability to install malware or disable EDR on the PAW itself.

### Host Firewall

The PAW firewall is configured with default-deny outbound. Permitted outbound connections are explicitly listed: the admin network CIDR, the identity provider's hostname, and the update mirror. All other outbound connections are blocked and logged. This prevents malware that does execute on the PAW from exfiltrating credentials to the internet or calling back to a command-and-control server.

On Linux, `nftables` rules enforced via `systemd-networkd` hooks and locked against modification by the standard user account. On macOS, the built-in pf rules applied via a launch daemon with restricted permissions. Outbound DNS should resolve only through a local resolver that drops queries for external names not on the allowlist.

### Antivirus and EDR

An Endpoint Detection and Response agent is installed on the PAW and reports to the security team's SIEM, not the general employee EDR dashboard. Alerts from the PAW are treated as high severity by default. The EDR agent runs under a protected process that the standard user account cannot stop or uninstall. On Linux, a combination of [Falco](https://falco.org/) for runtime anomaly detection and a commercial AV engine covers both behaviour and signature detection.

### Patching Cadence

The PAW OS and installed tools are patched on a faster cadence than general workstations — monthly at minimum, weekly where feasible. The minimal software footprint makes this practical: there are fewer packages and fewer conflicts. Automated patching via a locked update mechanism (not a user-triggered manual process) ensures the PAW is not left at an old version because an admin skipped the update prompt.

## PAW Network Access

The PAW connects to a dedicated admin network segment, either via a hardware-enforced VLAN on a managed switch or via a ZTNA client that only routes admin-segment traffic. There is no split-tunnel VPN that routes admin traffic while leaving internet traffic flowing through the default route — the entire PAW's network traffic goes through the admin tunnel or is blocked.

The admin network segment is isolated from the general corporate network. Hosts on the admin segment accept SSH and API connections only from PAW IP addresses (or the IP range assigned to PAWs). Network ACLs on routers and cloud security groups enforce this at the network layer independently of host-level controls.

For cloud environments, the admin network segment is a dedicated VPC or subnet with strict security group rules. PAW connections arrive via a VPN termination point or ZTNA gateway, and all cloud admin API calls originate from that known IP range. Cloud-level SCPs (Service Control Policies in AWS, Organization Policies in GCP) restrict sensitive IAM operations to sessions originating from that IP range.

## MFA Requirements for PAW Access

Hardware security tokens (FIDO2 / WebAuthn) are mandatory for all privileged operations. Software TOTP is not sufficient for PAW-initiated admin access — a malware-compromised daily-use device can read TOTP codes from an authenticator app in the same way it can read SMS.

Hardware tokens (YubiKey, FIDO2 key) provide phishing-resistant authentication because the private key never leaves the hardware device and the origin is verified cryptographically. The PAW itself is unlocked with a FIDO2 key + PIN. Admin system access from the PAW requires the hardware token again — not cached credentials from the unlock step.

Break-glass access, when the hardware token is unavailable, uses a backup hardware token stored in a physical safe, not a software fallback. The use of break-glass access is logged, alerted, and reviewed.

## Jump Servers vs PAW

A jump server (bastion host) is a hardened VM that sits at the boundary between the corporate network and the admin network segment. Administrators SSH into the jump server, then SSH from the jump server to production hosts. All production SSH traffic originates from a known IP address, simplifying firewall rules.

Jump servers solve the network access problem but not the endpoint risk problem. If the admin's general-purpose laptop is compromised, an attacker can:

1. Sit in the background and wait for the admin to open an SSH session to the jump server.
2. Inject commands into the SSH connection using a compromised SSH agent socket.
3. Steal the SSH key used to authenticate to the jump server and replay it later.

Jump servers are a **single point of failure for sessions.** A compromised jump server exposes every admin session that passes through it. A misconfiguration, unpatched vulnerability, or compromised admin account on the jump server gives an attacker a position to pivot to every production system reachable from it.

The stronger pattern combines a PAW with ZTNA rather than a jump server. The PAW is the trusted endpoint; ZTNA enforces that the connection comes from a known, attested device. The ZTNA client on the PAW verifies device posture (disk encrypted, EDR running, OS patched) before granting network access to the admin segment. There is no single jump server to compromise — each ZTNA session is individually attested and scoped.

When a jump server is used, it should be treated as a privileged system with the same hardening requirements as the targets it reaches:

- No persistent logins; session credentials expire.
- Session recording enabled for every connection (see below).
- Automated patch cadence.
- Access only from PAW IPs; no general corporate network access.
- All jump server activity shipped to SIEM in real time.

## Cloud-Native PAW Alternatives

For teams operating primarily in cloud environments, dedicated physical PAWs can be supplemented or replaced with cloud-managed access mechanisms that provide equivalent isolation without managing dedicated hardware.

### AWS Systems Manager Session Manager

[AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) provides browser-based terminal access to EC2 instances and on-premises servers without opening any inbound ports. The SSM agent on the instance connects outbound to the SSM endpoint; the operator initiates a session from the AWS Console or via `aws ssm start-session` from the CLI.

The PAW-equivalent property: there is no SSH port open on the instance, no SSH key to steal, and no static credential to exfiltrate. Session access is gated by IAM permissions. The IAM role used to start a session can be restricted by IP, require MFA, and be scoped to specific instance IDs.

Session Manager sessions are logged to CloudWatch Logs and S3. Every command run in every session is recorded. AWS CloudTrail logs the `StartSession` and `TerminateSession` API calls with the IAM identity that initiated them.

AWS CloudShell provides a browser-based shell with pre-configured AWS CLI access scoped to the authenticated IAM session. For teams that manage AWS infrastructure but do not run application servers, CloudShell acts as a PAW-like environment: it is isolated from the admin's local machine, credentials are issued via IAM (not stored locally), and the session is time-limited.

### GCP Identity-Aware Proxy TCP Tunnelling

[GCP Identity-Aware Proxy (IAP) TCP forwarding](https://cloud.google.com/iap/docs/tcp-forwarding-overview) provides a similar model for GCP. SSH sessions to Compute Engine instances are tunnelled through the IAP endpoint, which enforces IAM authentication and context-aware access policies before the TCP connection reaches the instance. The instance has no public IP and no firewall rule permitting inbound SSH from the internet.

IAP context-aware access can enforce device trust policies: connections are only allowed from devices that are enrolled in the corporate MDM, have their OS patched to a minimum version, and have disk encryption enabled. This is the cloud equivalent of a PAW network access policy.

## Bastion as a Service

Managed bastion services — including [AWS SSM](https://aws.amazon.com/systems-manager/), [Teleport](https://goteleport.com/), [Boundary](https://www.boundaryproject.io/), and [Cloudflare Access for Infrastructure](https://www.cloudflare.com/zero-trust/products/infrastructure/) — provide centrally managed privileged access with built-in session recording, RBAC, and audit logs without requiring teams to maintain their own jump server fleet.

The advantages over a self-managed jump server:

- **No server to patch.** The managed service handles the bastion infrastructure. There is no jump server OS to keep updated, no bastion VM to monitor for compromise.
- **Centralised access policy.** RBAC, MFA requirements, and IP restrictions are configured once and applied to all sessions. Adding or removing an admin's access is a single IAM change, not a change to authorized_keys files on N servers.
- **Native session recording.** Session recording is a built-in feature, not something bolted on via script logging or terminal multiplexer tricks.
- **Identity-brokered access.** Sessions are tied to the operator's SSO identity, not a shared `ubuntu` or `ec2-user` account. Audit logs show the human's name, not the system account.

## Session Recording for Privileged Access

Every privileged session — SSH, kubectl exec, database query tool, cloud console — must be recorded and stored for audit. Session recording is not optional for compliance under SOC 2, ISO 27001, PCI DSS, or FedRAMP; it is a control requirement.

Effective session recording captures:

- **Full terminal I/O:** every keystroke typed and every byte of output, stored in a format that can be replayed precisely as it appeared.
- **Timing data:** the recording can be played back at real time or accelerated to show exactly what happened in sequence.
- **Metadata:** the initiating identity (SSO user), the target system, the session start and end time, and the source IP.
- **Tamper-evident storage:** recordings are shipped to an append-only storage location (S3 Object Lock, GCS object retention, or a WORM-capable log system) that the admin who performed the session cannot modify or delete.

On self-managed infrastructure, Teleport provides end-to-end session recording for SSH, kubectl, database, and RDP sessions with HMAC-signed segments stored in S3. For Linux SSH sessions without Teleport, `auditd` combined with [tlog](https://github.com/Scribery/tlog) or `script` logging to a write-protected path provides a basic but auditable record.

Session recordings should be reviewed on a risk-based schedule: every break-glass session reviewed within 24 hours, randomly sampled regular sessions reviewed weekly. Anomaly detection on session recordings — commands that have never been run before, large data transfers, access at unusual hours — should generate alerts.

## Enforcement and Governance

A PAW program fails if admins can bypass it. Enforcement requires:

- **Cloud IAM conditions** that restrict sensitive API calls to sessions originating from PAW IP ranges. In AWS: `aws:SourceIp` conditions on sensitive IAM policies. In GCP: IAP context-aware access policies. In Azure: Conditional Access location-based policies.
- **SSH `authorized_keys` restricted to PAW IPs.** `from="10.100.0.0/24"` prepended to every authorized key entry restricts key usage to connections from the PAW network segment.
- **Certificate-based SSH with short TTLs.** SSH CAs issuing certificates that expire in 8 hours eliminate the static key entirely. An admin who is not logged in to their PAW and authenticated to the CA cannot connect to production regardless of what keys they have stored elsewhere.
- **MDM enrollment required before PAW use.** The PAW must be enrolled in the corporate MDM before network access is granted. MDM attestation confirms disk encryption status, OS version, and compliance posture.
- **Regular PAW audits.** Quarterly review of installed software on every PAW, comparison against the approved software list, and review of PAW firewall logs for blocked outbound connections (which indicate malware attempting to call back).

## Summary

The general-purpose workstation is the highest-risk endpoint in most environments because it combines unrestricted internet access with the highest privilege credentials. Separating those two functions is the core purpose of a PAW program.

A minimal PAW program for a 20-person team:

1. Dedicated VM or physical device for each admin, used exclusively for privileged operations.
2. Full-disk encryption, Secure Boot, BIOS password.
3. Default-deny outbound firewall; traffic permitted only to admin network segment and identity provider.
4. Hardware FIDO2 token required to unlock PAW and for all privileged authentications.
5. EDR agent reporting to SIEM with high-priority alerting.
6. Session recording for all SSH and cloud console sessions, stored in tamper-evident storage.
7. Cloud IAM conditions restricting sensitive operations to PAW IP range.

For cloud-native environments, AWS SSM Session Manager and GCP IAP TCP tunnelling provide PAW-equivalent isolation without physical hardware. For access management at scale, managed bastion services (Teleport, Boundary, Cloudflare Access) add identity-brokered RBAC, session recording, and auditable access without a self-managed jump server.

The attack paths — phishing, malware, browser exploitation, supply-chain — all rely on reaching privileged credentials from an exposed general-purpose device. A PAW removes that exposure. An admin's cloud admin credentials, production SSH keys, and Kubernetes kubeconfigs never exist on a device that runs untrusted content. That single structural change eliminates the largest class of privilege escalation vectors in most enterprise environments.
