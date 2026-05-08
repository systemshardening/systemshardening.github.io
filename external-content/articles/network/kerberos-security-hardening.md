---
title: "Kerberos Network Security Hardening"
description: "Kerberos is the default authentication protocol for Active Directory and Linux enterprise environments, but default configurations leave it vulnerable to kerberoasting, AS-REP roasting, golden ticket attacks, and delegation abuse. This guide covers pre-authentication enforcement, gMSA deployment, delegation hardening, encryption type restriction, krbtgt rotation, and detection of live attacks using Windows event IDs."
slug: kerberos-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - kerberos
  - active-directory
  - ticket-security
  - delegation
  - authentication
personas:
  - security-engineer
  - sysadmin
article_number: 508
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/kerberos-security-hardening/
---

# Kerberos Network Security Hardening

## The Problem

Kerberos is the backbone of authentication in Active Directory environments and a core component of Linux enterprise infrastructure via MIT Kerberos and FreeIPA. It replaced NTLM for good reason: it avoids transmitting passwords over the network, provides mutual authentication, and issues time-limited tickets rather than reusable credentials. For these reasons, organisations often treat it as inherently secure and leave its configuration largely at defaults.

That trust is misplaced. The default configuration exposes multiple high-severity attack paths that are actively exploited in real-world intrusions:

- **Kerberoasting** extracts service account password hashes from the domain without elevated privilege, then cracks them offline. Any authenticated domain user can perform this attack.
- **AS-REP roasting** targets accounts with pre-authentication disabled — a common legacy configuration — and retrieves crackable hash material without a valid password at all.
- **Golden ticket attacks** follow compromise of the `krbtgt` account. An attacker with the `krbtgt` hash can forge arbitrary Kerberos tickets that grant access to any service in the domain, and those tickets remain valid even after user password resets.
- **Delegation abuse** exploits unconstrained or misconfigured constrained delegation to impersonate any user — including domain admins — to services across the domain.
- **Silver ticket attacks** forge service tickets using a service account's hash, bypassing the KDC entirely for targeted lateral movement.

Each of these attack paths exists not because Kerberos the protocol is broken, but because Active Directory and Linux Kerberos deployments routinely enable features and accept defaults that introduce them. This guide addresses each one with specific, testable controls.

**Target systems:** Active Directory on Windows Server 2019/2022, MIT Kerberos 1.18+, FreeIPA 4.x, RHEL/Ubuntu Linux joined to AD or a Kerberos realm.

## Threat Model

- **Adversary 1 — Kerberoasting:** A compromised low-privilege domain user account queries the KDC for TGS tickets for service accounts with SPNs registered. The encrypted ticket bodies, encrypted with the service account's password hash, are extracted and cracked offline. Weak service account passwords fall in minutes.
- **Adversary 2 — AS-REP roasting:** An unauthenticated or low-privilege attacker identifies accounts with `DONT_REQ_PREAUTH` set. The KDC returns AS-REP responses — containing hash material encrypted with the account's password — without validating the requester's identity. The hash material is cracked offline.
- **Adversary 3 — Delegation abuse:** A compromised host has unconstrained delegation enabled. Any authentication to a service on that host captures the authenticating user's TGT. The attacker coerces a domain admin to authenticate (via printer bug, petitpotam, or similar) and then uses the captured TGT to impersonate them.
- **Adversary 4 — Golden/silver ticket forgery:** Following domain controller compromise and `krbtgt` hash extraction, the attacker forges TGTs that are accepted by all domain services. Silver tickets forged using a service account hash bypass the KDC for targeted service access.
- **Adversary 5 — Encryption downgrade:** A legacy configuration permits RC4 or DES encryption. An attacker forces RC4-encrypted tickets (faster to crack than AES) or exploits known weaknesses in legacy cipher suites.
- **Blast radius:** Golden ticket compromise is functionally equivalent to permanent domain admin — the attacker can forge access to any resource in the domain for the lifetime of the ticket (default 10 hours, renewable for 7 days) and can re-forge indefinitely until `krbtgt` is rotated twice.

## Configuration

### Step 1: Enforce Pre-Authentication (Eliminate AS-REP Roasting)

Kerberos pre-authentication requires the client to encrypt a timestamp with its own key before the KDC issues a TGT. This prevents the KDC from issuing crackable hash material to unauthenticated requesters. When an account has `UF_DONT_REQUIRE_PREAUTH` set in its `userAccountControl` attribute, the KDC skips this check.

Detect all accounts with pre-authentication disabled:

```powershell
# Find all accounts with DONT_REQUIRE_PREAUTH set in Active Directory.
# Flag value 0x400000 = 4194304 decimal.
Get-ADUser -Filter * -Properties UserAccountControl |
  Where-Object { $_.UserAccountControl -band 0x400000 } |
  Select-Object SamAccountName, DistinguishedName, UserAccountControl |
  Export-Csv -Path "C:\audit\no-preauth-accounts.csv" -NoTypeInformation

# Count of affected accounts.
(Get-ADUser -Filter * -Properties UserAccountControl |
  Where-Object { $_.UserAccountControl -band 0x400000 }).Count
```

Remove the flag from all accounts. There is no legitimate operational reason to disable pre-authentication in modern environments:

```powershell
# Re-enable pre-authentication on all accounts with it disabled.
Get-ADUser -Filter * -Properties UserAccountControl |
  Where-Object { $_.UserAccountControl -band 0x400000 } |
  ForEach-Object {
    Set-ADUser $_ -KerberosEncryptionType AES128,AES256
    # Clear the DONT_REQUIRE_PREAUTH flag.
    $uac = $_.UserAccountControl -band (-bnot 0x400000)
    Set-ADUser $_ -Replace @{UserAccountControl = $uac}
    Write-Output "Fixed: $($_.SamAccountName)"
  }
```

On Linux, detect accounts in a Kerberos realm with pre-auth disabled (FreeIPA):

```bash
# FreeIPA: list users with no pre-auth requirement.
ipa user-find --all | grep -B5 "krb-ticket-flags: 128" | grep "User login"

# Fix for a specific account.
ipa user-mod <username> --setattr=krbticketflags=0
```

After remediation, no accounts should appear in the pre-auth audit query. Add this query to your weekly Active Directory health checks.

### Step 2: Kerberoasting Mitigation — gMSA and Strong Passwords

Kerberoasting works because service account passwords set by humans are routinely weak or reused. The attack requires no special privilege: any authenticated domain user can request TGS tickets for any SPN.

**Audit current SPN registrations:**

```powershell
# List all SPNs and their associated accounts. Focus on user accounts (not computer$).
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
  -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires |
  Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, PasswordNeverExpires |
  Format-Table -AutoSize

# Identify high-risk accounts: SPNs on user accounts with old or non-expiring passwords.
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
  -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires |
  Where-Object { $_.PasswordNeverExpires -eq $true -or
                 $_.PasswordLastSet -lt (Get-Date).AddDays(-90) }
```

**Migrate service accounts to Group Managed Service Accounts (gMSAs):**

gMSAs use a 120-character, randomly generated password that Active Directory rotates automatically every 30 days. The password is never known to any human and cannot be cracked through kerberoasting because the search space is computationally infeasible.

```powershell
# Step 1: Create a KDS root key (one-time per domain, requires Domain Admin).
# The -EffectiveImmediately flag is for lab use; production should wait 10 hours.
Add-KdsRootKey -EffectiveImmediately

# Step 2: Create the gMSA account.
New-ADServiceAccount `
  -Name "svc-webapp" `
  -DNSHostName "webapp.example.com" `
  -PrincipalsAllowedToRetrieveManagedPassword "WebAppServers" `
  -KerberosEncryptionType AES128,AES256 `
  -ServicePrincipalNames "HTTP/webapp.example.com", "HTTP/webapp"

# Step 3: Install and test the gMSA on the target server.
# Run on the application server (must be a member of WebAppServers group).
Install-ADServiceAccount -Identity svc-webapp
Test-ADServiceAccount -Identity svc-webapp
# Expected: True

# Step 4: Configure the service to use the gMSA.
# In Services: Log On As → This account → DOMAIN\svc-webapp$
# The password field is left blank — Windows retrieves it automatically.
```

**For service accounts that cannot yet migrate to gMSA**, enforce a minimum 25-character password with complexity. Generate and store in a secrets manager:

```powershell
# Generate a 30-character random password for a legacy service account.
$password = [System.Web.Security.Membership]::GeneratePassword(30, 10)
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

Set-ADAccountPassword -Identity "svc-legacyapp" `
  -NewPassword $securePassword `
  -Reset

Write-Output "Password generated. Store in vault immediately — do not log."
# Store $password in HashiCorp Vault / Azure Key Vault / AWS Secrets Manager.
# Never write to a file or commit to source control.
```

### Step 3: Delegation Hardening

Kerberos delegation allows a service to request tickets on behalf of an authenticated user. Three forms exist, with significantly different security profiles.

**Unconstrained delegation** is the most dangerous. A service with unconstrained delegation receives a copy of the user's TGT in the service ticket. Any user who authenticates to a server with unconstrained delegation exposes their TGT, which can then be used to impersonate them to any other service in the domain.

Detect all hosts and accounts with unconstrained delegation:

```powershell
# Computers with unconstrained delegation enabled (flag 0x80000 = TRUSTED_FOR_DELEGATION).
Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
  -Properties TrustedForDelegation, Description |
  Select-Object Name, Description, DistinguishedName

# User accounts with unconstrained delegation.
Get-ADUser -Filter { TrustedForDelegation -eq $true } `
  -Properties TrustedForDelegation |
  Select-Object SamAccountName, DistinguishedName
```

Remove unconstrained delegation from all non-domain-controller machines:

```powershell
# Disable unconstrained delegation on a computer account.
Set-ADComputer -Identity "WEBSERVER01" -TrustedForDelegation $false

# Disable unconstrained delegation on a user/service account.
Set-ADUser -Identity "svc-legacy" -TrustedForDelegation $false

# Verify.
Get-ADComputer "WEBSERVER01" -Properties TrustedForDelegation |
  Select-Object Name, TrustedForDelegation
# Expected: TrustedForDelegation = False
```

**Constrained delegation** (S4U2Proxy) restricts which services the delegating account can impersonate users to. It is safer than unconstrained, but still has risks: with protocol transition (`TrustedToAuthForDelegation`), the service can request a ticket on behalf of any user — including users who never authenticated to the service at all.

Audit constrained delegation configurations:

```powershell
# Accounts with constrained delegation (msDS-AllowedToDelegateTo populated).
Get-ADObject -Filter { msDS-AllowedToDelegateTo -like "*" } `
  -Properties msDS-AllowedToDelegateTo, TrustedToAuthForDelegation |
  Select-Object Name, "msDS-AllowedToDelegateTo", TrustedToAuthForDelegation |
  Format-List

# Highlight accounts with protocol transition (the dangerous form).
Get-ADObject -Filter { TrustedToAuthForDelegation -eq $true } `
  -Properties TrustedToAuthForDelegation |
  Select-Object Name, DistinguishedName
```

**Resource-based constrained delegation (RBCD)** is configured on the resource (the target service) rather than the delegating account. An attacker who can write to `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object can configure RBCD themselves — enabling a powerful privilege escalation path if write permissions to computer objects are too broad.

Detect RBCD misconfigurations:

```powershell
# List all computer objects with RBCD configured.
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null } |
  Select-Object Name, "msDS-AllowedToActOnBehalfOfOtherIdentity"

# Check who has write access to computer objects in a given OU.
# Unexpectedly broad ACLs on GenericWrite or WriteDACL are RBCD abuse preconditions.
(Get-ACL "AD:OU=Servers,DC=example,DC=com").Access |
  Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|WriteDacl|WriteProperty" -and
    $_.IdentityReference -notmatch "Domain Admins|SYSTEM|Enterprise Admins"
  } |
  Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
```

### Step 4: Add High-Privilege Accounts to Protected Users

The **Protected Users** security group applies a hardened Kerberos policy to all member accounts. Membership enforces:

- No NTLM authentication (only Kerberos)
- No Kerberos delegation (unconstrained or constrained)
- No DES or RC4 encryption (AES only)
- TGT lifetime reduced to 4 hours (non-renewable)
- Credentials not cached on host devices

Add all tier-0 accounts (domain admins, enterprise admins, schema admins, domain controller service accounts):

```powershell
# Add the Domain Admins group members to Protected Users.
$domainAdmins = Get-ADGroupMember "Domain Admins" -Recursive |
  Where-Object { $_.objectClass -eq "user" }

foreach ($admin in $domainAdmins) {
  Add-ADGroupMember -Identity "Protected Users" -Members $admin
  Write-Output "Added to Protected Users: $($admin.SamAccountName)"
}

# Verify membership.
Get-ADGroupMember "Protected Users" | Select-Object Name, SamAccountName

# Check what protections are active for a user.
Get-ADUser -Identity "jsmith-admin" -Properties * |
  Select-Object SamAccountName, MemberOf, LastLogonDate
```

Test service accounts before adding them — if an application requires NTLM or delegation, Protected Users membership will break it. Perform impact testing in a lab environment first.

### Step 5: Encryption Type Hardening — Disable RC4 and DES

RC4 (ARCFOUR-HMAC) has been the default encryption type for Kerberos in Windows environments for years. It is significantly weaker than AES and crackable orders of magnitude faster than AES256. DES is even weaker and should not exist in any modern environment.

Disable RC4 and DES via Group Policy:

```
Computer Configuration
  → Windows Settings
    → Security Settings
      → Local Policies
        → Security Options
          → "Network security: Configure encryption types allowed for Kerberos"
            → Enable ONLY:
               [x] AES128_HMAC_SHA1
               [x] AES256_HMAC_SHA1
               [ ] DES_CBC_CRC         (disable)
               [ ] DES_CBC_MD5         (disable)
               [ ] RC4_HMAC_MD5        (disable)
```

Set `msDS-SupportedEncryptionTypes` on computer and service accounts to enforce AES:

```powershell
# Set AES128+AES256 on a specific computer account.
# 0x18 = AES128 (0x8) + AES256 (0x10).
Set-ADComputer -Identity "WEBSERVER01" `
  -KerberosEncryptionType AES128,AES256

# Set on a service account.
Set-ADUser -Identity "svc-webapp" `
  -KerberosEncryptionType AES128,AES256

# Verify the attribute is set correctly.
Get-ADComputer "WEBSERVER01" -Properties msDS-SupportedEncryptionTypes |
  Select-Object Name, msDS-SupportedEncryptionTypes
# Expected: 24 (0x18 = AES128 + AES256)

# Find accounts still advertising RC4 or DES.
Get-ADObject -Filter * -Properties msDS-SupportedEncryptionTypes |
  Where-Object {
    # 0x4 = RC4, 0x1 = DES_CBC_CRC, 0x2 = DES_CBC_MD5.
    $_."msDS-SupportedEncryptionTypes" -band 0x7
  } |
  Select-Object Name, "msDS-SupportedEncryptionTypes"
```

**On Linux** (`/etc/krb5.conf`), restrict permitted encryption types:

```bash
# /etc/krb5.conf — enforce AES only, disable RC4 and DES.

[libdefaults]
    default_realm = EXAMPLE.COM
    # Restrict ticket request encryption to AES.
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes   = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

    # Enforce pre-authentication at the client level.
    no_addresses = true
    forwardable = false
    proxiable   = false

    # Reject tickets with weak encryption (explicitly deny RC4 and DES).
    allow_weak_crypto = false

    # DNS lookups for KDC — disable if using static [realms] configuration.
    dns_lookup_kdc = false
    dns_lookup_realm = false

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com  = EXAMPLE.COM
```

Verify the configuration is effective:

```bash
# Request a TGT and inspect the encryption type used.
kinit jsmith@EXAMPLE.COM

# Show the ticket details including encryption type.
klist -e
# Confirm: Encryption type is aes256-cts-hmac-sha1-96.
# If rc4-hmac or des-cbc-* appears, the policy is not yet effective.

# Test that RC4 tickets are rejected.
kvno -e rc4-hmac HTTP/webapp.example.com
# Expected: kvno: KDC has no support for encryption type
```

### Step 6: krbtgt Account Rotation

The `krbtgt` account's password hash is the root of all Kerberos security in an Active Directory domain. Golden tickets are forged using the `krbtgt` NTLM hash. Rotating `krbtgt` invalidates all existing golden tickets — but the rotation must be performed twice, separated by at least the maximum ticket lifetime (default 10 hours), to ensure all DCs have replicated the new value.

**Manual rotation procedure:**

```powershell
# Step 1: Record the current krbtgt password version number.
Get-ADUser krbtgt -Properties msDS-KeyVersionNumber, PasswordLastSet |
  Select-Object SamAccountName, msDS-KeyVersionNumber, PasswordLastSet

# Step 2: First rotation.
# Generate a new random password. AD enforces this — the password is not user-controlled.
Set-ADAccountPassword -Identity krbtgt `
  -NewPassword (ConvertTo-SecureString `
    ([System.Web.Security.Membership]::GeneratePassword(128,32)) `
    -AsPlainText -Force) `
  -Reset

# Record the new key version number.
Get-ADUser krbtgt -Properties msDS-KeyVersionNumber |
  Select-Object SamAccountName, msDS-KeyVersionNumber

# Step 3: Wait for AD replication across all DCs (verify with repadmin).
repadmin /replsummary
# All DCs must show replication success before proceeding.

# Step 4: Wait at least the max ticket lifetime (default 10 hours).
# This ensures any tickets issued before the first rotation expire naturally.

# Step 5: Second rotation — this invalidates the previous key entirely.
Set-ADAccountPassword -Identity krbtgt `
  -NewPassword (ConvertTo-SecureString `
    ([System.Web.Security.Membership]::GeneratePassword(128,32)) `
    -AsPlainText -Force) `
  -Reset

# Step 6: Verify replication of the second rotation.
repadmin /showrepl * /csv | ConvertFrom-Csv | Where-Object { $_."Number of Failures" -gt 0 }

# Step 7: Confirm the key version incremented twice.
Get-ADUser krbtgt -Properties msDS-KeyVersionNumber, PasswordLastSet |
  Select-Object SamAccountName, msDS-KeyVersionNumber, PasswordLastSet
```

Following a confirmed domain compromise or suspected golden ticket usage, complete both rotations as quickly as possible — the 10-hour wait still applies, but compress the schedule as much as your replication topology permits.

**Schedule regular rotation.** Microsoft recommends rotating `krbtgt` every 90-180 days as a precaution against undiscovered compromise. Automate this using the [krbtgt Key Distribution Center Service Account Remediation script](https://github.com/microsoft/New-KrbtgtKeys.ps1) from Microsoft.

```powershell
# Download and use Microsoft's krbtgt rotation script for production use.
# It includes pre-flight replication checks and safe sequencing.
.\New-KrbtgtKeys.ps1 -Mode "WhatIf"    # Simulate first.
.\New-KrbtgtKeys.ps1 -Mode "Reset1"    # First rotation.
# -- wait for replication and ticket expiry --
.\New-KrbtgtKeys.ps1 -Mode "Reset2"    # Second rotation.
```

### Step 7: Linux Keytab and kinit Hardening

Linux systems joined to Active Directory or a Kerberos realm authenticate using keytab files. A compromised keytab grants persistent, pre-authenticated access to Kerberos services — effectively equivalent to having the account's credentials indefinitely.

```bash
# Check current keytab permissions. Must be 600, owned by the service user.
ls -la /etc/krb5.keytab
# Correct:  -rw------- 1 root root
# Dangerous: world-readable or group-readable

# Fix permissions on the system keytab.
chmod 600 /etc/krb5.keytab
chown root:root /etc/krb5.keytab

# For service-specific keytabs, scope to the service user only.
# Example: Apache Kerberos authentication.
chmod 600 /etc/apache2/krb5-http.keytab
chown www-data:www-data /etc/apache2/krb5-http.keytab

# Verify keytab contents: list principals and their encryption types.
klist -k -e /etc/krb5.keytab
# Ensure only AES entries appear — remove DES/RC4 entries.

# Remove weak encryption entries from a keytab.
# First, list all keys with their version numbers.
ktutil
  rkt /etc/krb5.keytab
  list
  # Delete entries for DES and RC4 (e.g., entry numbers 2, 4, 6 if they are weak).
  delent 2
  delent 4
  wkt /etc/krb5.keytab.new
  quit

mv /etc/krb5.keytab.new /etc/krb5.keytab
chmod 600 /etc/krb5.keytab
```

Configure ticket policies for interactive login (do not enable forwardable/proxiable by default):

```bash
# kinit flags: avoid forwardable tickets for interactive sessions.
# Forwardable TGTs can be forwarded to remote services and captured.
kinit -f    # AVOID: creates forwardable ticket.
kinit       # Correct: creates non-forwardable ticket by default.

# For automated services, use a keytab rather than a password, and configure
# ticket renewal with a bounded lifetime.
kinit -k -t /etc/service-account.keytab svc-worker@EXAMPLE.COM

# Inspect ticket flags on an existing TGT.
klist -f
# Flags to watch for and avoid in production:
# F = forwardable, P = proxiable, A = pre-authenticated (this one is fine and expected)
# D = post-dated, R = renewable (acceptable if renewal lifetime is bounded)
```

Scope ticket lifetimes in the KDC policy (Active Directory Fine-Grained Password and Kerberos Policy):

```powershell
# Set ticket lifetime policy via Default Domain Policy (or Fine-Grained Policy).
# Computer Configuration → Windows Settings → Security Settings → Account Policies
# → Kerberos Policy

# Recommended values:
# Maximum lifetime for service ticket:      600 minutes (10 hours)
# Maximum lifetime for user ticket:         600 minutes (10 hours)
# Maximum lifetime for user ticket renewal: 7 days
# Maximum tolerance for computer clock sync: 5 minutes (NTP drift)

# Set via Group Policy Object (replace $GPO with your policy name):
Set-GPRegistryValue -Name "Default Domain Policy" `
  -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
  -ValueName "MaxTicketAge" `
  -Value 10 -Type DWord
```

### Step 8: Monitoring — Detecting Live Attacks

#### Windows Event IDs for Kerberos Attack Detection

| Event ID | Description | Attack Signal |
|---|---|---|
| 4768 | TGT request (AS-REQ) | AS-REP roasting if `PreAuthType = 0` |
| 4769 | TGS request | Kerberoasting if unusual SPN targets |
| 4771 | Pre-authentication failure | Brute force or password spray |
| 4776 | NTLM credential validation | Protected Users bypass attempt |
| 4624 | Successful logon | Unusual ticket-based logon types |

**Detect kerberoasting — unusual TGS requests:**

```powershell
# Kerberoasting generates 4769 events with RC4 encryption type (0x17 = 23 decimal)
# from non-computer accounts. High volume in a short window is a strong signal.

$cutoff = (Get-Date).AddHours(-1)
Get-WinEvent -ComputerName "DC01" -FilterHashtable @{
  LogName   = "Security"
  Id        = 4769
  StartTime = $cutoff
} | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $ticketEncType = $xml.Event.EventData.Data |
    Where-Object { $_.Name -eq "TicketEncryptionType" } |
    Select-Object -ExpandProperty "#text"
  $serviceName = $xml.Event.EventData.Data |
    Where-Object { $_.Name -eq "ServiceName" } |
    Select-Object -ExpandProperty "#text"
  $requester = $xml.Event.EventData.Data |
    Where-Object { $_.Name -eq "TargetUserName" } |
    Select-Object -ExpandProperty "#text"

  # 0x17 = RC4. Flag requests for service accounts using RC4.
  if ($ticketEncType -eq "0x17" -and $serviceName -notlike "*$") {
    [PSCustomObject]@{
      Time        = $_.TimeCreated
      Requester   = $requester
      Service     = $serviceName
      EncType     = $ticketEncType
      Alert       = "KERBEROASTING INDICATOR: RC4 TGS for service account"
    }
  }
} | Format-Table -AutoSize
```

**Detect AS-REP roasting — pre-auth not required:**

```powershell
# Event 4768 with PreAuthType 0x0 = pre-authentication not used.
# Combined with failed (Result != 0x0) or succeeded requests to unusual accounts.

$cutoff = (Get-Date).AddHours(-4)
Get-WinEvent -ComputerName "DC01" -FilterHashtable @{
  LogName   = "Security"
  Id        = 4768
  StartTime = $cutoff
} | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $preAuthType = $xml.Event.EventData.Data |
    Where-Object { $_.Name -eq "PreAuthType" } |
    Select-Object -ExpandProperty "#text"
  $targetUser = $xml.Event.EventData.Data |
    Where-Object { $_.Name -eq "TargetUserName" } |
    Select-Object -ExpandProperty "#text"

  if ($preAuthType -eq "0") {
    [PSCustomObject]@{
      Time        = $_.TimeCreated
      Account     = $targetUser
      PreAuthType = $preAuthType
      Alert       = "AS-REP ROASTING: pre-auth not required"
    }
  }
} | Format-Table -AutoSize
```

**Detect golden ticket indicators — anomalous ticket properties:**

```powershell
# Golden tickets often have anomalous properties that differ from legitimate tickets:
# - Ticket lifetime outside policy bounds
# - SID history fields populated with unexpected values
# - PAC validation failures (Event 4769 with unusual client address)

# Monitor for Event 4769 with ticket origin from unexpected source IPs.
# Alert on TGS requests where the client IP does not match the account's
# typical workstation.

# Detect anomalous account usage patterns: domain admin accounts requesting TGS
# tickets from non-admin workstations, or at unusual hours.
$domainAdmins = (Get-ADGroupMember "Domain Admins" -Recursive |
  Select-Object -ExpandProperty SamAccountName) -join "|"

$cutoff = (Get-Date).AddDays(-1)
Get-WinEvent -ComputerName "DC01" -FilterHashtable @{
  LogName   = "Security"
  Id        = 4769
  StartTime = $cutoff
} | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $requester = $xml.Event.EventData.Data |
    Where-Object { $_.Name -eq "TargetUserName" } |
    Select-Object -ExpandProperty "#text"
  $clientIP = $xml.Event.EventData.Data |
    Where-Object { $_.Name -eq "IpAddress" } |
    Select-Object -ExpandProperty "#text"

  if ($requester -match $domainAdmins -and
      $clientIP -ne "::1" -and
      $clientIP -notmatch "^10\.10\.5\.") {
    [PSCustomObject]@{
      Time      = $_.TimeCreated
      Admin     = $requester
      ClientIP  = $clientIP
      Alert     = "DA account TGS from unexpected IP — possible golden ticket"
    }
  }
} | Format-Table -AutoSize
```

**Ship these events to your SIEM.** Configure Windows Event Forwarding or a Beats/NXLog agent to forward Security log events 4768, 4769, 4771, and 4776 from all domain controllers in real time.

```bash
# Sigma rule for kerberoasting detection (YAML — import into SIEM).
cat > /etc/sigma/rules/kerberoasting.yml << 'EOF'
title: Kerberoasting Service Ticket Request
status: stable
description: Detects kerberoasting via RC4-encrypted TGS requests for non-computer accounts
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter_computers:
    ServiceName|endswith: '$'
  condition: selection and not filter_computers
falsepositives:
  - Legacy applications that require RC4
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
EOF
```

## Verification Checklist

Run these checks after completing the configuration steps:

```powershell
# 1. Confirm no accounts have pre-auth disabled.
$noPreAuth = Get-ADUser -Filter * -Properties UserAccountControl |
  Where-Object { $_.UserAccountControl -band 0x400000 }
if ($noPreAuth) {
  Write-Warning "FAIL: $($noPreAuth.Count) accounts still have pre-auth disabled."
} else {
  Write-Output "PASS: No accounts with DONT_REQUIRE_PREAUTH found."
}

# 2. Confirm no user accounts with SPNs have weak passwords (< 25 chars is unverifiable
#    from AD alone — verify gMSA migration status instead).
$svcAccountsNotGmsa = Get-ADUser -Filter { ServicePrincipalName -ne "$null" } |
  Where-Object { $_.SamAccountName -notlike "*$" }
Write-Output "Service user accounts with SPNs (target = 0): $($svcAccountsNotGmsa.Count)"

# 3. Confirm no non-DC machines have unconstrained delegation.
$unconstrainedDelegation = Get-ADComputer -Filter { TrustedForDelegation -eq $true } |
  Where-Object { $_.Name -notmatch "DC\d+" }
if ($unconstrainedDelegation) {
  Write-Warning "FAIL: Non-DC machines with unconstrained delegation: $($unconstrainedDelegation.Name)"
} else {
  Write-Output "PASS: No non-DC machines with unconstrained delegation."
}

# 4. Confirm Protected Users group has all privileged accounts.
$protectedUsers = Get-ADGroupMember "Protected Users" | Select-Object -ExpandProperty SamAccountName
$domainAdmins   = Get-ADGroupMember "Domain Admins" -Recursive | Select-Object -ExpandProperty SamAccountName
$missing = $domainAdmins | Where-Object { $protectedUsers -notcontains $_ }
if ($missing) {
  Write-Warning "FAIL: DA accounts not in Protected Users: $($missing -join ', ')"
} else {
  Write-Output "PASS: All Domain Admins are in Protected Users."
}

# 5. Confirm krbtgt password age.
$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
$agedays = ((Get-Date) - $krbtgt.PasswordLastSet).Days
if ($agedays -gt 180) {
  Write-Warning "FAIL: krbtgt password is $agedays days old (threshold: 180 days)."
} else {
  Write-Output "PASS: krbtgt password age = $agedays days."
}
```

```bash
# 6. Linux: confirm krb5.conf disallows weak crypto.
grep -E "allow_weak_crypto|default_tkt_enctypes" /etc/krb5.conf
# Expected: allow_weak_crypto = false, enctypes list contains only aes*.

# 7. Linux: confirm keytab file permissions.
stat -c "%a %U %G %n" /etc/krb5.keytab
# Expected: 600 root root /etc/krb5.keytab

# 8. Confirm no RC4 keys in the keytab.
klist -k -e /etc/krb5.keytab | grep -i "rc4\|des\|arcfour"
# Expected: no output.
```

## Summary

The Kerberos attack surface in a default Active Directory or Linux Kerberos deployment is wide: pre-auth disabled on legacy accounts, human-set service account passwords crackable via kerberoasting, unconstrained delegation on servers that nobody remembers configuring, and the `krbtgt` account never rotated. Each of these is individually exploitable by a low-privilege attacker; in combination they represent a clear path to domain compromise.

| Risk | Control |
|---|---|
| AS-REP roasting | Enforce pre-auth on all accounts; audit weekly |
| Kerberoasting | Migrate SPNs to gMSAs; 25+ char passwords for exceptions |
| Unconstrained delegation | Audit and remove from all non-DC machines |
| RBCD abuse | Restrict write access to computer object ACLs |
| Protected Users exclusions | Add all tier-0 accounts; verify quarterly |
| RC4/DES encryption | GPO + `msDS-SupportedEncryptionTypes` = AES only |
| Golden ticket persistence | Rotate `krbtgt` twice every 90-180 days |
| Keytab exposure | 600 permissions, service-user-owned, AES keys only |
| Undetected attacks | SIEM ingestion of Event IDs 4768/4769/4771 from all DCs |

The controls are cumulative: disabling RC4 makes kerberoasting attacks slower but does not eliminate them; gMSA deployment eliminates them entirely for the accounts it covers. Work through each section in sequence, test in a lab environment against a non-production domain first, and run the verification checklist after each change.
