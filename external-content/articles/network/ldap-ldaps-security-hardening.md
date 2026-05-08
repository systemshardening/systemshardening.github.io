---
title: "LDAP and LDAPS Security Hardening for Directory Service Connections"
description: "LDAP on port 389 transmits bind credentials in cleartext, permits anonymous enumeration, and is trivially injectable. This guide covers enforcing LDAPS, disabling anonymous bind, writing correct OpenLDAP ACLs, preventing LDAP injection in application code, and hardening Active Directory LDAP signing and channel binding."
slug: ldap-ldaps-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - ldap
  - ldaps
  - active-directory
  - directory-service
  - credential-security
personas:
  - security-engineer
  - sysadmin
article_number: 496
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/network/ldap-ldaps-security-hardening/
---

# LDAP and LDAPS Security Hardening for Directory Service Connections

## The Problem

LDAP (Lightweight Directory Access Protocol) is the backbone of authentication and authorisation for most enterprise environments: Active Directory, OpenLDAP, FreeIPA, and almost every SSO system rely on it. It is also one of the most consistently misconfigured protocols in production.

The default LDAP port — 389 — carries credentials in plaintext. A bind operation sends the username and password over the wire unencrypted. Any observer on the network path — a compromised host, a cloud VPC tap, a malicious hypervisor — reads those credentials directly. This is not a theoretical risk: penetration testers routinely capture domain service account credentials this way during internal assessments.

Beyond cleartext credentials, LDAP deployments commonly suffer from:

- **Anonymous bind enabled.** Unauthenticated clients can enumerate directory contents — user accounts, group memberships, email addresses, organisational structure — without presenting any credentials.
- **Null base DN queries.** Querying with an empty base DN against the Root DSE leaks server capabilities, naming contexts, and supported LDAP versions to any unauthenticated client.
- **LDAP injection.** Application code that builds LDAP filter strings from user input is vulnerable to injection that bypasses authentication, returns unintended records, or causes denial of service.
- **Admin DN used for application binds.** Applications frequently bind as `cn=admin,dc=example,dc=com` because it "just works," giving the application read and write access to the entire directory — far beyond what authentication lookups require.
- **No audit logging.** Bind attempts, search volume, and attribute access are unmonitored, making LDAP enumeration and credential stuffing invisible.

**Target systems:** OpenLDAP 2.6+, Active Directory on Windows Server 2019/2022, FreeIPA 4.x, any application performing LDAP authentication (Java, Python, Go).

## Threat Model

- **Adversary 1 — On-path credential capture:** An attacker with access to the network segment between the application server and the LDAP server captures TCP traffic on port 389. Every bind operation leaks a service account username and password.
- **Adversary 2 — Anonymous directory enumeration:** An unauthenticated attacker reaches port 389 or 636 and binds anonymously, then iterates through `ou=users` and `ou=groups` to extract all account names, email addresses, and group memberships for use in phishing and password spray campaigns.
- **Adversary 3 — LDAP injection:** An attacker submits crafted input through an application login form. The application concatenates the input directly into an LDAP filter, allowing the attacker to bypass authentication entirely or retrieve all user records.
- **Adversary 4 — Service account privilege escalation:** An application's bind DN has write access to the directory. A compromised application server uses the bound credentials to create new admin accounts or modify group memberships.
- **Adversary 5 — StartTLS downgrade:** A man-in-the-middle strips or forges a StartTLS failure response, causing the client to fall back to cleartext communication. The application proceeds unaware that encryption was not established.
- **Access level:** Adversaries 1 and 5 are on the network path. Adversaries 2, 3, and 4 can reach the LDAP port directly.
- **Objective:** Extract credentials, enumerate users for targeted attacks, bypass authentication, or escalate privileges within the directory.
- **Blast radius:** A compromised service account or enumerated user list enables credential stuffing across all LDAP-integrated systems. A write-capable bind DN compromise is equivalent to domain admin access in smaller environments.

## Configuration

### Step 1: LDAPS vs StartTLS — Choose LDAPS

Two mechanisms exist for encrypting LDAP traffic:

- **LDAPS (port 636):** TLS is established before any LDAP communication occurs. The first byte is TLS handshake data. There is no protocol-level opportunity for downgrade.
- **StartTLS (LDAP over port 389 with the `STARTTLS` extended operation):** The connection starts as plaintext LDAP. The client sends a `STARTTLS` request, the server responds with success, and then TLS is negotiated. If an attacker intercepts the connection and returns a failure response for the `STARTTLS` request, many LDAP clients fall back to cleartext rather than failing hard.

The security argument is straightforward: **use LDAPS**. It eliminates the downgrade attack surface entirely. StartTLS exists as a transitional mechanism, but LDAPS on port 636 is the correct choice for new deployments and migrations.

Configure OpenLDAP to listen on 636 and reject plain 389:

```bash
# /etc/default/slapd (Debian/Ubuntu) or /etc/sysconfig/slapd (RHEL)
# Restrict slapd to LDAPS only. Remove ldap:/// to disable cleartext port 389.
SLAPD_URLS="ldaps:/// ldapi:///"
```

Verify with `ss`:

```bash
ss -tlnp | grep slapd
# Expected: only port 636 (ldaps) and the Unix socket (ldapi).
# If port 389 appears, cleartext LDAP is still active.
```

For Active Directory, enforce LDAPS at the domain level and block port 389 at the network layer (covered in the firewall section below).

### Step 2: OpenLDAP TLS Configuration

Providing a certificate is not sufficient — the configuration must also enforce certificate verification and restrict protocol versions.

```ldif
# Apply via ldapmodify to cn=config.
# File: tls-config.ldif

dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ssl/certs/internal-ca.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/certs/ldap-server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/certs/ldap-server.key
-
replace: olcTLSVerifyClient
olcTLSVerifyClient: demand
-
replace: olcTLSProtocolMin
olcTLSProtocolMin: 3.3
-
replace: olcTLSCipherSuite
olcTLSCipherSuite: HIGH:!aNULL:!MD5:!RC4:!3DES
```

```bash
# Apply the configuration change.
ldapmodify -Y EXTERNAL -H ldapi:/// -f tls-config.ldif

# Verify the certificate loads correctly.
openssl s_client -connect ldap.internal:636 -CAfile /etc/ssl/certs/internal-ca.crt \
  -servername ldap.internal </dev/null 2>&1 | grep -E "Verify return|subject="
```

Key settings explained:

- `olcTLSVerifyClient: demand` — clients must present a certificate signed by the CA. Set to `allow` if client certificates are not yet deployed, but plan to migrate to `demand`.
- `olcTLSProtocolMin: 3.3` — disables TLS 1.0 and 1.1, requiring TLS 1.2 at minimum. Use `3.4` to require TLS 1.3.
- `olcTLSCipherSuite` — eliminates anonymous DH (`!aNULL`), MD5-based ciphers, and legacy algorithms. Adjust to your organisation's cipher policy.

### Step 3: Disable Anonymous Bind

Anonymous bind must be disabled at the server level. OpenLDAP's `olcAllows` directive controls which non-standard features are permitted:

```ldif
# disable-anon-bind.ldif

dn: cn=config
changetype: modify
replace: olcAllows
olcAllows: none
```

Additionally, require authentication before any operations can proceed using `olcRequires`:

```ldif
# require-auth.ldif

dn: cn=config
changetype: modify
replace: olcRequires
olcRequires: authc
```

```bash
# Apply both.
ldapmodify -Y EXTERNAL -H ldapi:/// -f disable-anon-bind.ldif
ldapmodify -Y EXTERNAL -H ldapi:/// -f require-auth.ldif

# Verify anonymous bind is rejected.
ldapsearch -H ldaps://ldap.internal -x -b "dc=example,dc=com" "(uid=testuser)"
# Expected: ldap_bind: Inappropriate authentication (48)
```

### Step 4: Access Control Lists in OpenLDAP

After disabling anonymous bind, define what authenticated identities are permitted to read. OpenLDAP ACLs (`olcAccess` rules) follow a first-match-wins model. The correct posture is deny-by-default with explicit grants.

```ldif
# acl-config.ldif
# Apply in order: most specific rules first, deny-all last.

dn: olcDatabase={1}mdb,cn=config
changetype: modify

# Rule 1: Protect password hashes.
# Only the entry owner and the replication account can read userPassword.
add: olcAccess
olcAccess: {0}to attrs=userPassword
  by dn.exact="cn=replication,dc=example,dc=com" read
  by self write
  by anonymous auth
  by * none

# Rule 2: Protect shadow password attributes.
add: olcAccess
olcAccess: {1}to attrs=shadowLastChange
  by self write
  by * read

# Rule 3: Service account for application authentication lookups.
# Can read uid, cn, mail, memberOf on users — nothing else.
add: olcAccess
olcAccess: {2}to dn.subtree="ou=users,dc=example,dc=com"
  attrs=uid,cn,mail,memberOf
  by dn.exact="cn=app-bind,ou=service-accounts,dc=example,dc=com" read
  by self read
  by * none

# Rule 4: Deny everything else by default.
add: olcAccess
olcAccess: {3}to *
  by self read
  by dn.exact="cn=admin,dc=example,dc=com" write
  by * none
```

```bash
ldapmodify -Y EXTERNAL -H ldapi:/// -f acl-config.ldif

# Test that the service account can read uid but not userPassword.
ldapsearch -H ldaps://ldap.internal \
  -D "cn=app-bind,ou=service-accounts,dc=example,dc=com" \
  -w "$APP_BIND_PASSWORD" \
  -b "ou=users,dc=example,dc=com" \
  "(uid=alice)" uid mail
# userPassword must NOT appear in output.
```

Critical points for ACL design:

- The `userPassword` ACL must appear first. OpenLDAP evaluates `olcAccess` rules in indexed order; a permissive general rule before the password rule exposes hashes.
- `by anonymous auth` on the `userPassword` attribute permits the anonymous-to-authenticated transition (the bind operation itself). Removing it breaks authentication.
- Service accounts should access only the subtree and attributes they require for their specific function. An application that only checks group membership during login does not need `uid` or `mail`.

### Step 5: Bind DN Least Privilege

Do not use the directory admin DN for application authentication. Create dedicated service accounts scoped to the minimum required access:

```ldif
# create-service-account.ldif

dn: ou=service-accounts,dc=example,dc=com
objectClass: organizationalUnit
ou: service-accounts

dn: cn=app-bind,ou=service-accounts,dc=example,dc=com
objectClass: inetOrgPerson
cn: app-bind
sn: app-bind
uid: app-bind
userPassword: {SSHA}REPLACE_WITH_HASHED_PASSWORD
description: Read-only bind account for webapp authentication lookups
```

```bash
# Generate a strong password and hash it.
slappasswd -s "$(openssl rand -base64 32)"

ldapadd -Y EXTERNAL -H ldapi:/// -f create-service-account.ldif

# Verify the account cannot write to the directory.
ldapmodify -H ldaps://ldap.internal \
  -D "cn=app-bind,ou=service-accounts,dc=example,dc=com" \
  -w "$APP_BIND_PASSWORD" << 'EOF'
dn: uid=alice,ou=users,dc=example,dc=com
changetype: modify
replace: cn
cn: hacked
EOF
# Expected: ldap_modify: Insufficient access (50)
```

Operationally: rotate service account passwords on a schedule using a secrets manager (HashiCorp Vault, AWS Secrets Manager). Never embed the bind DN password in application configuration files or environment variables checked into source control.

### Step 6: LDAP Injection Prevention in Application Code

LDAP filters concatenated from user input are injectable. The canonical attack against a login form that builds `(&(uid=INPUT)(objectClass=person))` is to supply `*)(uid=*))(|(uid=*` as the username, which collapses the filter to `(&(uid=*)(objectClass=person))` — matching every user and authenticating as the first result.

Use parameterised LDAP APIs and sanitise input before any filter construction.

**Java (JNDI with input escaping):**

```java
import javax.naming.directory.SearchControls;
import javax.naming.directory.InitialDirContext;

// BAD: direct concatenation — never do this.
// String filter = "(&(uid=" + username + ")(objectClass=person))";

// GOOD: escape all filter-special characters before inserting into a filter.
// RFC 4515 characters requiring escaping: ( ) * \ NUL and values > 0x7F.
private static String escapeLdapFilter(String input) {
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '\\': sb.append("\\5c"); break;
            case '*':  sb.append("\\2a"); break;
            case '(':  sb.append("\\28"); break;
            case ')':  sb.append("\\29"); break;
            case '\0': sb.append("\\00"); break;
            default:   sb.append(c);
        }
    }
    return sb.toString();
}

String safeUsername = escapeLdapFilter(username);
String filter = "(&(uid=" + safeUsername + ")(objectClass=person))";

SearchControls controls = new SearchControls();
controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
// Restrict returned attributes — never return * by default.
controls.setReturningAttributes(new String[]{"uid", "cn", "mail"});
// Limit results to prevent DoS through unbounded searches.
controls.setCountLimit(1);
controls.setTimeLimit(5000); // 5 seconds.

ctx.search("ou=users,dc=example,dc=com", filter, controls);
```

**Python (ldap3 with safe filter construction):**

```python
from ldap3 import Server, Connection, SAFE_SYNC, SUBTREE
from ldap3.utils.conv import escape_filter_chars

# BAD: f"(&(uid={username})(objectClass=person))"

# GOOD: escape before embedding in the filter.
def build_auth_filter(username: str) -> str:
    safe_username = escape_filter_chars(username)
    return f"(&(uid={safe_username})(objectClass=person))"

server = Server("ldaps://ldap.internal", port=636, use_ssl=True)
conn = Connection(
    server,
    user="cn=app-bind,ou=service-accounts,dc=example,dc=com",
    password=get_secret("ldap/app-bind"),
    client_strategy=SAFE_SYNC,
    auto_bind=True,
)

search_filter = build_auth_filter(untrusted_username)
conn.search(
    search_base="ou=users,dc=example,dc=com",
    search_filter=search_filter,
    search_scope=SUBTREE,
    attributes=["uid", "cn", "mail"],
    size_limit=1,
    time_limit=5,
)
```

**Go (go-ldap with attribute escaping):**

```go
import (
    "github.com/go-ldap/ldap/v3"
    "fmt"
)

func buildAuthFilter(username string) string {
    // ldap.EscapeFilter handles RFC 4515 escaping.
    safeUsername := ldap.EscapeFilter(username)
    return fmt.Sprintf("(&(uid=%s)(objectClass=person))", safeUsername)
}

func authenticateUser(conn *ldap.Conn, username string) (*ldap.SearchResult, error) {
    searchRequest := ldap.NewSearchRequest(
        "ou=users,dc=example,dc=com",
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        1,    // SizeLimit — return at most 1 entry.
        5,    // TimeLimit — 5 seconds.
        false,
        buildAuthFilter(username),
        []string{"uid", "cn", "mail"}, // Explicit attribute list.
        nil,
    )
    return conn.Search(searchRequest)
}
```

Beyond escaping: validate that `username` matches an expected pattern before it reaches the LDAP layer at all. A username that contains `(`, `)`, `*`, or `\` is almost certainly malicious input:

```python
import re

USERNAME_RE = re.compile(r'^[a-zA-Z0-9._\-]{1,64}$')

def validate_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username))
```

### Step 7: Active Directory LDAP Hardening

Active Directory exposes LDAP on port 389 and LDAPS on port 636. Several Group Policy settings must be configured to enforce signing and prevent downgrade.

**Enforce LDAP signing (Group Policy):**

```
Computer Configuration
  → Windows Settings
    → Security Settings
      → Local Policies
        → Security Options
          → "Domain controller: LDAP server signing requirements"
            → Set to: Require signing
```

This forces all LDAP clients to sign their requests. Unsigned LDAP binds are rejected with error code `LDAP_UNWILLING_TO_PERFORM`. Before enforcing, audit existing clients with event ID 2889 (unsigned LDAP bind attempts):

```powershell
# Find unsigned LDAP bind events in the Directory Service log.
Get-WinEvent -LogName "Directory Service" |
  Where-Object { $_.Id -eq 2889 } |
  Select-Object TimeCreated, Message |
  Format-List
```

**Enforce LDAP channel binding (Windows Server 2022+):**

```
Computer Configuration
  → Windows Settings
    → Security Settings
      → Local Policies
        → Security Options
          → "Domain controller: LDAP server channel binding token requirements"
            → Set to: Always
```

Channel binding ties the LDAP session to the specific TLS channel, preventing relay attacks where an attacker intercepts a Kerberos or NTLM authentication and replays it over a different TLS session.

**Disable null sessions (LDAP anonymous bind on AD):**

```powershell
# Disable anonymous LDAP access on all domain controllers.
# This is a registry setting; deploy via GPO or DSC.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
  -Name "LDAPServerIntegrity" -Value 2 -Type DWord

# Verify.
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" |
  Select-Object LDAPServerIntegrity
# 2 = Require signing. 0 = None (insecure). 1 = Negotiate.
```

**Disable LDAP on port 389 entirely for AD (where client compatibility allows):**

```powershell
# Deploy LDAPS certificate via internal CA, then restrict LDAP to 636.
# Windows Firewall — block inbound port 389 on all DC network interfaces.
New-NetFirewallRule `
  -DisplayName "Block Cleartext LDAP" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 389 `
  -Action Block `
  -Profile Domain
```

Audit LDAPS certificate expiry on domain controllers:

```powershell
# Check the certificate bound to port 636 on the local DC.
netsh http show sslcert ipport=0.0.0.0:636 | Select-String "Certificate Hash"
```

### Step 8: Network-Level Protection

Firewall policy should restrict LDAP access to specific, known source subnets. No external access to LDAP or LDAPS should ever be permitted.

```bash
# iptables: restrict port 636 to the application server subnet only.
# All other traffic — including from the internet — is dropped.

APP_SUBNET="10.10.20.0/24"
LDAP_SERVER_IP="10.10.10.5"

# Allow LDAPS from application servers.
iptables -A INPUT -p tcp -s "$APP_SUBNET" --dport 636 -j ACCEPT

# Allow LDAPS from monitoring host (for cert expiry checks).
iptables -A INPUT -p tcp -s "10.10.10.100/32" --dport 636 -j ACCEPT

# Drop all other LDAPS traffic.
iptables -A INPUT -p tcp --dport 636 -j DROP

# Drop cleartext LDAP entirely.
iptables -A INPUT -p tcp --dport 389 -j DROP

# Save rules.
iptables-save > /etc/iptables/rules.v4
```

For nftables (preferred on modern systems):

```bash
# /etc/nftables.conf — add to the input chain.

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # LDAPS: only from application subnet.
        ip saddr 10.10.20.0/24 tcp dport 636 accept
        ip saddr 10.10.10.100 tcp dport 636 accept

        # Cleartext LDAP: rejected with TCP RST.
        tcp dport 389 reject with tcp reset

        # Drop unexpected LDAPS from any other source.
        tcp dport 636 drop
    }
}
```

### Step 9: Monitoring and Anomaly Detection

#### Audit Bind Attempts in OpenLDAP

Enable access logging with the `accesslog` overlay:

```ldif
# enable-accesslog.ldif

dn: cn=module,cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: accesslog

dn: olcDatabase=accesslog,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: accesslog
olcDbDirectory: /var/lib/ldap/accesslog
olcSuffix: cn=accesslog
olcAccess: {0}to * by dn.exact="cn=admin,dc=example,dc=com" read by * none
olcDbIndex: default eq
olcDbIndex: entryCSN,objectClass,reqEnd,reqResult,reqStart

dn: olcOverlay=accesslog,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcAccessLogConfig
olcOverlay: accesslog
olcAccessLogDB: cn=accesslog
olcAccessLogOps: bind writes
olcAccessLogSuccess: TRUE
olcAccessLogPurge: 30+00:00 01+00:00
```

```bash
ldapadd -Y EXTERNAL -H ldapi:/// -f enable-accesslog.ldif
```

#### Detect Failed Bind Storms

Failed bind storms indicate credential stuffing or a misconfigured application. Parse the access log and alert on threshold breach:

```bash
#!/bin/bash
# /usr/local/bin/ldap-bind-monitor.sh
# Run every 5 minutes from cron. Alert if >50 failed binds in the window.

THRESHOLD=50
WINDOW_MINUTES=5
ACCESSLOG_DB="cn=accesslog"
LDAP_ADMIN_DN="cn=admin,dc=example,dc=com"

failed_binds=$(ldapsearch -Y EXTERNAL -H ldapi:/// \
  -b "$ACCESSLOG_DB" \
  "(&(objectClass=auditBind)(reqResult!=0)(reqEnd>=$(date -d "-${WINDOW_MINUTES} minutes" +%Y%m%d%H%M%SZ)))" \
  reqDN 2>/dev/null | grep -c "^reqDN:")

if [ "$failed_binds" -gt "$THRESHOLD" ]; then
  echo "ALERT: $failed_binds failed LDAP bind attempts in the last ${WINDOW_MINUTES} minutes" |
    mail -s "LDAP bind storm detected" security@example.com
fi
```

#### Detect LDAP Enumeration

High-volume search queries from a single bind DN indicate enumeration. Log and alert:

```bash
# Parse slapd logs for query volume per bind DN (requires loglevel 256).
# /etc/ldap/slapd.d/cn=config.ldif: olcLogLevel: 256

# Detect enumeration: >500 search operations from one DN in 10 minutes.
journalctl -u slapd --since "10 minutes ago" |
  grep "SRCH" |
  grep -oP 'dn="[^"]+"' |
  sort | uniq -c | sort -rn |
  awk '$1 > 500 {print "ENUM ALERT: "$0}'
```

For Active Directory, enable advanced audit policy and watch for event ID 4661 (directory service object access) with high frequency from a single source:

```powershell
# Enable directory service access auditing.
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# Query for high-volume LDAP queries (Event 4661) in the last hour.
$cutoff = (Get-Date).AddHours(-1)
Get-WinEvent -LogName Security |
  Where-Object { $_.Id -eq 4661 -and $_.TimeCreated -gt $cutoff } |
  Group-Object { $_.Properties[1].Value } |
  Where-Object { $_.Count -gt 1000 } |
  Select-Object Count, Name |
  Sort-Object Count -Descending
```

## Verification Checklist

Run these checks to validate the configuration before declaring a hardening pass complete:

```bash
# 1. Confirm cleartext LDAP is not reachable.
nc -zv ldap.internal 389 2>&1 | grep -E "succeeded|refused"
# Expected: Connection refused.

# 2. Confirm LDAPS is reachable and presents a valid certificate.
openssl s_client -connect ldap.internal:636 \
  -CAfile /etc/ssl/certs/internal-ca.crt </dev/null 2>&1 |
  grep "Verify return code: 0"

# 3. Confirm anonymous bind is rejected.
ldapsearch -H ldaps://ldap.internal -x -b "dc=example,dc=com" "(objectClass=*)" 2>&1 |
  grep "Inappropriate authentication"

# 4. Confirm the service account cannot write.
# (See Step 5 above for the ldapmodify write test.)

# 5. Confirm TLS version floor.
openssl s_client -connect ldap.internal:636 -tls1 </dev/null 2>&1 |
  grep "handshake failure"
# Expected: handshake failure (TLS 1.0 rejected).

# 6. List active olcAccess rules.
ldapsearch -Y EXTERNAL -H ldapi:/// -b "olcDatabase={1}mdb,cn=config" olcAccess
```

## Summary

The default LDAP configuration is hostile to security: cleartext credentials on port 389, anonymous bind enabled, no ACLs beyond what the installer sets, and no audit logging. The configuration steps above address each layer:

| Risk | Control |
|---|---|
| Cleartext credentials | LDAPS on port 636; port 389 blocked |
| StartTLS downgrade | Disable StartTLS; use LDAPS exclusively |
| Anonymous enumeration | `olcAllows none` + `olcRequires authc` |
| Overpermissive read access | `olcAccess` ACLs, deny-by-default |
| LDAP injection | `escape_filter_chars` / `ldap.EscapeFilter` in application code |
| Admin DN abuse | Dedicated least-privilege service accounts |
| AD signing/relay | LDAP signing required + channel binding enforced |
| Network exposure | Firewall to application subnet only |
| Undetected attacks | Access log overlay + bind storm alerting |

Run the verification checklist after applying changes and on every infrastructure change that touches directory service connectivity. Certificate expiry is a recurring operational risk: monitor LDAPS certificate expiry and alert at 30 days.
