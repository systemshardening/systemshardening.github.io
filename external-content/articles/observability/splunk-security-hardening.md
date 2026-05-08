---
title: "Splunk Security Hardening: Authentication, RBAC, TLS, and Audit Logging"
description: "Splunk ingests every security log in your environment — compromising it gives an attacker a complete map of your defenses and an erasure tool for the audit trail. This guide covers SAML/LDAP authentication, role-based access control, TLS hardening for forwarder-to-indexer traffic, audit logging, and protecting the splunk.secret file."
slug: splunk-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - splunk
  - siem
  - log-management
  - authentication
  - audit-logging
personas:
  - security-engineer
  - security-analyst
article_number: 550
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/splunk-security-hardening/
---

# Splunk Security Hardening: Authentication, RBAC, TLS, and Audit Logging

## Problem

Splunk is the single most sensitive system in many security operations environments. It aggregates firewall logs, endpoint telemetry, authentication events, cloud API activity, and vulnerability scan results. Compromising Splunk is not like compromising a database — it is compromising your ability to detect that you have been compromised.

Default and underhardened Splunk deployments present several critical risks:

- **Built-in admin account with a weak or default password.** Splunk ships with a local `admin` account. If SAML or LDAP is configured but the built-in account is not disabled, it becomes a persistent backdoor that bypasses identity provider controls.
- **No TLS between Universal Forwarders and indexers.** Forwarder-to-indexer traffic is plaintext by default. An attacker on the network intercepts log data before it reaches the SIEM.
- **No index-level access control.** Analysts can search indexes they have no business reason to access — including security investigation data, HR system logs, and audit trails.
- **splunk.secret stored with world-readable permissions.** This file is used to encrypt all passwords stored in Splunk configuration files. Anyone who can read it can decrypt every Splunk credential.
- **Splunk Web accessible on all interfaces.** Splunk Web defaults to port 8000 on all network interfaces. In a multi-homed server, this may expose the web UI to network segments that should not reach it.
- **No audit logging to an external destination.** Splunk writes to the `_audit` index internally. An attacker who compromises Splunk can modify or delete that index, eliminating the audit trail of their own access.

**Target systems:** Splunk Enterprise 9.x (on-premises or self-managed); Splunk Cloud Platform (select configurations apply); distributed deployments with search heads, indexers, and Universal Forwarders.

## Threat Model

- **Adversary 1 — Stolen admin credentials:** The built-in local `admin` account is never disabled after SAML is configured. An attacker who obtains the password bypasses SSO, MFA, and identity provider controls entirely.
- **Adversary 2 — Forwarder traffic interception:** Universal Forwarders ship log data to indexers over plaintext TCP (port 9997 by default). An attacker on the internal network captures this stream and reads all security log data before it reaches the SIEM.
- **Adversary 3 — Over-privileged analyst account:** A Tier-1 analyst account has the `search` role, which grants access to all indexes. The analyst searches `index=hr_payroll` or `index=executive_communications` — data they have no business justification to access.
- **Adversary 4 — splunk.secret exfiltration:** An attacker with OS-level read access to the Splunk server reads `/opt/splunk/etc/auth/splunk.secret`. They decrypt `$SPLUNK_HOME/etc/system/local/authentication.conf` and recover plaintext LDAP bind credentials and other service account passwords.
- **Adversary 5 — Audit trail manipulation:** An attacker who gains Splunk admin access deletes events from the `_audit` index to cover their tracks. No external copy exists.
- **Adversary 6 — Deployment server compromise:** A Universal Forwarder trusts its deployment server without validating its identity. An attacker who can respond to the forwarder's connection (man-in-the-middle or rogue deployment server) pushes a malicious forwarder app that exfiltrates data.
- **Objective:** Read security log data; erase audit evidence; pivot to other systems using credentials recovered from Splunk configuration files.
- **Blast radius:** A compromised Splunk deployment exposes the contents of every log source in your environment, reveals the current state of your security monitoring, and provides credentials for every system that forwards logs via authenticated channels.

## Configuration

### Step 1: Authentication Hardening — SAML Integration and Disabling Built-in Admin

Configure SAML authentication via your identity provider (Okta, Azure AD, Ping) and disable the built-in admin account once SSO is verified working.

```ini
# $SPLUNK_HOME/etc/system/local/authentication.conf
# Configure SAML authentication.

[authentication]
authType = SAML
authSettings = okta_saml

[okta_saml]
# SAML 2.0 IdP metadata URL — Splunk fetches the signing certificate from this endpoint.
idpMetadataUrl = https://your-org.okta.com/app/splunk/sso/saml/metadata

# ACS URL registered in your IdP application.
assertionConsumerServiceUrl = https://splunk.example.com:8000/saml/acs

# Entity ID — must match what is registered in the IdP.
entityId = https://splunk.example.com

# Attribute names in the SAML assertion that map to Splunk fields.
# These vary by IdP; check your assertion XML.
attributeQuerySoapPassword =
attributeQuerySoapUsername =
idpSLOUrl = https://your-org.okta.com/app/splunk/slo/saml
redirectAfterLogoutToUrl = https://splunk.example.com:8000

# Map IdP group claims to Splunk roles.
# The claim name must match your IdP's group attribute.
idpAttributeName = groups

# Role mapping: IdP group → Splunk role.
# Defined in authorize.conf (see Step 2).
```

```ini
# $SPLUNK_HOME/etc/system/local/authorize.conf
# Map SAML group claims to Splunk roles.

[roleMap_okta_saml]
# Format: splunk_role = IdP_group_name
admin            = splunk-admins
power            = splunk-power-users
analyst_tier1    = soc-tier1
analyst_tier2    = soc-tier2
readonly         = splunk-readonly
```

After verifying that SAML login works for at least two admin accounts, disable the built-in local admin:

```bash
# Disable the built-in admin account via Splunk REST API.
# Run from a machine with network access to Splunk management port (8089).

# First, confirm SAML admin login works — then disable built-in admin.
curl -k -u admin:current_password \
  -X POST https://splunk.example.com:8089/services/admin/users/admin \
  -d "defaultApp=search" \
  -d "locked-out=1"

# Verify the account is locked.
curl -k -u saml_admin_user:saml_token \
  https://splunk.example.com:8089/services/admin/users/admin \
  | grep locked-out
```

Enforce MFA at the identity provider level. Splunk itself does not enforce MFA — this must be done in the IdP. All Splunk-bound SSO flows should require a second factor before the SAML assertion is issued.

For LDAP integration (alternative to SAML in environments without a modern IdP):

```ini
# $SPLUNK_HOME/etc/system/local/authentication.conf

[authentication]
authType = LDAP
authSettings = corp_ldap

[corp_ldap]
host = ldap.example.com
port = 636
SSLEnabled = 1
# CA certificate for LDAP server TLS verification.
# Prevents bind credentials from being captured by a rogue LDAP server.
sslRootCAPath = /opt/splunk/etc/auth/ldap-ca.pem

bindDN = CN=splunk-bind,OU=ServiceAccounts,DC=example,DC=com
# Store bind password in Splunk's encrypted credential store, not plaintext.
# Set via: splunk add ldap-server (interactive) or REST API.
bindDNpassword = $SPLUNK_CRED_ENCRYPTED$...

userBaseDN = OU=Users,DC=example,DC=com
userNameAttribute = sAMAccountName
userBaseFilter = (memberOf=CN=splunk-users,OU=Groups,DC=example,DC=com)

groupBaseDN = OU=Groups,DC=example,DC=com
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
```

### Step 2: Role-Based Access Control and Index-Level Permissions

Splunk roles control which indexes a user can search, what capabilities they have, and which fields are accessible. Default roles (`user`, `power`, `admin`) are too broad for most production environments.

```ini
# $SPLUNK_HOME/etc/system/local/authorize.conf
# Custom roles with index-level restrictions.

# Tier-1 SOC analyst: can search operational logs; cannot access sensitive indexes.
[role_analyst_tier1]
# Inherit baseline search capabilities from the user role.
importRoles = user
# Explicitly grant access only to the indexes this role needs.
srchIndexesAllowed = main;linux_syslog;windows_events;network_flows;web_access
srchIndexesDefault = main
# No access to: _internal, _audit, hr_data, finance_logs, executive_comms.
# If an index is not in srchIndexesAllowed, searches against it return no results.
# Capabilities: cannot edit saved searches owned by others; cannot manage inputs.
capabilities = search;schedule_search

# Tier-2 SOC analyst: broader index access; can investigate security events.
[role_analyst_tier2]
importRoles = analyst_tier1
srchIndexesAllowed = main;linux_syslog;windows_events;network_flows;web_access;security_events;endpoint_telemetry;dns_logs;auth_logs
# Still excluded: _audit, hr_data, finance_logs.
capabilities = search;schedule_search;list_inputs;rest_apps_view

# Threat hunter: can access all security indexes; read-only.
[role_threat_hunter]
importRoles = power
srchIndexesAllowed = *
srchIndexesDefault = security_events
# Wildcard allows all indexes but does not grant write or admin capability.
capabilities = search;schedule_search;list_inputs;rest_apps_view;output_file

# Splunk admin: full capabilities; audited separately.
[role_splunk_admin]
importRoles = admin
# admin role already has full access; document this explicitly.
# Limit admin role membership to 2-3 named accounts.
```

Enforce search-time field masking for PII fields. This uses Splunk's `fields.conf` and `transforms.conf` to mask sensitive field values at search time for roles that do not need them:

```ini
# $SPLUNK_HOME/etc/apps/pii_masking/local/transforms.conf
# Mask credit card numbers in search results for non-PII roles.

[mask_ccn]
REGEX = \b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b
FORMAT = [MASKED_CCN]
DEST_KEY = _raw

[mask_ssn]
REGEX = \b\d{3}-\d{2}-\d{4}\b
FORMAT = [MASKED_SSN]
DEST_KEY = _raw
```

```ini
# $SPLUNK_HOME/etc/apps/pii_masking/local/props.conf
# Apply PII masking transforms to specific source types for non-PII roles.

[source::...web_access...]
TRANSFORMS-mask_pii = mask_ccn,mask_ssn
```

### Step 3: TLS Hardening for Splunk Web and Management Port

```ini
# $SPLUNK_HOME/etc/system/local/web.conf
# Splunk Web TLS configuration.

[settings]
# Restrict Splunk Web to a specific interface (management/VPN network only).
# Do not bind to 0.0.0.0 in production.
server.socket_host = 10.0.10.5

# Enable HTTPS for Splunk Web.
enableSplunkWebSSL = true
privKeyPath = /opt/splunk/etc/auth/certs/splunkweb.key
serverCert = /opt/splunk/etc/auth/certs/splunkweb.pem
# CA certificate for chain validation.
caCertPath = /opt/splunk/etc/auth/certs/ca-bundle.pem

# Require TLS 1.2 minimum; disable weak protocols.
sslVersions = tls1.2,tls1.3
# Disable weak cipher suites.
cipherSuite = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384

# Security headers for Splunk Web responses.
# X-Frame-Options prevents Splunk Web from being embedded in iframes (clickjacking).
x_frame_options_sameorigin = true
# Content-Security-Policy — restrict resource loading to Splunk's own origin.
# Customise for any external JS/CSS your Splunk apps load.
contentSecurityPolicy = default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'

# Disable features that are not in use.
# Disable the free-text Splunk app bar search (reduces XSS surface).
appNavReportsLimit = 0

# Session timeout: force re-authentication after inactivity.
# Value in seconds: 3600 = 1 hour.
ui_inactivity_timeout = 3600

# Disable SplunkWeb if this host is an indexer-only node.
# Indexers have no business need to serve the web UI.
# startwebserver = 0  (uncomment on indexer-only hosts)
```

```ini
# $SPLUNK_HOME/etc/system/local/server.conf
# Management port (splunkd REST API) TLS configuration.

[sslConfig]
# Enable TLS for the management port (8089).
enableSplunkdSSL = true
# Use strong cipher suites only.
cipherSuite = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
sslVersions = tls1.2,tls1.3
# Require client certificate verification for management API calls.
# Useful when locking down automated REST API access.
requireClientCert = false
# Set to true if you use certificates for deployment server authentication.

serverCert = /opt/splunk/etc/auth/certs/splunkd.pem
sslRootCAPath = /opt/splunk/etc/auth/certs/ca-bundle.pem
```

### Step 4: Universal Forwarder TLS and Deployment Server Authentication

Forwarder-to-indexer traffic is the highest-volume path in a distributed Splunk deployment and the most commonly left unencrypted.

```ini
# $SPLUNK_HOME/etc/system/local/outputs.conf
# Universal Forwarder: configure encrypted output to indexers.

[tcpout]
defaultGroup = indexer_group
# Disable plaintext forwarding globally.
indexAndForward = false

[tcpout:indexer_group]
# Indexer cluster receiver group.
server = indexer1.example.com:9997,indexer2.example.com:9997,indexer3.example.com:9997

# Enable TLS for forwarder-to-indexer communication.
useSSL = true
sslCertPath = /opt/splunkforwarder/etc/auth/certs/forwarder.pem
sslRootCAPath = /opt/splunkforwarder/etc/auth/certs/ca-bundle.pem
sslVerifyServerCert = true
# CN name of the indexer certificate — validates you are talking to the correct indexer.
sslCommonNameToCheck = splunk-indexer.example.com
# Require TLS 1.2 minimum.
sslVersions = tls1.2,tls1.3
```

```ini
# Indexer receiver configuration — must match forwarder TLS settings.
# $SPLUNK_HOME/etc/system/local/inputs.conf (on indexers)

[splunktcp-ssl:9997]
disabled = 0
# All forwarder connections must use TLS; plaintext TCP (9997 without ssl) is not opened.
serverCert = /opt/splunk/etc/auth/certs/indexer.pem
sslRootCAPath = /opt/splunk/etc/auth/certs/ca-bundle.pem
requireClientCert = true
# When requireClientCert is true, only forwarders presenting a valid certificate connect.
# Issue per-forwarder certificates via your internal CA.
sslVersions = tls1.2,tls1.3
```

Deployment server authentication prevents rogue deployment servers from pushing apps to your forwarders:

```ini
# $SPLUNK_HOME/etc/system/local/deploymentclient.conf
# Universal Forwarder: validate deployment server identity.

[deployment-client]
# TLS-secured deployment server endpoint.
targetUri = deploymentserver.example.com:8089

[target-broker:deploymentServer]
targetUri = deploymentserver.example.com:8089
# Verify the deployment server's TLS certificate before accepting app bundles.
sslVerifyServerCert = true
sslRootCAPath = /opt/splunkforwarder/etc/auth/certs/ca-bundle.pem
sslCommonNameToCheck = splunk-ds.example.com
```

### Step 5: Protecting splunk.secret

`splunk.secret` is the symmetric encryption key used to protect all passwords stored in Splunk configuration files — LDAP bind passwords, S3 credentials, database connector passwords, and the Splunk admin password itself. It must be treated with the same care as a root CA private key.

```bash
# Verify current permissions on splunk.secret.
# Correct: owner splunk, mode 0600 (owner read/write only).
stat /opt/splunk/etc/auth/splunk.secret

# Fix permissions if incorrect.
chown splunk:splunk /opt/splunk/etc/auth/splunk.secret
chmod 600 /opt/splunk/etc/auth/splunk.secret

# splunk.secret must be identical across all Splunk nodes in a distributed deployment.
# Splunk generates it on first start. Copy it to all indexers, search heads, and
# heavy forwarders before they start for the first time.

# Verify the file is not world-readable.
# This check should run as part of your CIS benchmark validation.
find /opt/splunk/etc/auth/ -name "splunk.secret" ! -perm 600 -exec echo "ALERT: incorrect permissions on {}" \;

# Back up splunk.secret to a secrets manager (HashiCorp Vault, AWS Secrets Manager).
# If you lose splunk.secret, all encrypted passwords in your Splunk configuration
# become unrecoverable and must be manually reset.
vault kv put secret/splunk/splunk-secret \
  value="$(cat /opt/splunk/etc/auth/splunk.secret | base64)"
```

Also verify permissions on the broader `$SPLUNK_HOME/etc` directory:

```bash
# The entire etc/ tree should be owned by the splunk user.
# No files should be world-readable or world-writable.
find /opt/splunk/etc -perm /o+r -not -path "*/apps/*/metadata/*" | head -20
find /opt/splunk/etc -perm /o+w | head -20

# Correct ownership recursively (run only if there is a known misconfiguration).
# chown -R splunk:splunk /opt/splunk/etc
```

### Step 6: Audit Logging Within Splunk

Splunk writes security-relevant events to the `_audit` index and to `$SPLUNK_HOME/var/log/splunk/audit.log`. Both must be protected and shipped externally.

```bash
# The _audit index captures:
# - Login successes and failures
# - Search activity (who ran which search, against which indexes)
# - Configuration changes (role edits, input additions, forwarder management)
# - Admin actions (user creation, password changes)
# - REST API calls

# Query audit events for failed logins in the last 24 hours.
index=_audit action=login status=failure
| stats count by user, src_ip
| sort -count

# Query who searched sensitive indexes.
index=_audit action=search
| where match(search_terms, "index=hr_data|index=finance_logs|index=executive_comms")
| table _time, user, search_terms, total_run_time

# Query all admin configuration changes.
index=_audit action=edit_*
| table _time, user, action, object, info

# Query search head to indexer REST API calls.
index=_audit action=rest_call
| table _time, user, uri, method, status
```

Ship `_audit` index events and the raw audit log file to an external, tamper-resistant destination. An attacker who compromises Splunk admin access can delete events from `_audit`; an external copy cannot be touched via Splunk.

```yaml
# Filebeat configuration to ship Splunk's raw audit log to a separate SIEM
# or log store outside of Splunk itself.
# /etc/filebeat/filebeat.yml (on Splunk server)

filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/splunk/var/log/splunk/audit.log
    fields:
      log_source: splunk_audit
      splunk_host: splunk-sh1.example.com
    fields_under_root: true

output.logstash:
  # Forward to a Logstash instance that ships to a separate SIEM.
  # This destination must not be the same Splunk instance being audited.
  hosts: ["audit-logstash.example.com:5044"]
  ssl.enabled: true
  ssl.certificate_authorities: ["/etc/filebeat/certs/ca.pem"]
```

### Step 7: KV Store and Lookup File Permissions

Splunk's KV Store (MongoDB-based) and CSV lookup files can contain sensitive reference data: threat intelligence indicators, asset inventories, user attribute tables, and allowlists. Restrict access to these files at both the OS and Splunk role level.

```bash
# KV Store data directory — owned by splunk, not world-readable.
ls -la /opt/splunk/var/lib/splunk/kvstore/

# Correct permissions.
chmod 700 /opt/splunk/var/lib/splunk/kvstore/
chown -R splunk:splunk /opt/splunk/var/lib/splunk/kvstore/

# KV Store binds to localhost only by default.
# Verify it is not listening on external interfaces.
ss -tlnp | grep 8191
# Expected: 127.0.0.1:8191 only.
```

```ini
# $SPLUNK_HOME/etc/system/local/server.conf
# Ensure KV Store does not accept external connections.

[kvstore]
# KV Store listen address — restrict to loopback.
# The search head communicates with KV Store over localhost; no external access needed.
listenOnIPv6 = no
# port = 8191 (default)
```

For lookup files containing sensitive data:

```ini
# $SPLUNK_HOME/etc/apps/threat_intel/local/transforms.conf
# Restrict lookup file access to specific roles.

[threat_ioc_lookup]
filename = threat_ioc.csv
# Only allow roles with explicit access to use this lookup.
# Default is accessible to all roles with search permission.
# Restrict via the Splunk app's metadata/default.meta:
```

```ini
# $SPLUNK_HOME/etc/apps/threat_intel/metadata/default.meta
# Restrict transforms (including lookups) to analyst roles only.

[]
access = read : [ analyst_tier2, threat_hunter, splunk_admin ], write : [ splunk_admin ]
export = none
```

### Step 8: Secure Storage of Splunk App Credentials

Splunk apps often store credentials for third-party API integrations (ticketing systems, threat feeds, cloud APIs). These must use Splunk's built-in credential storage, not plaintext configuration values.

```bash
# Store app credentials via Splunk's credential store (REST API).
# The password is encrypted using splunk.secret and stored in passwords.conf.

curl -k -u admin:$ADMIN_PASSWORD \
  -X POST https://splunk.example.com:8089/servicesNS/nobody/my_app/storage/passwords \
  -d "name=virustotal_api_key" \
  -d "password=$VT_API_KEY" \
  -d "realm=threat_feeds"

# In the app's configuration:
# Reference the stored credential, not the plaintext value.
# myapp/local/app.conf — do NOT store API keys here.
# Instead, the app retrieves the credential from the storage/passwords endpoint at runtime.
```

```bash
# Audit: find plaintext passwords in Splunk configuration files.
# Plaintext passwords appear as unencrypted strings in conf files.
# Legitimate encrypted values start with $1$ (MD5) or $7$ (AES).

grep -rn "password\s*=" /opt/splunk/etc/apps/ \
  | grep -v '^\$1\$\|^\$7\$\|^#' \
  | grep -v "password = " \
  | head -30
# Investigate any line that does not have an encrypted value.
```

### Step 9: Telemetry

```
splunk_auth_login_attempts_total{result, user}              counter
splunk_auth_login_failures_total{user, src_ip}              counter
splunk_search_count_total{user, index}                      counter
splunk_audit_config_changes_total{user, action, object}     counter
splunk_forwarder_connections_active{forwarder_host}         gauge
splunk_indexer_disk_usage_bytes{indexer, index}             gauge
splunk_kv_store_status{status}                              gauge
```

Alert on:

- `splunk_auth_login_failures_total` spike for any user — brute-force or credential stuffing against the management port or Splunk Web.
- `splunk_audit_config_changes_total` for `action=edit_roles` — someone is modifying role permissions, which may indicate privilege escalation.
- Any search against a sensitive index (`hr_data`, `finance_logs`) by a role not in the approved access list.
- KV Store status transitions to `failed` — app lookups degrade silently; threat intelligence data becomes unavailable.
- Gap in audit log shipping — if the external audit log destination stops receiving events from `splunk_host`, the audit trail has gone silent.
- Forwarder connection count drops — if a forwarder stops connecting, log coverage has a gap.

## Expected Behaviour

| Signal | Default / Underhardened Splunk | Hardened Splunk |
|--------|---------------------------------|-----------------|
| SAML admin logs in; built-in admin unused | Built-in admin still active; bypasses IdP MFA | Built-in admin locked; only IdP-authenticated accounts work |
| Forwarder connects to indexer | Plaintext TCP on port 9997 | Mutual TLS; certificate required from both sides |
| Tier-1 analyst searches `index=hr_data` | Returns results | Returns zero results; role does not have `srchIndexesAllowed` for that index |
| Attacker reads `splunk.secret` | File mode 644; world-readable | File mode 600; only the splunk process owner can read |
| Attacker deletes `_audit` index entries | Audit trail is gone | External copy in separate SIEM is unaffected |
| App credential in `app.conf` | Plaintext API key visible to anyone with OS access | Encrypted via Splunk credential store; decryptable only with `splunk.secret` |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| SAML with built-in admin disabled | Eliminates local credential bypass; enforces IdP MFA | SAML misconfiguration locks everyone out | Maintain a break-glass procedure: documented process to temporarily re-enable local auth if IdP is unavailable |
| Mutual TLS for forwarder traffic | Validates forwarder identity; encrypts log data in transit | Certificate issuance and rotation per forwarder | Automate certificate issuance via your internal CA; use Splunk's deployment server to distribute certificates |
| Index-level RBAC | Prevents analysts from accessing data outside their scope | Role management complexity; onboarding requires explicit index grants | Maintain a role-to-index access matrix in your runbook; automate via IdP group synchronisation |
| External audit log shipping | Tamper-resistant copy of all Splunk security events | Additional infrastructure for receiving system | Use an immutable log destination (S3 with Object Lock, a separate SIEM instance) |
| splunk.secret mode 600 | Prevents OS users from decrypting Splunk credentials | If lost, all encrypted passwords must be manually reset | Back up `splunk.secret` to a secrets manager with strict access control before any other configuration |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| SAML IdP becomes unavailable | All SAML users cannot log in | Login failure spike in audit log; user reports | Activate break-glass local admin account; resolve IdP outage; re-lock local admin |
| Forwarder TLS cert expires | Forwarder stops sending data; indexer rejects connection | Forwarder connection count alert; data gap in index | Rotate forwarder certificate; restart forwarder; verify data resumes |
| splunk.secret mismatch across nodes | Search head cannot decrypt passwords stored on indexer | Search failures; `authentication failed` errors in splunkd.log | Copy correct `splunk.secret` from the original node; restart Splunk |
| Analyst bypasses index restriction via REST API | Analyst directly queries indexer REST API | REST API call in `_audit` with sensitive index name | Enforce network-level controls: analysts must use Splunk Web only; block direct access to port 8089 from analyst workstations |
| KV Store port exposed externally | External actors can query Splunk's internal data store | Port scan detection; unexpected connection on 8191 | Bind KV Store to loopback; apply firewall rules blocking port 8191 at network boundary |
| Audit log shipping lag | Gap in external audit trail | Alert on silence from `splunk_host` in external SIEM | Investigate Filebeat / log shipper health; verify network path to audit destination |

## Related Articles

- [Elasticsearch Security Hardening](/articles/observability/elasticsearch-security-hardening/)
- [Graylog Security Hardening](/articles/observability/graylog-security-hardening/)
- [Loki Security Hardening](/articles/observability/loki-security-hardening/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
- [Log Integrity](/articles/observability/log-integrity/)
- [SIEM Cost Optimisation](/articles/observability/siem-cost-optimization/)
- [Detection Engineering Metrics](/articles/observability/detection-engineering-metrics/)
