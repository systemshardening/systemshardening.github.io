---
title: "Roxy-WI LDAP Injection: Unauthenticated Auth Bypass via CVE-2026-33432"
description: "CVE-2026-33432 allows unauthenticated attackers to bypass Roxy-WI's LDAP authentication by injecting metacharacters into the login username. Full admin access grants control over HAProxy and Nginx on all managed servers. Patch to 8.2.9 and harden LDAP filter construction."
slug: roxy-wi-ldap-injection
date: 2026-05-04
lastmod: 2026-05-04
category: network
tags:
  - haproxy
  - nginx
  - ldap-injection
  - authentication-bypass
  - cve
personas:
  - platform-engineer
  - security-engineer
article_number: 441
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/network/roxy-wi-ldap-injection/
---

# Roxy-WI LDAP Injection: Unauthenticated Auth Bypass via CVE-2026-33432

## The Problem

Roxy-WI is an open-source web interface used by network teams to manage HAProxy, Nginx, Apache, and Keepalived across multiple servers from a single dashboard. In organisations with many load balancers and reverse proxies, Roxy-WI is the single pane of glass: admin access means the ability to change routing rules, modify TLS termination, disable health checks, and restart services across every managed host simultaneously.

CVE-2026-33432, disclosed April 20 2026 and assigned a CVSS score of 7.7 High, affects all Roxy-WI versions before 8.2.9 that have LDAP authentication enabled. When a user submits a login form, Roxy-WI takes the username string and concatenates it directly into an LDAP search filter without escaping any characters. The resulting query is sent to the LDAP server. An attacker who supplies a username containing LDAP metacharacters — `*`, `(`, `)`, `\`, `\00` — causes the filter to evaluate in a way the developer never intended. Supplying `*)(uid=*))(|(uid=*` as a username transforms a filter that was meant to find one specific user into a filter that matches every user in the directory, causing the LDAP bind to succeed without requiring a valid password.

A legitimate LDAP filter built from that username looks like this before any user input arrives:

```
(&(uid=<USERNAME>)(objectClass=posixAccount))
```

After the attacker's input is substituted with no escaping:

```
(&(uid=*)(uid=*))(|(uid=*)(objectClass=posixAccount))
```

The first term `(&(uid=*)(uid=*))` matches any entry that has a `uid` attribute, which is every user account. The OR clause that follows is evaluated but irrelevant — the filter already matched. Roxy-WI receives a successful LDAP response and grants the session full admin privileges.

The fix is unambiguous and has been standard practice since RFC 4515 defined LDAP filter string encoding in 2006: any user-supplied value inserted into an LDAP filter must have its special characters escaped before concatenation. The characters that carry meaning in LDAP filter syntax — `(`, `)`, `*`, `\`, and the null byte `\00` — must each be replaced with their escape sequences (`\28`, `\29`, `\2a`, `\5c`, and `\00` respectively). This is not a novel defensive technique; every LDAP client library written in the past fifteen years exposes an escaping function for exactly this purpose.

LDAP injection persists for a specific reason that SQL injection training does not address: developers who know to escape SQL special characters for database queries do not automatically know that LDAP has a separate, distinct set of metacharacters. A developer who escapes single quotes and semicolons — the characters that matter in SQL — will write LDAP filter construction code that looks safe to them but is entirely unprotected against the characters that carry meaning in LDAP filter syntax. The two character sets overlap only partially and require separate handling. Without explicit exposure to LDAP injection as a vulnerability class, the gap remains.

Roxy-WI 8.2.9, released as the fix for CVE-2026-33432, applies RFC 4515 escaping to user-supplied values before inserting them into LDAP search filters. The escaping converts every special character to its `\HH` hex representation, ensuring that the username is treated as a literal string value by the LDAP server regardless of what characters it contains.

## Threat Model

**Unauthenticated internet attacker reaching Roxy-WI's web interface.** Roxy-WI listens on port 443 or 8080 depending on deployment. Any instance reachable from the internet with LDAP authentication enabled is fully exposed. The exploit requires nothing beyond the ability to submit a login form: no credentials, no prior access, no vulnerability chain. A single request with a crafted username bypasses authentication entirely. The CVSS 7.7 rating reflects the high confidentiality and integrity impact on all systems Roxy-WI manages; the score is not 9.8 because the attack requires LDAP authentication to be enabled rather than applying to all deployments.

**Internal attacker on the management network bypassing LDAP authentication.** Even when Roxy-WI is not internet-exposed, an attacker with any foothold on the internal network that hosts the management interface — a compromised workstation, a misconfigured container, a lateral-movement pivot from another service — can exploit this vulnerability without any valid LDAP credential.

**Impact: full admin access to Roxy-WI.** Roxy-WI admin access is not a generic web application session. It is control over HAProxy and Nginx configuration on every server registered with the Roxy-WI instance. An attacker who obtains a Roxy-WI admin session can:

- Modify HAProxy backend server definitions to redirect traffic to attacker-controlled upstreams, intercepting requests and responses for any service behind those load balancers
- Replace Nginx TLS certificate and key paths in managed configurations, disrupting HTTPS service or substituting attacker-controlled certificates
- Disable HAProxy health checks to send traffic to unhealthy or decommissioned backends, causing service degradation or controlled outages
- Restart HAProxy or Nginx on all managed servers through the Roxy-WI interface, causing simultaneous disruption across the entire load balancer fleet

**Scale multiplier.** Organisations that use Roxy-WI typically manage tens to hundreds of servers from a single instance. A single successful exploitation does not compromise one server — it compromises every server under Roxy-WI management. The blast radius of a Roxy-WI admin account is proportional to the number of managed hosts, making this class of vulnerability disproportionately severe in environments where Roxy-WI manages production load balancers for multiple services.

## Hardening Configuration

### 1. Upgrade to Roxy-WI 8.2.9 or Later

The only complete remediation for CVE-2026-33432 is upgrading to 8.2.9, which applies RFC 4515 LDAP filter string escaping to all user-supplied values before they are inserted into search filters. No compensating control at the network or application level substitutes for the patch — the injection occurs in the authentication code path that must execute to accept any login attempt.

Verify the current Roxy-WI version before upgrading:

```bash
roxy-wi-manage version
```

If the instance was installed via pip:

```bash
pip show roxy-wi | grep Version
```

To upgrade using pip:

```bash
pip install --upgrade roxy-wi==8.2.9
systemctl restart roxy-wi
```

To upgrade a package-managed installation:

```bash
apt-get update && apt-get install --only-upgrade roxy-wi
systemctl restart roxy-wi
```

After upgrading, verify the version endpoint reflects 8.2.9 or later:

```bash
curl -s http://localhost:8080/api/v1/server/version | python3 -m json.tool
```

Confirm the returned version field shows `8.2.9` or higher before re-enabling LDAP authentication if it was disabled as a temporary mitigation.

### 2. Firewall the Roxy-WI Management Port

Roxy-WI should never be reachable from the open internet regardless of patch status. The management interface controls production load balancer configuration across your entire fleet; its attack surface should be restricted to specific trusted IP addresses. Apply a host-level firewall rule that limits access to the Roxy-WI port to the IP addresses or CIDRs of your operations team, VPN exit nodes, or bastion hosts.

With nftables, restricting the Roxy-WI port (8080 in this example; substitute 443 if TLS is terminated at Roxy-WI directly):

```bash
nft add table inet roxy_wi_mgmt
nft add chain inet roxy_wi_mgmt input \
  '{ type filter hook input priority 0; policy accept; }'
nft add rule inet roxy_wi_mgmt input \
  tcp dport 8080 \
  ip saddr != { 10.0.1.0/24, 172.16.0.5/32 } \
  drop
```

Persist the ruleset:

```bash
nft list ruleset > /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables
```

Replace `10.0.1.0/24` and `172.16.0.5/32` with the specific addresses of your team. In cloud environments where multiple tenants share RFC 1918 address space, restrict to specific host IPs rather than broad private ranges.

Also verify that no cloud security group or network ACL permits inbound access to the Roxy-WI port from `0.0.0.0/0` or `::/0`. Host firewall rules do not protect against attacks that arrive through cloud network paths that bypass the host's kernel netfilter stack in some configurations:

```bash
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.to-port,Values=8080" \
  --query 'SecurityGroups[*].{ID:GroupId,Permissions:IpPermissions}'
```

Any security group that permits port 8080 or 443 from `0.0.0.0/0` needs to be tightened to the specific IP range of your operations team.

### 3. Disable LDAP Authentication as an Immediate Mitigation

If upgrading to 8.2.9 is not immediately feasible — because of a change freeze, a containerised deployment that requires image building, or dependency constraints — disable LDAP authentication and switch to local account authentication. This removes the LDAP filter construction code path entirely, eliminating the injection vector until the patch can be applied.

In Roxy-WI's configuration file (typically `/etc/roxy-wi/roxy-wi.cfg` or `/var/www/roxy-wi/app/config/roxy-wi.cfg`):

```bash
grep -n "auth_type" /etc/roxy-wi/roxy-wi.cfg
```

Change the `auth_type` setting from `ldap` to `local`:

```bash
sed -i 's/^auth_type\s*=\s*ldap/auth_type = local/' /etc/roxy-wi/roxy-wi.cfg
systemctl restart roxy-wi
```

Before disabling LDAP, create local accounts for every LDAP user who requires continued access. Switching to local authentication without pre-creating accounts will lock out all LDAP-authenticated users immediately. Document the accounts created during the transition and the plan for re-enabling LDAP after patching, so the change is tracked in your audit log rather than appearing as an unexplained authentication change.

### 4. Check Audit Logs for Exploitation Attempts

If the Roxy-WI instance was reachable from untrusted networks before patching, audit the access logs for login attempts containing LDAP metacharacters in the username field. These characters — `*`, `(`, `)`, `\` — have no legitimate use in LDAP usernames and their presence in login requests indicates either active exploitation or automated scanning.

```bash
grep -E "(POST|GET).*/login" /var/log/roxy-wi/access.log \
  | grep -E '[*()\\]'
```

If Roxy-WI is behind Nginx or another reverse proxy, check the proxy's access log and correlate with Roxy-WI's own application log:

```bash
grep -E "POST /login" /var/log/nginx/access.log \
  | grep -v '"status":40[13]'
```

To search specifically for null-byte injection attempts, which are less visible in plain log inspection:

```bash
grep -aP "login.*\x00" /var/log/roxy-wi/access.log
strings /var/log/roxy-wi/access.log | grep -E '[*()\\].*login'
```

Any request containing LDAP metacharacters in the username field that received a non-401 response code before the patch was applied should be treated as a successful authentication bypass. If successful exploitation is confirmed, the response is: assume the attacker had full Roxy-WI admin access during the window between the exploitation attempt and the patch, audit all HAProxy and Nginx configuration on managed servers for unexpected changes, rotate all credentials stored in managed service configurations, and review managed server logs for changes made through the Roxy-WI interface during the exploitation window.

### 5. LDAP Injection Prevention: Safe Filter Construction in Application Code

For any application — not just Roxy-WI — that constructs LDAP filters from user-supplied input, the correct pattern is to escape all user-supplied values using a library-provided escaping function before they are inserted into the filter string. Writing your own escaping function is not the right approach: the full set of characters that require escaping in LDAP filter strings is non-obvious, and the RFC 4515 rules include edge cases (null bytes, multibyte sequences) that homegrown implementations miss.

**Vulnerable pattern in Python:**

```python
def authenticate_ldap(username, password):
    ldap_filter = f"(&(uid={username})(objectClass=posixAccount))"
    conn.search(search_base, ldap_filter)
```

**Safe pattern in Python using `ldap3`:**

```python
from ldap3.utils.conv import escape_filter_chars

def authenticate_ldap(username, password):
    safe_username = escape_filter_chars(username)
    ldap_filter = f"(&(uid={safe_username})(objectClass=posixAccount))"
    conn.search(search_base, ldap_filter)
```

`escape_filter_chars()` replaces each RFC 4515 special character with its `\HH` hex escape: `*` becomes `\2a`, `(` becomes `\28`, `)` becomes `\29`, `\` becomes `\5c`, and the null byte becomes `\00`. After escaping, the attacker's payload `*)(uid=*))(|(uid=*` becomes the literal string `\2a\29\28uid=\2a\29\29\28|\28uid=\2a`, which the LDAP server treats as a search for a user whose `uid` attribute is exactly that escaped string — an account that does not exist, so the search returns no results and authentication fails.

**Safe pattern in Java using Spring LDAP:**

```python
import org.springframework.ldap.core.LdapEncoder;

public boolean authenticateLdap(String username, String password) {
    String safeUsername = LdapEncoder.filterEncode(username);
    String filter = String.format("(&(uid=%s)(objectClass=posixAccount))", safeUsername);
    ldapTemplate.authenticate(LdapUtils.emptyLdapName(), filter, password);
}
```

For applications that cannot use a library escaping function, the minimum character set that must be escaped in LDAP filter values is: `\` (escape first, as the escape character itself), `*`, `(`, `)`, and the null byte. Escaping only SQL characters — single quote, semicolon, double dash — provides no protection against LDAP injection.

If you maintain or review application code that queries LDAP, audit filter construction sites with:

```bash
grep -rn \
  -e "ldap_search\|ldap_filter\|search_filter\|conn\.search\|ldapTemplate" \
  /path/to/your/project/src/ \
  | grep -v "escape_filter_chars\|filterEncode\|escapeFilter\|ldap_escape"
```

Any LDAP query construction that is not preceded by an escaping call warrants manual review.

## Expected Behaviour After Hardening

After upgrading to Roxy-WI 8.2.9, a login attempt using `*)(uid=*))(|(uid=*` as the username triggers the RFC 4515 escaping logic. The LDAP search filter that reaches the LDAP server is:

```
(&(uid=\2a\29\28uid=\2a\29\29\28|\28uid=\2a)(objectClass=posixAccount))
```

This searches for a user whose `uid` attribute is the literal escaped string — an account that does not exist in any directory. The LDAP server returns zero results, Roxy-WI receives no matching entry, and authentication fails with a normal invalid-credentials response. The attacker's attempt to inject filter syntax has been neutralised.

After applying the nftables firewall rule, the Roxy-WI port is unreachable from outside the management network. A connection attempt from an untrusted address should time out:

```bash
curl --connect-timeout 5 http://<roxy-wi-public-ip>:8080/login
```

Expected: connection times out or is refused. Any HTTP response body from an address outside the allowed CIDR indicates the firewall rule is not active on the relevant network path — verify with `nft list ruleset` and confirm no cloud security group is overriding the host firewall.

## Trade-offs and Operational Considerations

**Switching to local authentication during the patch window requires pre-creating local accounts.** Before disabling LDAP authentication, every LDAP-authenticated user who needs continued access must have a local Roxy-WI account created with a temporary password communicated through a separate channel. This is not a background task — if LDAP is disabled without pre-creating accounts, all LDAP users lose access immediately, including the admins responsible for completing the upgrade. Treat the account creation step as a prerequisite, not a follow-up action.

**Containerised deployments require image pull and restart coordination.** If Roxy-WI runs in Docker or Kubernetes, upgrading to 8.2.9 means pulling the new container image, not running a package manager upgrade on an existing host. This requires coordination with the team responsible for managed HAProxy and Nginx configurations, since restarting the Roxy-WI container does not restart the managed services but does interrupt any in-flight configuration operations in the web interface. Plan the image pull and container restart during a low-traffic window and confirm that all team members with open Roxy-WI sessions save any in-progress configuration changes before the restart.

**LDAP re-enablement after patching requires removing temporary local accounts.** If local accounts were created as a temporary measure during the patch window, they should be disabled or removed once LDAP authentication is re-enabled and verified. Leaving temporary accounts active — particularly ones created with simple temporary passwords — extends the attack surface beyond the LDAP injection vulnerability the patch addressed.

## Failure Modes

**Patched production Roxy-WI but an unpatched staging or test instance remains internet-accessible.** Roxy-WI instances in test and staging environments are frequently configured with the same LDAP credentials as production — or with credentials that share a password with production accounts. An attacker who exploits the unpatched test instance through CVE-2026-33432 gains access to LDAP bind credentials stored in the Roxy-WI configuration, which may work against the production LDAP server directly. A patched production instance does not protect against pivot attacks that begin at an unpatched adjacent instance. Audit every Roxy-WI deployment in the environment, not just the primary production instance, and apply the same patch and firewall controls to all of them.

**Firewall restricts external access but Roxy-WI is accessible from the developer VLAN.** Restricting the Roxy-WI management port to the operations team's IP range eliminates exposure to internet attackers. It does not eliminate exposure to anyone on the internal network segments that can reach the management port — including developer workstations, CI/CD build agents, and shared internal services. A compromised developer laptop on the same VLAN as Roxy-WI can exploit CVE-2026-33432 without any internet-facing exposure. Internal network segmentation that restricts Roxy-WI access to a dedicated operations VLAN provides meaningfully stronger isolation than a firewall rule that allows the entire corporate network.

**Log audit searches for `*` character but misses `\00` null-byte injection attempts.** Null bytes do not appear as printable characters in log files viewed with standard tools. A grep for `*`, `(`, or `)` in login fields will identify the most common LDAP injection payloads, but null-byte injection attempts — which can be used to truncate filter strings in some LDAP implementations — require binary-aware log inspection. The `grep -aP "\x00"` approach shown in the audit section above handles this, but operators who rely only on plain-text log viewing tools or SIEM rules that filter for printable characters will miss null-byte payloads entirely.

## Related Articles
- [HAProxy Hardening](/articles/network/haproxy-hardening/)
- [Nginx Hardening Beyond TLS](/articles/network/nginx-hardening-beyond-tls/)
- [Internal API Protection](/articles/network/internal-api-protection/)
- [nginx-ui Backup Disclosure](/articles/network/nginx-ui-backup-disclosure/)
- [Network Segmentation Patterns](/articles/network/network-segmentation-patterns/)
