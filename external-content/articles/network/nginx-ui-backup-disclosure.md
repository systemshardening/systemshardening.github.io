---
title: "Nginx UI Backup Disclosure: Lessons from CVE-2026-27944"
description: "CVE-2026-27944 exposes a critical API design flaw in Nginx UI: an unauthenticated endpoint that returns both encrypted backups and their decryption key. Learn how the silent-PR pattern works and how to prevent similar backup disclosure bugs."
slug: nginx-ui-backup-disclosure
date: 2026-05-03
lastmod: 2026-05-03
category: network
tags:
  - nginx
  - api-security
  - backup
  - cve
  - authentication
personas:
  - platform-engineer
  - security-engineer
article_number: 393
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/network/nginx-ui-backup-disclosure/
---

# Nginx UI Backup Disclosure: Lessons from CVE-2026-27944

## The Problem

The `/api/backup` endpoint in Nginx UI versions before 2.3.3 requires no session token, no API key, and no HTTP Basic credentials. A single unauthenticated request downloads the full system backup archive. The same response carries the AES key used to encrypt that archive in the `X-Backup-Security` response header, making the encryption purely cosmetic — the decryption key travels alongside the ciphertext in the same HTTP response.

```bash
curl -s -D - http://nginx-ui.example.com:9000/api/backup \
  -o backup.tar.gz.enc
```

The `X-Backup-Security` header in the response contains a value such as:

```
X-Backup-Security: AES256:c3VwZXJzZWNyZXRrZXkxMjM0NTY3ODkwYWJjZA==
```

Decrypting is a one-liner:

```bash
openssl enc -d -aes-256-cbc \
  -K "$(echo 'c3VwZXJzZWNyZXRrZXkxMjM0NTY3ODkwYWJjZA==' | base64 -d | xxd -p -c 256)" \
  -in backup.tar.gz.enc \
  -out backup.tar.gz
tar xzf backup.tar.gz
```

What the backup contains is the most sensitive material on the system that Nginx UI manages: virtual host configurations including upstream `proxy_pass` credentials, Let's Encrypt and ACME private keys for every TLS certificate managed through the UI, database connection strings stored in application configs, and Nginx UI's own session signing secrets. An attacker who retrieves and decrypts the backup does not need to break TLS or pivot through another service — the backup delivers the keys to the rest of the infrastructure directly.

CVE-2026-27944 received a CVSS 9.8 (Critical) score, reflecting the absence of any authentication prerequisite and the completeness of what an attacker gains: credential theft, TLS private key compromise, and persistent access through stolen session secrets. Nginx UI is an open-source web-based management interface for Nginx with approximately 20,000 GitHub stars at the time of disclosure. It targets exactly the class of operator — small team, self-hosted, minimal security tooling — who is least likely to monitor response headers for key material.

**The silent-PR pattern.** The fix for CVE-2026-27944 — a commit adding authentication middleware to the `/api/backup` route — was merged into the Nginx UI `main` branch on GitHub before any security advisory was published and before any CVE identifier was assigned. Watchers of the repository could read the pull request description, see the route change, and understand the vulnerability from the diff alone. IONIX and Security Affairs covered the issue in the days that followed, at which point a GitHub Security Advisory and a CVE ID were assigned retroactively.

This pattern is common in web UI projects that have no `SECURITY.md`, no coordinated disclosure process, and no formal relationship with a CVE Numbering Authority (CNA). The project maintainer fixes the problem as a regular code change. The fix is public, the vulnerability is implicitly disclosed in the diff, and the CVE process runs weeks behind. During that window, operators who rely on CVE feeds for patch prioritization are unaware that a critical unauthenticated endpoint exists. Operators who watch upstream repository commits would have seen the fix and patched immediately. For projects in this category — popular, self-hosted, no formal security process — watching the repository directly is more reliable than waiting for a CVE advisory.

## Threat Model

Nginx UI listens on port 9000 by default. Any instance accessible from the internet without an upstream firewall rule is fully exposed to CVE-2026-27944.

**Internet-exposed instances.** A Shodan search for `nginx-ui` on port 9000 at the time of disclosure found thousands of exposed instances. Many were deployed by operators who followed the project's quickstart documentation, which does not include a firewall configuration step. The project had no `SECURITY.md` and no formal CVE process prior to this disclosure.

**Internal attacker on the same network segment.** A threat actor with any foothold on a network that can reach port 9000 — a compromised IoT device, a misconfigured container with shared networking, an employee laptop on a corporate LAN — can exfiltrate the backup without escalating privileges on the Nginx host itself.

**What the attacker gains.** The impact is not limited to the Nginx UI instance:

- **Full TLS private keys.** Every certificate managed through Nginx UI has its private key inside the backup. An attacker who obtains these keys can perform active man-in-the-middle attacks against any service using those certificates, decrypting recorded TLS traffic and impersonating the server to clients that have not yet rotated to new certificates.
- **Upstream credentials.** Nginx configurations commonly embed credentials for upstream services: database connection strings, API tokens in `proxy_set_header Authorization`, LDAP bind passwords in auth module configs. These enable direct lateral movement to database servers, internal APIs, and identity systems.
- **Session secrets.** Nginx UI's own session signing keys are in the backup. An attacker who holds the session secret can forge valid session cookies for any Nginx UI account, including the admin account, without knowing any password.
- **ACME private keys.** If the ACME account key is in the backup, an attacker can revoke existing certificates or issue new ones for domains managed by that account, disrupting service availability or facilitating certificate-based impersonation.

**Affected versions.** All Nginx UI releases before 2.3.3. The project had no `SECURITY.md` file and no formal CVE reporting process before this disclosure. There is no version-specific backport; the fix is only in 2.3.3 and later.

## Hardening Configuration

### 1. Upgrade to Nginx UI 2.3.3 or Later

The immediate remediation is upgrading. The fix adds authentication middleware to the `/api/backup` route so that requests without a valid session return 401 before the handler executes.

```bash
nginx-ui --version
```

If the output shows a version below `2.3.3`, upgrade before applying any other control. The other controls below reduce the attack surface but do not substitute for the patch — other endpoints may have authentication gaps that a future disclosure will expose, and the only durable defence is running patched software.

```bash
systemctl stop nginx-ui
curl -L -o nginx-ui https://github.com/0xJacky/nginx-ui/releases/download/v2.3.3/nginx-ui-linux-amd64
chmod +x nginx-ui
mv nginx-ui /usr/local/bin/nginx-ui
systemctl start nginx-ui
```

### 2. Restrict Port 9000 with nftables

Regardless of patch status, Nginx UI's management port should never be reachable from the open internet. Restrict access to specific trusted IP ranges — the IPs of your ops team, a bastion host, or a VPN exit node.

```bash
nft add table inet nginx_ui_mgmt
nft add chain inet nginx_ui_mgmt input { type filter hook input priority 0 \; policy accept \; }
nft add rule inet nginx_ui_mgmt input tcp dport 9000 ip saddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop
nft list ruleset | grep -A 5 nginx_ui_mgmt
```

To persist this ruleset across reboots on a systemd system:

```bash
nft list ruleset > /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables
```

Replace `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16` with the specific CIDRs or individual addresses of your ops team. Allowing an entire RFC 1918 range is acceptable for isolated internal networks; for cloud environments where multiple tenants share RFC 1918 space, restrict to the specific host IPs.

### 3. Reverse Proxy Nginx UI Behind Nginx with Authentication

Place Nginx UI behind Nginx itself with an additional authentication layer. This adds defense in depth: even if the Nginx UI application-level auth is bypassed, the proxy layer requires valid HTTP Basic credentials before the request reaches the application.

```nginx
server {
    listen 443 ssl;
    server_name nginx-ui.internal.example.com;

    ssl_certificate     /etc/ssl/certs/nginx-ui-internal.crt;
    ssl_certificate_key /etc/ssl/private/nginx-ui-internal.key;

    location / {
        auth_basic "Nginx UI Management";
        auth_basic_user_file /etc/nginx/.htpasswd-nginx-ui;

        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Generate the `.htpasswd` file with a strong random password:

```bash
htpasswd -cB /etc/nginx/.htpasswd-nginx-ui ops-user
```

For teams using OAuth2 Proxy instead of HTTP Basic:

```nginx
location / {
    auth_request /oauth2/auth;
    error_page 401 = /oauth2/sign_in;

    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

location /oauth2/ {
    proxy_pass http://127.0.0.1:4180;
    proxy_set_header Host $host;
}
```

With this configuration, port 9000 should be bound to `127.0.0.1` only:

```bash
grep -i listen /etc/nginx-ui/config.yaml
```

If Nginx UI exposes its port on `0.0.0.0`, update its configuration to bind to `127.0.0.1:9000` so that direct access bypasses the proxy layer.

### 4. Detect Past Backup Exfiltration in Access Logs

If Nginx UI was exposed before patching, check whether the `/api/backup` endpoint was accessed. The window between when the fix PR was merged on `main` (visible to anyone watching the repository) and when most operators received the CVE notification was measured in days to weeks.

```bash
grep -E '"(GET|POST|HEAD)\s+/api/backup' /var/log/nginx/access.log \
  | awk '{print $1, $2, $7, $9}' \
  | sort -k1,1
```

If Nginx UI logs directly rather than through Nginx, check its own log:

```bash
grep '/api/backup' /var/log/nginx-ui/access.log \
  | grep -v '"status":401'
```

Any hit to `/api/backup` that did not return a 401 (i.e., any hit from before the patch was applied) should be treated as a confirmed exfiltration. The response to a confirmed hit is: rotate all TLS private keys managed by Nginx UI, rotate all credentials visible in Nginx configurations, and invalidate all active Nginx UI sessions by resetting the session signing secret.

### 5. Audit Your Own Web UI Projects for Unauthenticated Backup Routes

If you maintain or contribute to web UI projects that manage system configurations, run a periodic audit of your router definitions for backup, export, and download routes that lack authentication middleware.

```bash
grep -rn \
  -e '/backup' \
  -e '/export' \
  -e '/download' \
  -e '/dump' \
  /path/to/your/project/routes/ \
  | grep -v '_test\.' \
  | grep -v 'auth\|middleware\|require_login\|login_required\|authenticate'
```

For Go projects using Gin or Echo, grep the router registration files:

```bash
grep -rn 'GET\|POST' /path/to/project/router/ \
  | grep -E '(backup|export|download|dump)' \
  | grep -v 'Auth\|Middleware\|Guard'
```

Any route that matches a download or export pattern and does not show an adjacent authentication middleware registration warrants manual review. The question is not whether the endpoint is documented as internal — CVE-2026-27944 existed in a route that was presumably intended to be authenticated — it is whether the middleware is actually applied in the router configuration.

## Expected Behaviour After Hardening

After upgrading to Nginx UI 2.3.3, the `/api/backup` endpoint returns 401 for unauthenticated requests and the `X-Backup-Security` header is no longer present in any response:

```bash
curl -sI http://127.0.0.1:9000/api/backup
```

Expected output:

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json
```

The `X-Backup-Security` header should be absent from all responses. Confirm it is not present on any endpoint:

```bash
curl -sI http://127.0.0.1:9000/api/backup | grep -i 'x-backup'
```

No output means the header is gone. Any output here against a patched instance indicates the upgrade did not complete correctly.

Verify the nftables firewall rule is active and enforcing the port restriction:

```bash
nft list ruleset | grep -A 10 nginx_ui_mgmt
```

Expected output includes a rule dropping traffic to `tcp dport 9000` from addresses outside the trusted CIDR set. Test that the rule drops connections from an untrusted address by attempting to connect from outside the allowed range — the connection should time out rather than return a TCP RST, confirming the packet is dropped rather than rejected.

## Trade-offs and Operational Considerations

**IP restriction breaks remote access without VPN.** Restricting port 9000 to specific CIDRs means that an ops engineer working remotely without VPN access cannot reach the Nginx UI interface. This is the correct outcome — the restriction exists precisely to prevent unauthenticated access from arbitrary locations — but it requires that remote access workflows go through a VPN or bastion host. For teams that do not currently operate a VPN, this is a meaningful operational change, not just a configuration line.

**Reverse proxy auth adds a dependency on another config layer.** Placing Nginx UI behind Nginx with `auth_basic` or OAuth2 Proxy means that a misconfiguration in the outer Nginx server block can either lock everyone out of Nginx UI or accidentally expose it without the auth layer. The proxy configuration must be included in the team's change review and tested after every Nginx reload. Rotating the HTTP Basic password requires updating the `.htpasswd` file and notifying all users with Nginx UI access.

**Automated backup jobs need credential updates.** Some teams run automated scripts that hit `/api/backup` on a schedule to archive Nginx configurations externally. After upgrading to 2.3.3, those scripts must include session authentication. The correct approach is to use a dedicated Nginx UI API token with minimal permissions scoped only to backup access, rather than embedding admin credentials in a cron script. Review the Nginx UI 2.3.3 API token documentation to confirm the token scope model.

## Failure Modes

**Upgrading Nginx UI but leaving port 9000 open to the internet.** The patch for CVE-2026-27944 adds authentication to the backup endpoint. It does not eliminate the attack surface of the other endpoints exposed on port 9000. Future disclosures may affect other routes in Nginx UI. Leaving the management port accessible from the internet means that every future authentication bypass in any Nginx UI endpoint is immediately exploitable. The firewall restriction is not optional even after patching.

**Access logs not retained long enough to detect past exfiltration.** Default log rotation policies on many systems discard logs older than seven or thirty days. The window between the silent fix PR being merged and the CVE being assigned and publicized was several weeks. If logs have rotated, you cannot determine whether `/api/backup` was accessed during that window. If you cannot confirm that exfiltration did not occur, treat it as confirmed and rotate credentials. After patching, extend log retention for the Nginx UI access log to at least 90 days.

**Backup files stored world-readable after the patch.** Nginx UI stores backup archives on disk in `/var/www/nginx-ui/backup/` by default. The patch prevents unauthenticated download through the API endpoint, but if the backup directory is world-readable, any local user on the system can read the archive files directly from the filesystem. The AES encryption protects the backup only if the key is not co-located — and in vulnerable versions, the key was returned in the response header alongside the archive, which means historical backups downloaded before patching are decryptable by any attacker who captured the response. After patching, audit the permissions on the backup directory:

```bash
ls -la /var/www/nginx-ui/backup/
chmod 700 /var/www/nginx-ui/backup/
chown nginx-ui:nginx-ui /var/www/nginx-ui/backup/
```

If any backup archive was downloaded through the endpoint before the patch was applied, assume the corresponding AES key was also captured and the backup contents are known to the attacker. Restricting filesystem permissions on existing backups does not undo an API-level exfiltration.

## Related Articles
- [Nginx Hardening Beyond TLS](/articles/network/nginx-hardening-beyond-tls/)
- [HTTP Security Headers](/articles/network/http-security-headers/)
- [Internal API Protection](/articles/network/internal-api-protection/)
- [TLS Certificate Management](/articles/network/tls-nginx-envoy/)
- [Nginx Module Security](/articles/network/nginx-module-security/)
