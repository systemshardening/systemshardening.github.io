---
title: "nginx Module and Upstream TLS Security"
description: "Harden nginx against CVE-2026-1642 upstream TLS TOCTOU injection, CVE-2026-27654 DAV buffer overflow, and CVE-2026-27784 MP4 module overflow—and track nginx security releases before they reach your distribution."
slug: nginx-module-security
date: 2026-05-03
lastmod: 2026-05-03
category: network
tags: ["nginx", "cve-2026-1642", "cve-2026-27654", "tls", "upstream", "modules", "buffer-overflow"]
personas: ["systems-engineer", "sre", "security-engineer"]
article_number: 377
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/network/nginx-module-security/index.html"
---

# nginx Module and Upstream TLS Security

## Problem

nginx is architected as a small, event-driven core surrounded by a system of modules. Some modules are compiled in by default and always present: `ngx_http_gzip_module`, `ngx_http_proxy_module`, `ngx_http_ssl_module`, `ngx_http_rewrite_module`. Others are optional and require explicit compilation flags: `ngx_http_dav_module` (WebDAV), `ngx_http_mp4_module` (video pseudo-streaming), `ngx_http_image_filter_module`, `ngx_http_geoip_module`. Every module that is compiled in adds code that may execute against attacker-controlled input — request headers, request bodies, URL paths, and in the case of proxy modules, responses from upstream servers. Distribution packages (Ubuntu `nginx`, RHEL `nginx:1.24` module) tend to compile in a broad set of modules to serve the widest range of use cases, which means the DAV and MP4 modules are frequently present even on systems where they are never used. That compiled-in surface area is what three 2026 CVEs exploit.

**CVE-2026-1642** (CVSS 8.2, affects nginx 1.3.0 through 1.29.4) is a Time-of-Check to Time-of-Use (TOCTOU) race condition in nginx's upstream TLS handling, specifically in `ngx_http_upstream.c`. When nginx operates as a reverse proxy and establishes a TLS connection to an upstream HTTPS backend, the code checks the upstream TLS connection state at one point in time but reads data from that connection at a later point. A network-adjacent attacker who can perform a man-in-the-middle attack on the connection between nginx and the upstream server — for example, on a shared internal network segment, via ARP spoofing, or through a compromised network device — can inject plaintext data into the TLS stream during the race window. From nginx's perspective the injected bytes arrive on what appears to be an established, verified TLS session, so they are forwarded to the downstream client as a legitimate upstream response. This effectively nullifies TLS protection for the upstream leg of the connection. The vulnerability was fixed in nginx 1.29.5 and 1.28.2. NGINX Plus users require the R36 P2 patch. The CVE was published February 4, 2026, but awareness and distribution-level patches arrived at scale only in April–May 2026.

**CVE-2026-27654** (affects nginx 0.5.13 through 1.29.6, published April 7, 2026) is a buffer overflow in the optional `ngx_http_dav_module`. The WebDAV module processes `COPY` and `MOVE` requests, which include a `Destination` header specifying the target path. When nginx is configured with an `alias` directive alongside WebDAV handling, the code that resolves the destination path relative to the document root performs insufficient validation of path length and traversal sequences. A crafted `Destination` header can overflow an internal path buffer and, under the right conditions, write beyond the allocated region. This allows an unauthenticated attacker who can send WebDAV requests to overwrite memory structures, potentially gaining control of the nginx worker process or writing files outside the configured WebDAV root. The bug was fixed in nginx 1.29.7 and 1.28.3, both released April 7, 2026.

**CVE-2026-27784** (affects nginx 1.1.19 through 1.29.6, published April 7, 2026, 32-bit platforms only) is a buffer overflow in `ngx_http_mp4_module`. The MP4 module enables pseudo-streaming for H.264 video: it parses MP4 container metadata to support client requests for arbitrary time offsets via the `start=` query parameter, enabling video seeking without re-downloading from the beginning. The parser for MP4 box headers does not sufficiently validate lengths in certain atom types on 32-bit platforms, where pointer arithmetic overflow can trigger a write outside the allocated buffer. An attacker who can cause nginx to serve a malformed MP4 file — either by placing it on a server nginx proxies, or by uploading it if file upload is permitted — can crash the nginx worker process. On 32-bit platforms, the overflow is positioned to allow potential remote code execution. The fix was included in nginx 1.29.7 and 1.28.3.

The April 7, 2026 dual-release of CVE-2026-27654 and CVE-2026-27784 illustrates a pattern worth understanding: nginx publishes security fixes as new version releases, and the `CHANGES` file that accompanies each release describes fixes in engineering terms rather than security terms. The `CHANGES` entry for nginx 1.29.7 read "Bugfix: buffer overflow" for both issues — no CVE numbers, no CVSS scores, no indication of severity. The CVE identifiers were assigned and published separately after the release. An operator who monitors `nginx.org` releases and upgrades promptly may have deployed the fix before any CVE was public. An operator who waits for the Ubuntu `nginx` package or the RHEL nginx stream module received the fix days to weeks later, during which time the patch diff was public and any attacker could extract the vulnerability details from it. Effective nginx security operations requires monitoring both the upstream `nginx.org` release stream and the official security advisories page at `https://nginx.org/en/security_advisories.html`. nginx uses Mercurial for version control; the canonical change history for affected files is visible at `https://hg.nginx.org/nginx/log`. Watching changesets to `src/http/modules/ngx_http_dav_module.c`, `src/http/modules/ngx_http_mp4_module.c`, and `src/http/ngx_http_upstream.c` provides the earliest possible signal of security-relevant changes.

The installed nginx version can be checked with `nginx -v`. The `Server:` response header also leaks the version by default unless suppressed with `server_tokens off`. Operators should cross-reference the installed version against the current release table on `nginx.org` as part of routine change management.

**Target systems:** nginx 1.28.x < 1.28.3 and nginx 1.29.x < 1.29.7 are affected by CVE-2026-27654 (DAV overflow) and CVE-2026-27784 (MP4 overflow). nginx 1.3.0 through 1.29.4 is affected by CVE-2026-1642 (upstream TLS TOCTOU). NGINX Plus R36 and earlier require the R36 P2 patch for CVE-2026-1642.

## Threat Model

1. **CVE-2026-1642 MITM**: A network-adjacent attacker positioned between the nginx instance and an upstream HTTPS backend — achievable via ARP spoofing on a shared VLAN, through a compromised network device, or from a collocated container on the same pod network — exploits the TLS TOCTOU race to inject a malicious HTTP response body or headers into the upstream stream. nginx forwards the injected content to the downstream client as though it originated from the legitimate upstream service. In a TLS-bridging architecture (client TLS terminated at nginx, re-established to backend), this bypasses both TLS legs. The injected response can deliver malware, redirect OAuth callbacks to attacker-controlled endpoints, or poison a shared reverse proxy cache with adversary-controlled content served to many subsequent clients.

2. **CVE-2026-27654 DAV path traversal**: A client sends an HTTP `COPY` request to a WebDAV-enabled nginx location with a `Destination` header containing path traversal sequences, for example `Destination: http://example.com/dav/../../../etc/cron.d/malicious`. When the nginx `alias` directive resolves the destination path, the insufficient validation in the DAV module overflows the internal path buffer. Depending on heap layout, this can overwrite adjacently allocated file path data, causing nginx to write or overwrite files at attacker-specified filesystem locations outside the configured WebDAV root. The pre-condition is that WebDAV is enabled and reachable — a common configuration for file-sharing or content-upload workflows.

3. **CVE-2026-27784 MP4 module crash**: An attacker crafts or obtains a malformed MP4 file in which specific atom headers contain length values that trigger integer overflow during parsing on 32-bit systems. The attacker causes nginx to serve this file by placing it at a URL that nginx handles with the `mp4` directive enabled — either directly as static content if the attacker has write access to the served directory, or by poisoning an upstream that nginx proxies. When a client requests the file with a `start=` query parameter, the MP4 module parses the atom headers, the overflow occurs, the nginx worker crashes (SIGABRT or SIGSEGV appears in the error log), and on 32-bit platforms the overflow may be exploitable for RCE. Each worker crash triggers nginx's master process to spawn a replacement worker, but during the gap active connections are dropped.

4. **Patch-gap attacker**: nginx 1.29.7 is published on April 7, 2026, with `CHANGES` entries that read "Bugfix: buffer overflow" without CVE identifiers. Within hours, researchers and attackers alike run `diff -r nginx-1.29.6 nginx-1.29.7` and identify the precise lines changed in `ngx_http_dav_module.c` and `ngx_http_mp4_module.c`. The CVE details are published the same day or shortly after, but nginx deployments that haven't yet upgraded — particularly those waiting for Ubuntu or RHEL distribution packages — are now running known-vulnerable software against a publicly understood exploit path. This window is typically measured in days, but a coordinated attacker targeting a specific nginx deployment can act within hours of the diff being public.

The blast radius of these vulnerabilities varies significantly by deployment context. CVE-2026-1642 is highest consequence in architectures where nginx is the sole TLS termination point and downstream services implicitly trust traffic that arrives from nginx — poisoning the nginx-to-upstream connection poisons all downstream trust. CVE-2026-27654 and CVE-2026-27784 are scoped to systems with the respective modules enabled; environments that have audited their compiled-in modules and disabled unused functionality are not affected. The patch-gap risk applies to all four CVEs but is most acute when distribution package lag exceeds five to seven days.

## Configuration / Implementation

### Upgrading nginx

Check the currently installed version before and after any upgrade:

```bash
nginx -v
# nginx version: nginx/1.29.6
```

On Debian/Ubuntu systems, upgrade nginx using the system package manager:

```bash
sudo apt-get update
sudo apt-get install --only-upgrade nginx
nginx -v
# nginx version: nginx/1.29.7
```

If the distribution repository still carries an older version (Ubuntu 24.04 LTS shipped nginx 1.24.x for an extended period), add the official nginx repository to get current releases:

```bash
# Add nginx official signing key
curl -fsSL https://nginx.org/keys/nginx_signing.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg

# Add nginx stable or mainline repository
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
  https://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" \
  | sudo tee /etc/apt/sources.list.d/nginx.list

sudo apt-get update
sudo apt-get install --only-upgrade nginx
```

On RHEL/Rocky/AlmaLinux:

```bash
sudo dnf upgrade nginx
nginx -v
```

For NGINX Plus, check the version and apply the R36 P2 patch through the official NGINX Plus package repository:

```bash
nginx -v | grep -i plus
# nginx version: nginx/1.25.x (nginx-plus-r36)
sudo apt-get update && sudo apt-get install --only-upgrade nginx-plus
```

After upgrading, reload the configuration without dropping connections:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

### Auditing and disabling unused modules

List every module compiled into the running nginx binary:

```bash
nginx -V 2>&1 | tr ' ' '\n' | grep -- '--with'
```

Look specifically for these high-risk optional modules:

```bash
nginx -V 2>&1 | tr ' ' '\n' | grep -E 'dav|mp4|image_filter|geoip|perl'
```

If `--with-http_dav_module` or `--with-http_mp4_module` appears and you do not use those features, the safest remediation is to block the relevant HTTP methods and directives at the configuration level rather than recompiling nginx (which may not be practical for distribution-packaged binaries).

**Blocking WebDAV methods without recompiling:**

Add `limit_except` blocks to every `location` context that is not explicitly a WebDAV endpoint:

```nginx
# nginx.conf or included site config
server {
    listen 443 ssl;
    server_name example.com;

    # Default: restrict to safe read methods everywhere
    location / {
        limit_except GET POST HEAD {
            deny all;
        }
        try_files $uri $uri/ =404;
    }

    # If a specific location genuinely needs WebDAV (see WebDAV hardening below)
    # configure it explicitly and restrict access
}
```

**Disabling the mp4 directive:**

If `ngx_http_mp4_module` is compiled in but you do not need video pseudo-streaming, simply do not use the `mp4` directive. The vulnerability is only triggered when `mp4` is present in a `location` block:

```nginx
# Do NOT do this unless you need video seeking and have trusted source material:
# location ~* \.mp4 {
#     mp4;
# }

# Safe: serve MP4 files as static downloads without the module's parser
location ~* \.mp4 {
    add_header Content-Disposition "attachment";
}
```

### Upstream TLS hardening (CVE-2026-1642 mitigation)

The core mitigation for CVE-2026-1642 is upgrading to nginx 1.29.5+ or 1.28.2+. However, the following configuration hardens the upstream TLS connection against MITM attacks regardless of version and reduces the race window by removing session reuse:

```nginx
# upstream TLS proxy configuration
upstream backend_service {
    server upstream.internal.company.com:443;
    keepalive 32;
}

server {
    listen 443 ssl;
    server_name example.com;

    location /api/ {
        proxy_pass https://backend_service;

        # Verify the upstream certificate against a trusted CA bundle
        proxy_ssl_verify          on;
        proxy_ssl_trusted_certificate /etc/nginx/trusted-upstream-ca.pem;
        proxy_ssl_verify_depth    2;

        # Pin the upstream server name to prevent certificate substitution
        proxy_ssl_name            upstream.internal.company.com;

        # Disable TLS session reuse — reduces the TOCTOU race window
        proxy_ssl_session_reuse   off;

        # Use TLS 1.3 only for upstream connections
        proxy_ssl_protocols       TLSv1.3;

        # Enforce strong ciphers on the upstream leg
        proxy_ssl_ciphers         HIGH:!aNULL:!MD5;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Generate or obtain the upstream CA certificate bundle. For internal microservices using a private CA:

```bash
# Export the internal CA certificate
openssl x509 -in /path/to/internal-ca.crt -out /etc/nginx/trusted-upstream-ca.pem
# Or bundle multiple CA certs
cat /path/to/root-ca.crt /path/to/intermediate-ca.crt \
  > /etc/nginx/trusted-upstream-ca.pem
chmod 644 /etc/nginx/trusted-upstream-ca.pem
```

### WebDAV hardening if it must stay enabled

If WebDAV is required (file sharing workflows, content management systems), apply these mitigations to reduce CVE-2026-27654 exposure while waiting for the upgrade:

```nginx
server {
    listen 443 ssl;
    server_name files.example.com;

    # WebDAV root must not use 'alias' with path components that could be traversed
    # Prefer 'root' over 'alias' for WebDAV locations
    root /var/www/webdav;

    location /dav/ {
        # Only permit authenticated clients to use write methods
        auth_basic           "WebDAV Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;

        # Restrict DAV methods explicitly
        dav_methods          PUT DELETE MKCOL COPY MOVE;
        dav_ext_methods      PROPFIND OPTIONS;
        dav_access           user:rw group:r all:r;

        # Prevent path traversal in Destination headers using a map
        # Reject any Destination that resolves outside /dav/
        if ($http_destination !~* "^https?://[^/]+/dav/") {
            return 403;
        }

        # Store temporary upload bodies on a separate filesystem
        client_body_temp_path /var/tmp/nginx-dav-tmp;
        client_max_body_size  50m;
    }

    # All other locations: block write methods
    location / {
        limit_except GET HEAD OPTIONS {
            deny all;
        }
    }
}
```

For additional defence, run the WebDAV-enabled nginx instance in a separate systemd service unit with a restricted filesystem namespace:

```ini
# /etc/systemd/system/nginx-dav.service override
[Service]
ReadWritePaths=/var/www/webdav /var/tmp/nginx-dav-tmp /var/log/nginx
ReadOnlyPaths=/etc/nginx
PrivateTmp=true
NoNewPrivileges=true
```

### MP4 module protection

If the MP4 module must remain enabled for video seeking, restrict its use to specific trusted locations and authenticated users:

```nginx
server {
    listen 443 ssl;
    server_name media.example.com;

    # Serve MP4 files with seeking support only from the trusted media directory
    location ~* ^/media/trusted/.*\.mp4$ {
        # Require authentication before parsing the MP4
        auth_request /auth;

        mp4;
        mp4_buffer_size     1m;
        mp4_max_buffer_size 5m;

        root /var/www/media;
    }

    # Block mp4 directive for any other .mp4 path
    location ~* \.mp4$ {
        add_header Content-Disposition "attachment";
        root /var/www/media;
    }

    # Never enable 'mp4' directive for proxied content from user-controlled sources
    # location /user-uploads/ {
    #     mp4;  <-- DO NOT DO THIS
    # }
}
```

### Monitoring nginx security releases

Subscribe to the nginx security advisories RSS feed and poll it from a monitoring script or pipeline:

```bash
# Check current CVEs listed on the nginx security advisories page
curl -s https://nginx.org/en/security_advisories.html \
  | grep -oP 'CVE-\d{4}-\d+' \
  | sort -u

# Check the installed nginx version and compare to latest stable
INSTALLED=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
LATEST=$(curl -s https://nginx.org/en/download.html \
  | grep -oP 'nginx-\K\d+\.\d+\.\d+(?=\.tar\.gz)' \
  | sort -V | tail -1)
echo "Installed: $INSTALLED  Latest: $LATEST"
[ "$INSTALLED" = "$LATEST" ] && echo "UP TO DATE" || echo "UPDATE AVAILABLE"
```

If you have a local clone of the nginx Mercurial repository, watch for changes to security-sensitive source files:

```bash
# Clone the nginx repository (one-time setup)
hg clone https://hg.nginx.org/nginx /opt/nginx-hg

# Pull latest changes and display recent commits to security-sensitive modules
hg pull -R /opt/nginx-hg -u
hg log -R /opt/nginx-hg -l 10 \
  --template "{date|shortdate} {desc|firstline}\n" \
  -- src/http/modules/ngx_http_dav_module.c \
     src/http/modules/ngx_http_mp4_module.c \
     src/http/ngx_http_upstream.c
```

Subscribe to the nginx-announce mailing list at `https://mailman.nginx.org/mailman/listinfo/nginx-announce` for email notification of all new releases.

If nginx is deployed via a Docker image, use Renovate or Dependabot to track the `nginx` image tag on Docker Hub. Add a `renovate.json` rule to watch the `nginx` repository:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["nginx"],
      "matchDatasources": ["docker"],
      "automerge": false,
      "labels": ["security", "nginx"],
      "schedule": ["at any time"]
    }
  ]
}
```

After every nginx upgrade, scan the `CHANGES` file for security-relevant language and check whether accompanying CVEs have been published:

```bash
# After upgrading, review the CHANGES file for the new version
NGINX_VERSION=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
curl -s "https://nginx.org/en/CHANGES-${NGINX_VERSION%.*}" \
  | grep -iA2 'bugfix\|overflow\|security\|memory corruption\|use.after.free'
```

## Expected Behaviour

The following table describes observable outcomes for each scenario under default nginx with vulnerable modules versus a patched and hardened configuration.

| Signal | Default nginx with modules (unpatched) | Patched + modules disabled/hardened |
|---|---|---|
| WebDAV COPY with `Destination: /dav/../../../etc/passwd` | Worker process crashes or overwrites `/etc/passwd` (CVE-2026-27654 on 1.29.6 + alias); nginx error log shows SIGSEGV or unexpected file write | Returns `403 Forbidden` due to `if ($http_destination)` check; no filesystem write outside `/dav/`; event logged in access log |
| Request for malformed MP4 with `?start=0` via `mp4` location | Worker process crashes (SIGSEGV in error log); master spawns replacement worker; client receives 502; on 32-bit: potential RCE | If upgraded to 1.29.7/1.28.3: overflow fixed; if `mp4` directive removed: file served as plain download without parsing; no crash |
| Upstream TLS MITM injection (CVE-2026-1642, nginx <= 1.29.4) | nginx worker delivers injected HTTP response to downstream client; no error in nginx logs; TLS appears intact from nginx's perspective | Patched nginx (1.29.5+/1.28.2+): race window closed; `proxy_ssl_verify on` + `proxy_ssl_session_reuse off` adds defence-in-depth; MITM injection fails |
| `curl -I https://example.com` — inspect `Server:` header | Returns `Server: nginx/1.29.6` — version disclosed to any client, enabling version-targeted attacks | Returns `Server: nginx` (or absent) after `server_tokens off`; version not disclosed |
| Review nginx `CHANGES` after upgrade — "Bugfix: buffer overflow" with no CVE | Operator has no signal that this was a security fix; may defer upgrade | Cross-referencing with `nginx.org/en/security_advisories.html` and `hg log` confirms security-relevant change; upgrade prioritised accordingly |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Disabling DAV module (blocking COPY/MOVE/DELETE methods) | Eliminates CVE-2026-27654 attack surface entirely; WebDAV write operations no longer reachable | Breaks any WebDAV client (macOS Finder, Windows WebDAV, rclone, Cyberduck) that depends on nginx for file operations | Migrate file operations to a dedicated WebDAV service (Apache httpd, Caddy) or use an authenticated API endpoint; if nginx WebDAV is mandatory, apply the `Destination` header validation and upgrade to 1.29.7+ |
| Disabling MP4 module (removing `mp4` directive) | Eliminates CVE-2026-27784 attack surface; nginx no longer parses MP4 container metadata | Breaks video seeking (time-offset requests with `?start=`) for HLS-adjacent workflows that depend on nginx MP4 pseudo-streaming | Serve MP4 files as plain static content (clients download then seek locally); or migrate pseudo-streaming to a purpose-built media server (Wowza, Kaltura, or nginx with patched 1.29.7+) |
| `proxy_ssl_verify on` for upstream connections | Verifies upstream certificate authenticity; prevents certificate substitution attacks in addition to closing the CVE-2026-1642 race window | Breaks upstream connections that use self-signed certificates or an internal CA not present in the trusted bundle | Distribute the internal CA certificate to nginx (`proxy_ssl_trusted_certificate`); rotate self-signed certs to CA-signed equivalents; use `proxy_ssl_verify off` only for specific non-sensitive upstream locations, not globally |
| `proxy_ssl_session_reuse off` | Removes the TLS session state that contributes to the CVE-2026-1642 TOCTOU race; slightly simplifies TLS state machine | Increases TLS handshake overhead for every upstream connection; may increase upstream latency by 10–50 ms per reconnect depending on network conditions | Mitigate latency cost with HTTP/2 or HTTP/3 keepalive to the upstream (`keepalive` directive in upstream block) so fewer TLS handshakes occur overall; measure with `proxy_connect_timeout` and upstream response timing before and after |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| DAV methods disabled breaks file upload workflow | Users or automated tools receive `405 Method Not Allowed` on PUT/COPY/DELETE requests; file sync clients report errors | Application error logs show 405 responses; WebDAV client reports "method not allowed"; `curl -X COPY` test against the endpoint returns 405 | Identify which application requires WebDAV and create a targeted `location` block that re-enables only the required methods with authentication, rather than a blanket block across all locations |
| `proxy_ssl_verify on` fails with misconfigured CA bundle | nginx logs `SSL_CTX_load_verify_locations("/etc/nginx/trusted-upstream-ca.pem") failed`; upstream requests return 502; all proxied traffic fails | nginx error log shows TLS certificate verification errors; `curl --cacert /etc/nginx/trusted-upstream-ca.pem https://upstream.internal.company.com` fails from the nginx host | Verify CA bundle contains the correct root and intermediate certificates: `openssl verify -CAfile /etc/nginx/trusted-upstream-ca.pem <(openssl s_client -connect upstream.internal.company.com:443 -showcerts 2>/dev/null)`; update bundle; reload nginx |
| nginx package upgrade introduces unsupported directive or changed syntax | `nginx -t` fails after upgrade; nginx refuses to reload; traffic drops if the master process cannot exec the new binary against the old config | `sudo nginx -t` output shows configuration parse error; `journalctl -u nginx` shows failed reload; Prometheus `nginx_up` gauge drops to 0 | Review nginx `CHANGES` for deprecated or renamed directives (e.g., `proxy_cache_lock_timeout` behaviour changes); pin problematic directive to new syntax; test upgrades in staging with `nginx -t` before applying to production |
| MP4 module disabled breaks video seek for media streaming application | Video players receive the full MP4 file on seek; clients that use `?start=` parameter receive the file from byte 0 instead of the requested offset; user experience degrades but no error is returned | Playback analytics show increased buffering; CDN/access logs show large full-file responses replacing small range requests; QA test of `curl "https://media.example.com/video.mp4?start=30"` returns full file | Enable `mp4` directive only on patched 1.29.7+ nginx for the specific media location; restrict to authenticated users; ensure source MP4 files are validated with `mp4info` or `ffprobe` before being placed in the served directory to reduce malformed-file risk |

## Related Articles

- [nginx Hardening Beyond TLS](/articles/network/nginx-hardening-beyond-tls/)
- [TLS Configuration for nginx and Envoy](/articles/network/tls-nginx-envoy/)
- [WAF Rule Tuning and False Positive Management](/articles/network/waf-rule-tuning/)
- [HTTP Security Headers](/articles/network/http-security-headers/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
