---
title: "HTTP Security Headers in Production: CSP, HSTS, and Permissions-Policy Without Breaking Your App"
description: "Security headers are free, server-side controls that instruct browsers to restrict dangerous behaviour."
slug: "http-security-headers"
date: 2026-01-17
lastmod: 2026-01-17
category: "network"
tags: ["security-headers", "csp", "hsts", "permissions-policy", "content-security-policy", "nginx", "hardening"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 36
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Fastly"
    id: 71
    category: "cdn-edge"
premium_pack: "security-headers-templates"
published: true
layout: article.njk
permalink: "/articles/network/http-security-headers/index.html"
---

# HTTP Security Headers in Production: CSP, HSTS, and Permissions-Policy Without Breaking Your App

## Problem

Security headers are free, server-side controls that instruct browsers to restrict dangerous behaviour. They cost nothing to deploy and protect against entire classes of attacks: cross-site scripting (XSS), clickjacking, MIME sniffing, protocol downgrade, and unauthorized feature access. Despite this, most production deployments get them wrong:

- **Content-Security-Policy (CSP)** is either missing entirely or set to a policy so permissive (`unsafe-inline`, `unsafe-eval`) that it provides no real protection. When teams do deploy a strict CSP, it breaks third-party analytics, CDN-loaded fonts, embedded iframes, and inline scripts, causing an immediate rollback.
- **HSTS with `preload`** is treated as a quick win, but preload submission is effectively permanent. Removing your domain from the HSTS preload list takes months. If you later need to serve HTTP for any reason (legacy integrations, certificate failures), your site becomes unreachable.
- **Permissions-Policy** (formerly Feature-Policy) is either absent or configured with deprecated syntax that browsers ignore silently.
- **Reporting is not configured.** Without `report-uri` or `report-to`, you have no visibility into violations. You deploy a strict policy, something breaks, and you only find out when users report it.

The result: teams either skip security headers or deploy them once, encounter breakage, and revert to a permissive configuration that provides no meaningful protection.

**Target systems:** Any web application served over HTTPS. Configuration examples use [NGINX](https://nginx.org) 1.24+, but the header values apply to any web server or CDN.

## Threat Model

- **Adversary:** Attacker who has achieved partial code injection (stored XSS, DOM-based XSS) or controls a resource loaded by the page (compromised CDN, malicious ad network, supply chain attack on a JavaScript dependency).
- **Access level:** The attacker can inject or modify content served to the user's browser. They do not control the server.
- **Objective:** Exfiltrate session tokens or user data via injected scripts, redirect users to phishing pages, load malicious resources from attacker-controlled domains, or hijack browser features (camera, microphone, geolocation) through injected code.
- **Blast radius:** Every user who loads a page without adequate security headers. CSP alone mitigates the majority of XSS exploitation. HSTS prevents protocol downgrade attacks for all connections to the domain.

## Configuration

### Content-Security-Policy: Report-Only Rollout

Never deploy CSP in enforcement mode on day one. Start with `Content-Security-Policy-Report-Only` to collect violations without breaking anything. Monitor for 2-4 weeks before switching to enforcement.

**Step 1: Deploy a strict baseline in report-only mode.**

```nginx
# /etc/nginx/conf.d/security-headers.conf
# Place in the server {} block for your application.

add_header Content-Security-Policy-Report-Only
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; report-uri /csp-report; report-to csp-endpoint"
    always;

add_header Report-To
    '{"group":"csp-endpoint","max_age":86400,"endpoints":[{"url":"/csp-report"}]}'
    always;
```

**Step 2: Set up a reporting endpoint.** You need something to receive violation reports. Options range from a simple logging proxy to a dedicated service:

```nginx
# Proxy CSP reports to a lightweight collector.
# This can be a simple Node/Python app that writes reports to a log file
# or forwards them to your SIEM.

location /csp-report {
    proxy_pass http://127.0.0.1:8900/report;
    proxy_set_header Content-Type "application/csp-report";

    # Rate limit report submissions to prevent report flooding.
    limit_req zone=csp_reports burst=10 nodelay;
}
```

```nginx
# In the http {} block, define the rate limit zone for reports.
limit_req_zone $binary_remote_addr zone=csp_reports:1m rate=5r/s;
```

**Step 3: Analyse violations for 2-4 weeks.** Common violations you will see:

- Inline `<script>` tags and `onclick` handlers: require `'unsafe-inline'` or migration to nonce-based CSP.
- `eval()` usage (common in older bundlers): requires `'unsafe-eval'` or bundler reconfiguration.
- Third-party domains for analytics, fonts, CDN assets: must be explicitly whitelisted.

**Step 4: Build your production policy.** Here are three real-world CSP policies for common application types.

**SPA with CDN assets (React, Vue, Angular):**

```nginx
add_header Content-Security-Policy
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://images.yourcdn.com; connect-src 'self' https://api.yourapp.com https://analytics.yourapp.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
    always;
```

**API-only service (minimal CSP):**

```nginx
add_header Content-Security-Policy
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    always;
```

**Static marketing site:**

```nginx
add_header Content-Security-Policy
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
    always;
```

### Nonce-Based CSP for Inline Scripts

If your application requires inline scripts (common in server-rendered applications), use nonces instead of `'unsafe-inline'`:

```nginx
# Generate a unique nonce per request using a map or set variable.
# This requires the NGINX njs module or application-level nonce generation.

# Option 1: Application generates the nonce and passes it via header.
# Your application sets X-CSP-Nonce on the response. NGINX reads it.

set $csp_nonce $upstream_http_x_csp_nonce;

add_header Content-Security-Policy
    "default-src 'self'; script-src 'self' 'nonce-$csp_nonce'; style-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    always;

# Hide the nonce header from the client.
proxy_hide_header X-CSP-Nonce;
```

Your application must generate a cryptographically random nonce per request and include it in both the CSP header and the inline script tags:

```html
<script nonce="abc123randomvalue">
  // This script executes because the nonce matches the CSP header.
</script>
```

### HSTS: Strict-Transport-Security

```nginx
# Start with a short max-age to verify nothing breaks.
# 1 day = 86400 seconds.
add_header Strict-Transport-Security "max-age=86400" always;
```

After confirming no issues for one week, increase to the recommended value:

```nginx
# Production HSTS: 2 years, include subdomains.
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
```

**Preload: proceed with caution.** Adding `preload` submits your domain to browser vendors' built-in HSTS list. This is effectively irreversible.

```nginx
# Only add preload after running HSTS for at least 1 month
# with includeSubDomains and max-age >= 31536000.
# WARNING: Removal from the preload list takes months.
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

Before adding `preload`, verify every subdomain supports HTTPS. A forgotten subdomain (`legacy.yoursite.com`, `staging.yoursite.com`) that does not have a valid certificate will become completely unreachable.

### Permissions-Policy

```nginx
# Restrict browser features. Deny all by default, allow only what you need.
add_header Permissions-Policy
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    always;
```

If your application uses geolocation:

```nginx
add_header Permissions-Policy
    "camera=(), microphone=(), geolocation=(self), payment=(), usb=()"
    always;
```

### Other Essential Headers

```nginx
# Prevent MIME type sniffing. Browsers will not execute a file
# with a mismatched Content-Type (e.g., text/plain treated as JavaScript).
add_header X-Content-Type-Options "nosniff" always;

# Prevent clickjacking. DENY blocks all framing.
# Use SAMEORIGIN if your app uses iframes to embed its own pages.
add_header X-Frame-Options "DENY" always;

# Control Referer header leakage.
# strict-origin-when-cross-origin: send full URL for same-origin,
# only origin for cross-origin, nothing for downgrade (HTTPS to HTTP).
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### Complete Security Headers Configuration

```nginx
# /etc/nginx/conf.d/security-headers.conf
# Include this file in your server {} blocks.
# systemshardening.com - Article #36

# --- Content-Security-Policy ---
# Adjust per application type. This is a strict baseline.
add_header Content-Security-Policy
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"
    always;

# --- HSTS ---
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

# --- Permissions-Policy ---
add_header Permissions-Policy
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    always;

# --- Standard security headers ---
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

## Expected Behaviour

After deploying security headers, verify them:

```bash
# Check all security headers at once.
curl -sI https://your-domain.com | grep -iE "(content-security|strict-transport|permissions-policy|x-content-type|x-frame|referrer-policy)"

# Expected output (values will match your configuration):
# Content-Security-Policy: default-src 'self'; script-src 'self'; ...
# Strict-Transport-Security: max-age=63072000; includeSubDomains
# Permissions-Policy: camera=(), microphone=(), geolocation=(), ...
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Referrer-Policy: strict-origin-when-cross-origin

# Verify CSP report-only mode generates reports (not blocks).
# Open browser DevTools > Console. Violations appear as warnings,
# not errors. Resources still load.

# Verify HSTS by checking for HTTP-to-HTTPS redirect:
curl -sI http://your-domain.com | grep -i location
# Expected: Location: https://your-domain.com/

# Test CSP violation reporting:
# Inject a script tag via DevTools that loads from an external domain.
# Check your /csp-report endpoint for the violation report.
```

Online scanners for validation:

- `securityheaders.com` provides a letter grade and identifies missing headers.
- `csp-evaluator.withgoogle.com` analyses your CSP for common weaknesses.

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| CSP `default-src 'self'` | Blocks all external resources by default | Third-party scripts, fonts, analytics break | Whitelist specific domains; use report-only mode first |
| CSP without `'unsafe-inline'` | Blocks inline scripts and styles | Server-rendered apps with inline scripts break | Use nonce-based CSP or refactor to external scripts |
| CSP without `'unsafe-eval'` | Blocks `eval()`, `new Function()`, `setTimeout(string)` | Some bundlers and template engines require eval | Reconfigure bundler; some libraries have no workaround |
| HSTS `preload` | Permanent HTTPS enforcement at browser level | Cannot serve HTTP for any reason; removal takes months | Test with short `max-age` first; verify all subdomains have valid certs |
| HSTS `includeSubDomains` | All subdomains must use HTTPS | Forgotten subdomains without certs become unreachable | Audit all DNS records before enabling |
| Permissions-Policy denying all | Browser features disabled for all origins | Breaks legitimate feature usage (maps needing geolocation) | Allow specific features for `self` where needed |
| `X-Frame-Options: DENY` | No page can frame your content | Breaks legitimate iframe embedding (widget, embedded checkout) | Use `SAMEORIGIN` if you embed your own pages; use CSP `frame-ancestors` for fine-grained control |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| CSP too restrictive | Page loads but scripts, styles, or images are missing; blank white page in worst case | Browser console shows CSP violation errors; CSP reports sent to report endpoint | Switch to `Content-Security-Policy-Report-Only` and add missing sources |
| CSP `'unsafe-inline'` accidentally removed | Inline scripts and styles stop executing; page layout breaks | Immediate visual breakage on pages with inline styles | Re-add `'unsafe-inline'` or deploy nonces; use report-only to find all inline usage first |
| HSTS preload with broken subdomain | Subdomain returns certificate error in all browsers; no override possible | Users report "connection not secure" for specific subdomains | Issue valid certificate for the subdomain; removal from preload list takes 6-12 weeks via hstspreload.org |
| HSTS max-age set too long before testing | All traffic forced to HTTPS even if certificate expires or is misconfigured | Site unreachable until certificate is fixed; cached HSTS persists in browsers | Fix certificate immediately; users can clear HSTS cache in `chrome://net-internals/#hsts` but most will not |
| CSP report flooding | Attacker triggers thousands of CSP violations per second | Report endpoint overloaded; logging pipeline saturated | Rate limit the report endpoint; sample reports instead of collecting all |
| Duplicate headers from multiple config levels | NGINX `add_header` in a `location` block overrides all headers from `server` block | Some security headers disappear on specific paths | Use `include` files consistently; test every location block separately |

**NGINX `add_header` inheritance caveat:** If you add any `add_header` directive inside a `location` block, all `add_header` directives from the parent `server` block are ignored for that location. This is the most common source of missing security headers. Either include your security headers file in every location block or use the `headers-more` module which does not have this inheritance behaviour.

## When to Consider a Managed Alternative

**Transition point:** When you manage CSP policies across 5+ applications with different requirements, when your team spends more than 2-4 hours per month adjusting headers after deployments, or when you need CSP violation reporting at scale without building your own collection pipeline.

**What managed providers handle:**

- **[Cloudflare](https://www.cloudflare.com):** Automatic HTTPS with one-click HSTS. Managed security headers configurable via dashboard or API. CSP can be managed at the edge without touching origin server configuration. Automatic certificate issuance for all subdomains eliminates the HSTS subdomain risk. Report collection and analysis included in Business tier.

- **[Fastly](https://www.fastly.com):** Edge-level header management via VCL or Compute@Edge. Headers can be set, modified, or removed at the CDN layer. Useful for adding security headers to legacy applications where modifying the origin server is not possible.

**What you still control:** CSP policies must still be authored by your team because they depend on your application's resource loading patterns. No provider can auto-generate a correct CSP for your specific application. The provider handles deployment and reporting; you handle policy authoring and testing.


## Related Articles

- [NGINX Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls](/articles/network/nginx-hardening-beyond-tls/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [WAF Rule Tuning That Does Not Break Legitimate Traffic: ModSecurity and Coraza in Practice](/articles/network/waf-rule-tuning/)
- [Preventing HTTP Request Smuggling: Configuration for NGINX, HAProxy, and Envoy](/articles/network/request-smuggling-prevention/)
- [Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared](/articles/network/rate-limiting-ingress/)
