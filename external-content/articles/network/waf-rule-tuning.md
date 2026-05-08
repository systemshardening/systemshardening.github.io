---
title: "WAF Rule Tuning That Does Not Break Legitimate Traffic: ModSecurity and Coraza in Practice"
description: "A self-managed Web Application Firewall (WAF) with default rules generates dozens of false positives per day."
slug: "waf-rule-tuning"
date: 2026-02-22
lastmod: 2026-02-22
category: "network"
tags: ["waf", "modsecurity", "coraza", "owasp-crs", "nginx", "false-positives", "rule-tuning"]
personas: ["security-engineer", "platform-engineer"]
article_number: 42
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Fastly"
    id: 71
    category: "cdn-edge"
  - name: "Wallarm"
    id: 83
    category: "api-security"
premium_pack: "waf-tuning-configs"
published: true
layout: article.njk
permalink: "/articles/network/waf-rule-tuning/index.html"
---

# WAF Rule Tuning That Does Not Break Legitimate Traffic: ModSecurity and Coraza in Practice

## Problem

A self-managed Web Application Firewall (WAF) with default rules generates dozens of false positives per day. Every application update, new API endpoint, or content change triggers new false positives. Teams respond in one of two ways, both wrong:

- **Disable the WAF.** After the third incident where the WAF blocks legitimate traffic (a customer's order submission, an admin saving a blog post, a webhook from a payment provider), the team sets the WAF to detection-only mode and never switches back.
- **Suppress all alerts.** Rules that fire frequently are disabled wholesale, removing protection for entire attack categories (SQL injection, XSS, remote code execution) because one rule in the category had false positives.

The root cause is that the OWASP Core Rule Set (CRS) is designed to be generic. It protects against common attacks across all web applications, which means it flags patterns that are legitimate in your specific application. A JSON API that accepts HTML content in a field will trigger XSS rules. A search endpoint that accepts complex query syntax will trigger SQL injection rules. A file upload endpoint will trigger every rule that inspects request bodies.

Effective WAF operation requires per-endpoint tuning: excluding specific rules for specific parameters on specific URIs. This is tedious but essential. A WAF that blocks attacks without blocking users is possible, but only with disciplined, incremental tuning.

**Target systems:** ModSecurity 3.x with [NGINX](https://nginx.org) or Apache, Coraza 0.6+ (Go-native WAF, ModSecurity-compatible), OWASP CRS 4.x.

## Threat Model

- **Adversary:** External attacker sending crafted HTTP requests designed to exploit application vulnerabilities: SQL injection, cross-site scripting (XSS), remote code execution (RCE), local file inclusion (LFI), server-side request forgery (SSRF).
- **Access level:** Unauthenticated or authenticated HTTP access to any endpoint. The WAF sits between the attacker and the application, inspecting every request and response.
- **Objective:** Exploit application vulnerabilities to extract data, execute commands, or gain unauthorized access. The WAF's role is to block exploitation attempts even when the application is vulnerable (defence in depth).
- **Blast radius:** Without a WAF, every unpatched vulnerability in every backend application is directly exploitable. With a properly tuned WAF, exploitation requires either a novel attack pattern not covered by rules or a bypass technique that evades detection.

## Configuration

### ModSecurity 3 with NGINX: Installation and CRS Setup

```bash
# Install ModSecurity 3 module for NGINX (Debian/Ubuntu).
apt install libmodsecurity3 libnginx-mod-http-modsecurity

# Download the OWASP Core Rule Set.
cd /etc/nginx
git clone https://github.com/coreruleset/coreruleset.git /etc/nginx/owasp-crs
cp /etc/nginx/owasp-crs/crs-setup.conf.example /etc/nginx/owasp-crs/crs-setup.conf
```

**ModSecurity main configuration:**

```
# /etc/nginx/modsecurity/modsecurity.conf

# Start in detection-only mode. Do not block anything.
# Change to "On" only after tuning is complete.
SecRuleEngine DetectionOnly

# Request body inspection.
SecRequestBodyAccess On
SecRequestBodyLimit 1048576
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject

# Response body inspection (optional, adds latency).
SecResponseBodyAccess Off

# Audit logging for security analysis.
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABCFHZ
SecAuditLogType Serial
SecAuditLog /var/log/modsecurity/audit.log

# Temporary files directory.
SecTmpDir /tmp/modsecurity
SecDataDir /var/log/modsecurity/data

# Include the OWASP CRS.
Include /etc/nginx/owasp-crs/crs-setup.conf
Include /etc/nginx/owasp-crs/rules/*.conf
```

**NGINX configuration to load ModSecurity:**

```nginx
# /etc/nginx/nginx.conf - http {} block

modsecurity on;
modsecurity_rules_file /etc/nginx/modsecurity/modsecurity.conf;
```

### Coraza: Go-Native Alternative

Coraza is a Go-native WAF engine that is compatible with ModSecurity rules, including the OWASP CRS. It avoids the C library dependency of ModSecurity 3 and integrates natively with Go-based proxies (Caddy, [Traefik](https://traefik.io) via plugins, or standalone).

**Coraza with Caddy:**

```
# Caddyfile with Coraza WAF
{
    order coraza_waf first
}

:443 {
    coraza_waf {
        directives `
            SecRuleEngine DetectionOnly
            SecRequestBodyAccess On
            SecRequestBodyLimit 1048576
            Include /etc/coraza/owasp-crs/crs-setup.conf
            Include /etc/coraza/owasp-crs/rules/*.conf
        `
    }

    reverse_proxy api-backend:8080
}
```

**Coraza as a standalone NGINX sidecar (using coraza-spoa for [HAProxy](https://www.haproxy.org)/NGINX):**

```yaml
# coraza-spoa-config.yaml
# Coraza SPOA (Stream Processing Offload Agent) configuration.
bind: 0.0.0.0:9999
applications:
  - name: default
    directives: |
      SecRuleEngine DetectionOnly
      SecRequestBodyAccess On
      SecRequestBodyLimit 1048576
      Include /etc/coraza/owasp-crs/crs-setup.conf
      Include /etc/coraza/owasp-crs/rules/*.conf
    response_code: 403
    log:
      file: /var/log/coraza/coraza.log
      level: info
```

### CRS Paranoia Levels

The OWASP CRS uses paranoia levels (PL1 through PL4) to control rule aggressiveness. Higher levels catch more attacks but generate more false positives.

```
# /etc/nginx/owasp-crs/crs-setup.conf

# PL1 (default): Low false positives, catches common attacks.
# PL2: More rules enabled, moderate false positives.
# PL3: Aggressive, significant false positives expected.
# PL4: Maximum paranoia, requires extensive tuning.
# Start at PL1. Only increase after tuning PL1 to zero false positives.
SecAction "id:900000, phase:1, pass, t:none, nolog, \
  setvar:tx.blocking_paranoia_level=1, \
  setvar:tx.detection_paranoia_level=2"
```

Setting `detection_paranoia_level` higher than `blocking_paranoia_level` lets you see what PL2 rules would catch without blocking traffic. This is the recommended approach for gradually increasing paranoia.

### Rule Exclusion Patterns

This is where the real tuning work happens. You need to exclude specific rules for specific parameters on specific URIs.

**Create a tuning file that loads after the CRS rules:**

```
# /etc/nginx/modsecurity/crs-tuning.conf
# This file contains rule exclusions specific to your application.
# Load AFTER the CRS rules.

# --- Pattern 1: Exclude a rule for a specific parameter on a specific URI ---
# The "content" field in the blog editor triggers XSS rules.
# Rule 941100: XSS Attack Detected via libinjection
# Rule 941110: XSS Filter - Category 1
SecRule REQUEST_URI "^/api/blog/posts" \
  "id:10001, phase:1, pass, nolog, \
   ctl:ruleRemoveTargetById=941100;ARGS:content, \
   ctl:ruleRemoveTargetById=941110;ARGS:content"

# --- Pattern 2: Exclude a rule for all parameters on a specific URI ---
# The search endpoint accepts complex query syntax that triggers SQLi rules.
# Rule 942100: SQL Injection Attack Detected via libinjection
SecRule REQUEST_URI "^/api/search" \
  "id:10002, phase:1, pass, nolog, \
   ctl:ruleRemoveById=942100"

# --- Pattern 3: Exclude a specific parameter globally ---
# The "Authorization" header triggers rules due to base64 content.
SecRuleUpdateTargetById 920274 "!REQUEST_HEADERS:Authorization"

# --- Pattern 4: Exclude rules for webhook endpoints ---
# Payment provider webhooks send bodies that trigger multiple rules.
SecRule REQUEST_URI "^/webhooks/stripe" \
  "id:10003, phase:1, pass, nolog, \
   ctl:ruleRemoveById=920170, \
   ctl:ruleRemoveById=921110, \
   ctl:ruleRemoveById=941100, \
   ctl:ruleRemoveById=942100"

# --- Pattern 5: Exclude rules for file upload endpoints ---
# File upload content triggers nearly every rule category.
SecRule REQUEST_URI "^/api/upload" \
  "id:10004, phase:1, pass, nolog, \
   ctl:ruleRemoveById=200002, \
   ctl:ruleRemoveById=941100, \
   ctl:ruleRemoveById=942100, \
   ctl:ruleRemoveById=949110, \
   ctl:ruleEngine=Off"
```

**Load the tuning file after CRS rules:**

```
# /etc/nginx/modsecurity/modsecurity.conf
# Add at the end, AFTER the CRS include:
Include /etc/nginx/owasp-crs/crs-setup.conf
Include /etc/nginx/owasp-crs/rules/*.conf
Include /etc/nginx/modsecurity/crs-tuning.conf
```

### Staged Rollout: Detection to Blocking

**Phase 1: Detection only (2-4 weeks).**

```
# modsecurity.conf
SecRuleEngine DetectionOnly
```

Monitor the audit log for false positives. Identify the top rule IDs firing and the URIs they fire on:

```bash
# Find the most frequently triggered rules.
grep -oP 'id "\K[0-9]+' /var/log/modsecurity/audit.log \
  | sort | uniq -c | sort -rn | head -20

# Find the URIs triggering the most rules.
grep -oP 'REQUEST_URI.*? ".*?"' /var/log/modsecurity/audit.log \
  | sort | uniq -c | sort -rn | head -20
```

**Phase 2: Blocking with exceptions (1-2 weeks).**

After adding exclusions for all known false positives:

```
# modsecurity.conf
SecRuleEngine On
```

Keep the audit log active and monitor for new false positives from real traffic.

**Phase 3: Ongoing tuning.** Every application deployment may introduce new patterns that trigger rules. Include WAF smoke tests in your CI/CD pipeline:

```bash
#!/bin/bash
# waf-smoke-test.sh
# Run after deployment to verify the WAF does not block critical endpoints.

BASE_URL="https://staging.yourapp.com"
FAILURES=0

# Test: Login endpoint accepts valid credentials.
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"testpass123"}' \
  "$BASE_URL/api/auth/login")
if [ "$STATUS" = "403" ]; then
  echo "FAIL: Login blocked by WAF (HTTP 403)"
  FAILURES=$((FAILURES + 1))
fi

# Test: Blog post with HTML content.
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -d '{"title":"Test Post","content":"<h1>Hello</h1><p>World</p>"}' \
  "$BASE_URL/api/blog/posts")
if [ "$STATUS" = "403" ]; then
  echo "FAIL: Blog post blocked by WAF (HTTP 403)"
  FAILURES=$((FAILURES + 1))
fi

# Test: Search with special characters.
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/api/search?q=user%27s+guide+%22best+practices%22")
if [ "$STATUS" = "403" ]; then
  echo "FAIL: Search blocked by WAF (HTTP 403)"
  FAILURES=$((FAILURES + 1))
fi

# Test: WAF still blocks actual attacks.
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/api/search?q=1'+OR+'1'%3D'1")
if [ "$STATUS" != "403" ]; then
  echo "FAIL: SQL injection NOT blocked by WAF (expected 403, got $STATUS)"
  FAILURES=$((FAILURES + 1))
fi

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  "$BASE_URL/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
if [ "$STATUS" != "403" ]; then
  echo "FAIL: XSS NOT blocked by WAF (expected 403, got $STATUS)"
  FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -gt 0 ]; then
  echo "$FAILURES WAF smoke tests failed."
  exit 1
else
  echo "All WAF smoke tests passed."
fi
```

### Testing with OWASP ZAP

Use OWASP ZAP to verify the WAF blocks known attack patterns:

```bash
# Run ZAP against your staging environment with WAF enabled.
docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t https://staging.yourapp.com \
  -r zap-report.html

# Compare results with WAF on vs. WAF off.
# WAF should reduce the number of high/medium findings.
```

## Expected Behaviour

After completing the detection-to-blocking rollout:

```bash
# Verify WAF is active and blocking.
# SQL injection attempt:
curl -s -o /dev/null -w "%{http_code}" \
  "https://yourapp.com/api/search?q=1'+OR+'1'='1"
# Expected: 403

# XSS attempt:
curl -s -o /dev/null -w "%{http_code}" \
  "https://yourapp.com/api/search?q=<script>alert(1)</script>"
# Expected: 403

# Path traversal attempt:
curl -s -o /dev/null -w "%{http_code}" \
  "https://yourapp.com/api/files?path=../../etc/passwd"
# Expected: 403

# Remote code execution attempt:
curl -s -o /dev/null -w "%{http_code}" \
  -X POST -H "Content-Type: application/json" \
  -d '{"cmd":"$(cat /etc/passwd)"}' \
  "https://yourapp.com/api/execute"
# Expected: 403

# Legitimate traffic should pass:
curl -s -o /dev/null -w "%{http_code}" \
  "https://yourapp.com/api/search?q=security+best+practices"
# Expected: 200

curl -s -o /dev/null -w "%{http_code}" \
  -X POST -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com"}' \
  "https://yourapp.com/api/users"
# Expected: 200 (or 201)

# Check audit log for blocked requests.
tail -20 /var/log/modsecurity/audit.log
# Should show entries for the attack attempts, not for legitimate traffic.
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| CRS PL1 (default) | Catches common attacks with low false positives | Does not catch obfuscated or advanced attacks | Use PL1 for blocking, PL2 for detection; increase blocking PL after tuning |
| CRS PL2+ | Catches more attack variations | Significant false positives on most applications | Requires per-URI, per-parameter rule exclusions; budget 4-8 hours for initial tuning |
| `SecRuleEngine On` | Blocks attacks in real time | False positives block legitimate traffic immediately | Always run DetectionOnly first; have a fast rollback procedure |
| Per-URI rule exclusions | Eliminates false positives for specific endpoints | Over-exclusion reduces protection for those endpoints | Exclude the minimum: specific rules for specific parameters, not entire rule categories |
| Response body inspection | Catches data leakage (credit cards, SSNs in responses) | Adds 5-15ms latency per request; increases memory usage | Enable only for specific endpoints that handle sensitive data |
| Audit logging (full) | Complete forensic record of blocked and detected events | High disk I/O; audit logs grow quickly | Log only relevant events (`SecAuditEngine RelevantOnly`); rotate logs aggressively |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| False positive blocks critical endpoint | Customers cannot submit orders, login, or upload files; HTTP 403 on legitimate actions | Support tickets; monitoring shows 403 spike on specific URI; audit log shows rule ID | Add rule exclusion to `crs-tuning.conf`; reload NGINX; switch to DetectionOnly as emergency fallback |
| Rule update introduces new false positives | After CRS update, previously working endpoints return 403 | 403 spike correlates with CRS update deployment time | Pin CRS to a specific version; test updates in staging before production; review CRS changelog for new rules |
| ModSecurity module crash | NGINX worker process segfaults; 502 errors; no WAF protection | NGINX error log shows segfault; `dmesg` shows crash; service monitoring alerts | Restart NGINX; if crashes persist, disable ModSecurity and file a bug; consider migrating to Coraza |
| Audit log fills disk | Disk full; NGINX cannot write logs; entire server degrades | Disk usage monitoring alerts; NGINX starts returning 500 errors | Implement log rotation (`logrotate`); reduce `SecAuditLogParts`; set `SecAuditEngine RelevantOnly` |
| Exclusion too broad | An entire attack category is no longer detected for an endpoint | Security scan (ZAP, Burp) finds vulnerabilities that should be caught by WAF | Narrow exclusions to specific parameters (`ctl:ruleRemoveTargetById`) instead of removing entire rules (`ctl:ruleRemoveById`) |
| WAF bypassed via encoding | Attacker uses double encoding, Unicode, or case variation to evade rules | Attack succeeds despite WAF; post-incident analysis reveals evasion technique | Enable CRS normalization transforms (`t:urlDecodeUni`, `t:htmlEntityDecode`); increase paranoia level |

## When to Consider a Managed Alternative

**Transition point:** When WAF rule tuning consumes more than 4-8 hours per month, when every application deployment requires WAF testing and exclusion updates, or when you need protection against zero-day attack patterns that require rule updates faster than your team can deploy them.

**What managed providers handle:**

- **[Cloudflare](https://www.cloudflare.com):** Managed WAF with rules that are automatically updated for new attack patterns. The managed ruleset eliminates the CRS tuning cycle entirely. You configure sensitivity levels and exceptions through a dashboard or API, not by editing rule files. Includes bot management and DDoS protection. Free tier includes basic WAF; Pro ($20/month) adds managed rules.

- **[Fastly](https://www.fastly.com):** Signal Sciences (now Fastly Next-Gen WAF) uses a decision engine that distinguishes attacks from anomalies with very low false positive rates. Unlike traditional WAFs, it does not rely on regex pattern matching, which reduces the tuning burden significantly. SmartParse technology analyses request context instead of matching patterns.

- **[Wallarm](https://www.wallarm.com):** API-focused WAF that automatically discovers your API schema and creates protection rules. Particularly effective for JSON and GraphQL APIs where traditional CRS rules generate excessive false positives. Includes API discovery, vulnerability scanning, and automated rule generation.

**What you still control:** Application-specific exclusions and custom rules will always require your knowledge of your application's legitimate traffic patterns. A managed WAF handles rule maintenance and updates; you handle the policy decisions about what constitutes legitimate traffic for your specific application. Managed WAFs also require initial configuration and periodic review of blocked requests.


## Related Articles

- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [HTTP Security Headers in Production: CSP, HSTS, and Permissions-Policy Without Breaking Your App](/articles/network/http-security-headers/)
- [NGINX Hardening Beyond TLS: Request Filtering, Buffer Limits, and Connection Controls](/articles/network/nginx-hardening-beyond-tls/)
- [Preventing HTTP Request Smuggling: Configuration for NGINX, HAProxy, and Envoy](/articles/network/request-smuggling-prevention/)
- [Rate Limiting at the Ingress Layer: NGINX, Envoy, and Cloud Load Balancers Compared](/articles/network/rate-limiting-ingress/)
