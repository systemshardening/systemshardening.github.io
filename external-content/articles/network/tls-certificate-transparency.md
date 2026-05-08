---
title: "TLS Certificate Transparency Monitoring: CT Logs, CAA Records, and Misissuance Detection"
description: "Certificate Transparency requires all publicly trusted TLS certificates to be logged in append-only public logs. Monitoring CT logs for your domains detects rogue certificates issued without your knowledge — a key indicator of domain hijacking, CA compromise, or insider misissuance."
slug: "tls-certificate-transparency"
date: 2026-05-01
lastmod: 2026-05-01
category: "network"
tags: ["certificate-transparency", "tls", "caa", "pki", "misissuance", "monitoring"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 313
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/network/tls-certificate-transparency/index.html"
---

# TLS Certificate Transparency Monitoring: CT Logs, CAA Records, and Misissuance Detection

## Problem

A valid TLS certificate for your domain can be issued by any of the ~150 publicly trusted Certificate Authorities. If any one of those CAs is compromised, coerced, or makes an operational error, they can issue a valid certificate for your domain without your knowledge or consent. This certificate would be trusted by all browsers and would enable convincing phishing attacks, man-in-the-middle attacks, and credential theft.

High-profile examples include nation-state attacks on certificate authorities (DigiNotar, Comodo), CA operational errors (Symantec), and compromised CA infrastructure used for malware signing.

Certificate Transparency (CT, RFC 9162) addresses this by requiring all publicly trusted TLS certificates to be logged in public, append-only, cryptographically auditable logs before they can be trusted. Every browser now requires CT compliance for trusted certificates. This means every certificate issued for your domain — by any CA — is publicly searchable.

The gap organisations miss: CT logs are public, but you have to actively monitor them. A rogue certificate for `api.example.com` appears in CT logs within minutes of issuance, but if nobody is watching the logs, the certificate can be used for months before it is detected.

Additional weaknesses:

- **No CAA records.** DNS CAA (Certification Authority Authorisation) records restrict which CAs may issue certificates for your domain. Without CAA records, any CA may issue for your domain. CAA does not prevent a compromised CA from ignoring the record, but compliant CAs check it and CAs that violate CAA records face browser distrust.
- **Wildcard certificate overuse.** A wildcard `*.example.com` certificate is issued once and covers all subdomains. A stolen wildcard certificate enables MITM on every subdomain — a much broader blast radius than a single-domain certificate.
- **No monitoring of existing certificates.** Organisations do not track when their own certificates are issued. A certificate expiring unexpectedly — or a certificate for a subdomain nobody recognises — is not detected until it causes an incident.

**Target systems:** All public-facing TLS endpoints; DNS hosting for CAA record management; `crt.sh`, Facebook CT Monitor, Google Certificate Transparency; Certspotter, CertStream.

## Threat Model

- **Adversary 1 — Rogue certificate for phishing:** An attacker submits a domain control validation (DCV) request to a CA using a compromised DNS record or email account. The CA issues a valid certificate for `login.example.com`. The attacker hosts a phishing page with a valid TLS lock icon.
- **Adversary 2 — MITM via compromised CA:** A nation-state compromises a trusted CA and issues a certificate for `api.example.com`. Traffic to the API is intercepted; the valid certificate passes browser validation.
- **Adversary 3 — Insider misissuance:** A CA employee issues a certificate for an organisation's domain for personal use or at an adversary's request. Without CT monitoring, the certificate is never discovered.
- **Adversary 4 — Wildcard certificate theft:** A wildcard `*.example.com` certificate is stolen from the organisation's certificate store (or the CA's issuance system). An attacker uses it for a universal MITM.
- **Adversary 5 — Subdomain takeover via expired certificate:** An organisation's subdomain `old-service.example.com` is still reachable but points to a decommissioned cloud resource. An attacker claims the cloud resource and obtains a valid TLS certificate for the subdomain via automated ACME validation.
- **Access level:** Adversaries 1 and 5 can reach public-facing systems. Adversary 2 requires nation-state capability. Adversary 3 is an insider. Adversary 4 needs access to certificate private keys.
- **Objective:** Create trusted TLS connections to attacker-controlled infrastructure; intercept encrypted traffic; steal credentials.
- **Blast radius:** A rogue certificate enables MITM on all connections to the affected domain until the certificate is revoked and browsers update their CRL/OCSP cache.

## Configuration

### Step 1: CAA DNS Records

Restrict which CAs may issue certificates for your domain:

```bash
# Add CAA records to your DNS zone.
# Syntax: <domain> CAA <flag> <tag> <value>
# flag: 0 = non-critical; 128 = critical (CA must understand this record).
# tag: issue (single domain), issuewild (wildcard), iodef (report misissuance).

# Only Let's Encrypt and DigiCert may issue certificates.
example.com. IN CAA 0 issue "letsencrypt.org"
example.com. IN CAA 0 issue "digicert.com"

# Wildcards: restrict to DigiCert only (more restrictive).
example.com. IN CAA 0 issuewild "digicert.com"

# Report any CA misissuance attempt to our security team.
example.com. IN CAA 0 iodef "mailto:security@example.com"

# Verify CAA records are correctly set.
dig CAA example.com +short
# Expected: 0 issue "letsencrypt.org", 0 issue "digicert.com", etc.

# Test all subdomains inherit CAA (they do by DNS inheritance).
dig CAA api.example.com +short
# If no CAA record for api.example.com, the parent example.com CAA applies.
```

### Step 2: CT Log Monitoring with crt.sh

```bash
# Query crt.sh for all certificates issued for your domain.
curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  jq -r '.[] | "\(.issued_at) \(.common_name) \(.issuer_name)"' | \
  sort | \
  head -20

# Alert on certificates issued in the last 24 hours.
YESTERDAY=$(date -u --date="24 hours ago" +"%Y-%m-%dT%H:%M:%SZ")

curl -s "https://crt.sh/?q=%.example.com&output=json" | \
  jq --arg since "$YESTERDAY" \
  '.[] | select(.issued_at > $since) | {
    issued: .issued_at,
    cn: .common_name,
    san: .name_value,
    issuer: .issuer_name,
    id: .id
  }'
```

### Step 3: Real-Time Monitoring with CertStream

CertStream provides a real-time stream of newly issued certificates from CT logs:

```python
#!/usr/bin/env python3
# ct_monitor.py — monitor CT logs for certificates matching your domains.
import certstream
import re
from datetime import datetime

# Domains to monitor (use regex for subdomain matching).
WATCH_PATTERNS = [
    re.compile(r'(^|\.)example\.com$'),
    re.compile(r'(^|\.)example\.io$'),
    # Include common phishing variants.
    re.compile(r'examp1e\.com$'),           # Homograph attack.
    re.compile(r'example-corp\.com$'),      # Hyphenated variant.
]

ALERT_KEYWORDS = [
    "login", "auth", "secure", "account", "payment",
    "admin", "api", "internal",
]

def process_message(message, context):
    if message['message_type'] != "certificate_update":
        return

    domains = message['data']['leaf_cert']['all_domains']

    for domain in domains:
        for pattern in WATCH_PATTERNS:
            if pattern.search(domain):
                cert = message['data']['leaf_cert']
                issuer = cert['subject'].get('O', 'Unknown')

                alert = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "domain": domain,
                    "issuer": issuer,
                    "serial": cert.get('serial_number'),
                    "fingerprint": cert.get('fingerprint'),
                    "not_before": cert.get('not_before'),
                    "not_after": cert.get('not_after'),
                    "suspicious": any(kw in domain for kw in ALERT_KEYWORDS),
                }

                if alert["suspicious"]:
                    print(f"ALERT: Suspicious certificate for {domain}")
                    send_security_alert(alert)
                else:
                    print(f"INFO: Certificate for {domain} by {issuer}")

certstream.listen_for_events(process_message, url='wss://certstream.calidog.io/')
```

### Step 4: Automated CT Monitoring Pipeline

Deploy as a long-running service:

```yaml
# kubernetes/ct-monitor-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ct-monitor
  namespace: security
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: ct-monitor
          image: example/ct-monitor:v1.2.0@sha256:abc123
          env:
            - name: SLACK_WEBHOOK_URL
              valueFrom:
                secretKeyRef:
                  name: ct-monitor-secrets
                  key: slack-webhook-url
            - name: WATCHED_DOMAINS
              value: "example.com,example.io"
          resources:
            limits:
              cpu: "200m"
              memory: "256Mi"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            periodSeconds: 30
```

```python
# send_security_alert.py — send to Slack on suspicious certificate.
import requests, os

def send_security_alert(alert: dict):
    webhook = os.environ["SLACK_WEBHOOK_URL"]
    color = "danger" if alert["suspicious"] else "warning"

    message = {
        "attachments": [{
            "color": color,
            "title": f"Certificate Transparency Alert: {alert['domain']}",
            "fields": [
                {"title": "Domain", "value": alert["domain"], "short": True},
                {"title": "Issuer", "value": alert["issuer"], "short": True},
                {"title": "Valid From", "value": alert["not_before"], "short": True},
                {"title": "Valid Until", "value": alert["not_after"], "short": True},
                {"title": "Fingerprint", "value": alert["fingerprint"], "short": False},
            ],
            "footer": f"CT Monitor | {alert['timestamp']}",
        }]
    }
    requests.post(webhook, json=message)
```

### Step 5: Certificate Inventory Reconciliation

Compare CT log findings against your authorised certificate inventory:

```python
# ct_reconciler.py — detect certificates not in internal inventory.

AUTHORISED_CERTIFICATES = {
    # fingerprint: {"domain": ..., "purpose": ..., "owner": ..., "expiry": ...}
    "sha256:abc123": {
        "domain": "api.example.com",
        "purpose": "production API",
        "owner": "platform-team",
        "expiry": "2027-01-15",
    },
    # ... all known certificates.
}

def reconcile_with_ct_logs(ct_findings: list[dict]) -> list[dict]:
    """Return CT findings not in the authorised inventory."""
    unknown = []
    for cert in ct_findings:
        fp = cert["fingerprint"]
        if fp not in AUTHORISED_CERTIFICATES:
            unknown.append({
                **cert,
                "status": "UNKNOWN — not in inventory",
                "action_required": True,
            })
    return unknown

# Run daily; alert on any unknown certificate.
```

### Step 6: Response Playbook for Rogue Certificates

```markdown
## Rogue Certificate Response Procedure

### Detection
- CT monitor alerts on certificate for `login.example.com` issued by an unrecognised CA.
- The certificate is not in our internal inventory.

### Immediate Response (within 1 hour)
1. Determine if the certificate is being actively used:
   ```bash
   # Check if anything is serving this certificate.
   echo | openssl s_client -connect login.example.com:443 2>/dev/null | \
     openssl x509 -fingerprint -noout
   # Compare fingerprint to the suspicious certificate's fingerprint.
   ```

2. If the certificate is in active use:
   - Activate the incident response process.
   - Contact the issuing CA's abuse contact to request revocation.
   - Check DNS for any changes (subdomain takeover?).
   - Rotate any credentials that may have been exposed.

3. If not in active use (certificate was issued but not deployed):
   - Report to the CA's misissuance reporting contact (`iodef`).
   - Document the incident.
   - Review how the certificate was obtained (DCV bypass?).

### CA Revocation Request
All CAs must provide a revocation mechanism:
- Let's Encrypt: https://letsencrypt.org/docs/revoking/
- DigiCert: https://www.digicert.com/kb/revoke-cert.htm
- Sectigo: security@sectigo.com

### CAA Strengthening
After any misissuance incident, review CAA records:
- Remove unused CAs from the `issue` record.
- Consider adding `accounturi` parameter to restrict which CA account may issue.
```

### Step 7: CAA with Account Binding (letsencrypt.org)

For Let's Encrypt, bind CAA to a specific account:

```bash
# Get your Let's Encrypt account URI.
certbot show_account
# Expected: Account URI: https://acme-v02.api.letsencrypt.org/acme/acct/123456789

# Update CAA record with accounturi parameter.
# This restricts issuance to ONLY your specific LE account.
example.com. IN CAA 0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789"

# Now even if another LE account tries to issue for your domain, the CA will check
# the accounturi and refuse (if the CA supports this validation).
```

### Step 8: Telemetry

```
ct_certificates_found_total{domain, issuer, status}        counter
ct_unknown_certificates_total{domain}                      counter
ct_suspicious_certificates_total{domain, reason}           counter
ct_monitor_lag_seconds{}                                   gauge  (stream processing lag)
caa_records_present{domain}                                gauge  (1=yes, 0=no)
certificate_expiry_days{domain, fingerprint}               gauge
```

Alert on:

- `ct_unknown_certificates_total` non-zero — a certificate for your domain is not in your inventory; immediate investigation.
- `ct_suspicious_certificates_total` — keyword match on sensitive subdomain names (`login`, `admin`, `api`); possible phishing setup.
- `caa_records_present` == 0 — your domain has no CAA records; any CA can issue.
- `ct_monitor_lag_seconds` > 300 — monitoring stream is delayed; detection window increases.
- Certificate expiry in < 7 days — renewal may be failing; check ACME automation.

## Expected Behaviour

| Signal | No CT monitoring | CT monitoring in place |
|--------|-----------------|----------------------|
| Rogue certificate issued | Discovered when used in phishing attack | Detected in CT log within minutes of issuance |
| Unauthorised CA issues for domain | No detection | CAA record causes CA to decline; if violated, CT log reveals it |
| Subdomain takeover via expired cert | Attacker has valid cert for months | CT alert on new certificate for abandoned subdomain |
| Wildcard cert compromise | Unknown scope of misuse | CT records show exact domain coverage |
| Certificate expiry surprise | Discovered when site goes HTTPS-down | Inventory tracking shows expiry 30+ days ahead |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| CAA with `issuewild` restriction | Wildcards only from one CA | One CA becomes critical dependency | Ensure the CA is HA; test revocation process |
| Real-time CertStream | Seconds latency on detection | Requires long-running service | Run as Kubernetes Deployment; auto-restart on failure |
| `accounturi` in CAA | Only your specific ACME account can issue | Breaking if account is lost | Back up account key; know recovery process |
| Certificate inventory | Reconciliation catches unknowns | Overhead to maintain inventory | Automate from ACME issuance events; append-only |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| CT monitor stream disconnects | Certificates issued but not detected | Monitor health check fails | Auto-reconnect; alert on stream disconnect |
| CAA record missing after DNS migration | New CA can issue unrestricted | CT scan detects certificates from unexpected CAs | Re-add CAA records post-migration; verify after every DNS change |
| False positive flood | Alert fatigue from legitimate cert renewals | High alert volume, mostly from own CAs | Allowlist own CA issuer names; only alert on unknown issuers |
| Revocation not adopted | Rogue cert still trusted after revocation | Browser still shows green lock for revoked cert | OCSP Stapling must be active; OCSP response must be fresh |

## Related Articles

- [DNS Security: DNSSEC and CAA Records](/articles/network/dns-security-dnssec-caa/)
- [TLS Hardening for nginx and Envoy](/articles/network/tls-nginx-envoy/)
- [cert-manager PKI Hardening](/articles/kubernetes/cert-manager-pki-hardening/)
- [Certificate Expiry Monitoring](/articles/observability/certificate-expiry-monitoring/)
- [Network Time Security (NTS)](/articles/network/network-time-security-nts/)
