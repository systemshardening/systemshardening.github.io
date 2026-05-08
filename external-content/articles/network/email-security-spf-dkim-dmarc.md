---
title: "Email Security Hardening: SPF, DKIM, DMARC, and BIMI"
description: "SPF limits who can send as your domain. DKIM signs messages. DMARC enforces policy and sends reports. BIMI shows your logo in supporting clients. Most organisations have gaps in all four."
slug: "email-security-spf-dkim-dmarc"
date: 2026-04-30
lastmod: 2026-04-30
category: "network"
tags: ["email", "spf", "dkim", "dmarc", "bimi"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 249
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/network/email-security-spf-dkim-dmarc/index.html"
---

# Email Security Hardening: SPF, DKIM, DMARC, and BIMI

## Problem

Email spoofing is trivial without DNS-based authentication: anyone can send an email claiming to be from your domain. Phishing campaigns, BEC (Business Email Compromise) attacks, and supply chain impersonation all exploit unprotected domains.

Four complementary DNS-based mechanisms provide layered protection:

- **SPF (Sender Policy Framework):** Declares which IP addresses and mail servers are authorised to send email for your domain. Receiving mail servers check that the sending server's IP is in the SPF record.
- **DKIM (DomainKeys Identified Mail):** Cryptographically signs outgoing messages. The private signing key is held by the sending mail server; the public key is published in DNS. Receiving servers verify the signature, confirming the message was not altered in transit and originated from a server with the signing key.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance):** Ties SPF and DKIM together, specifying what receiving servers should do with messages that fail both checks (`none`, `quarantine`, or `reject`) and where to send aggregate and forensic failure reports.
- **BIMI (Brand Indicators for Message Identification):** Displays your verified logo next to authenticated email in supporting clients (Gmail, Apple Mail, Yahoo). Requires a Verified Mark Certificate (VMC) and a passing DMARC `p=reject` or `p=quarantine` policy.

The common gaps:

- SPF record includes `~all` (softfail) instead of `-all` (fail); spoofed email is still delivered.
- SPF lookup chain exceeds the 10-lookup limit and breaks silently; legitimate email starts failing.
- DKIM keys are 1024-bit (RSA-1024 is considered weak; 2048-bit is minimum); or keys are never rotated.
- DMARC at `p=none` forever — reports come in but no action is taken.
- Multiple sending services (ESP, transactional email, CRM) each added their own SPF includes without reconciliation; the record is stale.
- DMARC aggregate reports are delivered but never parsed; the insight they contain (which sources are failing) is wasted.

The consequence: a domain that has technically deployed SPF+DKIM+DMARC but at `p=none` provides almost no protection — it just generates reports.

**Target systems:** Any domain sending email; Google Workspace, Microsoft 365, AWS SES, SendGrid, Postfix on self-hosted infrastructure; DMARC report processors (dmarcian, Postmark's DMARC Digests, self-hosted parsedmarc).

## Threat Model

- **Adversary 1 — Direct spoofing:** An attacker sends email from `attacker-server.com` with `From: ceo@example.com`. Without DMARC enforcement, this reaches recipients. With `p=reject` and aligned DKIM/SPF, receiving servers reject it.
- **Adversary 2 — Subdomain spoofing:** Your DMARC record covers `example.com` but not `mail.example.com` or `legacy.example.com`. An attacker uses a subdomain that has no DMARC record. Without a wildcard subdomain DMARC record, the attack succeeds.
- **Adversary 3 — DKIM key compromise:** An attacker obtains the DKIM private signing key (from a compromised mail server or HSM). They sign arbitrary email that passes DKIM validation. Key rotation limits the window of the compromise.
- **Adversary 4 — SPF bypass via third-party sender:** A legitimate SaaS provider (marketing email, CRM) is compromised. They can send as your domain because they are in your SPF record. DKIM per-selector isolation means a compromised ESP's key doesn't affect your main mail server's DKIM.
- **Adversary 5 — Report hijacking:** Aggregate DMARC reports (`rua=`) are sent to an address that is no longer monitored. An attacker is spoofing your domain at scale; the reports are silently accumulating unread.
- **Access level:** Adversaries 1 and 2 only need the ability to send email. Adversary 3 needs access to the signing key. Adversary 4 needs compromise of the authorised sender. Adversary 5 needs the `rua` inbox to go unmonitored.
- **Objective:** Deliver spoofed email that appears to come from a trusted domain; bypass email security controls; conduct phishing or BEC attacks.
- **Blast radius:** Without DMARC enforcement: any sender can spoof your domain. With `p=reject`: spoofed messages are rejected by receiving servers that enforce DMARC (>95% of commercial mailboxes).

## Configuration

### Step 1: Audit Your Current State

Before making changes, understand what exists:

```bash
# Check SPF record.
dig TXT example.com | grep spf

# Check DMARC record.
dig TXT _dmarc.example.com | grep dmarc

# Check DKIM record (requires knowing the selector — check email headers or mail server config).
dig TXT <selector>._domainkey.example.com | grep DKIM

# Use a public validator.
curl -s "https://dmarcian.com/dmarc-inspector/?domain=example.com"

# Check for existing issues.
# SPF: more than 10 DNS lookups?
# DKIM: key size < 2048?
# DMARC: policy = none?
```

Enumerate all services that send email as your domain:

- Primary mail server (Google Workspace / Microsoft 365)
- Transactional email (SendGrid, AWS SES, Postmark, Mailgun)
- CRM (Salesforce, HubSpot)
- Marketing (Mailchimp, Klaviyo)
- Monitoring/alerting (PagerDuty, Datadog, StatusPage)
- Internal services (Jenkins, Jira, GitHub)

Every service that sends email needs to be in your SPF record or use their own DKIM key (and be covered by DMARC alignment).

### Step 2: Publish a Strict SPF Record

SPF is a DNS TXT record on your domain:

```dns
; Good: explicit list of authorised senders, hard fail for everything else.
example.com. IN TXT "v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.0/24 -all"

; Bad: softfail (~all) means spoofed messages are delivered with a warning flag.
; example.com. IN TXT "v=spf1 include:_spf.google.com ~all"
```

SPF record construction rules:

1. **Use `-all` not `~all`.** `-all` (hardfail) tells receivers to reject messages from unlisted senders. `~all` (softfail) marks them but still delivers.
2. **Stay under 10 DNS lookups.** Each `include:`, `a:`, `mx:`, and `redirect=` costs one lookup. Count them:

```bash
# Count SPF lookups (simplified; use an SPF checker tool for accuracy).
dig TXT example.com | grep -oE 'include:[^ ]+' | wc -l
# Add the lookups within each included record recursively.
```

If you're over 10 lookups, flatten the SPF record by resolving `include:` to their IP ranges:

```bash
# Resolve all IPs in an SPF record.
python3 -c "
import dns.resolver
import re

def resolve_spf(domain, depth=0):
    if depth > 5:
        return []
    try:
        txt = dns.resolver.resolve(domain, 'TXT')
        for r in txt:
            spf = r.to_text().strip('\"')
            if 'v=spf1' in spf:
                includes = re.findall(r'include:(\S+)', spf)
                ips = re.findall(r'ip[46]:(\S+)', spf)
                for inc in includes:
                    ips.extend(resolve_spf(inc, depth+1))
                return ips
    except:
        return []
    return []

print('\n'.join(resolve_spf('example.com')))
"
```

Replace `include:` directives with their resolved IPs if flattening is needed.

3. **Don't include SPF for subdomains that don't send email.** Add a blocking SPF record to prevent use:

```dns
; Block spoofing via subdomains that don't send email.
legacy.example.com. IN TXT "v=spf1 -all"
noreply.example.com. IN TXT "v=spf1 include:sendgrid.net -all"
```

### Step 3: Generate and Publish DKIM Keys

Each sending service needs a DKIM key pair. Use 2048-bit RSA minimum (4096-bit for new deployments); Ed25519 is supported by major providers and offers equivalent security at smaller key size.

**For self-hosted Postfix with OpenDKIM:**

```bash
# Generate a 2048-bit RSA DKIM key pair.
opendkim-genkey -b 2048 -d example.com -s mail2026 -t

# Output:
# mail2026.private  — keep on mail server (never expose)
# mail2026.txt      — publish in DNS

cat mail2026.txt
# mail2026._domainkey IN TXT ( "v=DKIM1; k=rsa; "
#   "p=MIIBIjANBgkqhkiG9w0BAQ..." )

# Install private key.
mv mail2026.private /etc/opendkim/keys/example.com/mail2026.private
chmod 600 /etc/opendkim/keys/example.com/mail2026.private
chown opendkim: /etc/opendkim/keys/example.com/mail2026.private
```

Publish the TXT record:

```dns
mail2026._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIIBIjAN..."
```

For each third-party sender, they provide the DKIM public key and selector — you publish the DNS record, they hold the private key.

**Verify DKIM signing is working:**

```bash
# Send a test email and check the headers.
# Or use mail-tester.com to verify all three mechanisms.

# Verify the DNS record.
dig TXT mail2026._domainkey.example.com
```

**DKIM key rotation (annually or on suspected compromise):**

```bash
# Generate a new key with a new selector name.
opendkim-genkey -b 2048 -d example.com -s mail2027 -t

# Publish the new DNS record.
# Update OpenDKIM config to sign with the new selector.
# Keep the old DNS record for 48 hours (in-flight messages may still reference it).
# After 48 hours, remove the old DNS record and old private key.
```

### Step 4: Deploy DMARC Progressively

DMARC is deployed in stages to avoid disrupting legitimate email before you understand your sending landscape:

**Stage 1: Monitor (`p=none`)**

```dns
_dmarc.example.com. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com; ruf=mailto:dmarc-forensic@example.com; sp=none; adkim=s; aspf=s"
```

- `p=none` — report but don't reject anything yet.
- `rua=` — aggregate reports (sent daily; XML; shows which senders pass/fail).
- `ruf=` — forensic reports (per-failure; may contain message headers).
- `adkim=s` — strict alignment: the DKIM signing domain must exactly match the From domain.
- `aspf=s` — strict alignment: the SPF envelope sender must exactly match the From domain.

Run `p=none` for 2–4 weeks. During this time, parse the aggregate reports to identify:
- Which of your services are failing SPF/DKIM
- Any spoofing attempts against your domain

**Stage 2: Quarantine (`p=quarantine`)**

After fixing all legitimate senders:

```dns
_dmarc.example.com. IN TXT "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@example.com; adkim=s; aspf=s"
```

- `p=quarantine` — failing messages go to spam.
- `pct=25` — apply the policy to 25% of failing messages (gradual rollout). Increase to 100 over time.

**Stage 3: Reject (`p=reject`)**

```dns
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com; adkim=s; aspf=s"
```

Full enforcement. BIMI requires at least `p=quarantine` (Gmail) or `p=reject` (most implementations).

**Subdomain policy:**

```dns
; Apply reject to all subdomains too.
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; sp=reject; rua=mailto:..."
```

`sp=reject` applies the subdomain policy to all subdomains that don't have their own `_dmarc` record.

### Step 5: Process DMARC Aggregate Reports

Aggregate reports are XML files sent daily from receiving mail servers. Parse them to understand your authentication landscape:

```bash
# Install parsedmarc (open-source DMARC report parser).
pip install parsedmarc

# Process a report.
parsedmarc report.xml.gz --output json | jq .

# Or: point it at the rua mailbox directly.
parsedmarc --imap-host imap.gmail.com \
           --imap-user dmarc-reports@example.com \
           --imap-password "$IMAP_PASSWORD" \
           --elasticsearch-host localhost:9200
```

Key fields to monitor in reports:

```xml
<record>
  <row>
    <source_ip>198.51.100.1</source_ip>       <!-- Who sent -->
    <count>150</count>                          <!-- How many messages -->
    <policy_evaluated>
      <dkim>fail</dkim>                         <!-- DKIM result -->
      <spf>pass</spf>                           <!-- SPF result -->
      <disposition>none</disposition>           <!-- Action taken (p=none = no action) -->
    </policy_evaluated>
  </row>
</record>
```

A source IP sending 150 messages with DKIM failure means: a sending service is authorised in SPF but isn't signing with DKIM. Fix: configure DKIM on that service, or investigate if it's a spoofing attempt.

### Step 6: BIMI — Brand Logo in Email Clients

BIMI requires:
1. DMARC at `p=quarantine` or `p=reject` (Stage 3 above).
2. A Verified Mark Certificate (VMC) from DigiCert or Entrust (certifies your trademark).
3. An SVG logo file hosted at a stable URL.
4. A BIMI DNS record.

```bash
# Convert logo to BIMI-compliant SVG (strict subset; no scripts or animations).
# Use the BIMI SVG validator: https://bimigroup.org/bimi-generator/

# Publish BIMI DNS record.
default._bimi.example.com. IN TXT "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
```

Without a VMC, BIMI is published with `a=` empty — some clients show the logo unverified; Gmail and Apple Mail require the VMC.

### Step 7: Monitor and Alert

```
dmarc_pass_rate{domain}                          gauge
dmarc_fail_total{domain, source_ip, reason}      counter
dmarc_reject_total{domain}                       counter
dkim_signing_success_total{selector}             counter
dkim_signing_failure_total{selector, reason}     counter
spf_lookup_count{domain}                         gauge (alert if > 9)
```

Alert on:

- `dmarc_pass_rate` dropping below 95% — a legitimate sending source is failing; investigate before the drop causes deliverability problems.
- `spf_lookup_count` approaching 10 — SPF is close to breaking; flatten before it fails.
- Spike in `dmarc_fail_total` from an unfamiliar source IP — active spoofing campaign; confirm `p=reject` is in place.
- DKIM key age > 365 days — rotation overdue.

## Expected Behaviour

| Signal | No protection | SPF+DKIM+DMARC `p=none` | DMARC `p=reject` |
|--------|--------------|------------------------|-----------------|
| Direct spoofing from external IP | Delivered | Delivered (reports sent) | Rejected at receiving server |
| Subdomain spoofing | Delivered | Delivered (if no `sp=`) | Rejected (with `sp=reject`) |
| DKIM key compromise window | N/A | Indefinite | Limited to rotation interval |
| Deliverability visibility | None | Aggregate reports | Aggregate reports |
| BIMI logo display | Not applicable | Not applicable | Available with VMC |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `p=reject` | Full spoofing protection | Misconfigured legitimate senders bounce | Run `p=none` → `p=quarantine` → `p=reject` progressively; fix all senders first. |
| `adkim=s` strict alignment | Prevents subdomain DKIM bypass | Third-party senders must sign with your exact domain | Most modern ESPs support custom DKIM domains; configure them before enabling strict. |
| DKIM 4096-bit | Stronger signature | Larger DNS record; some older DNS implementations have issues | 2048-bit is the practical minimum; 4096-bit for new deployments is safe. |
| SPF `-all` | Prevents softfail bypass | A missing sender causes their email to bounce | Audit all senders before switching from `~all` to `-all`. |
| DMARC report processing | Visibility into authentication failures | Report volume can be large (XML processing overhead) | Use parsedmarc or a hosted service; alert on aggregate patterns, not individual messages. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| New sending service not in SPF | Email from that service bounces or lands in spam | Deliverability complaints; DMARC reports show SPF fail from new IP | Add the service to SPF; if over 10 lookups, flatten the record. |
| DKIM private key lost | Cannot sign new email; DKIM fails on all outbound | Bounce rate increases; DMARC reports show DKIM fail | Generate new key pair; publish new DNS selector; update mail server; retire old selector. |
| SPF over 10 lookups | All SPF checks fail with `permerror`; DMARC fails | DMARC reports show `permerror`; deliverability collapses | Flatten SPF by replacing `include:` with explicit IP ranges. |
| `rua` inbox not monitored | Spoofing campaigns go undetected | No monitoring; discovered only when users report phishing | Set up automated report parsing; alert on anomalies. |
| BIMI VMC expired | Logo disappears from email clients | Mail client no longer shows logo | Renew VMC annually (DigiCert/Entrust provide reminders). |
| `p=quarantine` catches legitimate mailing list | Mailing list mail quarantined (because lists break DKIM) | User complaints; DMARC reports show failures from list servers | Use `l=` flag in DKIM or configure list to not modify signed content; or allowlist the list server in DMARC. |

## Related Articles

- [DNS Security: DNSSEC and CAA Records](/articles/network/dns-security-dnssec-caa/)
- [HTTP Security Headers](/articles/network/http-security-headers/)
- [OAuth 2.0 and OIDC Implementation Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
- [API Key Lifecycle at Scale](/articles/cross-cutting/api-key-lifecycle/)
- [AI Social Engineering Defence](/articles/ai-landscape/ai-social-engineering-defence/)
