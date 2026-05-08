---
title: "Shadow IT Detection: Finding and Managing Unauthorised Services and Infrastructure"
description: "Employees using unsanctioned SaaS, spinning up personal cloud accounts, and running unapproved services create invisible attack surface that falls outside security controls and compliance scope. This guide covers DNS-based SaaS discovery, cloud account enumeration, certificate transparency monitoring, and governing shadow IT without blocking productivity."
slug: shadow-it-detection
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - shadow-it
  - saas-discovery
  - asset-discovery
  - dns-security
  - governance
personas:
  - security-engineer
  - security-analyst
article_number: 613
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cross-cutting/shadow-it-detection/
---

# Shadow IT Detection: Finding and Managing Unauthorised Services and Infrastructure

## Problem

Shadow IT is the gap between what the security team thinks the organisation uses and what the organisation actually uses. It grows whenever the official procurement and approval process is too slow, too restrictive, or too opaque for the pace of actual work.

The risk is not that employees are being malicious. The risk is that legitimate business activity is happening in systems the security team cannot see, cannot protect, and cannot respond to when something goes wrong:

- **Data processed outside DLP controls.** An employee uploads a spreadsheet of customer records to an unapproved AI assistant to write a report. There is no DLP policy covering that service, no data residency agreement, and no way to retrieve or audit the data after the fact.
- **Personal credentials managing company data.** A developer creates a personal AWS account to prototype a feature and funds it on a personal card. The account has no MFA policy, no CloudTrail, no access reviews. It holds production data copied from the approved environment.
- **Shadow infrastructure outside incident response scope.** A team builds a microservice on a personal DigitalOcean account because the internal Kubernetes cluster approval takes two weeks. When the service is compromised, the incident response team has no visibility and no credentials to investigate.
- **Compliance scope expansion.** A marketing team processes EU customer email through an unapproved US-only provider. This creates a GDPR violation the legal team is unaware of until a subject access request or a regulator inquiry surfaces it.
- **OAuth application accumulation.** An employee grants a third-party productivity app access to their corporate Google Workspace. The app is later acquired by a company with weaker security practices. The OAuth token continues to grant ongoing access to corporate calendar, email, and Drive.

Shadow IT is not a niche problem. Studies consistently find that the actual number of SaaS applications in use at mid-to-large organisations is three to ten times higher than the number known to IT. The security team's job is to close that gap without making the approved path more painful than the shadow path.

**Scope of this guide:** DNS log-based SaaS discovery, CASB deployment, cloud account enumeration via corporate email, certificate transparency monitoring, OAuth application auditing, network egress analysis, and a governance model that addresses the root cause rather than just blocking symptoms.

## Threat Model

- **Adversary 1 — Third-party breach via shadow SaaS:** A SaaS tool employees use informally (an AI writing assistant, a Slack alternative, a freelancer coordination platform) suffers a breach. Corporate data uploaded by employees is exposed. The security team has no existing relationship with the vendor, no DPA, and no way to assess what data was affected.
- **Adversary 2 — Abandoned cloud account takeover:** An ex-employee created a personal AWS account during their tenure and used it to host company services. After leaving, the account is forgotten. An attacker enumerates accounts associated with the company's email domain, identifies the abandoned account, and exploits IAM misconfigurations to access data that was never properly migrated or deleted.
- **Adversary 3 — Malicious OAuth application:** An attacker publishes a seemingly useful productivity tool to the Google Workspace Marketplace or Microsoft AppSource. Employees authorise it with broad scopes. The application harvests email, calendar, and file access tokens.
- **Adversary 4 — Shadow infrastructure as initial access:** An unapproved service running on unmanaged infrastructure is not patched on the same cadence as official systems. A known vulnerability in an exposed web framework gives an attacker a foothold. The compromised host is inside the corporate network via VPN, providing lateral movement opportunities.
- **Access level:** Adversaries 1 and 2 require no internal access — they exploit external exposure. Adversary 3 requires only a convincing UI. Adversary 4 requires a vulnerable service to be network-reachable.
- **Objective:** Data exfiltration, persistent access, compliance violations enabling extortion, or lateral movement into core infrastructure.

## Detection Methods

### Step 1: DNS Log-Based SaaS Discovery

Corporate DNS resolvers see every domain lookup made from managed endpoints and offices. Analysing these logs against a categorised list of SaaS domains is the lowest-effort, highest-return shadow IT detection technique.

Deploy a passive DNS logging pipeline using your existing recursive resolver or a DNS security gateway:

```bash
# Using dnstap on an Unbound resolver — stream query logs to a file.
# /etc/unbound/unbound.conf addition:
dnstap:
    dnstap-enable: yes
    dnstap-socket-path: "/var/run/unbound/dnstap.sock"
    dnstap-send-identity: yes
    dnstap-log-resolver-query-messages: yes
    dnstap-log-client-response-messages: yes
```

Feed those logs into your SIEM and join against a SaaS domain taxonomy. Commercial threat intelligence feeds (Zscaler, Netskope, Cisco Umbrella) provide categorised domain lists; the open-source alternative is maintaining a curated CSV:

```python
# shadow_it_dns_scan.py
# Reads a dnstap-derived JSONL file and flags SaaS domains not in the approved list.

import json
import csv
from collections import defaultdict

APPROVED_SAAS = {
    "slack.com", "github.com", "atlassian.com", "jira.atlassian.com",
    "confluence.atlassian.com", "zoom.us", "google.com", "microsoft.com",
    "office365.com", "okta.com"
}

SAAS_TAXONOMY = {}  # domain -> category, loaded from CSV
with open("saas_taxonomy.csv") as f:
    for row in csv.DictReader(f):
        SAAS_TAXONOMY[row["domain"]] = row["category"]

hits = defaultdict(lambda: {"count": 0, "clients": set(), "category": ""})

with open("dns_queries.jsonl") as f:
    for line in f:
        event = json.loads(line)
        qname = event.get("qname", "").rstrip(".")
        # Match on apex domain to catch subdomains.
        apex = ".".join(qname.split(".")[-2:])
        if apex in SAAS_TAXONOMY and apex not in APPROVED_SAAS:
            hits[apex]["count"] += 1
            hits[apex]["clients"].add(event.get("client_ip"))
            hits[apex]["category"] = SAAS_TAXONOMY[apex]

for domain, data in sorted(hits.items(), key=lambda x: -x[1]["count"]):
    print(f"{domain:40s}  {data['category']:30s}  "
          f"queries={data['count']:5d}  unique_clients={len(data['clients'])}")
```

The output shows which unapproved SaaS categories are in active use. Prioritise by category (file sharing, HR, CRM, AI assistants) and by number of unique client IPs — widespread use suggests a legitimate unmet need, not a one-off experiment.

### Step 2: CASB for SaaS Discovery and Risk Scoring

A Cloud Access Security Broker sits between users and the internet (proxy-based) or integrates with cloud identity providers (API-based). It provides richer context than DNS logs: file upload volumes, data classification, user identity, and application risk scoring.

**Proxy-based CASB** (Netskope, Zscaler, Palo Alto SASE) routes all web traffic through an inspection point. It can block uploads of sensitive data to unapproved applications and log exact URLs and payloads.

**API-based CASB** integrates directly with approved SaaS platforms (Google Workspace, Microsoft 365, Salesforce) via API to audit what third-party applications have been granted access and what data has been shared.

Configure a Netskope tenant policy as a representative example:

```
# Netskope Real-time Policy — block upload of sensitive files to unsanctioned apps
Policy name: Block PII upload to unsanctioned SaaS
Conditions:
  - App instance: NOT IN [sanctioned_app_list]
  - Activity: UPLOAD
  - DLP profile: PII_and_credentials
Action: Block
  Alert: yes
  User notification: "This application is not approved for company data. 
                     Submit a request at go/saas-approval."
```

**Risk scoring** is built into most CASB products. Each discovered application is rated on factors including:

- Data residency and sovereignty
- Availability of SSO/SCIM integration
- Breach history
- SOC 2 / ISO 27001 certification
- Data retention and deletion guarantees
- Subprocessor disclosure

Publish the resulting application catalogue to the security team and use it to drive the approval fast-track described in the governance section.

### Step 3: Cloud Account Enumeration via Corporate Email

Cloud providers allow accounts to be created with any email address. Employees frequently use their corporate `@company.com` address as the account owner email. This creates a corpus of cloud accounts that the organisation may not know exist.

AWS, GCP, and Azure all have mechanisms to identify accounts associated with a domain through their identity federation and organisation management services.

**AWS — IAM Identity Center and Detective Controls:**

```bash
# List all accounts in the AWS Organisation (covers only managed accounts).
aws organizations list-accounts --query 'Accounts[*].[Id,Name,Email,Status]' \
  --output table

# Cross-reference by searching CloudTrail for API calls from accounts
# NOT in the above list — indicates activity from an unregistered account
# that has assumed a role in a managed account.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time 2026-04-01 \
  --query 'Events[?userIdentity.accountId!=`<YOUR_ORG_ID>`]'
```

For accounts created completely outside the organisation, use **AWS re:Post's account recovery workflow** to claim accounts whose root email is a corporate address — AWS support will assist when you can demonstrate domain ownership.

**GCP — Resource Manager:**

```bash
# List all projects in the organisation hierarchy.
gcloud projects list --filter="parent.type=organization" \
  --format="table(projectId,name,createTime,lifecycleState)"

# Projects NOT in this list but accessible via corporate credentials
# represent shadow accounts. To surface these, check for projects
# where corporate users have Owner or Editor roles via IAM policy export.
gcloud asset search-all-iam-policies \
  --scope="organizations/ORG_ID" \
  --query="policy:@company.com AND policy.role:roles/owner"
```

**Azure — Entra ID tenant discovery:**

Employees sometimes create personal Azure tenants using corporate email. Entra ID cross-tenant access policies and the Microsoft 365 admin centre's "External collaboration" report surface tenants where corporate accounts have activity.

### Step 4: Certificate Transparency Monitoring

Every TLS certificate issued by a publicly trusted CA is logged to Certificate Transparency (CT) logs. Any domain or subdomain that receives a publicly trusted certificate appears in these logs — including shadow infrastructure deployed on personal cloud accounts using company-owned domain names.

Use `certspotter` or `crt.sh` to monitor for new certificate issuance:

```bash
# Query crt.sh for all certificates issued for company.com and subdomains
# in the last 30 days.
curl -s "https://crt.sh/?q=%25.company.com&output=json" \
  | jq -r '.[] | select(.not_before > "2026-04-07") | [.name_value, .issuer_name, .not_before] | @tsv' \
  | sort -u > recent_certs.tsv

# Compare against the official asset register.
comm -23 \
  <(awk '{print $1}' recent_certs.tsv | sort) \
  <(sort official_asset_register.txt) \
  > unknown_domains.txt

cat unknown_domains.txt
```

Automate this as a daily job. New entries that are not in the official asset register are candidates for investigation — they may be legitimate services that were never registered, test environments that have grown into production, or genuine shadow infrastructure.

The **certspotter** daemon (sslmate.com/certspotter) is a purpose-built tool for this:

```bash
# Install certspotter and configure hooks.
# /etc/certspotter/hooks.d/alert_new_cert.sh
#!/bin/bash
# Called when a new cert is found for a watched domain.
DOMAIN="$1"
CERT_PATH="$2"
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK \
  -H 'Content-type: application/json' \
  -d "{\"text\": \"New certificate issued for: ${DOMAIN}\nInvestigate: https://crt.sh/?q=${DOMAIN}\"}"
```

### Step 5: OAuth Application Audit

Employees connecting third-party apps to corporate Google Workspace or Microsoft 365 accounts is one of the most common and least-monitored forms of shadow IT. Each OAuth grant gives a third party ongoing access to corporate data.

**Google Workspace — Admin SDK:**

```bash
# List all third-party OAuth applications with access to Workspace data.
# Requires admin.googleapis.com and oauth2 scope on the service account.
gcloud auth activate-service-account --key-file=admin-sa.json

python3 - <<'EOF'
from googleapiclient.discovery import build
from google.oauth2 import service_account

creds = service_account.Credentials.from_service_account_file(
    "admin-sa.json",
    scopes=["https://www.googleapis.com/auth/admin.reports.audit.readonly"],
    subject="admin@company.com"
)
service = build("admin", "reports_v1", credentials=creds)

response = service.activities().list(
    userKey="all",
    applicationName="token",
    eventName="authorize"
).execute()

for activity in response.get("items", []):
    for event in activity.get("events", []):
        params = {p["name"]: p.get("value") for p in event.get("parameters", [])}
        print(f"{activity['actor']['email']:40s}  "
              f"{params.get('app_name','?'):40s}  "
              f"{params.get('scope','?')}")
EOF
```

**Microsoft 365 — Graph API:**

```bash
# List all OAuth2 permission grants across the tenant.
az login --service-principal -u $APP_ID -p $CLIENT_SECRET --tenant $TENANT_ID

az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" \
  --query "value[].{Client:clientId,Scope:scope,ConsentType:consentType}" \
  --output table
```

Review the output for applications with broad scopes (`Mail.ReadWrite`, `Files.ReadWrite.All`, `Calendars.ReadWrite`) that are not in the approved application catalogue. Revoke grants for unknown applications immediately; investigate before revocation for known applications used by significant numbers of employees, as there may be a legitimate workflow dependency.

### Step 6: Network Egress Analysis

DNS logs show domain lookups; flow logs show data volumes. Combine both to identify high-volume data movement to uncategorised destinations:

```bash
# Using VPC Flow Logs (AWS). Find top destination IPs not in known ranges.
# Export flow logs from CloudWatch Logs Insights:
aws logs start-query \
  --log-group-name "/aws/vpc/flowlogs" \
  --start-time $(date -d '7 days ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields @timestamp, srcAddr, dstAddr, bytes, action
    | filter action = "ACCEPT" and bytes > 1000000
    | stats sum(bytes) as totalBytes by dstAddr
    | sort totalBytes desc
    | limit 50
  '

# Resolve top IPs to hostnames and cross-reference with asset register.
for ip in $(cat top_destinations.txt); do
  host "$ip" 2>/dev/null | grep -o 'domain name pointer.*' || echo "$ip  UNRESOLVED"
done
```

Flag destinations that:
- Are not associated with approved SaaS providers
- Receive more than 100 MB/day from internal hosts
- Are hosted in cloud regions outside the organisation's approved data residency zones

### Step 7: Public Cloud Resource Discovery with Shodan and Censys

Shadow infrastructure often exposes services on public IPs. Use Shodan and Censys to search for assets in corporate IP ranges and certificate-linked assets that are not in the official infrastructure inventory.

```bash
# Shodan CLI — search for services in corporate IP ranges.
pip install shodan
shodan init $SHODAN_API_KEY

# Search by ASN (replace with your ASN).
shodan search --fields ip_str,port,org,product "asn:AS12345" > shodan_asn_results.txt

# Search by certificate organisation name.
shodan search --fields ip_str,port,ssl.cert.subject \
  'ssl.cert.subject.O:"Company Name Ltd"' > shodan_cert_results.txt

# Cross-reference Shodan results against official asset register.
awk '{print $1}' shodan_asn_results.txt | sort > discovered_ips.txt
comm -23 discovered_ips.txt <(sort official_ips.txt) > unknown_ips.txt
echo "Unknown IPs in corporate IP space:"
cat unknown_ips.txt
```

Censys provides similar capability via its API:

```python
# censys_scan.py — find hosts in corporate cert namespace not in asset register.
import censys.search

c = censys.search.CensysHosts()
for host in c.search(
    'services.tls.certificates.leaf_data.subject.organization: "Company Name"',
    fields=["ip", "services.port", "services.service_name"]
):
    print(host["ip"], [s["port"] for s in host.get("services", [])])
```

Services discovered this way that are not in the official inventory should be treated as potentially rogue infrastructure until proven otherwise.

## Governance: Addressing the Root Cause

Detection without governance creates a security team that spends its time playing whack-a-mole. Shadow IT grows because the approved path is too slow or too bureaucratic. The governance model must address that root cause.

**Build an approved alternatives catalogue.** Maintain a publicly accessible internal catalogue of approved tools by category: file sharing, project management, AI assistants, CRM, survey tools. When employees discover the catalogue has a good answer to their need, they use the approved option. Keep it current — an approved-alternatives list that recommends deprecated or poorly-rated tools will be ignored.

**Create a fast-track approval process.** Not every SaaS request needs a full security review. Implement a two-tier model:

- **Fast track (5 business days):** For tools that process non-confidential internal data only, provide a Google Workspace / Microsoft 365 SSO integration, have SOC 2 Type II, and have no history of significant data breaches. Pre-populate the fast-track list with common legitimate tools.
- **Full review (15–30 business days):** For tools processing customer PII, health data, financial data, or accessing confidential intellectual property. Requires DPA review, security questionnaire, and legal sign-off.

Communicate both tracks and their timelines clearly. Most shadow IT appears when employees don't know the fast-track option exists.

**Block only the highest-risk categories.** Blanket blocking of all uncategorised SaaS is unworkable and will generate more shadow IT, not less — employees will use personal devices and personal networks to bypass it. Focus blocking on genuinely high-risk categories:

- Unapproved AI services with training-on-input data retention policies
- Personal cloud storage (Dropbox personal, iCloud) on managed devices
- Remote access tools not approved by IT (TeamViewer personal, ngrok free tier)
- Applications with known security issues or active enforcement actions

**Build a shadow IT amnesty process.** When a team is using an unapproved tool to meet a real need, the goal is to bring it into compliance or migrate to an approved alternative — not to punish the team. An amnesty period where teams can register existing shadow IT without penalty, in exchange for completing a risk assessment and agreeing to a migration timeline, surfaces the majority of the shadow IT that periodic discovery would otherwise take months to find.

**Assign remediation SLAs by risk tier:**

| Discovery method | Risk tier | SLA |
|---|---|---|
| Unapproved AI with PII | Critical | Immediate block + 48h review |
| Personal cloud account with company data | High | 5 days — migrate or decommission |
| Unapproved SaaS, non-sensitive data | Medium | 30 days — register or migrate |
| Internal test service, no external exposure | Low | 90 days — register or decommission |

## Verification

After running discovery tools, validate completeness by cross-referencing across methods:

```bash
# Check that certificate transparency results are reconciled against
# the DNS discovery results — a domain in CT logs but not in DNS logs
# may be dormant shadow infrastructure.

# CT-discovered domains not seen in DNS logs (potentially dormant).
comm -23 <(sort ct_discovered_domains.txt) <(sort dns_observed_domains.txt)

# DNS-observed domains not in CT logs (HTTP-only services, internal names).
comm -23 <(sort dns_observed_domains.txt) <(sort ct_discovered_domains.txt)
```

Establish a quarterly shadow IT review process:
- Re-run all discovery methods and diff against the previous quarter's output
- Review the approved alternatives catalogue for staleness
- Audit OAuth grants — revoke any grants to applications that were approved in a previous period but no longer meet the approval criteria
- Check cloud account enumeration results against the employee offboarding list — ex-employee accounts should have been revoked

## Summary

Shadow IT is a governance gap before it is a technical gap. Technical detection — DNS log analysis, CASB, certificate transparency monitoring, OAuth auditing, network flow analysis, and external attack surface discovery — surfaces the scope of the problem. But each discovery method only addresses a slice of the shadow IT universe, and none of them solve the root cause.

The objective is to reduce the cost of using approved tools below the cost of using shadow tools. That means fast-track approval processes, a maintained approved-alternatives catalogue, and a governance posture that distinguishes between high-risk shadow IT that requires immediate action and low-risk shadow IT that requires a migration plan. Detection tools and governance policy together reduce the invisible attack surface without blocking the legitimate productivity needs that caused shadow IT to grow in the first place.
