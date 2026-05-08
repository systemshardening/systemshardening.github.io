---
title: "Building a Threat Intelligence Programme: From Feed Consumption to Actionable Decisions"
description: "Raw threat intelligence feeds without a consumption process generate noise, not decisions. A mature threat intelligence programme ingests indicators, enriches them with context, maps them to your environment, and produces prioritised actions. This guide covers intelligence types, source selection, MISP deployment, and integrating threat intel into detection and vulnerability management."
slug: threat-intelligence-program
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - threat-intelligence
  - misp
  - ioc
  - mitre-attack
  - threat-hunting
personas:
  - security-engineer
  - security-analyst
article_number: 609
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/threat-intelligence-program/
---

# Building a Threat Intelligence Programme: From Feed Consumption to Actionable Decisions

## Problem

Many security teams subscribe to threat intelligence feeds. Fewer have a functioning threat intelligence programme — a systematic process for turning raw indicators and adversary data into prioritised, time-bounded security decisions.

The common failure is volume without consumption. A team signs up for three free OSINT feeds and a commercial subscription, routes the indicators into a SIEM, and watches the alert count double. Nobody can explain what threat actors they are tracking, whether any tracked actor targets their industry, or whether a given IOC is still active or two years stale. The feed adds noise, not signal.

Common failure modes in threat intelligence:

- **Feed ingestion without analysis.** IP blocklists and hash lists flow into the SIEM. Every match generates an alert. No analyst can tell whether the matching IOC belongs to a tracked campaign, a false positive, or a sinkholed domain from 2022.
- **Tactical-only focus.** Teams collect IOCs — IPs, hashes, domains — but have no strategic or operational layer. They know an IP is malicious; they do not know which threat actor uses it, what their objectives are, or what TTPs follow initial access.
- **No lifecycle management.** Indicators decay. An IP flagged as a C2 server in 2023 is likely reassigned or sinkholed. Blocklists filled with stale IOCs generate false positives, erode analyst trust, and obscure genuine hits.
- **No environment mapping.** Threat intelligence describes threats in general. Without mapping to your specific technology stack, industry, and geography, you cannot determine which threats are relevant to you.
- **No feedback loop.** Intelligence that cannot be validated against actual detections or hunt findings cannot be improved. Without feedback, feed quality is invisible.

**Target systems:** MISP (Malware Information Sharing Platform), OpenCTI, Elastic SIEM or Splunk for IOC ingestion, Sigma rules for TTP-based detection, MITRE ATT&CK Navigator for threat actor mapping.

## Threat Model

- **Adversary 1 — Opportunistic commodity threat:** Ransomware-as-a-service affiliates using commodity tooling (Cobalt Strike, Metasploit, commodity stealers). They target known-unpatched internet-exposed services. Public IOC feeds contain their infrastructure.
- **Adversary 2 — Targeted sector-specific threat actor:** A threat group known to target your industry (finance, healthcare, energy). They use spear-phishing, living-off-the-land techniques, and custom implants. Their TTPs are documented in MITRE ATT&CK. Their infrastructure rotates frequently, making IOC-based detection unreliable; TTP-based detection is required.
- **Adversary 3 — Supply chain threat:** A threat actor compromising software dependencies, CI/CD pipelines, or managed service providers to reach downstream targets. Indicators are upstream in third parties; threat intelligence sharing groups and ISAC feeds carry early warning.
- **Adversary 4 — Insider or credential abuse:** An adversary using legitimate credentials obtained through phishing, credential stuffing, or infostealer malware. Internal telemetry and honeypot data, combined with leaked credential feeds, provide the intelligence signal.
- **Access level:** All adversaries achieve initial access via internet-exposed services, phishing, supply chain, or credential reuse. Lateral movement and privilege escalation follow.
- **Objective:** Data exfiltration, ransomware deployment, or persistent access for espionage.
- **Blast radius:** Undetected compromise at initial access allows adversaries to achieve their primary objective before detection. Early detection from threat intelligence-informed alerts limits dwell time.

## Configuration

### Step 1: Intelligence Types — What You Are Collecting

Threat intelligence operates at three levels. A mature programme consumes all three.

```
Strategic intelligence
  ├── Adversary intent: What motivates tracked threat actors?
  ├── Capability: What tools and techniques does this actor use?
  ├── Targeting: Which industries and geographies?
  └── Consumers: CISO, board, risk team — decisions on investment and risk

Operational intelligence
  ├── Active campaigns: What is this actor doing right now?
  ├── TTPs: MITRE ATT&CK technique mappings for this campaign
  ├── Infrastructure patterns: C2 infrastructure patterns, staging domains
  └── Consumers: Security engineers — detection rule development, threat hunting

Tactical intelligence
  ├── Indicators of Compromise (IOCs)
  │   ├── IP addresses (C2, scanning sources, exfil destinations)
  │   ├── Domains and URLs (phishing, C2, malware distribution)
  │   ├── File hashes (SHA-256 of malware samples)
  │   └── Email indicators (sender addresses, subject patterns)
  └── Consumers: SIEM, EDR, firewalls — automated blocking and alerting
```

Tactical IOCs decay rapidly. An IP address has a useful life of days to weeks. A file hash may be valid for months if the malware variant is not recompiled. A domain has intermediate longevity. Always store the `confidence` and `expiry` date alongside every IOC.

### Step 2: Source Selection and Curation

```yaml
# threat-intel-sources.yaml — curated source inventory
sources:
  osint_free:
    - name: AlienVault OTX (Open Threat Exchange)
      url: https://otx.alienvault.com
      feed_type: [ip, domain, hash, url]
      ingestion: MISP feed (STIX/JSON)
      quality: medium  # Large volume; variable quality; must filter by pulse rating
      refresh_interval: 1h

    - name: Abuse.ch (MalwareBazaar, URLhaus, ThreatFox)
      url: https://abuse.ch
      feed_type: [hash, url, ip]
      ingestion: CSV/JSON API
      quality: high  # Focused on malware and botnet infrastructure
      refresh_interval: 15m

    - name: CISA Known Exploited Vulnerabilities
      url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
      feed_type: [cve]
      ingestion: JSON API
      quality: high  # Authoritative; confirmed exploitation in the wild
      refresh_interval: 24h

    - name: PhishTank
      url: https://phishtank.org
      feed_type: [url, domain]
      ingestion: JSON/CSV download
      quality: medium  # Community-verified phishing URLs
      refresh_interval: 1h

    - name: Emerging Threats (Proofpoint ET Open)
      url: https://rules.emergingthreats.net
      feed_type: [ip, rule]
      ingestion: Suricata/Snort rule format
      quality: high  # Well-maintained; mapped to threat categories
      refresh_interval: 24h

  isac:
    - name: FS-ISAC (financial sector)
      notes: "Membership required; feeds via STIX/TAXII; sector-specific campaigns"
    - name: H-ISAC (healthcare)
      notes: "Membership required; covers ransomware targeting healthcare"
    - name: E-ISAC (energy/ICS)
      notes: "Membership required; ICS-specific threat actors (Sandworm, Volt Typhoon)"

  commercial:
    - name: Recorded Future
      ingestion: STIX/TAXII or API
      differentiator: "Dark web monitoring, early warning on exploits, threat actor profiles"
    - name: Mandiant Threat Intelligence
      ingestion: API
      differentiator: "First-party incident response data; high-confidence attribution"
    - name: VirusTotal Intelligence
      ingestion: API (requires paid tier)
      differentiator: "Retrohunting on malware samples; YARA rule-based hunting"

  internal:
    - name: Honeypot network
      notes: "Self-hosted Cowrie (SSH), Dionaea (SMB/FTP), or T-Pot platform"
      value: "High-confidence; attackers interacting with honeypots have no legitimate reason"
    - name: Incident data
      notes: "IOCs and TTPs extracted from confirmed incidents; highest confidence"
    - name: DNS sinkholes
      notes: "Track what internal hosts attempt to resolve; flag malware C2 lookups"
```

Source selection must match your threat model. An energy company facing ICS-specific threat actors needs E-ISAC feeds and Dragos intelligence, not generic commodity feeds. A SaaS company primarily facing credential stuffing needs leaked credential feeds and ATO-focused intelligence.

### Step 3: MISP Deployment

MISP (Malware Information Sharing Platform) is the standard self-hosted platform for aggregating, enriching, and sharing threat intelligence.

```bash
# Deploy MISP using Docker Compose.
git clone https://github.com/MISP/misp-docker
cd misp-docker
cp template.env .env

# Configure key settings in .env:
# MISP_BASEURL=https://misp.internal.example.com
# MISP_ADMIN_EMAIL=security@example.com
# MISP_ADMIN_PASSPHRASE=$(openssl rand -base64 32)
# MYSQL_PASSWORD=$(openssl rand -base64 32)

docker compose up -d

# Verify MISP is running.
docker compose ps
# misp-core   Up   443/tcp, 80/tcp
# misp-mysql  Up   3306/tcp
# misp-redis  Up   6379/tcp
```

```python
# Configure MISP feeds via API.
# misp_setup/configure_feeds.py

import requests

MISP_URL = "https://misp.internal.example.com"
MISP_KEY = "YOUR_MISP_API_KEY"

HEADERS = {
    "Authorization": MISP_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Add AlienVault OTX as a MISP feed.
otx_feed = {
    "Feed": {
        "name": "AlienVault OTX",
        "url": "https://reputation.alienvault.com/reputation.generic",
        "provider": "AlienVault",
        "source_format": "misp",
        "input_source": "network",
        "enabled": True,
        "caching_enabled": True,
        "fixed_event": False,
        "delta_merge": False,
        "publish": False,
        "tag_id": False,
        "default_tag_id": False,
        "lookup_visible": True,
        "headers": "",
        "distribution": 0,  # Your organisation only.
    }
}

resp = requests.post(
    f"{MISP_URL}/feeds/add",
    json=otx_feed,
    headers=HEADERS,
    verify=True,
)
print(resp.json())

# Fetch all enabled feeds immediately.
requests.post(f"{MISP_URL}/feeds/fetchFromAllFeeds", headers=HEADERS)
```

```bash
# MISP cron job: fetch all feeds every hour.
# /etc/cron.d/misp-feeds
0 * * * * www-data /var/www/MISP/app/Console/cake Server fetchFeeds 2>&1 | logger -t misp-feeds

# Decay old indicators daily.
0 2 * * * www-data /var/www/MISP/app/Console/cake Admin decayIndicators 2>&1 | logger -t misp-decay
```

**Sharing groups** control which intelligence is shared with external parties. Create granular groups:

```python
# Create a sharing group for ISAC members only.
sharing_group = {
    "SharingGroup": {
        "name": "FS-ISAC Sharing Group",
        "releasability": "Members of FS-ISAC only",
        "description": "Threat intelligence shared with FS-ISAC member organisations",
        "active": True,
        "roaming": False,  # Do not forward beyond defined members.
    }
}

resp = requests.post(
    f"{MISP_URL}/sharing_groups/add",
    json=sharing_group,
    headers=HEADERS,
)
```

### Step 4: MITRE ATT&CK Threat Actor Profiling

MITRE ATT&CK provides a structured taxonomy of adversary techniques. Map each tracked threat actor to their known ATT&CK techniques to understand what detections you need.

```python
# threat_actors/profile_builder.py
# Build a threat actor profile from ATT&CK STIX data.

from mitreattack.stix20 import MitreAttackData

# Download ATT&CK STIX bundle: https://github.com/mitre/cti
attack = MitreAttackData("enterprise-attack.json")

def build_actor_profile(actor_name: str) -> dict:
    """
    Returns techniques used by a named threat actor,
    grouped by tactic, with detection guidance.
    """
    groups = attack.get_groups()
    actor = next(
        (g for g in groups if actor_name.lower() in g["name"].lower()),
        None
    )
    if not actor:
        raise ValueError(f"Actor '{actor_name}' not found in ATT&CK")

    techniques = attack.get_techniques_used_by_group(actor["id"])

    profile = {
        "actor": actor["name"],
        "description": actor.get("description", ""),
        "aliases": actor.get("aliases", []),
        "techniques_by_tactic": {},
    }

    for technique in techniques:
        for phase in technique.get("kill_chain_phases", []):
            tactic = phase["phase_name"]
            profile["techniques_by_tactic"].setdefault(tactic, []).append({
                "technique_id": technique["external_references"][0]["external_id"],
                "technique_name": technique["name"],
                "detection": technique.get("detection", ""),
            })

    return profile

# Example: profile APT29 (Cozy Bear).
profile = build_actor_profile("APT29")
for tactic, techniques in profile["techniques_by_tactic"].items():
    print(f"\n{tactic.upper()}")
    for t in techniques:
        print(f"  {t['technique_id']}: {t['technique_name']}")
```

```bash
# Visualise threat actor profiles in ATT&CK Navigator.
# Export a layer file for browser-based ATT&CK Navigator.

curl -s https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
  | python3 generate_navigator_layer.py --actor "APT29" \
  > apt29-layer.json

# Open https://mitre-attack.github.io/attack-navigator/
# Import apt29-layer.json to see which techniques APT29 uses highlighted.
```

**Gap analysis:** Compare the ATT&CK techniques used by your tracked threat actors against your detection coverage. Techniques without a corresponding detection rule or alert are blind spots.

```python
# gap_analysis/coverage_check.py

def find_detection_gaps(actor_techniques: list, sigma_rules: list) -> list:
    """
    Returns ATT&CK technique IDs used by actor that have no Sigma rule coverage.
    """
    covered_techniques = set()
    for rule in sigma_rules:
        for tag in rule.get("tags", []):
            if tag.startswith("attack.t"):
                # e.g. "attack.t1059.001" → "T1059.001"
                technique_id = tag.replace("attack.", "").upper()
                covered_techniques.add(technique_id)

    actor_technique_ids = {t["technique_id"] for t in actor_techniques}
    return sorted(actor_technique_ids - covered_techniques)

gaps = find_detection_gaps(profile_techniques, loaded_sigma_rules)
print(f"Detection gaps for {actor_name}: {gaps}")
```

### Step 5: IOC Integration into SIEM

Pull IOCs from MISP into your SIEM for automated matching. Use the MISP API to export by type and confidence.

```python
# siem_integration/misp_exporter.py
# Export active, high-confidence IOCs from MISP for SIEM ingestion.

import requests
from datetime import datetime, timedelta

def export_iocs(
    misp_url: str,
    misp_key: str,
    ioc_type: str,           # "ip-dst", "domain", "md5", "sha256"
    min_confidence: int = 70, # 0-100; filter noise
    max_age_days: int = 30,
) -> list[str]:
    """
    Returns a list of active IOC values for a given type.
    """
    cutoff = (datetime.utcnow() - timedelta(days=max_age_days)).strftime("%Y-%m-%d")

    payload = {
        "returnFormat": "json",
        "type": ioc_type,
        "to_ids": True,          # Only exportable, actionable IOCs.
        "timestamp": cutoff,
        "enforceWarninglist": True,  # Exclude whitelisted values.
    }

    resp = requests.post(
        f"{misp_url}/attributes/restSearch",
        json=payload,
        headers={
            "Authorization": misp_key,
            "Accept": "application/json",
        },
    )
    resp.raise_for_status()

    attributes = resp.json().get("response", {}).get("Attribute", [])
    return [attr["value"] for attr in attributes]

# Export IP IOCs and write to a file Suricata or SIEM can consume.
malicious_ips = export_iocs(MISP_URL, MISP_KEY, "ip-dst")
with open("/etc/threat-intel/malicious-ips.txt", "w") as f:
    f.write("\n".join(malicious_ips))

# Export domain IOCs.
malicious_domains = export_iocs(MISP_URL, MISP_KEY, "domain")
with open("/etc/threat-intel/malicious-domains.txt", "w") as f:
    f.write("\n".join(malicious_domains))
```

```yaml
# Elastic SIEM: ingest IOC list as a threat indicator index.
# Use Elastic's Threat Intel filebeat module.

filebeat.inputs:
  - type: threat-intel
    name: misp
    enabled: true
    url: "https://misp.internal.example.com"
    api_key: "${MISP_API_KEY}"
    ioc_expiration_duration: "30d"  # Auto-expire IOCs after 30 days.
    interval: 1h
    
output.elasticsearch:
  hosts: ["https://elastic.internal.example.com:9200"]
  index: "filebeat-threat-intel-%{+yyyy.MM}"
```

```yaml
# Splunk: add threat intel lookup table from MISP export.
# Add to transforms.conf
[malicious_ips]
filename = malicious_ips.csv
case_sensitive_match = false

# Threat intel correlation search (scheduled every 15 minutes).
index=network sourcetype=firewall
| lookup malicious_ips ip AS dest_ip OUTPUT threat_description
| where isnotnull(threat_description)
| table _time, src_ip, dest_ip, dest_port, threat_description, action
```

**TTP-based detection with Sigma:** IOC-based detection is reactive and easily evaded. TTP-based detection using Sigma rules is more durable — an attacker must change their technique, not just their infrastructure.

```yaml
# sigma/rules/apt29-spearphishing-attachment.yml
# Detects T1566.001 - Spearphishing Attachment, as used by APT29.

title: Suspicious Office Child Process (APT29 TTP)
id: a9c4e443-8d36-4e11-a5e2-d4b9e6d4a321
status: production
description: >
  Detects Microsoft Office applications spawning unusual child processes,
  consistent with macro-enabled document exploitation. Used by APT29
  (T1566.001 Phishing: Spearphishing Attachment, T1059.005 VBScript).
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/groups/G0016/
author: security-team@example.com
date: 2026-05-07
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1059.005
  - threat_actor.apt29
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
  condition: selection
falsepositives:
  - Legitimate macros in controlled environments (very rare)
level: high
```

### Step 6: Threat-Informed Vulnerability Prioritisation

Threat intelligence directly improves vulnerability management by identifying which CVEs are actively exploited by threat actors relevant to your organisation.

```python
# threat_informed_vuln/prioritiser.py
# Cross-reference open vulnerabilities with threat actor TTPs and active exploitation.

from dataclasses import dataclass

@dataclass
class ThreatContext:
    cve_id: str
    exploited_by_actors: list[str]   # Tracked actors exploiting this CVE
    exploit_in_wild: bool             # Confirmed exploitation in the wild
    cisa_kev: bool                    # In CISA KEV catalog
    exploit_kit_integration: bool     # In commodity exploit kit (Metasploit, etc.)
    active_campaign: bool             # Currently active campaign using this CVE

def threat_adjusted_priority(
    cvss_score: float,
    threat_ctx: ThreatContext,
    asset_is_internet_exposed: bool,
) -> tuple[str, str]:
    """
    Returns (priority_tier, rationale).
    Priority tiers: P0 (emergency), P1 (critical), P2 (high), P3 (standard)
    """
    # P0: CISA KEV + internet exposed = patch within 24 hours.
    if threat_ctx.cisa_kev and asset_is_internet_exposed:
        return "P0", f"{threat_ctx.cve_id} is in CISA KEV and asset is internet-exposed"

    # P0: Tracked threat actor actively exploiting this CVE.
    if threat_ctx.active_campaign and threat_ctx.exploited_by_actors:
        actors = ", ".join(threat_ctx.exploited_by_actors)
        return "P0", f"Active campaign by {actors} exploiting {threat_ctx.cve_id}"

    # P1: In CISA KEV (exploited in wild), even if not internet exposed.
    if threat_ctx.cisa_kev:
        return "P1", f"{threat_ctx.cve_id} confirmed exploited in the wild (CISA KEV)"

    # P1: Tracked threat actor exploitation + high CVSS.
    if threat_ctx.exploited_by_actors and cvss_score >= 7.0:
        return "P1", f"{threat_ctx.cve_id} exploited by tracked actors; CVSS {cvss_score}"

    # P2: Exploit kit integration (commodity; likely to be used against any target).
    if threat_ctx.exploit_kit_integration and cvss_score >= 6.0:
        return "P2", f"{threat_ctx.cve_id} in commodity exploit kit; CVSS {cvss_score}"

    # P3: CVSS-based standard prioritisation.
    if cvss_score >= 9.0:
        return "P2", f"CVSS {cvss_score}; no active exploitation context"
    return "P3", f"CVSS {cvss_score}; no active exploitation evidence"
```

```bash
# Correlate open vulnerability tickets against CISA KEV.
# Run daily; any match is P0 and triggers immediate Slack/PagerDuty alert.

#!/bin/bash
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OPEN_CVES_FILE="/var/data/vuln-mgmt/open-cves.txt"

curl -s "$KEV_URL" -o /tmp/kev.json

while IFS= read -r cve; do
  match=$(jq --arg cve "$cve" \
    '.vulnerabilities[] | select(.cveID == $cve) | .cveID' \
    /tmp/kev.json)
  if [ -n "$match" ]; then
    echo "P0 ALERT: $cve is unpatched and in CISA KEV"
    # Page on-call.
    python3 /opt/scripts/page_oncall.py \
      --severity critical \
      --message "Unpatched CISA KEV vulnerability: $cve — patch within 24 hours"
  fi
done < "$OPEN_CVES_FILE"
```

### Step 7: Intelligence Sharing

Sharing intelligence with trusted peers improves collective defences and often returns higher-quality intelligence than you contribute. Key principles:

```yaml
# sharing-policy.yaml — outbound intelligence sharing policy

internal_sharing:
  - audience: "Security Operations (SOC)"
    types: [tactical_iocs, active_campaigns]
    format: "MISP events via API; daily digest email"
    frequency: real_time

  - audience: "Security Engineering"
    types: [ttp_analysis, detection_gaps, threat_actor_profiles]
    format: "Confluence pages; Slack channel #threat-intel"
    frequency: weekly

  - audience: "Executive / Risk team"
    types: [strategic_intelligence, threat_landscape_summary]
    format: "Monthly briefing deck; one-page threat summary"
    frequency: monthly

external_sharing:
  - recipient: "FS-ISAC (sector ISAC)"
    types: [high_confidence_iocs, campaign_reports]
    tlp: "TLP:AMBER+STRICT"  # Members only; no further sharing.
    restrictions: "Remove internal asset references; anonymise victim data"
    review_required: true

  - recipient: "CISA (government partner)"
    types: [novel_malware_samples, critical_infrastructure_threats]
    tlp: "TLP:WHITE"
    process: "Submit via CISA reporting portal; coordinate on public disclosure"

tlp_definitions:
  TLP:RED: "Only named recipients; not for distribution"
  TLP:AMBER: "Organisation and clients only"
  TLP:AMBER+STRICT: "Organisation only; no client sharing"
  TLP:GREEN: "Community; not for public release"
  TLP:WHITE: "Unrestricted public release"
```

**Responsible disclosure timeline** for internally discovered vulnerabilities:

```
Day 0:   Vulnerability discovered internally or by external researcher.
Day 1:   Notify vendor privately (security@vendor.com or HackerOne programme).
Day 14:  Follow up if no acknowledgement.
Day 45:  If no patch progress, notify vendor of disclosure intent.
Day 90:  Public disclosure, coordinated with vendor if patch available.
         If vendor unresponsive: disclose with available mitigations.
```

### Step 8: Measuring Intelligence Quality

Most threat intelligence programmes measure volume (number of IOCs ingested). Volume is the wrong metric. Measure precision, recall, and operational utility.

```python
# metrics/intel_quality.py

def calculate_programme_metrics(
    iocs_ingested: int,
    iocs_matched_in_traffic: int,
    matches_confirmed_malicious: int,
    matches_false_positive: int,
    detections_linked_to_intel: int,
    total_detections: int,
    hunts_conducted: int,
    hunts_yielding_findings: int,
) -> dict:
    return {
        # Precision: of IOCs that matched, what fraction were genuinely malicious?
        # Low precision → noisy feeds creating false positive alerts.
        "ioc_precision": (
            matches_confirmed_malicious /
            (matches_confirmed_malicious + matches_false_positive)
            if (matches_confirmed_malicious + matches_false_positive) > 0
            else 0
        ),

        # Match rate: what fraction of ingested IOCs ever matched traffic?
        # Very low match rate suggests feeds irrelevant to your environment.
        "ioc_match_rate": iocs_matched_in_traffic / iocs_ingested if iocs_ingested > 0 else 0,

        # Intel-driven detection rate: what fraction of total detections
        # were enabled by threat intelligence (IOC match or TTP-based Sigma rule)?
        # This measures the programme's contribution to detection.
        "intel_driven_detection_pct": (
            detections_linked_to_intel / total_detections * 100
            if total_detections > 0 else 0
        ),

        # Hunt yield rate: what fraction of threat hunts produced findings?
        # Intel-driven hunts should yield higher than baseline.
        "hunt_yield_rate": (
            hunts_yielding_findings / hunts_conducted
            if hunts_conducted > 0 else 0
        ),

        # Actionable intelligence ratio: IOCs with a match / total IOCs ingested.
        # A ratio below 0.001 (0.1%) suggests the feed is not suited to your environment.
        "actionable_ratio": iocs_matched_in_traffic / iocs_ingested if iocs_ingested > 0 else 0,
    }
```

### Step 9: Telemetry

```
threat_intel_iocs_ingested_total{source, type}           counter
threat_intel_iocs_active_total{type}                     gauge
threat_intel_ioc_matches_total{type, outcome}            counter  # outcome: confirmed, fp, unknown
threat_intel_feed_last_update_timestamp{source}          gauge
threat_intel_ioc_precision_ratio{source}                 gauge
threat_intel_detections_linked_total{}                   counter
threat_intel_hunts_conducted_total{}                     counter
threat_intel_hunts_with_findings_total{}                 counter
threat_intel_actor_profiles_tracked_total{}              gauge
```

Alert on:

- `threat_intel_feed_last_update_timestamp` older than `2 * refresh_interval` — a feed has stopped updating; investigate source availability.
- `threat_intel_ioc_precision_ratio{source}` < 0.5 — more than half of IOC matches from this source are false positives; suspend feed and review.
- `threat_intel_ioc_matches_total{outcome="confirmed"}` = 0 for 30 days — a feed has produced no confirmed detections; evaluate relevance to your environment.
- `threat_intel_iocs_active_total{type="ip"}` growing without bound — indicator expiry is not functioning; stale IOCs accumulating.

## Expected Behaviour

| Signal | No programme | Mature programme |
|--------|-------------|------------------|
| New threat actor targeting your sector | Unknown until incident | ISAC feed triggers actor profile update; detection rules reviewed within 48h |
| CISA KEV vulnerability disclosed | Treated as any other CVE | Automatically P0 priority; patch SLA 24h; on-call paged |
| Malicious IP in firewall logs | Alert may or may not fire | IOC matched in SIEM; alert fires with threat context including actor and campaign |
| Novel phishing campaign in sector | Unknown until internal victim | ISAC sharing provides early warning; email gateway rules updated pre-arrival |
| Commodity malware hash | Hash may not be in EDR | MISP feed provides hash within hours of public disclosure; EDR and SIEM updated |
| Threat hunt request | Ad-hoc; no direction | ATT&CK gap analysis identifies highest-value hunt hypotheses |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Self-hosted MISP | Full control; no data sharing with third party | Operational overhead; feed management burden | Use Docker deployment; automate feed fetches via cron |
| High-volume free feeds (OTX) | Broad coverage; no cost | High false positive rate; stale indicators | Filter by `to_ids=true`; enforce `enforceWarninglist`; set 30-day expiry |
| TTP-based Sigma rules | Actor-agnostic; durable against infrastructure rotation | More complex to develop; higher false positive risk | Tune with local context; test in detection-as-code pipeline before production |
| IOC expiry (30-day default) | Reduces stale-indicator false positives | May miss long-lived infrastructure | Adjust per IOC type: IPs 14d, domains 30d, hashes 90d |
| ISAC membership | High-quality sector-specific intelligence | Membership cost; requires reciprocal sharing | Start with free government-affiliated ISACs; join paid ISAC as programme matures |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Feed stops updating | IOCs stale; new campaigns undetected | `feed_last_update_timestamp` alert | Investigate source; switch to backup feed; open support ticket |
| IOC precision collapses | Alert fatigue; analysts stop investigating | `ioc_precision_ratio` < 0.5 | Suspend low-precision source; enable warninglist filtering; review ingestion pipeline |
| No TTP coverage for tracked actors | ATT&CK gap analysis shows blind spots | Quarterly gap review | Develop or adopt Sigma rules for uncovered techniques |
| Stale indicators not expired | Growing false positive rate | `iocs_active_total` grows unbounded | Enable MISP decay model; set `ioc_expiration_duration` in Filebeat |
| Intelligence not reaching consumers | Detections not intel-driven | `intel_driven_detection_pct` < 10% | Review dissemination process; automate SIEM lookup table updates |
| No feedback from SOC | Feed quality invisible; no improvement | Analyst escalation rate = 0 | Implement structured feedback form; hold monthly intel-SOC review |

## Related Articles

- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
- [Security Metrics Program](/articles/cross-cutting/security-metrics-program/)
- [Penetration Testing Methodology](/articles/cross-cutting/penetration-testing-methodology/)
- [Incident Response Hardening Playbook](/articles/cross-cutting/incident-response-hardening-playbook/)
- [Suricata IDS/IPS Deployment](/articles/network/suricata-ids-ips/)
