---
title: "User Behavior Analytics: Detecting Insider Threats and Compromised Accounts"
description: "Signature-based detection misses insider threats and compromised credentials entirely. UBA builds behavioral baselines per user and entity, then surfaces deviations — off-hours access, bulk downloads, impossible travel — as risk scores that trigger investigation before damage is done."
slug: user-behavior-analytics
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - uba
  - insider-threat
  - anomaly-detection
  - siem
  - behavioral-analytics
personas:
  - security-engineer
  - security-analyst
article_number: 544
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/user-behavior-analytics/
---

# User Behavior Analytics: Detecting Insider Threats and Compromised Accounts

## Problem

A disgruntled employee copies 40,000 customer records to a personal drive the week before their resignation. A phishing campaign yields valid credentials for a finance analyst; the attacker logs in from Bucharest at 2 AM and starts querying invoice exports. Neither event contains a single known-bad indicator. No malware hash, no CVE, no blocked IP. Signature-based SIEM rules produce zero alerts.

User Behavior Analytics (UBA) — also called UEBA when extended to non-human entities — addresses this blind spot by building statistical baselines of normal activity per user and per entity (workstation, service account, API key), then generating risk scores when observed behavior deviates significantly from that baseline. The approach is effective precisely because it does not depend on knowing what "bad" looks like: it only requires knowing what "normal" looks like.

The specific threat classes UBA targets:

- **Malicious insiders.** Employees, contractors, or partners who intentionally exfiltrate data, sabotage systems, or conduct fraud using legitimate access they already hold. Traditional controls (firewall, antivirus, DLP keyword rules) are blind to activity that stays within authorized channels.
- **Unintentional insiders.** Employees who violate policy without malicious intent — sharing credentials, misconfiguring storage permissions, using personal cloud sync on corporate data. The damage is real even when the intent is benign.
- **Compromised accounts.** External attackers operating with stolen credentials. The account holder is innocent; the behavior is foreign. Deviations from the account owner's baseline (login time, location, access pattern, data volume) are the only reliable signal.
- **Credential sharing.** Multiple people using a single account produces a blended behavioral profile that deviates from any individual's baseline, particularly when logins overlap geographically or temporally.

## Threat Model

**Adversary:** An attacker or malicious insider who holds valid credentials and operates entirely within authorized access controls. They will not trigger firewall blocks, antivirus alerts, or failed-login thresholds (after initial access). Their goal is data exfiltration, financial fraud, or system sabotage.

**Blast radius without UBA:** The attacker operates undetected until an external indicator surfaces — a fraud complaint, a data breach notification from a downstream partner, a tip, or a file integrity alert on a final-stage target. Mean time to detect (MTTD) for insider threats without behavioral analytics typically exceeds 85 days.

**Detection capability with UBA:** Anomalous behavior deviations appear in risk scores within the first session or within hours of credential compromise, depending on how severe the deviation is from established baselines. High-confidence signals like impossible travel surface immediately; subtler signals like gradual access creep accumulate over days and cross a threshold.

## Data Sources

UBA effectiveness is proportional to the richness of its input data. Priority sources, in order of signal density:

| Source | Key fields | UBA signal |
|---|---|---|
| Authentication logs (AD, Okta, Azure AD, SSH) | user, timestamp, source IP, MFA result, device, success/failure | Login time, location, device fingerprint, failure patterns |
| File access logs (CIFS/NFS audit, SharePoint, S3 access logs) | user, object path, operation, bytes transferred | Volume, sensitivity tier, new-resource access |
| Network flow (NetFlow, VPC flow logs, firewall logs) | src IP, dst IP/port, bytes, protocol | Exfiltration volume, new outbound destinations |
| Application logs (ERP, CRM, HRIS, source control) | user, action, record ID, query scope | Bulk queries, administrative actions, privileged operations |
| Endpoint telemetry (EDR, Sysmon, auditd) | process, file path, USB events, clipboard | Local data staging, removable media, screen capture |
| HR feed (employment status, role, department, termination date) | user, status, manager, access tier | Pre-departure risk amplification, role-change context |

The HR feed is under-utilized but high-value. Feeding termination dates and resignation events into UBA allows the system to automatically raise the risk multiplier on departing employees, who represent a disproportionate share of insider data theft.

## Elastic Security UEBA

[Elastic Security](https://www.elastic.co/security) includes a built-in UEBA capability under **Entity Analytics**. It ingests authentication and user activity data, builds per-entity baselines using machine learning jobs, and exposes a risk score timeline for each user and host.

### Enabling Entity Analytics

```yaml
# kibana.yml — enable entity analytics features
xpack.securitySolution.enableExperimental:
  - "riskScoringRoutesEnabled"
  - "entityAnalyticsEnabled"
```

Entity risk scoring requires data views covering authentication (`logs-*`, `auditbeat-*`) and endpoint telemetry. The default scoring period is 30 days.

### Built-in ML Job Groups

Elastic ships a set of pre-built ML jobs organized into groups. The `security_auth` group is the starting point for UBA:

```bash
# List available ML job groups via the Kibana Dev Console
GET _ml/anomaly_detectors?groups=security_auth

# Key jobs in this group:
# auth_high_count_logon_events           — unusual login volume for a user
# auth_rare_source_ip_for_a_user         — login from an IP not seen before
# auth_unusual_hour_for_a_user           — login at an unusual time of day
# auth_unusual_count_of_authentication_events — spike vs. 30-day rolling baseline
```

Enable the full suite:

```bash
PUT _ml/anomaly_detectors/auth_rare_source_ip_for_a_user/_open
PUT _ml/anomaly_detectors/auth_unusual_hour_for_a_user/_open

# Start the datafeed (the datafeed queries Elasticsearch on a schedule)
POST _ml/datafeeds/datafeed-auth_rare_source_ip_for_a_user/_start
POST _ml/datafeeds/datafeed-auth_unusual_hour_for_a_user/_start
```

Each job requires a minimum of two weeks of data before anomaly scores stabilize. Elastic automatically applies seasonal decomposition to account for weekly patterns (weekday vs. weekend access volumes differ by up to 80% for office workers), preventing excessive false positives on Monday mornings.

### Risk Score Aggregation

Elastic aggregates anomaly scores from individual ML jobs into a **user risk score** that rolls up all signals:

```bash
# Retrieve current risk scores for top risky users
GET .entity-risk-score-latest-default/_search
{
  "size": 10,
  "sort": [{ "user.risk.calculated_score_norm": { "order": "desc" } }],
  "_source": ["user.name", "user.risk.calculated_score_norm", "user.risk.level", "@timestamp"]
}
```

Risk level thresholds (configurable):
- **Critical:** ≥ 90 — immediate investigation required
- **High:** 70–89 — analyst review within 4 hours
- **Medium:** 40–69 — review within 24 hours
- **Low:** < 40 — monitor, no immediate action

## Key UBA Use Cases

### Off-Hours Access Anomalies

The baseline for each user includes a distribution of login timestamps. An analyst who always logs in between 08:00 and 18:30 local time generating an authenticated session at 02:15 is a high-confidence anomaly. Combined with access to sensitive resources, this pattern covers the majority of compromised credential attacks from foreign time zones.

Elastic ML job `auth_unusual_hour_for_a_user` models this using a time-of-day distribution per user. An anomaly score above 75 on this job alone warrants investigation.

### Bulk File Downloads

Normal file access has a characteristic distribution: users open and modify a manageable set of documents in a session. An exfiltration event looks different — hundreds or thousands of reads in a short window, often to files outside the user's normal working set.

Detection with an Elasticsearch transform:

```json
PUT _transform/uba_bulk_download_detector
{
  "source": {
    "index": ["logs-*"],
    "query": {
      "bool": {
        "filter": [
          { "term": { "event.category": "file" } },
          { "term": { "event.action": "open" } }
        ]
      }
    }
  },
  "pivot": {
    "group_by": {
      "user.name": { "terms": { "field": "user.name" } },
      "session_hour": {
        "date_histogram": { "field": "@timestamp", "fixed_interval": "1h" }
      }
    },
    "aggregations": {
      "file_open_count": { "value_count": { "field": "file.path" } },
      "unique_directories": { "cardinality": { "field": "file.directory" } },
      "bytes_transferred": { "sum": { "field": "file.size" } }
    }
  },
  "dest": { "index": "uba-bulk-download-hourly" },
  "sync": { "time": { "field": "@timestamp", "delay": "60s" } }
}
```

Alert when `file_open_count` in any one-hour window exceeds 3 standard deviations above the user's 30-day mean.

### Access to New Sensitive Resources

Users develop access patterns over months. They access the same project folders, the same database schemas, the same dashboards. First-time access to a resource classified as sensitive (PII tier, financial tier, source code) — especially combined with other anomaly signals — is a strong indicator of data collection behavior.

The `auth_rare_source_ip_for_a_user` ML job in Elastic models source IP rarity. An equivalent pattern applies to file paths and database tables: resources never accessed in the prior 60 days carry a high rarity score.

### Geographic Anomalies (Impossible Travel)

If a user authenticates successfully from London at 09:00 and from São Paulo at 09:45, one of the two sessions cannot be the legitimate account holder. This "impossible travel" detection is one of the highest-precision UBA signals with a near-zero false positive rate (only VPN and split-tunneling cause false positives).

Detection query using Elasticsearch scripted metric aggregation:

```json
GET logs-*/_search
{
  "size": 0,
  "aggs": {
    "by_user": {
      "terms": { "field": "user.name", "size": 1000 },
      "aggs": {
        "impossible_travel": {
          "scripted_metric": {
            "init_script": "state.events = []",
            "map_script": """
              if (doc['source.geo.location'].size() > 0 && doc['@timestamp'].size() > 0) {
                state.events.add([
                  'ts': doc['@timestamp'].value.toInstant().toEpochMilli(),
                  'lat': doc['source.geo.location'].lat,
                  'lon': doc['source.geo.location'].lon
                ])
              }
            """,
            "combine_script": "return state.events",
            "reduce_script": """
              def all = [];
              for (s in states) { all.addAll(s) }
              all.sort((a,b) -> Long.compare(a.ts, b.ts));
              def MAX_SPEED_KMH = 900;
              def violations = [];
              for (int i = 1; i < all.size(); i++) {
                def prev = all[i-1]; def curr = all[i];
                def dt_hours = (curr.ts - prev.ts) / 3600000.0;
                if (dt_hours < 2) {
                  def dlat = curr.lat - prev.lat;
                  def dlon = curr.lon - prev.lon;
                  def dist_km = Math.sqrt(dlat*dlat + dlon*dlon) * 111;
                  if (dt_hours > 0 && dist_km / dt_hours > MAX_SPEED_KMH) {
                    violations.add([prev: prev, curr: curr, speed_kmh: dist_km / dt_hours])
                  }
                }
              }
              return violations
            """
          }
        }
      }
    }
  }
}
```

### Privilege Escalation Patterns

Legitimate users rarely need to escalate privileges outside of predefined change windows. Sequences of: normal login → access to admin interface → `sudo` or `RunAs` invocation → access to credential stores represent a kill chain pattern even when each individual step is "authorized."

UBA models this as a sequence anomaly — the combination of events within a session window is rare even if each event in isolation is not. Elastic's [Sequence detection](https://www.elastic.co/guide/en/security/current/rules-ui-create.html) in Security rules (EQL sequences) covers this:

```
sequence by user.name with maxspan=30m
  [authentication where event.outcome == "success"]
  [process where process.name in ("sudo", "su", "runas.exe")]
  [file where file.path : ("*/etc/shadow", "*/etc/passwd", "*\\SAM", "*\\NTDS.dit")]
```

## Building UBA Without a Commercial Tool

Organizations without Elastic Security Platinum or a dedicated UEBA platform can implement meaningful behavioral detection using Elasticsearch aggregations and transforms, or Splunk SPL.

### Elasticsearch Aggregation-Based Anomaly Detection

The core pattern is a **baseline transform** that runs continuously and a **comparison query** that runs on a schedule to detect deviations:

```json
PUT _transform/uba_user_daily_baseline
{
  "source": { "index": ["auditbeat-*", "filebeat-*"] },
  "pivot": {
    "group_by": {
      "user.name": { "terms": { "field": "user.name" } },
      "day_of_week": {
        "terms": {
          "script": "doc['@timestamp'].value.dayOfWeekEnum.getValue()"
        }
      }
    },
    "aggregations": {
      "avg_logins_per_day": { "avg": { "field": "event.id" } },
      "avg_files_accessed": { "avg": { "field": "file.inode" } },
      "typical_src_ips": { "cardinality": { "field": "source.ip" } }
    }
  },
  "dest": { "index": "uba-baseline-by-user-dow" },
  "frequency": "1h",
  "sync": { "time": { "field": "@timestamp", "delay": "10m" } }
}
```

Compare today's activity against the baseline for the same day-of-week using a scheduled Watcher alert:

```json
PUT _watcher/watch/uba_login_anomaly
{
  "trigger": { "schedule": { "interval": "1h" } },
  "input": {
    "search": {
      "request": {
        "indices": ["auditbeat-*"],
        "body": {
          "size": 0,
          "aggs": {
            "by_user": {
              "terms": { "field": "user.name", "size": 500 },
              "aggs": {
                "logins_today": {
                  "filter": { "range": { "@timestamp": { "gte": "now-24h" } } }
                }
              }
            }
          }
        }
      }
    }
  },
  "condition": {
    "script": {
      "source": """
        for (bucket in ctx.payload.aggregations.by_user.buckets) {
          if (bucket.logins_today.doc_count > 50) return true;
        }
        return false;
      """
    }
  },
  "actions": {
    "notify_siem": {
      "webhook": {
        "method": "POST",
        "url": "https://siem.internal/api/alerts",
        "body": "{{ctx.payload}}"
      }
    }
  }
}
```

### Splunk UBA Essentials

For teams on Splunk without the full UBA add-on, the `tstats` command with `eventstats` enables peer group comparisons:

```spl
| tstats count as file_opens
    where index=wineventlog EventCode=4663
    by _time span=1h user file_path
| eventstats avg(file_opens) as peer_avg stdev(file_opens) as peer_stdev by user
| eval zscore = (file_opens - peer_avg) / peer_stdev
| where zscore > 3
| table _time user file_opens peer_avg zscore
| sort -zscore
```

The `eventstats` command computes the per-user average and standard deviation over the search window, then `zscore` measures how far today's hour deviates. Values above 3 represent events outside 99.7% of the user's normal distribution.

## Peer Group Analysis

Individual baselines alone produce alerts when a user's role legitimately changes — a developer promoted to tech lead will suddenly access more repositories, which looks like an anomaly against their own prior baseline. Peer group analysis addresses this by comparing users to colleagues with similar roles, departments, and access tiers.

The principle: if 95% of senior engineers in the infosec team access the secrets management UI between 1 and 10 times per week, and one user accesses it 340 times in a week, that is anomalous relative to peers even if that user's own access history is sparse.

Implementation requires enriching events with HR attributes (department, job level, manager) at ingest time:

```json
PUT _enrich/policy/user-enrichment
{
  "match": {
    "indices": "hr-user-directory",
    "match_field": "user.name",
    "enrich_fields": ["department", "job_level", "employment_status", "manager"]
  }
}

POST _enrich/policy/user-enrichment/_execute
```

Then add the enrich processor to the ingest pipeline and build baselines grouped by `department` and `job_level` rather than by individual user.

## Risk Score Aggregation Across Weak Signals

No single UBA signal is definitive. The value of a risk scoring architecture is that it can aggregate multiple weak signals — each insufficient on its own — into a composite score that crosses an investigation threshold.

A practical scoring model:

| Signal | Base score | Multipliers |
|---|---|---|
| Off-hours login | 15 | ×2 if from new IP, ×3 if combined with file access |
| New sensitive resource access | 20 | ×2 if bulk (>100 objects), ×3 if departing employee |
| Impossible travel | 60 | ×1.5 if MFA bypassed |
| Bulk download (>3σ) | 35 | ×2 if external destination |
| Privilege escalation sequence | 45 | ×2 if outside change window |
| Peer group outlier (>3σ) | 25 | ×1.5 if new to role |

Scores decay over time if no new signals arrive (typical half-life: 72 hours), preventing stale anomalies from permanently tainting a user's risk profile.

## Investigation Workflow

When a user risk score crosses the Critical threshold (≥ 90), the following workflow ensures consistent, evidence-preserving triage.

**Step 1 — Context pull (< 5 minutes).** Before contacting the user or their manager, gather context. What is the user's role? Are they on a termination or PIP? Have they raised IT tickets recently? Is their manager flagged for a reorg? HR context eliminates a large fraction of false positives without touching the user.

**Step 2 — Session reconstruction.** Pull all authentication events for the user in the preceding 72 hours. Identify the specific session that triggered the high-score signals. Map source IPs to geolocation. Identify the exact resources accessed.

```bash
# Elasticsearch — reconstruct a user's session timeline
curl -s -X GET "https://es.internal:9200/auditbeat-*/_search" \
  -H 'Content-Type: application/json' -d '{
  "query": {
    "bool": {
      "filter": [
        { "term": { "user.name": "jsmith" } },
        { "range": { "@timestamp": { "gte": "now-72h" } } }
      ]
    }
  },
  "sort": [{ "@timestamp": { "order": "asc" } }],
  "size": 1000,
  "_source": ["@timestamp", "event.action", "source.ip", "source.geo.country_name",
              "file.path", "process.name", "user.name"]
}'
```

**Step 3 — Evidence preservation.** Before taking any action that might alert the subject, preserve log data. Mark relevant indices as frozen or export to immutable storage. If this may become a legal matter, involve counsel before interviewing the employee.

**Step 4 — Lateral validation.** Check whether any of the accessed resources show downstream anomalies — files modified, data exported, configurations changed. A user who viewed 500 records without exporting any is a very different investigation than one who exported them to an external S3 bucket.

**Step 5 — Disposition.** Outcomes: (a) confirmed false positive — adjust model weighting to reduce noise for this user class; (b) policy violation — HR escalation; (c) confirmed malicious insider — HR and legal; (d) compromised account — force credential reset, revoke all active sessions, begin IR process for the adversary's access scope.

```bash
# Force Okta session revocation for a compromised account
curl -s -X DELETE "https://yourorg.okta.com/api/v1/users/USER_ID/sessions" \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}"

# Revoke all OAuth tokens
curl -s -X POST "https://yourorg.okta.com/api/v1/users/USER_ID/lifecycle/expire_password" \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}"
```

## Baseline Stability and Tuning

New UBA deployments need a minimum four-week warm-up period before anomaly scores are reliable. During this period, suppress alerts or lower their priority. Track the false positive rate weekly — a well-tuned deployment targeting insider threats should achieve a precision above 40% (meaning fewer than 6 in 10 high-score alerts are false positives) within 90 days.

Key tuning levers:
- **Seasonal adjustment.** Monthly payroll runs, quarterly financial closes, and annual audits create legitimate spikes in access to financial systems. Tag these calendar events and suppress or adjust thresholds accordingly.
- **Role-change grace periods.** When HR data shows a role change, reset the individual baseline and apply the peer group baseline exclusively for 30 days.
- **Service account separation.** Ensure service accounts are modeled separately from human users. A deployment pipeline that runs 10,000 file operations per night is not an anomaly, but it will contaminate human-user baselines if mixed.
- **Feedback loops.** Every confirmed false positive and true positive should feed back into model weights. Elastic Security supports analyst feedback on alert dispositions through the Case Management workflow, which can be exported to retrain ML jobs.

## Summary

UBA addresses the detection gap that signature-based tools cannot close: legitimate credentials used in illegitimate ways. The core components are multi-source data collection (auth, file, network, HR), per-entity behavioral baselines with seasonal adjustment, rule-based anomaly patterns for high-precision signals (impossible travel, bulk downloads), and risk score aggregation across weak signals. Elastic Security provides a production-ready implementation path with built-in ML job groups and entity risk scoring. Organizations without a commercial platform can build equivalent coverage using Elasticsearch transforms and Watcher, or Splunk SPL with peer group statistics. The investigation workflow — context pull, session reconstruction, evidence preservation, lateral validation, disposition — ensures that high-score alerts are handled consistently and that genuine incidents are contained before significant damage occurs.
