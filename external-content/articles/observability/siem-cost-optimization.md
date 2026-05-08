---
title: "SIEM Cost Optimization: Cardinality, Retention, Sampling, and Index-Tier Strategy"
description: "SIEM bills double yearly because nobody owns the spend. Cardinality control, retention tiering, and sampling reduce cost 40-70% without losing detection."
slug: "siem-cost-optimization"
date: 2026-04-27
lastmod: 2026-04-27
category: "observability"
tags: ["siem", "splunk", "elastic", "cost-optimization", "observability"]
personas: ["security-engineer", "sre", "soc-analyst"]
article_number: 205
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/observability/siem-cost-optimization/index.html"
---

# SIEM Cost Optimization: Cardinality, Retention, Sampling, and Index-Tier Strategy

## Problem

SIEM bills follow a predictable trajectory: a vendor-pitched price quote at signing; a 2x increase the following year because "log volume grew"; a 4x increase the year after when retention requirements shift. By year three, the security organization is fighting for its budget against the SIEM line item.

The drivers are mostly self-inflicted:

- **Indiscriminate forwarding.** A team adds new instrumentation; the logs flow to the SIEM at full volume even though only specific signals are needed.
- **High-cardinality fields.** A log field like `request_id` or `user_session` creates one index entry per unique value. Index storage scales with cardinality, not volume.
- **Hot retention used for everything.** Hot-tier (search-instantly) is typically 10-20x more expensive per GB than cold-tier (search-with-delay). Many SIEMs default everything to hot.
- **Detection rules over the noisiest sources.** Rules that scan every event in a high-volume index are expensive even when they fire rarely.
- **Duplicate enrichment.** The same enrichment runs at ingest, at search, and in dashboards.
- **Long retention by default.** "Just keep everything for 365 days" multiplies cost by 5-10x compared to differentiated retention.

By 2026 every major SIEM (Splunk, Elastic, Sentinel, Chronicle, Sumo Logic, Logscale, Panther) supports cost-control primitives: tiered retention, sampling, summary indexes, ingest-time filtering, dataset routing. Few teams use them well.

This article covers cardinality reduction, retention tiering, ingest-time sampling that preserves detection, summary indexes for high-volume metrics, and the operational discipline of treating SIEM-spend as a measured engineering output.

**Target systems:** Splunk Enterprise / Cloud, Elastic Stack, Microsoft Sentinel, Google Chronicle, Sumo Logic, CrowdStrike Logscale, Panther; vendor-neutral patterns with vendor-specific implementations.

## Threat Model

The "adversary" here is the structural failure mode of SIEM cost growth, with security implications:

- **Adversary 1 — Cost overrun forces dropped sources:** budget pressure makes the SOC drop or sample sources, creating detection gaps.
- **Adversary 2 — Retention budget cliff:** an incident requires 90-day forensic data; retention was 14 days because cost was too high.
- **Adversary 3 — Cardinality explosion:** a misbehaving service emits one new index entry per request; daily cost spikes 10x; emergency response prioritizes cost over detection.
- **Adversary 4 — Slow searches under load:** high index size makes detection-rule searches time out; rules run late or skip events.
- **Access level:** the failure mode is internal — over-spend leads to over-correction.
- **Objective:** an adversary observing a thrifty SIEM can move into the gaps the cost optimization created.
- **Blast radius:** detection gaps are the same as if the rule never existed. A SIEM cost program done poorly leaves the same coverage holes a real attacker exploits.

## Configuration

### Step 1: Measure Per-Source Spend

You can't optimize what you don't measure. Compute per-source bytes, events, and cost.

For Splunk:

```spl
| metadata type=hosts index=*
| stats sum(totalCount) as events, sum(totalSizeBytes)/1024/1024/1024 as gb_total
  by index, host
| eval daily_gb = gb_total / 30
| eval daily_cost = daily_gb * 4.5    // license $/GB/day
| sort - daily_cost
| head 50
```

For Elastic:

```bash
# Per-index size and document count.
curl -s 'localhost:9200/_cat/indices?v&format=json' | \
  jq 'sort_by(."store.size") | reverse | .[0:30]'
```

Build a dashboard ranking sources by cost. The top 20 sources are typically 80% of spend. Optimize them first.

### Step 2: Cardinality Audit

Identify high-cardinality fields. In Splunk:

```spl
| metasearch index=high_volume_index
| eval _time_bucket=relative_time(_time, "@h")
| stats dc(request_id) as rid_card,
        dc(user_id) as user_card,
        dc(trace_id) as trace_card,
        count
  by _time_bucket
```

A field with cardinality approaching the row count is a unique-per-event identifier. Indexing it expands the inverted-index dramatically. Don't index it by default; project to a derived field if you need partial cardinality.

For Elastic:

```bash
# See field cardinality stats.
curl -s 'localhost:9200/logs-*/_field_caps?fields=*&format=json' | \
  jq '.fields | to_entries | map(select(.value.keyword)) | length'

# For specific index, check field cardinality.
curl -s 'localhost:9200/logs-app-*/_search?size=0&q=*' \
  -H 'Content-Type: application/json' \
  -d '{
    "aggs": {
      "field_card": {
        "cardinality": {"field": "request_id.keyword"}
      }
    }
  }'
```

For each high-cardinality field, decide:

- **Drop entirely** if you never search by it.
- **Keep but don't index** — store the value in `_source` only; not searchable but visible on demand.
- **Hash to bucket** — replace `request_id` with `request_id_bucket = hash(request_id) % 1024`. Loses one-to-one searchability; preserves population statistics.

### Step 3: Tiered Retention

Differentiate retention by source. Detection-relevant: short hot, then warm. Compliance: long cold. Forensic-only: archive.

```yaml
# Example retention tiers.
audit_logs_critical:
  hot: 30d         # search-immediate
  warm: 90d        # search with seconds-to-minutes delay
  cold: 365d       # search with minutes-to-hours delay
  archive: 7y      # restore-required

application_logs:
  hot: 7d
  warm: 30d
  cold: 90d
  archive: 1y

debug_logs:
  hot: 1d
  warm: 0d
  cold: 0d
  archive: 0d
```

Splunk's index lifecycle:

```ini
# indexes.conf
[audit_logs]
homePath = $SPLUNK_DB/audit/db
coldPath = $SPLUNK_DB/audit/colddb
maxHotBuckets = 5
maxDataSize = auto_high_volume
homePath.maxDataSizeMB = 100000      # 100 GB hot
coldPath.maxDataSizeMB = 1000000     # 1 TB cold
frozenTimePeriodInSecs = 31536000    # 1 year before frozen
coldToFrozenScript = /opt/splunk/bin/move-to-archive.sh
```

The `coldToFrozenScript` moves the bucket to S3 / GCS / Azure blob storage at $0.001/GB/month — orders of magnitude cheaper than active SIEM storage.

### Step 4: Ingest-Time Sampling

Some sources have signal density too low to justify full ingestion. Sample at ingest time, with structure that preserves detection.

```yaml
# Splunk Edge Processor / Cribl pipeline example.
- type: filter
  description: "Drop 90% of HTTP 200 access logs; keep all errors and 5% of 200s"
  filter: |
    if event.status >= 400 || random() < 0.05 {
      keep
    } else {
      drop
    }

- type: aggregate
  description: "Roll up dropped 200s into per-minute summary metrics"
  by: [host, path]
  every: 60s
  emit: ["count", "sum(bytes)", "p99(latency_ms)"]
```

Detection on errors and outliers gets full fidelity. Aggregate metrics on the routine 200s replace per-event detail.

For Elastic:

```yaml
# Logstash filter for sampling.
filter {
  if [status] >= 400 {
    # Keep all errors; tag for retention.
    mutate { add_field => { "retention_tier" => "hot" } }
  } else if rand() < 0.05 {
    mutate { add_field => { "retention_tier" => "warm" } }
  } else {
    drop {}
  }
}
```

### Step 5: Summary Indexes for Detection-Already-Aggregated

Detections that scan high-volume indexes are expensive. Pre-aggregate at ingest time into a summary index that detection rules query instead.

```spl
# Daily summary of per-user activity.
index=auth_events earliest=@d-1d latest=@d
| stats count as event_count,
        dc(source_ip) as unique_ips,
        dc(user_agent) as unique_uas,
        first(event_time) as first_event,
        last(event_time) as last_event
  by user_id, hour
| collect index=auth_summary
```

Detection rule queries `auth_summary` (small index, fast searches) rather than the full `auth_events`. Storage cost for the summary is a fraction of the source.

The trade-off: rules can no longer correlate at sub-hour granularity from the summary alone. For most behavioural rules ("user X accessed N distinct IPs in the past day"), hour-bucketed aggregates suffice.

### Step 6: Cardinality Constraints in Detection Rules

Some detection rules naturally produce high-cardinality output (one row per source IP, one row per user). When these rules run continuously, the result indexes themselves become expensive.

```spl
# Bad: one row per source IP, every minute, indefinitely.
index=auth_logs status=failure
| stats count by source_ip, _time
| outputlookup auth_failures.csv

# Better: aggregated, with cardinality control.
index=auth_logs status=failure
| stats count as failures by source_ip
| where failures > 10
| outputlookup auth_failures_high.csv
```

Cap output cardinality of detection-result outputs to alerts-only or top-N.

### Step 7: Cost Allocation Per Team

Make spend visible. Per-source-team SIEM cost dashboard:

```spl
| metadata type=indexes
| eval team = case(
    match(index, "^app-payments"), "payments-team",
    match(index, "^app-auth"), "auth-team",
    match(index, "^infra-"), "platform-team",
    1=1, "shared")
| stats sum(totalSizeBytes)/1024/1024/1024 as gb_total
  by team
| eval daily_cost = gb_total / 30 * 4.5
| sort - daily_cost
```

Send the report monthly to engineering managers. Teams that own their cost figure out their own optimization.

### Step 8: Quarterly Audit

Schedule quarterly:

- **Top sources by spend.** Anyone in the top 10 needs an explanation.
- **Sources with no detection rules attached.** Why are we paying to index data nobody searches?
- **Stale rules.** Rules that haven't fired in 180 days but query expensive indexes.
- **Cardinality drift.** Fields that were OK at design and are now unique-per-event.

Each line item is an action: keep, drop, sample, route to cheaper tier, summarize.

## Expected Behaviour

| Signal | Unmanaged | Managed |
|--------|-----------|---------|
| Annual SIEM spend growth | 50-150% | <30% (matches log volume growth) |
| Hot-tier proportion | 80-100% | 20-40% |
| Detection coverage | Same | Same (or better — fewer slow searches) |
| Search latency p99 | Seconds-to-minutes | Sub-second on summary indexes |
| Cardinality of largest source | Often unbounded | Bounded by ingest-time hashing / dropping |
| Per-team cost visibility | None | Quarterly report |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Tiered retention | Massive cost reduction | Search-on-cold-data is slower | Detections run on hot tier; forensic queries on cold tier are user-facing-acceptable. |
| Ingest sampling | Cost reduction with low signal-loss | Some detection nuance lost on under-sampled sources | Keep all errors / outliers; sample only the routine baseline. |
| Summary indexes | Detection rules cheap | Detail lost at summary granularity | Keep raw data in cold tier; summary in hot. |
| Cardinality constraints | Predictable index cost | Some search patterns no longer work directly | Educate teams; provide derived-field libraries. |
| Per-team allocation | Engineering accountability | Allocation discussions can be political | Use simple, transparent rules; show per-team trend over time. |
| Quarterly audit | Continuous improvement | Engineering effort | Automate the reports; the audit is reading 5 dashboards. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Sampling drops the very events that matter | Detection rule fires less often | Rule TPR drops; correlations lost | Always keep `severity:high` and outliers unsampled. Tune the sampling logic to preserve the tail. |
| Cold-tier search timeout | User can't query for forensic data | Cold-tier search returns timeout | Cold tier should be slow but functional. If timing out, allocate more cold-tier capacity (still cheap) or move to a faster tier. |
| Cardinality explosion not caught | Daily cost spikes | Cost metric jumps; quarterly audit catches | Add cardinality alerts: per-index, per-day field-cardinality > threshold triggers Slack ping. |
| Summary index drift from raw | Detection on summary differs from detection on raw | Cross-check sample queries | Periodic backfill comparison: query raw and summary for same period; alert on divergence. |
| Retention shortened too aggressively | Compliance audit can't find required data | Audit failure | Confirm legal/compliance requirements before reducing retention; some industries (PCI, HIPAA) mandate specific minimums. |
| Per-team allocation fights | Teams game the system to reduce their numbers | Cost grows in untracked sources | Lock per-source ownership; new sources require designation. |

## Related Articles

- [Detection Engineering Metrics](/articles/observability/detection-engineering-metrics/)
- [Detection-as-Code with Sigma](/articles/observability/detection-as-code-sigma/)
- [Building a Security Audit Log Pipeline That Scales](/articles/observability/audit-log-pipeline/)
- [OpenTelemetry PII Leakage](/articles/observability/otel-pii-leakage/)
- [Centralized Logging Architecture for Security](/articles/observability/centralized-logging/)
