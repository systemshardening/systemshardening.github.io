---
title: "Advanced Security Event Correlation: EQL Sequences, Entity Graphs, and Automated Response"
description: "Single-event SIGMA rules miss multi-stage attacks where every individual event looks benign. EQL sequence detection, graph-based entity correlation, and temporal pattern analysis close this gap — turning scattered low-confidence signals into high-confidence attack-chain alerts."
slug: security-event-correlation-advanced
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - event-correlation
  - threat-detection
  - siem
  - eql
  - attack-chain
personas:
  - security-engineer
  - security-analyst
article_number: 557
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/security-event-correlation-advanced/
---

# Advanced Security Event Correlation: EQL Sequences, Entity Graphs, and Automated Response

## Problem

The attacker lands on a web server through a supply-chain dependency vulnerability. A reverse shell spawns. The attacker runs `id`, then `cat /etc/passwd`, then probes internal services. Six hours later they escalate privileges using a cached sudo token. The next morning they move laterally to a database host and begin exfiltrating credentials.

Every individual event in that sequence has a SIGMA rule match rate of zero. A developer running `cat /etc/passwd` during debugging is normal. A process opening a network connection is normal. A sudo invocation is normal. None of these events, in isolation, meets the threshold for an alert.

The sequence reveals the attack. The sequence is what most detection stacks never examine.

Single-event detection — one rule, one event, one alert — is the dominant paradigm in SIGMA, Elastic detection rules, and Splunk saved searches. It works for known-bad indicators: a process named `mimikatz.exe`, a domain that appears on a blocklist, a file hash that matches a known ransomware sample. It fails catastrophically for multi-stage attacks where the attacker uses nothing inherently suspicious — legitimate binaries, valid credentials, normal protocols — but combines them in a sequence that reveals intent.

The gaps in single-event detection:

- **No temporal context.** A rule that fires on a single process creation event has no memory of what happened on the same host in the preceding 30 minutes.
- **No entity linking.** Five alerts about the same user account across authentication, file access, and network systems look like five separate alerts. The connection — same actor, same session, coordinated activity — is invisible without explicit entity correlation.
- **Linear rule logic.** IF event matches condition THEN alert. Real attacks are not linear. They are sequences, graphs, and chains of causally related events.
- **Alert fatigue from partial signals.** Low-confidence individual signals either miss attacks (threshold too high) or generate overwhelming noise (threshold too low). There is no middle ground in single-event detection.

This article covers Elastic EQL sequence detection with `maxspan` constraints, anti-join patterns for detecting absence of expected events, Splunk's `transaction` command for multi-event grouping, building a graph-based correlation engine in Python with NetworkX, temporal correlation patterns including sliding windows and long-dwell detection, incremental rule development strategy, and SOAR integration for automated enrichment and response on correlated alerts.

**Target systems:** Elastic Security with EQL (Event Query Language), Splunk Enterprise Security, Python 3.11+ with NetworkX 3.x and Redis for state management.

## Threat Model

**Adversary:** A post-initial-access attacker operating with valid credentials and legitimate tooling ("living off the land"). They produce no known-bad indicators individually. Their attack chain spans multiple systems and hours or days of elapsed time.

**Blast radius without sequence correlation:** The attacker reaches their objective (credential theft, data exfiltration, ransomware deployment) before any detection fires. Dwell time for these attacks averages 14-21 days. With sequence correlation, the attack chain generates a high-confidence alert at the second or third stage — typically within 30-60 minutes of initial access.

**Secondary concern:** Alert fatigue exploitation. An adversary aware of your detection thresholds deliberately generates events that trigger single-signal alerts, burying real signal in noise. Sequence detection with risk aggregation addresses this: the threshold is not "any suspicious event" but "this specific combination in this order within this timeframe."

## Configuration

### Part 1: Elastic EQL for Sequence Detection

Elastic's [Event Query Language (EQL)](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) is purpose-built for sequence detection. Unlike KQL or Lucene, EQL understands sequences, temporal ordering, and correlation across events in a single query.

#### Basic Sequence Syntax

A sequence query in EQL requires events to occur in order, on the same entity, within a time window:

```eql
sequence by host.name with maxspan=30m
  [process where process.name == "cmd.exe" and event.type == "start"]
  [process where process.args : ("whoami", "net user", "ipconfig", "systeminfo")]
  [network where network.direction == "egress" and destination.port != 443]
```

The `by host.name` clause links events to the same entity. The `maxspan=30m` resets if the first event in the sequence is older than 30 minutes when the third event is observed. The three events must occur in the stated order — not just within the window, but sequentially.

#### Detecting the Initial Access to Lateral Movement Chain

The canonical multi-stage attack: initial access via a web shell, internal reconnaissance, credential access, then lateral movement to a second host.

```eql
sequence by user.name with maxspan=4h
  /* Stage 1: Initial access — shell spawned from a web server process */
  [process where event.type == "start"
    and process.parent.name in ("nginx", "apache2", "httpd", "tomcat", "java")
    and process.name in ("bash", "sh", "cmd.exe", "powershell.exe")]

  /* Stage 2: Reconnaissance — enumeration commands within the session */
  [process where event.type == "start"
    and process.name in ("id", "whoami", "hostname", "uname", "net.exe", "ipconfig.exe")
    and process.parent.name in ("bash", "sh", "cmd.exe", "powershell.exe")]

  /* Stage 3: Credential access — reading shadow file or LSASS interaction */
  [any where
    (file.path : ("/etc/shadow", "/etc/passwd", "*/SAM", "*/NTDS.dit"))
    or
    (process.name == "lsass.exe" and process.pe.original_file_name == "lsass.exe"
     and event.action == "accessed")]

  /* Stage 4: Lateral movement — connection to an internal host on admin ports */
  [network where network.direction == "egress"
    and destination.port in (22, 445, 3389, 5985, 5986)
    and not destination.ip : ("127.0.0.0/8", "::1")]
```

This query fires only when all four stages occur on the same user within four hours, in order. A developer who runs `id` and then opens a network connection does not match — they do not go through the web-shell parent process. The combination of all four stages has a near-zero false positive rate.

#### EQL Anti-Joins: Detecting Absence of Expected Events

Anti-joins detect cases where a suspicious sequence occurs *without* the defensive response that should follow. This catches attackers who disable logging, stop EDR agents, or clear audit trails before operating.

```eql
sequence by host.name with maxspan=10m
  /* A process that looks like defense evasion */
  [process where process.name in ("net.exe", "sc.exe", "wmic.exe")
    and process.args : ("stop", "delete", "disable")
    and process.args : ("*defender*", "*sense*", "*splunk*", "*sysmon*", "*audit*")]

  /* Followed by a sensitive file access... */
  [file where file.path : ("*/etc/shadow", "*\\SAM", "*\\NTDS.dit")]

  /* ...but NOT preceded by an authorized maintenance window ticket */
  ![ process where process.name == "maintenance-wrapper.exe"
     and process.args : "--authorized" ]
```

The `![...]` syntax is an EQL anti-join: the sequence only matches if that event did NOT occur within the window and correlation key. Pair this with a maintenance-window registration system that writes authorized events to the log stream to suppress false positives during legitimate maintenance.

#### Using `any where` for Cross-Source Correlation

EQL's `any where` clause matches events regardless of their type, enabling correlation across event categories:

```eql
sequence by source.ip with maxspan=5m
  [authentication where event.outcome == "failure"] with runs=5
  [authentication where event.outcome == "success"]
  [any where event.category in ("network", "file", "process")]
```

The `with runs=5` modifier requires the authentication failure event to match five times before the sequence continues. This detects brute-force login followed by successful access followed by any subsequent activity — all from the same source IP.

### Part 2: Splunk Transaction Command for Multi-Event Correlation

For Splunk environments, the `transaction` command groups raw events into logical sessions or attack sequences.

#### Basic Transaction Grouping

```spl
index=windows_security EventCode IN (4624, 4625, 4648, 4672, 4688, 4698)
| transaction host startswith="EventCode=4624" endswith="EventCode=4698"
    maxspan=2h maxpause=30m keepevicted=true
| where eventcount >= 3
| eval attack_stages=mvcount(EventCode)
| stats values(EventCode) as stages, count, max(_time) as last_seen by host
| where attack_stages >= 3
```

The `transaction` command groups events on the same host that start with a successful login (4624) and end with a scheduled task creation (4698 — common persistence mechanism). Events within a 30-minute pause gap and a 2-hour total window are grouped into one transaction. Transactions with 3+ distinct event codes represent multi-stage activity.

#### Detecting Kerberoasting Followed by Privilege Use

```spl
(index=windows_security EventCode=4769 ServiceName!="krbtgt" TicketEncryptionType=0x17)
OR (index=windows_security EventCode=4672 SubjectUserName!="SYSTEM")
| transaction SubjectUserName maxspan=6h
| where mvcount(EventCode) >= 2
  AND mvfind(EventCode, "4769") >= 0
  AND mvfind(EventCode, "4672") >= 0
| eval correlation_confidence="HIGH"
| table _time SubjectUserName correlation_confidence EventCode host
```

Event 4769 with encryption type 0x17 (RC4) is the Kerberoasting indicator. Event 4672 is special privileges assigned to a new logon — a privilege escalation marker. Together on the same account within 6 hours is a high-confidence Kerberoasting-to-privilege-escalation chain.

### Part 3: Graph-Based Correlation with NetworkX

For teams running custom correlation logic outside a SIEM — or augmenting SIEM output — a graph-based approach models the attack surface as a property graph where nodes are entities (users, hosts, IPs, processes) and edges are events with timestamps and weights.

#### Building the Entity Graph

```python
# correlation_engine.py
import networkx as nx
import redis
import json
import pickle
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str          # "auth", "process", "network", "file"
    source_entity: str       # "user:jsmith", "host:db-01", "ip:10.0.1.45"
    target_entity: str
    attributes: dict
    severity: int            # 1-10

class EntityCorrelationGraph:
    def __init__(self, redis_client: redis.Redis, decay_hours: int = 24):
        self.graph = nx.MultiDiGraph()
        self.redis = redis_client
        self.decay_hours = decay_hours
        self._load_persisted_graph()

    def ingest_event(self, event: SecurityEvent) -> list[dict]:
        """Add an event edge to the graph and return newly triggered correlations."""
        # Add or update nodes.
        for entity in (event.source_entity, event.target_entity):
            if not self.graph.has_node(entity):
                entity_type, entity_id = entity.split(":", 1)
                self.graph.add_node(entity,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    risk_score=0)
            else:
                self.graph.nodes[entity]["last_seen"] = event.timestamp

        # Add event edge.
        self.graph.add_edge(
            event.source_entity,
            event.target_entity,
            timestamp=event.timestamp.isoformat(),
            event_type=event.event_type,
            severity=event.severity,
            attributes=event.attributes
        )

        # Propagate risk scores.
        self._propagate_risk(event)

        # Check correlation patterns.
        correlations = self._check_patterns(event)

        # Persist graph state.
        self._persist_graph()

        return correlations

    def _propagate_risk(self, event: SecurityEvent):
        """Increase risk score on both entities; decay old scores."""
        now = event.timestamp
        for entity in (event.source_entity, event.target_entity):
            node = self.graph.nodes[entity]
            # Decay existing score by half-life.
            if "last_scored" in node:
                hours_elapsed = (now - node["last_scored"]).total_seconds() / 3600
                decay_factor = 0.5 ** (hours_elapsed / self.decay_hours)
                node["risk_score"] = node["risk_score"] * decay_factor
            # Add new event contribution.
            node["risk_score"] += event.severity
            node["last_scored"] = now

    def _check_patterns(self, event: SecurityEvent) -> list[dict]:
        correlations = []

        # Pattern 1: A user entity involved in both auth and process events
        # within a 30-minute window — possible session-linked activity.
        user_entity = event.source_entity
        if user_entity.startswith("user:"):
            correlations.extend(
                self._check_lateral_movement_pattern(user_entity, event.timestamp)
            )

        # Pattern 2: A host entity that is both a target of auth events
        # and a source of outbound network events within 60 minutes.
        if event.target_entity.startswith("host:"):
            correlations.extend(
                self._check_pivoting_pattern(event.target_entity, event.timestamp)
            )

        # Pattern 3: High aggregate risk on any single entity.
        for entity in (event.source_entity, event.target_entity):
            score = self.graph.nodes[entity].get("risk_score", 0)
            if score >= 50:
                correlations.append({
                    "correlation_type": "high_entity_risk",
                    "entity": entity,
                    "risk_score": score,
                    "timestamp": event.timestamp.isoformat(),
                    "confidence": "medium" if score < 80 else "high"
                })

        return correlations

    def _check_lateral_movement_pattern(self,
                                         user_entity: str,
                                         now: datetime) -> list[dict]:
        """Detect: same user — auth success on host A, then process + network on host B."""
        window = timedelta(hours=1)
        recent_edges = [
            (u, v, d) for u, v, d in self.graph.edges(data=True)
            if (u == user_entity or v == user_entity)
            and datetime.fromisoformat(d["timestamp"]) > now - window
        ]
        auth_hosts = {v.split(":")[1] for u, v, d in recent_edges
                      if d["event_type"] == "auth" and d.get("attributes", {}).get("outcome") == "success"}
        process_hosts = {v.split(":")[1] for u, v, d in recent_edges
                         if d["event_type"] == "process"}
        # Alert if the user has process activity on a different host
        # than where they authenticated — cross-host session.
        pivot_hosts = process_hosts - auth_hosts
        if auth_hosts and pivot_hosts:
            return [{
                "correlation_type": "lateral_movement_sequence",
                "user": user_entity,
                "auth_hosts": list(auth_hosts),
                "pivot_hosts": list(pivot_hosts),
                "timestamp": now.isoformat(),
                "confidence": "high"
            }]
        return []

    def _check_pivoting_pattern(self, host_entity: str, now: datetime) -> list[dict]:
        """Detect: host received auth, then initiated outbound network within 60 min."""
        window = timedelta(hours=1)
        recent_edges = [
            (u, v, d) for u, v, d in self.graph.edges(data=True)
            if (u == host_entity or v == host_entity)
            and datetime.fromisoformat(d["timestamp"]) > now - window
        ]
        received_auth = any(
            d["event_type"] == "auth" and v == host_entity
            for u, v, d in recent_edges
        )
        initiated_network = any(
            d["event_type"] == "network" and u == host_entity
            for u, v, d in recent_edges
        )
        if received_auth and initiated_network:
            return [{
                "correlation_type": "auth_then_pivot",
                "host": host_entity,
                "timestamp": now.isoformat(),
                "confidence": "medium"
            }]
        return []

    def get_attack_subgraph(self, entity: str, depth: int = 2) -> nx.MultiDiGraph:
        """Extract the local subgraph around a high-risk entity for visualization."""
        neighbors = nx.ego_graph(self.graph, entity, radius=depth)
        return neighbors

    def _persist_graph(self):
        self.redis.set("correlation:graph", pickle.dumps(self.graph), ex=86400)

    def _load_persisted_graph(self):
        data = self.redis.get("correlation:graph")
        if data:
            self.graph = pickle.loads(data)
```

The graph state persists in Redis with a 24-hour TTL. An attacker who performs reconnaissance at 09:00 and credential access at 14:00 — a 5-hour gap — still appears as a connected subgraph because both events share the same user and host entities as nodes.

#### Risk Scoring Across Weak Signals

Graph-based correlation enables aggregating low-confidence signals into high-confidence composite alerts. Individual signals that would not cross an alert threshold individually — a user running `net user` (score: 5), then a new outbound connection (score: 8), then a file read in `/etc` (score: 7) — accumulate on the same user and host entities. When the composite risk score crosses the alert threshold (50 in the example above), a single high-confidence alert fires rather than three low-confidence individual ones.

```python
SIGNAL_WEIGHTS = {
    # Authentication signals
    ("auth", "failure"):                 3,
    ("auth", "success_after_failures"):  15,
    ("auth", "off_hours"):               8,
    ("auth", "new_source_ip"):           12,
    # Process signals
    ("process", "recon_command"):        5,
    ("process", "credential_dump"):      40,
    ("process", "defense_evasion"):      30,
    ("process", "living_off_the_land"):  10,
    # Network signals
    ("network", "new_external_dest"):    12,
    ("network", "large_egress"):         20,
    ("network", "tor_exit_node"):        50,
    # File signals
    ("file", "sensitive_path_access"):   15,
    ("file", "bulk_read"):               25,
}

def score_event(event: SecurityEvent) -> int:
    key = (event.event_type, event.attributes.get("signal_subtype", ""))
    return SIGNAL_WEIGHTS.get(key, event.severity)
```

### Part 4: Temporal Correlation Patterns

Beyond sequence detection, attacks reveal themselves through temporal patterns that single-event rules cannot capture.

#### Sliding Window Correlation

A sliding window accumulates events on the same entity over a rolling time interval. Unlike transaction-based grouping (which starts/stops on specific events), a sliding window continuously evaluates risk:

```python
import time
from collections import deque

class SlidingWindowCorrelator:
    def __init__(self, window_seconds: int = 900):  # 15-minute window
        self.window = window_seconds
        # entity_id -> deque of (timestamp, score) tuples
        self.entity_windows: dict[str, deque] = {}

    def add_event(self, entity: str, score: int, timestamp: float = None) -> float:
        ts = timestamp or time.time()
        if entity not in self.entity_windows:
            self.entity_windows[entity] = deque()

        # Add current event.
        self.entity_windows[entity].append((ts, score))

        # Evict events outside the window.
        cutoff = ts - self.window
        while self.entity_windows[entity] and self.entity_windows[entity][0][0] < cutoff:
            self.entity_windows[entity].popleft()

        # Return accumulated score for the entity.
        return sum(s for _, s in self.entity_windows[entity])
```

A user who triggers a score of 12 at 09:00, 8 at 09:07, 15 at 09:11, and 20 at 09:22 accumulates a windowed score of 55 — crossing the alert threshold — even though no single event would have done so.

#### Session-Based Correlation

Group events by authenticated session identity (session ID, cookie, bearer token) rather than by time alone. All events bearing the same session token within 24 hours belong to the same actor:

```eql
sequence by user.name, session.id with maxspan=24h
  [authentication where event.outcome == "success"]
  [file where file.path : ("*/credentials*", "*/secrets*", "*/.aws/credentials*")]
  [network where destination.port == 443 and network.bytes_sent > 1000000]
```

A credential file access followed by a large outbound transfer — both authenticated under the same session — is a data exfiltration sequence even spread across hours.

#### Long-Dwell Detection

APT actors deliberately space actions hours or days apart to defeat time-windowed rules. Long-dwell detection uses time-bucketed aggregation to find entities whose risk accumulates gradually over days:

```python
def check_long_dwell(entity: str, lookback_days: int = 7) -> Optional[dict]:
    """
    Returns a long-dwell alert if an entity has had consistent low-score
    activity across multiple days — behavior typical of slow APT movement.
    """
    daily_scores = []
    for day_offset in range(lookback_days):
        day_score = get_daily_risk_score(entity, days_ago=day_offset)
        daily_scores.append(day_score)

    # Alert if: non-zero activity on 5+ of the last 7 days,
    # even though no single day exceeded the alert threshold.
    active_days = sum(1 for s in daily_scores if s > 5)
    total_score = sum(daily_scores)

    if active_days >= 5 and total_score >= 80:
        return {
            "alert_type": "long_dwell_pattern",
            "entity": entity,
            "active_days": active_days,
            "total_7d_score": total_score,
            "daily_scores": daily_scores,
            "confidence": "high" if active_days >= 6 else "medium"
        }
    return None
```

This pattern catches attackers who operate for 15-30 minutes per day over a week — each day below threshold, the cumulative pattern unmistakably adversarial.

### Part 5: Building Correlation Rules Incrementally

Correlation rule development follows a deliberate progression from high-confidence simple sequences to complex multi-stage chains. Starting with complex rules produces high false positive rates; starting simple builds analyst trust and establishes tuning baselines.

**Week 1-2: Two-event sequences with high individual signal**

Begin with two-event sequences where each individual event is itself elevated-confidence:

```eql
/* Two-event sequence: both events are individually suspicious.
   Combined, near-zero false positive rate. */
sequence by host.name with maxspan=10m
  [process where process.name in ("mimikatz.exe", "procdump.exe", "wce.exe")]
  [network where destination.port in (443, 80, 53)]
```

**Week 3-4: Two-event sequences with individually benign events**

Expand to sequences where neither event alone would alert:

```eql
/* Neither event is suspicious alone; the combination in context is. */
sequence by user.name with maxspan=30m
  [process where process.parent.name in ("winword.exe", "excel.exe", "outlook.exe")
    and process.name in ("powershell.exe", "cmd.exe", "wscript.exe")]
  [network where destination.port not in (80, 443)
    and not destination.ip : "10.0.0.0/8"]
```

**Week 5-8: Three-event chains with `maxspan` tuning**

Add a third stage once false positive rates are acceptable on two-event rules:

```eql
sequence by host.name with maxspan=2h
  [process where process.name == "powershell.exe"
    and process.command_line : ("*-EncodedCommand*", "*-enc*", "*bypass*")]
  [file where event.action == "creation"
    and file.path : ("*/Temp/*", "*/AppData/*", "*/Users/Public/*")]
  [network where destination.port == 443
    and process.name == "powershell.exe"]
```

**Month 3+: Four-stage chains with entity graph integration**

Integrate graph-based risk scores as preconditions for longer sequences:

```python
def should_evaluate_long_chain(entity: str, graph: EntityCorrelationGraph) -> bool:
    """Only run expensive 4-stage EQL queries on entities with elevated graph risk."""
    node = graph.graph.nodes.get(entity, {})
    return node.get("risk_score", 0) >= 20
```

Evaluate expensive long-chain sequences only on entities the graph engine has already flagged as elevated risk. This reduces query load by 85-95% while preserving detection capability.

### Part 6: Testing Correlation Rules

#### Synthetic Attack Scenarios

Test each correlation rule against a synthetic event stream before production deployment. Synthetic events follow the exact sequence the rule targets:

```python
# test_correlation_rules.py
import pytest
from datetime import datetime, timedelta

def make_event(event_type, source, target, attrs, severity, offset_minutes=0):
    return SecurityEvent(
        timestamp=datetime(2026, 5, 7, 9, 0) + timedelta(minutes=offset_minutes),
        event_type=event_type,
        source_entity=source,
        target_entity=target,
        attributes=attrs,
        severity=severity
    )

def test_lateral_movement_pattern_fires():
    graph = EntityCorrelationGraph(redis_client=FakeRedis(), decay_hours=24)

    events = [
        make_event("auth", "user:attacker", "host:web-01",
                   {"outcome": "success"}, 5, offset_minutes=0),
        make_event("process", "user:attacker", "host:web-01",
                   {"name": "bash", "parent": "nginx"}, 8, offset_minutes=5),
        make_event("process", "user:attacker", "host:db-02",
                   {"name": "mysql", "signal_subtype": "recon_command"}, 10, offset_minutes=25),
    ]

    all_correlations = []
    for event in events:
        all_correlations.extend(graph.ingest_event(event))

    types = [c["correlation_type"] for c in all_correlations]
    assert "lateral_movement_sequence" in types

def test_benign_single_session_no_false_positive():
    graph = EntityCorrelationGraph(redis_client=FakeRedis(), decay_hours=24)

    events = [
        make_event("auth", "user:devops", "host:app-01",
                   {"outcome": "success"}, 5, offset_minutes=0),
        make_event("process", "user:devops", "host:app-01",
                   {"name": "kubectl"}, 3, offset_minutes=10),
    ]

    all_correlations = []
    for event in events:
        all_correlations.extend(graph.ingest_event(event))

    lateral_correlations = [c for c in all_correlations
                            if c["correlation_type"] == "lateral_movement_sequence"]
    assert len(lateral_correlations) == 0
```

Run these tests in CI on every change to correlation rules. A synthetic attack scenario that stops matching indicates a regression; a benign scenario that starts matching indicates a new false positive source.

#### Tabletop Exercises for Long-Dwell Rules

Long-dwell rules cannot be validated with unit tests alone — the multi-day event stream is difficult to synthesize accurately. Run a tabletop exercise quarterly: replay 7 days of production logs (with real events) through the correlation engine in compressed time to verify that the long-dwell patterns fire on known-historical incidents and do not fire on normal operational periods.

### Part 7: SOAR Integration for Correlated Alert Response

Single-event alerts and correlated chain alerts require different automated response postures. A single low-confidence signal warrants enrichment. A confirmed 4-stage attack chain warrants containment.

#### Tiered Response Based on Correlation Confidence

```yaml
# soar-workflow.yaml (Tines, Torq, or Splunk SOAR)
name: correlated-alert-response
trigger:
  source: correlation_engine
  event_type: correlation_fired

steps:
  - name: classify_confidence
    action: evaluate
    conditions:
      - if: event.confidence == "high" and event.correlation_type == "lateral_movement_sequence"
        then: goto isolate_and_page
      - if: event.confidence == "medium"
        then: goto enrich_and_queue
      - default: goto enrich_only

  - name: enrich_only
    actions:
      - lookup_threat_intel: event.source_ip
      - lookup_cmdb: event.source_host
      - lookup_user_profile: event.user
      - append_enrichment_to_case: true

  - name: enrich_and_queue
    actions:
      - lookup_threat_intel: event.source_ip
      - lookup_cmdb: event.source_host
      - lookup_user_profile: event.user
      - lookup_recent_changes: event.source_host
      - create_case:
          severity: medium
          assignee: soc-tier-1
          sla_hours: 4

  - name: isolate_and_page
    actions:
      - lookup_threat_intel: event.source_ip
      - lookup_cmdb: event.source_host
      - lookup_user_profile: event.user
      # Automated containment before human review.
      - isolate_host:
          host: event.pivot_hosts
          method: network_quarantine
          duration_minutes: 120
          auto_extend: false
      - revoke_sessions:
          user: event.user
          provider: okta
      - create_case:
          severity: critical
          assignee: soc-tier-2
          page_oncall: true
          sla_minutes: 15
```

#### Enrichment at Correlation Time

Correlated alerts carry more context than single-event alerts. Enrich the combined incident with the full graph subgraph:

```python
def build_incident_context(correlation: dict,
                            graph: EntityCorrelationGraph) -> dict:
    primary_entity = correlation.get("user") or correlation.get("host")
    subgraph = graph.get_attack_subgraph(primary_entity, depth=2)

    return {
        "correlation": correlation,
        "entity_summary": {
            node: {
                "risk_score": data.get("risk_score", 0),
                "first_seen": data.get("first_seen", "").isoformat()
                              if hasattr(data.get("first_seen", ""), "isoformat") else "",
                "last_seen": data.get("last_seen", "").isoformat()
                             if hasattr(data.get("last_seen", ""), "isoformat") else "",
            }
            for node, data in subgraph.nodes(data=True)
        },
        "event_edges": [
            {
                "from": u,
                "to": v,
                "event_type": d.get("event_type"),
                "timestamp": d.get("timestamp"),
            }
            for u, v, d in subgraph.edges(data=True)
        ],
        "related_hosts": [n for n in subgraph.nodes()
                          if n.startswith("host:")],
        "related_ips": [n for n in subgraph.nodes()
                        if n.startswith("ip:")],
    }
```

The analyst who opens the SOAR incident sees the full entity graph for the primary entity — every host touched, every IP contacted, every user account involved, with timestamps — rather than a single isolated event.

## Expected Behaviour

| Scenario | Single-Event SIGMA | EQL Sequence + Graph Correlation |
|---|---|---|
| Web shell spawns bash, runs `id`, makes outbound connection | 0 alerts (all events individually benign) | 1 high-confidence attack-chain alert within 5 minutes |
| Kerberoasting followed by privilege escalation | 1 low-confidence alert (RC4 TGS-REQ) | 1 high-confidence correlated alert with session context |
| APT operating 20 min/day for 7 days | 7 separate low-confidence alerts, likely noise-filtered | 1 long-dwell alert on day 5 with full 7-day event graph |
| Developer running `net user` during debugging | 1 alert (suppressed after review) | 0 alerts (no matching sequence context) |
| Alert-fatigue noise injection | Many low-confidence alerts | Score increases on noise source; pattern diverges from attack chains |
| Automated response time for confirmed lateral movement | Manual review required | Network quarantine applied within 60 seconds of correlation |

## Trade-offs

| Decision | Security Benefit | Cost | Mitigation |
|---|---|---|---|
| EQL sequence detection | Near-zero false positive rate on multi-stage sequences | Requires Elastic Security license; queries are more expensive than KQL | Limit maxspan to necessary windows; run sequences on filtered indices (not wildcard). |
| Graph-based entity correlation | Captures time-dispersed multi-host patterns | NetworkX graph grows unbounded without pruning; Redis persistence adds dependency | Prune nodes last-seen > 48h nightly; graph size stays manageable for <50k daily events per host. |
| Long-dwell detection | Catches APT campaigns that defeat time-windowed rules | High latency (days to trigger); requires persistent event storage | Combine with network flow baseline anomalies for earlier indicators. |
| SOAR automated containment on high-confidence alerts | Seconds to containment vs. 15-30 minute manual response | Auto-containment of a false positive disrupts production | Require two independent high-confidence signals (EQL match AND graph risk > 60) before auto-containment; single-signal correlation queues for human review. |
| Incremental rule development | Low initial false positive rates; analyst trust maintained | Detection coverage is partial for months | Prioritize highest-impact attack chains first: web shell to lateral movement, credential access to exfiltration. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| EQL sequence window too tight | Attack chains that span 2h fail to match 1h `maxspan` | Post-incident review shows events that should have correlated | Tune `maxspan` per attack type; web shell chains: 4h; credential access: 12h; exfiltration: 24h. |
| Graph memory exhaustion | Correlation engine OOM; alerts stop firing | Redis key expiry on `correlation:graph`; graph not loading on restart | Add node pruning scheduled job; cap graph at 100k nodes via LRU eviction on entity last-seen. |
| False positive auto-containment | Production host isolated; application downtime | Service health alerts fire after containment | Add a 5-minute "pending containment" state with analyst override before network quarantine executes; auto-rollback containment if health checks fail. |
| Sequence rule fires on pentest | Red-team activity treated as real incident; SOC mobilizes | Pentest schedule not communicated to detection team | Establish a pre-pentest notification process that writes a suppression window event to the log stream; EQL anti-join on suppression events to skip sequences during authorized testing. |
| Long-dwell scoring resets on Redis restart | 7-day accumulation lost; APT actor detection window missed | Long-dwell alerts stop firing; incident post-mortem shows gap | Persist daily risk snapshots to durable storage (S3, Elasticsearch); Redis is cache layer only; rebuild graph from durable store on restart. |
| Correlated enrichment service unavailable | Analyst opens incident with no context | SOAR step logs enrichment failure | Degrade gracefully: create incident with raw correlation data; mark enrichment-pending; retry enrichment asynchronously. |

## Related Articles

- [Detection-as-Code with Sigma: Versioned, Tested, Vendor-Neutral SIEM Rules](/articles/observability/detection-as-code-sigma/)
- [User Behavior Analytics: Detecting Insider Threats and Compromised Accounts](/articles/observability/user-behavior-analytics/)
- [Alert Deduplication and Correlation Patterns: Beating Alert Fatigue at Scale](/articles/observability/alert-correlation/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
- [Threat Hunting with osquery: Fleet-Wide Scheduled Queries and Anomaly Investigation](/articles/observability/threat-hunting-osquery/)
