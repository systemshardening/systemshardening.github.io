---
title: "Database Activity Monitoring: Audit Logs, SQL Inspection, and SIEM Integration"
description: "Application logs tell you what the API did. Database audit logs tell you what actually happened to the data. Learn how to configure pgaudit, MySQL audit plugins, MongoDB auditing, and Redis monitoring to detect SQL injection, privilege escalation, and exfiltration at the data layer."
slug: database-activity-monitoring
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - database-security
  - pgaudit
  - mysql-audit
  - sql-monitoring
  - data-access-logging
personas:
  - security-engineer
  - data-engineer
article_number: 545
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/database-activity-monitoring/
---

# Database Activity Monitoring: Audit Logs, SQL Inspection, and SIEM Integration

## Problem

Application logs record what the application layer decided to do. Database audit logs record what the database engine actually executed. These are not the same thing.

An attacker who obtains a leaked connection string, a misconfigured service account, or a SQL injection foothold bypasses the application entirely. They connect to the database directly, or inject statements that the application executes on their behalf. The application logs show nothing unusual — the normal service account issued the query. Only a database-level audit log captures the actual SQL statement, the connected client, and the volume of rows returned.

The asymmetry matters:

- **Application logs have no visibility into injected SQL.** A vulnerable ORM query that returns ten thousand rows because a `UNION SELECT` was appended looks like a normal request in the application log. The database sees the full statement.
- **Databases are the final authoritative store.** An attacker who exfiltrates from a cache or API may leave gaps in the application audit trail. The database is the last checkpoint.
- **Direct database connections are invisible to application logs.** DBAs, data engineers, and automated jobs connect directly. Without database audit logging, their access is unrecorded.
- **Privilege changes in the database are not application events.** `GRANT`, `REVOKE`, and role assignments happen in the database engine — no application code is involved.

**Target systems:** PostgreSQL (pgaudit extension), MySQL (Percona Audit Log Plugin, MySQL Enterprise Audit), MongoDB (mongod `--auditDestination`), Redis. SIEM targets: Elasticsearch/OpenSearch, Splunk, Graylog.

## Threat Model

- **Adversary 1 — SQL injection:** An attacker injects SQL through an unparameterised application query. The injected `UNION SELECT` retrieves rows from tables the application never intended to access.
- **Adversary 2 — Compromised service account:** An attacker obtains a database connection string from a leaked `.env` file or misconfigured secret store. They connect directly and run bulk `SELECT` queries.
- **Adversary 3 — Insider privilege escalation:** A developer with read-only database access issues `GRANT SUPERUSER` to their account or creates a new superuser. No application code mediates this; it is a direct database operation.
- **Adversary 4 — Data exfiltration via bulk export:** An attacker or malicious insider uses `COPY TO`, `SELECT INTO OUTFILE`, or `mongodump` to export entire tables in a single operation.
- **Adversary 5 — Lateral movement to other schemas:** A compromised application account accesses schemas or tables outside its normal operational scope.
- **Access level:** Adversaries 1 and 5 have application-mediated access. Adversaries 2, 3, and 4 have direct database access. All are invisible to application-layer logs.
- **Objective:** Extract sensitive data, escalate privileges, or persist access without triggering application-layer alerts.
- **Blast radius:** Without database audit logging, all of the above attacks proceed undetected until after a breach is confirmed by other means (data appearing for sale, customer complaints, backup anomalies). With audit logging and SIEM integration, each attack generates detectable log patterns within minutes.

## Configuration

### Step 1: PostgreSQL — pgaudit

pgaudit is the standard audit extension for PostgreSQL. It hooks into the PostgreSQL executor and emits structured log entries for every audited statement.

Install and enable the extension:

```sql
-- postgresql.conf or ALTER SYSTEM:
shared_preload_libraries = 'pgaudit'

-- After restart, enable in the database:
CREATE EXTENSION pgaudit;
```

Configure global audit scope in `postgresql.conf`:

```ini
# Log all DDL (CREATE, DROP, ALTER) and privilege changes.
pgaudit.log = 'ddl, role, misc_set'

# For sensitive databases, add read and write:
# pgaudit.log = 'ddl, role, read, write, misc_set'

# Include the connection client hostname in every log line.
log_hostname = on
log_connections = on
log_disconnections = on

# Suppress repetitive catalog lookups from audit output.
pgaudit.log_catalog = off

# Include the statement parameter values (bind variables).
pgaudit.log_parameter = on

# Prefix every audit line for grep/syslog filtering.
pgaudit.log_relation = on
```

Configure object-level auditing for specific tables:

```sql
-- Create a dedicated audit role (pgaudit uses role membership to scope object audit).
CREATE ROLE pgaudit_monitor;

-- Audit all SELECT, INSERT, UPDATE, DELETE on the payments table.
GRANT SELECT, INSERT, UPDATE, DELETE ON payments TO pgaudit_monitor;

-- Activate object-level audit for connections running as, or SET ROLE to, pgaudit_monitor.
ALTER ROLE pgaudit_monitor SET pgaudit.log = 'read, write';
ALTER ROLE pgaudit_monitor SET pgaudit.log_relation = on;

-- Grant to the application role so object-level audit fires on its queries.
GRANT pgaudit_monitor TO app_user;
```

A pgaudit log line for a SELECT looks like:

```
AUDIT: OBJECT,1,1,READ,SELECT,TABLE,public.payments,
  SELECT id, card_last4, amount FROM payments WHERE user_id = $1,<none>
```

Ship to syslog and forward to Elasticsearch:

```ini
# postgresql.conf
log_destination = 'syslog'
syslog_facility = 'LOCAL0'
syslog_ident = 'postgres'
```

```yaml
# /etc/vector/vector.yaml — ingest PostgreSQL syslog, extract audit fields.
sources:
  postgres_syslog:
    type: syslog
    address: "0.0.0.0:514"
    mode: udp

transforms:
  parse_pgaudit:
    type: remap
    inputs: [postgres_syslog]
    source: |
      .db_engine = "postgresql"
      if starts_with(string!(.message), "AUDIT:") {
        parts = split(string!(.message), ",", limit: 9)
        .audit_type      = parts[0]  # SESSION or OBJECT
        .statement_id    = parts[1]
        .substatement_id = parts[2]
        .class           = parts[3]  # READ, WRITE, DDL, ROLE, etc.
        .command         = parts[4]  # SELECT, INSERT, GRANT, etc.
        .object_type     = parts[5]  # TABLE, SEQUENCE, etc.
        .object_name     = parts[6]
        .statement       = parts[7]
        .is_audit        = true
      }

sinks:
  siem:
    type: elasticsearch
    inputs: [parse_pgaudit]
    endpoint: "https://siem.internal:9200"
    index: "db-audit-%Y.%m.%d"
```

### Step 2: MySQL — Percona Audit Log Plugin

The Percona Audit Log Plugin is free and available for MySQL 5.7+, MariaDB, and Percona Server. It captures all queries, connections, and table accesses.

Install and configure:

```sql
-- Enable the plugin (Percona Server / MySQL with plugin compiled in):
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- Verify it loaded:
SHOW PLUGINS WHERE Name = 'audit_log';
```

```ini
# my.cnf [mysqld] section:
plugin-load-add         = audit_log.so
audit_log_format        = JSON           # Structured output; easier to parse than XML.
audit_log_policy        = ALL            # Log queries, logins, and table access.
audit_log_rotate_on_size = 100000000     # Rotate at 100 MB.
audit_log_rotations     = 5
audit_log_file          = /var/log/mysql/audit.json

# Filter: log only specific users (reduces volume for busy servers).
# Leave unset to log all users.
# audit_log_include_accounts = 'app_user@%,admin@localhost'

# Log query execution time for slow-query detection.
audit_log_connection_policy = ALL
audit_log_statement_policy  = ALL
```

A MySQL audit JSON event:

```json
{
  "timestamp": "2026-05-07T14:23:01Z",
  "id": 42,
  "class": "general",
  "event": "status",
  "connection_id": 1234,
  "account": {"user": "app_user", "host": "10.0.1.55"},
  "login": {"user": "app_user", "os": "", "ip": "10.0.1.55", "proxy": ""},
  "query_time": 0.002,
  "query": "SELECT id, email FROM users WHERE id = 99 UNION SELECT 1,schema_name FROM information_schema.schemata--",
  "status": 0,
  "db": "production"
}
```

MySQL Enterprise Audit (MySQL Enterprise Edition) provides the same capability with a GUI filter builder and supports filtering by event class, user, host, and database at the server level. The JSON log format is identical; the pipeline configuration below applies to both.

Forward MySQL audit JSON to Elasticsearch using Vector:

```yaml
sources:
  mysql_audit:
    type: file
    include: ["/var/log/mysql/audit.json"]
    read_from: end

transforms:
  tag_mysql:
    type: remap
    inputs: [mysql_audit]
    source: |
      .db_engine = "mysql"
      .db_user = .account.user
      .client_ip = .login.ip
      .sql_statement = .query

sinks:
  siem:
    type: elasticsearch
    inputs: [tag_mysql]
    endpoint: "https://siem.internal:9200"
    index: "db-audit-%Y.%m.%d"
```

### Step 3: MongoDB Auditing

MongoDB auditing is available in MongoDB Enterprise and Percona Server for MongoDB. Enable via `mongod.conf`:

```yaml
# mongod.conf
auditLog:
  destination: file
  format: JSON
  path: /var/log/mongodb/audit.json
  # Filter: only log specific actions (reduces volume).
  filter: >
    {
      atype: {
        $in: [
          "authenticate",
          "authCheck",
          "createCollection",
          "dropCollection",
          "createUser",
          "dropUser",
          "grantRolesToUser",
          "revokeRolesFromUser",
          "find",
          "insert",
          "update",
          "delete",
          "logout"
        ]
      }
    }
```

A MongoDB audit event for a `find` on a sensitive collection:

```json
{
  "atype": "find",
  "ts": {"$date": "2026-05-07T14:30:00.000Z"},
  "uuid": {"$binary": "..."},
  "local": {"ip": "127.0.0.1", "port": 27017},
  "remote": {"ip": "10.0.1.88", "port": 49200},
  "users": [{"user": "app_service", "db": "production"}],
  "roles": [{"role": "readWrite", "db": "production"}],
  "param": {
    "ns": "production.customer_pii",
    "command": {"find": "customer_pii", "filter": {}, "limit": 100000}
  },
  "result": 0
}
```

An empty filter (`"filter": {}`) combined with a high limit on a sensitive collection is a strong indicator of bulk data access.

### Step 4: Redis Security Monitoring

Redis does not have a built-in audit log extension. Security monitoring relies on a combination of `CONFIG` logging, the `MONITOR` command (for short-term inspection only), and the `ACL LOG` for access control violations.

Enable ACL logging and keyspace notifications:

```ini
# redis.conf
acllog-max-len 256          # Retain last 256 ACL violation events in memory.
loglevel notice             # Capture AUTH failures and CONFIG changes at notice level.

# Keyspace notifications: send events to pub/sub for external consumers.
# K = keyspace events, E = keyevent events, g = generic commands, $ = string commands.
notify-keyspace-events "KEg$"
```

Query ACL log from a monitoring script:

```bash
# Retrieve ACL violations (AUTH failures, command denials).
redis-cli ACL LOG

# Expected output for a brute-force AUTH attempt:
# 1) 1) "count"
#    2) (integer) 47
#    3) "reason"
#    4) "auth"
#    5) "context"
#    6) "toplevel"
#    7) "object"
#    8) "AUTH"
#    9) "username"
#   10) "default"
#   11) "age-seconds"
#   12) "4.2"
#   13) "client-info"
#   14) "id=1234 addr=203.0.113.42:44300 ..."
```

Use a sidecar exporter to ship Redis slow log and ACL log to syslog:

```python
#!/usr/bin/env python3
"""redis-audit-exporter: ships Redis ACL log and slow log to syslog."""
import redis
import syslog
import json
import time

r = redis.Redis(host="localhost", port=6379)

seen_acl_entries = set()

def export_acl_log():
    entries = r.acl_log()
    for entry in entries:
        key = (entry.get(b"object"), entry.get(b"age-seconds"))
        if key not in seen_acl_entries:
            seen_acl_entries.add(key)
            event = {
                "db_engine": "redis",
                "event_type": "acl_violation",
                "reason": entry.get(b"reason", b"").decode(),
                "username": entry.get(b"username", b"").decode(),
                "client_info": entry.get(b"client-info", b"").decode(),
                "count": int(entry.get(b"count", 1)),
            }
            syslog.syslog(syslog.LOG_WARNING, json.dumps(event))

while True:
    export_acl_log()
    time.sleep(10)
```

High-risk Redis commands to alert on: `CONFIG SET`, `CONFIG REWRITE`, `DEBUG`, `FLUSHALL`, `FLUSHDB`, `SLAVEOF`/`REPLICAOF`, `MODULE LOAD`. Any use of these commands by a non-admin client should generate an immediate alert.

### Step 5: Detecting SQL Injection in Audit Logs

SQL injection leaves characteristic patterns in database audit logs. SIEM rules should match on these signatures in the `sql_statement` or `query` field:

```
# Elasticsearch — detect UNION-based SQL injection.
{
  "query": {
    "bool": {
      "must": [
        {"term": {"db_engine": "postgresql"}},
        {"match_phrase": {"sql_statement": "UNION SELECT"}},
        {"range": {"@timestamp": {"gte": "now-5m"}}}
      ]
    }
  }
}
```

Key patterns to detect:

| Pattern | Example fragment | Indicates |
|---------|-----------------|-----------|
| `UNION SELECT` | `' UNION SELECT username,password FROM users--` | Column extraction via union injection |
| `information_schema` | `FROM information_schema.tables` | Schema enumeration |
| `SLEEP(` / `pg_sleep(` | `AND SLEEP(5)--` | Blind time-based injection |
| `LOAD_FILE(` | `UNION SELECT LOAD_FILE('/etc/passwd')` | File read via injection |
| Comment sequences | `--`, `/*`, `#` at end of values | Injection termination |
| Stacked queries | `; DROP TABLE` | Stacked statement injection |
| High error rate | >5 syntax errors per session | Injection probing |

High error rates per connection are particularly reliable: a legitimate application using parameterised queries almost never produces SQL syntax errors in production. Ten syntax errors from a single client IP in one minute is a high-confidence injection signal.

### Step 6: Detecting Privilege Escalation

Privilege changes in a database are discrete, auditable events. pgaudit with `pgaudit.log = 'role'` captures every `GRANT`, `REVOKE`, `CREATE ROLE`, and `ALTER ROLE`. Alert on any of these events in production:

```
# Elasticsearch — alert on any GRANT or role creation in production.
{
  "query": {
    "bool": {
      "must": [
        {"terms": {"command": ["GRANT", "REVOKE", "CREATE ROLE", "ALTER ROLE", "DROP ROLE"]}},
        {"term": {"db_engine": "postgresql"}}
      ]
    }
  }
}
```

Specific privilege escalation indicators:

- `GRANT SUPERUSER` or `ALTER ROLE x WITH SUPERUSER` — direct superuser grant
- `GRANT pg_read_all_data TO app_user` — broad read grant to a restricted account
- `CREATE USER admin2 WITH PASSWORD` — new privileged account creation
- `GRANT ALL PRIVILEGES ON *.* TO 'x'@'%'` — MySQL wildcard grant
- `grantRolesToUser` with `root` or `dbAdmin` roles in MongoDB

Any privilege escalation during off-hours (outside 08:00–18:00 local business hours) deserves immediate escalation regardless of the account involved. Legitimate privilege changes are planned operations that occur during business hours through change management processes.

### Step 7: Detecting Data Exfiltration

Bulk data access has distinct characteristics that separate it from normal application queries:

**Large result sets.** PostgreSQL's `pgaudit.log_parameter` captures bind variable values. Combine with `pg_stat_statements` to correlate execution counts with rows returned:

```sql
-- Identify queries returning abnormally large row counts.
SELECT query, calls, rows, rows / calls AS avg_rows_per_call
FROM pg_stat_statements
WHERE rows / calls > 10000
ORDER BY rows DESC
LIMIT 20;
```

**COPY and export commands.** `COPY TO` in PostgreSQL and `SELECT INTO OUTFILE` in MySQL write data directly to files or stdout:

```
# pgaudit log for a COPY exfiltration attempt:
AUDIT: SESSION,1,1,MISC,COPY,,,COPY payments TO '/tmp/payments.csv' CSV HEADER,<none>
```

Alert on any `COPY TO`, `SELECT INTO OUTFILE`, `\copy` client command, or `mongodump`/`mongoexport` connection pattern (identifiable by the `appName: mongodump` field in MongoDB audit events).

**Repeated full-table scans.** A legitimate application using an ORM rarely performs full-table scans. A `SELECT * FROM customers` with no `WHERE` clause from an application account is a strong exfiltration signal, especially if it returns more than a few hundred rows.

**Bulk access from service accounts.** Application service accounts access a limited set of tables and columns. Detecting cross-schema or cross-table access from a service account indicates either a compromised account or SQL injection that has escalated the query scope.

### Step 8: Detecting Unusual Access Patterns

Behavioral anomalies are often the earliest indicator of a compromised account or session:

**Off-hours queries.** Generate a baseline of normal query activity by hour of day for each database user. Alert when a user or service account issues more than their 99th percentile query volume outside their normal active window:

```
# Elasticsearch aggregation — queries by user and hour for baseline.
{
  "aggs": {
    "by_user": {
      "terms": {"field": "db_user"},
      "aggs": {
        "by_hour": {
          "date_histogram": {
            "field": "@timestamp",
            "calendar_interval": "hour"
          }
        }
      }
    }
  }
}
```

**Queries from unexpected client IPs.** Application service accounts should only connect from known application server CIDRs. A service account login from a developer workstation IP or an external IP is a strong indicator of credential theft:

```
# Alert: service account connecting from outside known application server subnet.
{
  "query": {
    "bool": {
      "must": [
        {"term": {"db_user": "app_service"}},
        {"range": {"@timestamp": {"gte": "now-5m"}}}
      ],
      "must_not": [
        {"cidr": {"client_ip": {"cidr": "10.0.1.0/24"}}}
      ]
    }
  }
}
```

**New database users connecting for the first time.** New accounts in production that were not created through the change management process are a high-priority alert:

```sql
-- PostgreSQL: query last login time for all roles.
SELECT rolname, rolcanlogin, rolsuper
FROM pg_roles
WHERE rolcanlogin = true
ORDER BY oid DESC
LIMIT 20;
```

**Sudden access to previously untouched tables.** Use a rolling 30-day window of `object_name` values per `db_user`. Alert when a user accesses a table not in their 30-day history, especially if that table contains PII or payment data.

### Step 9: SIEM Integration and Retention

All database audit logs require longer retention than application debug logs. Recommended minimums:

| Log type | Minimum retention | Reason |
|----------|------------------|--------|
| DDL (schema changes) | 2 years | Regulatory (SOC 2, PCI DSS 10.7) |
| Privilege changes (GRANT, REVOKE) | 2 years | Privilege audit trail |
| DML on sensitive tables (payments, PII) | 1 year | Breach investigation lookback |
| Connection events | 90 days | Lateral movement investigation |
| General query log | 30 days | Operational debugging |

Normalise across database engines to a common schema in the SIEM:

```json
{
  "@timestamp": "2026-05-07T14:23:01Z",
  "db_engine": "postgresql",
  "db_name": "production",
  "db_user": "app_service",
  "client_ip": "10.0.1.55",
  "client_app": "payments-api",
  "command_class": "READ",
  "command": "SELECT",
  "object_type": "TABLE",
  "object_name": "payments",
  "sql_statement": "SELECT id, amount FROM payments WHERE user_id = $1",
  "rows_returned": 1,
  "duration_ms": 3,
  "is_audit": true
}
```

The normalised `command_class` field (READ, WRITE, DDL, ROLE, CONNECT) allows single alert rules to cover multiple database engines without engine-specific branching.

### Step 10: Telemetry

```
db_audit_events_total{db_engine, db_name, command_class, db_user}     counter
db_audit_privilege_changes_total{db_engine, db_name, command}          counter (alert on any increment)
db_audit_sqli_patterns_total{db_engine, pattern_type}                  counter
db_audit_bulk_access_total{db_engine, db_user, object_name}            counter
db_audit_off_hours_queries_total{db_engine, db_user}                   counter
db_audit_new_client_ips_total{db_engine, db_user}                      counter
```

Alert thresholds:

- `db_audit_privilege_changes_total` increments at any time — immediate page.
- `db_audit_sqli_patterns_total` > 0 in any 5-minute window — high-priority alert.
- `db_audit_bulk_access_total` for any `object_name` containing `pii`, `payment`, or `credential` — immediate page.
- `db_audit_off_hours_queries_total` > 2x rolling baseline — escalate for review.

## Expected Behaviour

| Attack scenario | Application log visibility | Database audit log visibility |
|-----------------|---------------------------|-------------------------------|
| SQL injection via UNION SELECT | None (application sees normal query) | Full injected statement, including UNION clause |
| Compromised service account connecting directly | None | Connection event with client IP; all queries recorded |
| Superuser grant by insider | None | `GRANT SUPERUSER` event with actor, timestamp |
| COPY TO exfiltration | None | COPY statement with destination path; triggers alert |
| Off-hours bulk SELECT | None | Connection time + query volume anomaly detected |
| New account creation in production | None | CREATE USER event; triggers immediate alert |
| MongoDB bulk find with empty filter | None | `find` audit event with empty filter and high limit |
| Redis FLUSHALL | None | ACL log entry or keyspace notification |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `pgaudit.log = 'read, write'` | Full query visibility | Significant log volume on busy databases | Enable per-table via object audit on sensitive tables only; use session audit selectively. |
| `pgaudit.log_parameter = on` | Captures bind variable values for full SQL reconstruction | May log PII in parameter values | Scrub parameters in the SIEM pipeline for known-PII column patterns; or disable and rely on statement structure alone. |
| MySQL JSON audit format | Structured; pipeline-friendly | Larger on-disk footprint than syslog format | Rotate at 100 MB; compress with gzip at rest. |
| MongoDB filter expression | Reduces audit volume | May miss audit events if filter is misconfigured | Test filter against known event types in staging; alert on unexpected silence from the audit stream. |
| Redis ACL log (in-memory) | Zero write I/O overhead | Lost on restart; limited to 256 entries | Export via sidecar on a 10-second interval; store to syslog before restart. |
| Normalised SIEM schema | Single alert rules across all DB engines | Schema mapping requires maintenance as DB versions change | Pin schema version in Vector config; test against a sample of each engine's output on upgrade. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| pgaudit not loaded after PostgreSQL restart | Audit log silent; `SHOW shared_preload_libraries` missing pgaudit | Alert on zero audit events for > 10 minutes from a database that normally produces them | Add `shared_preload_libraries` to configuration management; test after every PostgreSQL restart. |
| MySQL audit plugin disabled by `UNINSTALL PLUGIN` | Audit log stops; no entries for connections or queries | Alert on zero audit events; monitor `SHOW PLUGINS` in a scheduled check | Require `PLUGIN_ADMIN` privilege to install/uninstall plugins; restrict to DBA accounts only. |
| MongoDB audit log destination unreachable | `mongod` falls back to no logging silently | Alert on zero audit events from MongoDB source | Set `auditLog.destination` to `syslog` as a fallback; test log delivery in pre-production. |
| Audit log disk full stops database writes | PostgreSQL enters recovery mode; all writes fail | Disk utilisation alert before reaching 100% | Mount audit log on a dedicated volume; rotate aggressively; ship to remote sink and truncate locally. |
| Vector pipeline lag | SIEM alert latency > 15 minutes | Pipeline throughput metric drops; SIEM ingest timestamp lags `@timestamp` | Scale Vector workers; add a `log_pipeline_lag_seconds` metric to the pipeline. |
| High log volume from `pgaudit.log = 'read'` on OLAP workload | Log volume overwhelms SIEM ingest budget | SIEM ingest cost alert | Restrict `read` class to object-level audit on sensitive tables; exclude reporting/analytics users from session audit. |

## Related Articles

- [Application Security Logging](/articles/observability/application-security-logging/)
- [Audit Log Pipeline Design](/articles/observability/audit-log-pipeline/)
- [Elasticsearch Security Hardening](/articles/observability/elasticsearch-security-hardening/)
- [Detection Rules and Sigma Correlation](/articles/observability/detection-rules/)
- [SIEM Cost Optimisation](/articles/observability/siem-cost-optimization/)
