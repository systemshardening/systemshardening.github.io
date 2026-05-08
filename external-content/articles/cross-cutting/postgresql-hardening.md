---
title: "Hardening PostgreSQL for Production: Authentication, Encryption, Row-Level Security, and Audit Logging"
description: "PostgreSQL defaults prioritise developer convenience over security. A stock installation on most distributions allows local trust authentication (any."
slug: "postgresql-hardening"
date: 2026-03-13
lastmod: 2026-03-13
category: "cross-cutting"
tags: ["postgresql", "database", "tls", "rls", "pgaudit", "authentication"]
personas: ["systems-engineer", "sre"]
article_number: 96
difficulty: "intermediate"
estimated_reading_time: 20
provider_bridges:
  - name: "Neon"
    id: 153
    category: "managed-databases"
  - name: "Supabase"
    id: 154
    category: "managed-databases"
  - name: "Aiven"
    id: 156
    category: "managed-databases"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
premium_pack: "postgresql-hardening-pack"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/postgresql-hardening/index.html"
---

# Hardening [PostgreSQL](https://www.postgresql.org) for Production: Authentication, Encryption, Row-Level Security, and Audit Logging

## Problem

PostgreSQL defaults prioritise developer convenience over security. A stock installation on most distributions allows local trust authentication (any local user connects without a password), TLS is disabled (all queries and results travel in plaintext), `pgaudit` is not installed (no record of which queries accessed which data), and row-level security is unused (any application user with SELECT on a table sees all rows, including other tenants' data in multi-tenant databases).

Database hardening is the last mile. Infrastructure hardening (network policies, seccomp, RBAC) protects the perimeter. But a SQL injection vulnerability that reaches a poorly hardened PostgreSQL instance gives the attacker access to every row in every table the application user can query.

**Target systems:** PostgreSQL 15+ on Ubuntu 24.04 LTS, RHEL 9, or running in [Kubernetes](https://kubernetes.io). Covers both self-managed and containerised deployments.

## Threat Model

- **Adversary:** Attacker with application-level database access (SQL injection, compromised application credentials) or network access to the PostgreSQL port (5432).
- **Objective:** Read/exfiltrate all data. Escalate from application user to superuser. Modify or delete data for sabotage or fraud. Read other tenants' data in multi-tenant databases.
- **Blast radius:** Without hardening, all data in all databases on the instance. With hardening, limited to the specific tables and rows the compromised user is authorised to access.

## Configuration

### pg_hba.conf Hardening

`pg_hba.conf` controls who can connect from where and how they authenticate.

```bash
# /etc/postgresql/16/main/pg_hba.conf
# (Debian/Ubuntu path - RHEL uses /var/lib/pgsql/16/data/pg_hba.conf)

# TYPE  DATABASE  USER       ADDRESS         METHOD

# Local connections: require SCRAM-SHA-256 password authentication.
# NEVER use 'trust' in production - it allows anyone to connect as any user.
local   all       all                        scram-sha-256

# IPv4 connections from application servers only.
# Restrict to specific CIDRs - not 0.0.0.0/0.
hostssl all       app_user   10.0.1.0/24     scram-sha-256

# Admin connections: require client certificate AND password.
hostssl all       admin      10.0.0.5/32     cert

# Replication connections: from specific replication hosts only.
hostssl replication repl_user 10.0.2.0/24    scram-sha-256

# Deny everything else.
# This is implicit (PostgreSQL denies connections not matching any rule),
# but making it explicit documents the intent.
host    all       all        0.0.0.0/0       reject
host    all       all        ::/0            reject
```

Key changes from the default:

- Replaced `trust` with `scram-sha-256` everywhere
- Used `hostssl` instead of `host`, forces TLS for all remote connections
- Restricted application connections to a specific CIDR
- Admin connections require client certificates
- Explicit reject-all at the end

```bash
# Reload pg_hba.conf without restarting PostgreSQL:
sudo -u postgres psql -c "SELECT pg_reload_conf();"
```

### TLS Configuration

```bash
# Generate a TLS certificate (or use cert-manager in Kubernetes).
# For self-managed:
sudo openssl req -new -x509 -days 365 -nodes \
  -out /etc/postgresql/16/main/server.crt \
  -keyout /etc/postgresql/16/main/server.key \
  -subj "/CN=postgresql.example.com"

sudo chown postgres:postgres /etc/postgresql/16/main/server.{crt,key}
sudo chmod 600 /etc/postgresql/16/main/server.key
```

```ini
# postgresql.conf - TLS settings
ssl = on
ssl_cert_file = '/etc/postgresql/16/main/server.crt'
ssl_key_file = '/etc/postgresql/16/main/server.key'

# Minimum TLS version
ssl_min_protocol_version = 'TLSv1.3'

# For TLS 1.2 compatibility (if needed):
# ssl_min_protocol_version = 'TLSv1.2'
# ssl_ciphers = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
```

```bash
# Verify TLS is working:
psql "host=localhost dbname=postgres user=admin sslmode=verify-full sslrootcert=/etc/ssl/certs/ca-certificates.crt"

# Check the connection is using TLS:
SELECT ssl_is_used();
-- Expected: t (true)

# Check TLS version:
SELECT version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid();
-- Expected: TLSv1.3, TLS_AES_256_GCM_SHA384
```

### Role and Privilege Management

```sql
-- Create roles with minimal privileges.
-- NEVER let the application connect as the postgres superuser.

-- Application user: can read and write application tables only.
CREATE ROLE app_user WITH LOGIN PASSWORD 'strong-password-here';
GRANT CONNECT ON DATABASE appdb TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;

-- Read-only user for reporting/analytics.
CREATE ROLE readonly_user WITH LOGIN PASSWORD 'another-strong-password';
GRANT CONNECT ON DATABASE appdb TO readonly_user;
GRANT USAGE ON SCHEMA public TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON TABLES TO readonly_user;

-- Revoke default public schema permissions.
-- By default, all users can create objects in the public schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

### Row-Level Security (Multi-Tenant Isolation)

```sql
-- Enable RLS on a multi-tenant table.
-- Each tenant sees only their own rows.

ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;
-- FORCE ensures RLS applies even to the table owner.

-- Policy: users can only see rows where tenant_id matches their session variable.
CREATE POLICY tenant_isolation ON orders
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- The application sets the tenant context on each connection:
-- SET app.tenant_id = 'tenant-uuid-here';
-- SELECT * FROM orders;  -- Returns only this tenant's orders.
```

```sql
-- Verify RLS is working:
SET ROLE app_user;
SET app.tenant_id = 'tenant-a-uuid';
SELECT count(*) FROM orders;
-- Returns only tenant A's orders.

SET app.tenant_id = 'tenant-b-uuid';
SELECT count(*) FROM orders;
-- Returns only tenant B's orders.

-- Without setting tenant_id:
RESET app.tenant_id;
SELECT count(*) FROM orders;
-- Returns 0 rows (policy blocks all rows when variable is not set).
```

### pgaudit: Query Audit Logging

```bash
# Install pgaudit:
# Debian/Ubuntu:
sudo apt install postgresql-16-pgaudit

# RHEL/Rocky:
sudo dnf install pgaudit_16
```

```ini
# postgresql.conf - pgaudit configuration
shared_preload_libraries = 'pgaudit'

# Log all DDL (CREATE, ALTER, DROP) and DML (SELECT, INSERT, UPDATE, DELETE)
# on audited tables.
pgaudit.log = 'ddl, write, role'

# For full query logging (high volume - use selectively):
# pgaudit.log = 'all'

# Log the statement text (not just the operation type)
pgaudit.log_statement_once = on

# Log the parameter values (WARNING: may contain sensitive data)
# pgaudit.log_parameter = on

# Log to the standard PostgreSQL log
pgaudit.log_level = 'log'
```

```sql
-- Enable per-table audit logging for sensitive tables:
-- Only log access to specific tables, not all tables.
CREATE ROLE auditor;
GRANT SELECT ON orders, users, payments TO auditor;
SET pgaudit.role = 'auditor';
-- Now only queries that access orders, users, or payments are logged.
```

```bash
# Restart PostgreSQL to load pgaudit:
sudo systemctl restart postgresql

# Verify pgaudit is active:
sudo -u postgres psql -c "SHOW shared_preload_libraries;"
-- Expected: pgaudit

# Check audit logs:
grep "AUDIT" /var/log/postgresql/postgresql-16-main.log | tail -5
-- Expected: AUDIT entries showing DDL and DML operations
```

### Connection Pooler Security (PgBouncer)

```ini
# /etc/pgbouncer/pgbouncer.ini
[databases]
appdb = host=127.0.0.1 port=5432 dbname=appdb

[pgbouncer]
listen_addr = 10.0.1.0
listen_port = 6432
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt

# TLS between application and PgBouncer
client_tls_sslmode = require
client_tls_cert_file = /etc/pgbouncer/server.crt
client_tls_key_file = /etc/pgbouncer/server.key

# TLS between PgBouncer and PostgreSQL
server_tls_sslmode = verify-full
server_tls_ca_file = /etc/ssl/certs/ca-certificates.crt

# Connection limits
max_client_conn = 200
default_pool_size = 20
reserve_pool_size = 5
reserve_pool_timeout = 3

# Disable admin console access from non-localhost
admin_users = pgbouncer_admin
stats_users = pgbouncer_stats
```

## Expected Behaviour

- `psql` without TLS is rejected: `FATAL: no pg_hba.conf entry for host ... SSL off`
- Application user can only access its own database tables with appropriate privileges
- RLS enforces tenant isolation: queries return only the current tenant's rows
- pgaudit logs all DDL and DML on sensitive tables to the PostgreSQL log
- PgBouncer requires TLS for both client and server connections
- Backups are encrypted and tested for restorability

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| TLS for all connections | 1-5% throughput reduction (TLS handshake); negligible for persistent connections | Applications must configure SSL client certificates or `sslmode=require` | Use connection pooling (PgBouncer) to maintain persistent TLS connections. |
| Row-level security | 1-5% per-query overhead for simple policies | Policy bugs can expose data or block legitimate queries; must test extensively | Write integration tests that verify tenant isolation. Include in CI. |
| pgaudit on DDL+DML | Significant log volume (10-100x normal logging for write-heavy workloads) | Disk I/O and storage cost | Enable selectively on sensitive tables using `pgaudit.role`. Ship to external storage. |
| SCRAM-SHA-256 auth | Stronger than MD5 | Old PostgreSQL clients (<10) and old drivers may not support SCRAM | Upgrade clients. SCRAM has been available since PostgreSQL 10 (2017). |
| Revoke PUBLIC schema privileges | Default `CREATE` on public schema is removed | Applications that create tables at runtime fail | Grant CREATE only to migration/admin roles, not application users. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| pg_hba.conf too restrictive | Application can't connect | Application logs: `FATAL: no pg_hba.conf entry for host` | Add correct entry to pg_hba.conf. Reload (no restart needed): `SELECT pg_reload_conf();` |
| RLS policy bug | Users see other tenants' data | Integration tests fail; security audit query reveals cross-tenant access | Fix policy. Audit affected data. Notify affected tenants. |
| pgaudit fills disk | PostgreSQL server runs out of space; writes fail | Disk usage alert; PostgreSQL logs: `could not write to log file` | Configure log rotation. Ship logs to external storage ([Grafana](https://grafana.com) Cloud #108, Axiom #112). Reduce audit scope. |
| TLS certificate expires | All new connections fail | cert-manager alerts ([Certificate Expiry Monitoring: Automated Detection Across TLS, mTLS, and Signing Certificates](/articles/observability/certificate-expiry-monitoring/)); application connection errors | Renew certificate. PostgreSQL requires reload (not restart) for cert changes: `SELECT pg_reload_conf();` |
| PgBouncer connection exhaustion | Application receives "too many connections" errors | PgBouncer stats show pool full; application timeout errors | Increase `max_client_conn` and `default_pool_size`. Investigate connection leaks in the application. |

## When to Consider a Managed Alternative

Self-managed PostgreSQL HA (streaming replication + failover) requires significant expertise. Version upgrades require `pg_upgrade` or logical replication migration (hours of downtime planning). Security patching requires testing and coordinated restarts.

- **[Neon](https://neon.tech):** Serverless Postgres with branching, scale-to-zero. From $19/month. Good for development and small production workloads.
- **[Supabase](https://supabase.com):** Postgres + auth + realtime + storage. From $25/month. Firebase alternative built on Postgres.
- **[Aiven](https://aiven.io):** Multi-database managed platform (Postgres, Kafka, [Redis](https://redis.io), OpenSearch). From $19/month. For teams needing multiple managed data services.
- **[Crunchy Data](https://www.crunchydata.com):** Postgres-specialist. Kubernetes operator. Enterprise support.
- **[Grafana Cloud](https://grafana.com/cloud)** for pgaudit log aggregation and query analysis dashboards.

**Premium content pack:** PostgreSQL hardening configuration pack. pg_hba.conf templates for common architectures, TLS configuration, pgaudit rule sets for SOC 2 compliance, RLS policy examples for multi-tenant databases, PgBouncer hardened config, and backup encryption scripts.


## Related Articles

- [Hardening Redis in Production: Authentication, TLS, ACLs, and Command Restriction](/articles/cross-cutting/redis-hardening/)
- [Securing Message Queues in Production: Kafka, RabbitMQ, and NATS Hardening](/articles/cross-cutting/message-queue-hardening/)
- [Migrating from Self-Hosted Prometheus to Grafana Cloud: Preserving Dashboards, Alerts, and History](/articles/cross-cutting/migrate-prometheus-grafana-cloud/)
- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
