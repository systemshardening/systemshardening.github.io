---
title: "Hardening Redis in Production: Authentication, TLS, ACLs, and Command Restriction"
description: "Redis defaults prioritise developer convenience: no authentication, no TLS, all 200+ commands available, and binding to all interfaces."
slug: "redis-hardening"
date: 2026-01-01
lastmod: 2026-01-01
category: "cross-cutting"
tags: ["redis", "database", "tls", "acl", "authentication", "hardening"]
personas: ["systems-engineer", "sre"]
article_number: 97
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Upstash"
    id: 157
    category: "managed-databases"
  - name: "Redis Inc."
    id: 158
    category: "managed-databases"
  - name: "Aiven"
    id: 156
    category: "managed-databases"
premium_pack: "redis-hardening-pack"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/redis-hardening/index.html"
---

# Hardening [Redis](https://redis.io) in Production: Authentication, TLS, ACLs, and Command Restriction

## Problem

Redis defaults prioritise developer convenience: no authentication, no TLS, all 200+ commands available, and binding to all interfaces. In production, an unprotected Redis instance is a direct path to data theft (dump all keys), command injection (`EVAL` executes arbitrary Lua), and denial of service (`FLUSHALL` deletes all data, `DEBUG SLEEP` freezes the server). Redis is one of the most commonly exploited services in production breaches.

## Threat Model

- **Adversary:** Network attacker who can reach the Redis port (6379), or compromised application with Redis credentials.
- **Objective:** Read all cached data (sessions, tokens, user data). Inject Lua code via `EVAL`. Delete all data via `FLUSHALL`. Write SSH keys to disk via `CONFIG SET dir` + `CONFIG SET dbfilename` (the classic Redis RCE).
- **Blast radius:** All data in all Redis databases on the instance.

## Configuration

### Redis 6+ ACLs

```bash
# /etc/redis/users.acl
# Redis 6+ ACL file - per-user authentication and command restrictions.

# Default user: disabled (no anonymous access)
user default off

# Application user: can read/write keys but cannot run admin commands
user app_user on >strong-password-here ~* &* +@all -@admin -@dangerous
# Breakdown:
# on         = user is active
# >password  = password (use >HASH for hashed passwords)
# ~*         = can access all key patterns
# &*         = can access all pub/sub channels
# +@all      = allow all command categories
# -@admin    = deny admin commands (CONFIG, DEBUG, SHUTDOWN, etc.)
# -@dangerous = deny dangerous commands (FLUSHALL, FLUSHDB, KEYS, etc.)

# Read-only user: for monitoring and analytics
user readonly_user on >another-strong-password ~* &* +@read -@write -@admin -@dangerous

# Admin user: full access (use only for maintenance)
user admin_user on >admin-strong-password ~* &* +@all
```

```bash
# redis.conf - reference the ACL file
aclfile /etc/redis/users.acl

# Or inline in redis.conf:
# user app_user on >strong-password ~* &* +@all -@admin -@dangerous
```

### Dangerous Command Restriction

Even with ACLs, explicitly rename or disable the most dangerous commands:

```bash
# redis.conf - rename dangerous commands
# Use ACLs (above) as the primary control. Rename as defense-in-depth.

rename-command FLUSHALL ""       # Disable completely
rename-command FLUSHDB ""        # Disable completely
rename-command DEBUG ""          # Disable completely
rename-command CONFIG "CONFIG_b4f8c2a1"  # Rename to a secret string
rename-command SHUTDOWN "SHUTDOWN_e7d3f5"  # Rename
rename-command KEYS ""           # Disable (use SCAN instead. KEYS blocks the server)
rename-command EVAL ""           # Disable Lua scripting if not used
rename-command SCRIPT ""         # Disable script management
```

### TLS Configuration

```bash
# redis.conf - TLS settings (Redis 6+)
port 0                           # Disable unencrypted port
tls-port 6379                    # TLS-only on standard port

tls-cert-file /etc/redis/tls/redis.crt
tls-key-file /etc/redis/tls/redis.key
tls-ca-cert-file /etc/redis/tls/ca.crt

# Minimum TLS version
tls-protocols "TLSv1.3"

# Require client certificate (mutual TLS - for admin connections)
# tls-auth-clients yes

# For replication TLS
tls-replication yes

# Verify client certificates against CA
tls-auth-clients optional
```

```bash
# Client connection with TLS:
redis-cli --tls \
  --cert /etc/redis/tls/client.crt \
  --key /etc/redis/tls/client.key \
  --cacert /etc/redis/tls/ca.crt \
  -h redis.example.com \
  -p 6379 \
  --user app_user \
  --pass 'strong-password-here'
```

### Network Isolation

```bash
# redis.conf - bind to specific interfaces only
bind 127.0.0.1 10.0.1.5
# NEVER bind to 0.0.0.0 unless behind TLS + ACL + network policy

# Protected mode (rejects connections from non-localhost without auth)
protected-mode yes
```

```yaml
# Kubernetes NetworkPolicy: restrict Redis access
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: redis-access
  namespace: data
spec:
  podSelector:
    matchLabels:
      app: redis
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api-server
      ports:
        - port: 6379
          protocol: TCP
```

### Connection Limits

```bash
# redis.conf - connection management
maxclients 1000          # Maximum simultaneous connections
timeout 300              # Close idle connections after 5 minutes
tcp-keepalive 60         # TCP keepalive interval

# Memory limits
maxmemory 2gb            # Maximum memory usage
maxmemory-policy allkeys-lru  # Eviction policy when maxmemory is reached
```

### Monitoring

```yaml
# Prometheus alert rules for Redis security
groups:
  - name: redis-security
    rules:
      - alert: RedisAuthFailure
        expr: increase(redis_rejected_connections_total[5m]) > 10
        labels:
          severity: warning
        annotations:
          summary: "Redis authentication failures: {{ $value }} in 5 minutes"

      - alert: RedisExposedToInternet
        expr: redis_connected_clients > 100
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Redis has {{ $value }} connected clients, possible exposure"

      - alert: RedisDangerousCommand
        expr: increase(redis_commands_total{cmd=~"flushall|flushdb|debug|config|keys"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Dangerous Redis command executed: {{ $labels.cmd }}"
```

## Expected Behaviour

- `redis-cli` without TLS and authentication is rejected
- Application user can read/write data but cannot run `FLUSHALL`, `CONFIG`, `DEBUG`, or `KEYS`
- Admin commands require the admin user with a separate strong password
- All connections encrypted with TLS 1.3
- Redis bound to specific interfaces; not reachable from the internet
- Authentication failures generate alerts

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| TLS on all connections | 1-5% throughput reduction; latency increase for new connections | Applications must configure TLS certificates | Use connection pooling to maintain persistent TLS connections. |
| Disable `KEYS` command | Applications using `KEYS` must switch to `SCAN` | `KEYS` is a common but dangerous pattern (blocks server on large datasets) | Migrate to `SCAN` in application code before disabling. |
| Disable `EVAL` | Lua scripting unavailable | Some applications use Lua scripts for atomic operations | Keep `EVAL` enabled only if the application requires it; restrict to the app_user ACL. |
| ACLs per user | Each application needs its own credentials | More credentials to manage | Use [Vault](https://www.vaultproject.io) for dynamic Redis credentials. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| ACL misconfigured | Application can't connect; `NOAUTH` or `NOPERM` error | Application logs show Redis auth/permission error | Fix ACL file. Reload ACLs: `redis-cli ACL LOAD`. No restart needed. |
| TLS certificate expired | All new connections fail | [cert-manager](https://cert-manager.io) alerts ([Certificate Expiry Monitoring: Automated Detection Across TLS, mTLS, and Signing Certificates](/articles/observability/certificate-expiry-monitoring/)); Redis logs show TLS errors | Renew certificate. Redis requires restart to load new cert (or use `CONFIG SET tls-cert-file`). |
| FLUSHALL executed | All data lost | Monitoring shows key count drops to zero; application errors spike | Restore from RDB/AOF backup. Investigate who executed the command (check Redis slow log and ACL audit). |
| `CONFIG SET dir` exploit | Attacker writes files to disk via Redis | Unexpected files in /var/lib/redis or other directories; Redis slow log shows CONFIG command | Disable CONFIG command via rename-command. Audit written files. Rotate any credentials that may have been compromised. |

## When to Consider a Managed Alternative

Redis HA (Sentinel/Cluster) is operationally complex. TLS certificate management, ACL maintenance, and backup verification add ongoing burden.

- **[Upstash](https://upstash.com):** Serverless Redis with per-request pricing. TLS and auth built-in. Scale to zero.
- **[Redis Inc.](https://redis.io):** Official managed Redis Cloud. From $12/month.
- **[Aiven](https://aiven.io):** Multi-database managed platform with Redis. From $19/month.
- **[Grafana Cloud](https://grafana.com/cloud):** For Redis monitoring dashboards and alerting.

**Premium content pack:** Redis hardening configuration pack. ACL templates by use case (cache, session store, queue), TLS configuration, dangerous command lockdown, Sentinel hardened config, and Prometheus alert rules.


## Related Articles

- [Hardening PostgreSQL for Production: Authentication, Encryption, Row-Level Security, and Audit Logging](/articles/cross-cutting/postgresql-hardening/)
- [Securing Message Queues in Production: Kafka, RabbitMQ, and NATS Hardening](/articles/cross-cutting/message-queue-hardening/)
- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
- [Incident Response Hardening Playbook: From Detection to Post-Mortem](/articles/cross-cutting/incident-response-hardening-playbook/)
