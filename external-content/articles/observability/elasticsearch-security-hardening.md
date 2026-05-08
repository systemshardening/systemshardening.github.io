---
title: "Elasticsearch Security Hardening: TLS, Role-Based Access, and Audit Logging"
description: "Elasticsearch clusters exposed without authentication have been the source of hundreds of data breaches. Enabling TLS between nodes and clients, configuring role-based access control, and enabling audit logging closes the most common attack vectors against ELK and EFK stacks."
slug: "elasticsearch-security-hardening"
date: 2026-05-01
lastmod: 2026-05-01
category: "observability"
tags: ["elasticsearch", "opensearch", "elk-stack", "tls", "rbac", "audit-logging"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 307
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/observability/elasticsearch-security-hardening/index.html"
---

# Elasticsearch Security Hardening: TLS, Role-Based Access, and Audit Logging

## Problem

Elasticsearch clusters have been found exposed on the internet without authentication more times than any other database type. Shodan regularly indexes tens of thousands of open Elasticsearch instances containing customer data, credentials, and internal system logs. The reason is almost always the same: Elasticsearch's default configuration enables no security features, and teams deploying it for internal use fail to enable them before the cluster becomes accessible.

Even internally, an Elasticsearch cluster without authentication is a significant risk:

- **All data accessible without credentials.** Elasticsearch's default configuration accepts all HTTP requests. Any process that can reach port 9200 reads and modifies any index — including security event logs, application logs containing PII, and user data.
- **No node-to-node encryption.** In a multi-node cluster, data replication between nodes occurs over unencrypted HTTP. An attacker on the internal network captures replication traffic to read all cluster data.
- **Kibana passes credentials in plaintext.** Without HTTPS between Kibana and users, session tokens and basic auth credentials are transmitted in cleartext.
- **No index-level access control.** Without role-based access control, every user who can authenticate can read every index — including security event data, access logs, and audit trails.
- **No audit trail of data access.** Elasticsearch does not log which user read which documents by default. An insider who exfiltrates data from Elasticsearch leaves no trace.

**Target systems:** Elasticsearch 8.x (security enabled by default); Elasticsearch 7.x (security requires manual configuration); OpenSearch 2.x (fork of Elasticsearch 7.10 with security plugin); self-managed and cloud deployments.

## Threat Model

- **Adversary 1 — Unauthenticated access from internet:** An Elasticsearch cluster is accessible from the internet (misconfigured security group, cloud firewall, or Kubernetes service). An attacker queries `http://host:9200/_cat/indices` and receives a list of all indices, then dumps all data.
- **Adversary 2 — Internal network sniffing of node traffic:** An attacker on the internal network captures Elasticsearch node-to-node traffic. All data being replicated — including security logs — is readable in plaintext without TLS transport encryption.
- **Adversary 3 — Over-permissive role access to sensitive indices:** A log aggregation role can read all indices including `security-events-*` and `user-sessions-*`. A user with only the log aggregation role should not read security events.
- **Adversary 4 — API key exfiltration:** Elasticsearch API keys are stored as documents and accessible to admins. An admin whose credentials are compromised lists all API keys and uses them to authenticate as other users.
- **Adversary 5 — Audit log bypass:** An attacker who reads sensitive documents does not appear in any log because audit logging is not enabled. Forensic investigation finds no evidence of the access.
- **Access level:** Adversary 1 needs network access. Adversaries 2 and 3 need internal network position. Adversary 4 needs compromised admin credentials. Adversary 5 exploits a configuration gap.
- **Objective:** Extract logs containing credentials, PII, security events; establish persistent access; evade forensic detection.
- **Blast radius:** An Elasticsearch cluster aggregating logs from all systems contains a complete record of internal activity. Exfiltration gives an attacker insight into every system's behaviour, credentials logged in error messages, and security control configurations.

## Configuration

### Step 1: Enable TLS for HTTP and Transport

Elasticsearch 8.x enables security by default. For older versions or manual configuration:

```yaml
# elasticsearch.yml

# Cluster identity.
cluster.name: production-logging
node.name: es-node-1

# Enable security (required for auth, TLS, RBAC).
xpack.security.enabled: true

# Transport layer TLS (between Elasticsearch nodes).
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: /etc/elasticsearch/certs/node.p12
xpack.security.transport.ssl.truststore.path: /etc/elasticsearch/certs/node.p12

# HTTP layer TLS (client to Elasticsearch).
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: /etc/elasticsearch/certs/http.p12
```

```bash
# Generate certificates using Elasticsearch's built-in CA tool.
# Creates a CA and per-node certificates.
elasticsearch-certutil ca --out /etc/elasticsearch/certs/elastic-stack-ca.p12 --pass ""
elasticsearch-certutil cert \
  --ca /etc/elasticsearch/certs/elastic-stack-ca.p12 \
  --dns es-node-1,es-node-1.example.com \
  --ip 10.0.50.10 \
  --out /etc/elasticsearch/certs/node.p12 \
  --pass ""

# Generate HTTP TLS certificate.
elasticsearch-certutil http
# Interactive wizard; generates kibana/elasticsearch certificates.
```

```bash
# Set the built-in user passwords after enabling security.
elasticsearch-setup-passwords interactive
# Sets passwords for: elastic, kibana_system, logstash_system, beats_system, apm_system, remote_monitoring_user.

# Store passwords in Vault, not in configuration files.
vault kv put secret/elasticsearch/bootstrap \
  elastic_password="$(openssl rand -base64 32)" \
  kibana_system_password="$(openssl rand -base64 32)"
```

### Step 2: Role-Based Access Control

Create roles with minimum required permissions per user type:

```bash
# Elasticsearch REST API: create roles.

# Read-only role for Kibana dashboard viewers (log data only).
curl -X PUT "https://es-node-1:9200/_security/role/log-viewer" \
  -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": [
      {
        "names": ["logs-*", "metrics-*"],
        "privileges": ["read", "view_index_metadata"]
      }
    ],
    "applications": [
      {
        "application": "kibana-.kibana",
        "privileges": ["read"],
        "resources": ["*"]
      }
    ]
  }'

# Security team role: read security indices; cannot write.
curl -X PUT "https://es-node-1:9200/_security/role/security-analyst" \
  -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": [
      {
        "names": ["security-events-*", "audit-logs-*", "logs-*"],
        "privileges": ["read", "view_index_metadata"]
      }
    ]
  }'

# Log ingest role for Logstash/Fluent Bit (write-only; no read).
curl -X PUT "https://es-node-1:9200/_security/role/log-ingest" \
  -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": [
      {
        "names": ["logs-*", "metrics-*"],
        "privileges": ["create_index", "create", "index", "write"]
      }
    ]
  }'

# Platform admin role: manage indices and cluster settings; cannot read data.
# "manage" privilege allows index lifecycle management but not data access.
curl -X PUT "https://es-node-1:9200/_security/role/platform-admin" \
  -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster": ["monitor", "manage_ilm", "manage_index_templates"],
    "indices": [
      {
        "names": ["*"],
        "privileges": ["manage", "monitor"]
        # NOT: read, write, delete.
      }
    ]
  }'
```

### Step 3: API Keys for Service Authentication

Use API keys for service-to-service authentication (Logstash, Fluent Bit, Beats):

```bash
# Create an API key for Logstash with a specific role.
curl -X POST "https://es-node-1:9200/_security/api_key" \
  -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "logstash-ingest-key",
    "expiration": "365d",
    "role_descriptors": {
      "log-ingest": {
        "indices": [
          {
            "names": ["logs-*"],
            "privileges": ["create_index", "create", "index"]
          }
        ]
      }
    }
  }'

# Store the API key in Vault; inject into Logstash via environment variable.
# logstash.conf:
# elasticsearch {
#   hosts => ["https://es-node-1:9200"]
#   api_key => "${ELASTICSEARCH_API_KEY}"
#   ssl_certificate_authorities => ["/etc/logstash/certs/ca.crt"]
# }
```

### Step 4: Audit Logging

```yaml
# elasticsearch.yml — enable audit logging.
xpack.security.audit.enabled: true

# Log all security-relevant events.
xpack.security.audit.logfile.events.include:
  - authentication_success
  - authentication_failed
  - anonymous_access_denied
  - access_denied
  - access_granted
  - connection_denied
  - run_as_granted
  - security_config_change
  - api_key_created
  - api_key_invalidated

# Log which indices were accessed (important for data access audit).
xpack.security.audit.logfile.events.include:
  - access_granted
# With emit_request_body: false (default) — logs the request metadata, not the body.

# Output to a dedicated log file (keep separate from application logs).
xpack.security.audit.logfile.path: /var/log/elasticsearch/audit.log
```

```bash
# Ship audit logs to a separate, tamper-resistant destination.
# Elasticsearch audit logs should NOT be stored in Elasticsearch itself.
# Store in: S3 with Object Lock, a separate SIEM, or an immutable log store.

# /etc/filebeat/filebeat.yml — ship ES audit logs.
filebeat.inputs:
  - type: log
    paths:
      - /var/log/elasticsearch/audit.log
    fields:
      log_type: elasticsearch_audit

output.elasticsearch:
  # Different ES cluster for audit logs — separate from the audited cluster.
  hosts: ["https://audit-es:9200"]
  api_key: "${AUDIT_ES_API_KEY}"
```

### Step 5: Index-Level Document Security

Restrict which documents a role can see within an index (field-level and document-level security):

```bash
# Role that can only read non-PII fields from user logs.
curl -X PUT "https://es-node-1:9200/_security/role/sanitised-log-reader" \
  -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": [
      {
        "names": ["logs-app-*"],
        "privileges": ["read"],
        "field_security": {
          "grant": ["timestamp", "level", "message", "service", "trace_id"],
          "except": ["user.email", "user.ip", "user.name", "request.body"]
        },
        "query": "{\"term\": {\"environment\": \"production\"}}"
      }
    ]
  }'
# This role: can read production logs; cannot see PII fields; no staging logs.
```

### Step 6: Network Access Controls

```yaml
# Kubernetes NetworkPolicy for Elasticsearch pods.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: elasticsearch-access
  namespace: logging
spec:
  podSelector:
    matchLabels:
      app: elasticsearch
  policyTypes:
    - Ingress
  ingress:
    # Kibana can reach Elasticsearch on 9200.
    - from:
        - podSelector:
            matchLabels:
              app: kibana
      ports:
        - port: 9200

    # Log shippers (Logstash, Fluent Bit) on 9200.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: logging-agents
      ports:
        - port: 9200

    # ES node-to-node transport on 9300.
    - from:
        - podSelector:
            matchLabels:
              app: elasticsearch
      ports:
        - port: 9300

    # Monitoring (Prometheus) on 9114 (Elasticsearch exporter).
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 9114
    # NO: direct developer access to port 9200.
    # Developers access Elasticsearch via Kibana only.
```

### Step 7: Index Lifecycle Management for Log Retention

```bash
# ILM policy: move old indices to cheaper storage; delete after retention period.
curl -X PUT "https://es-node-1:9200/_ilm/policy/standard-logs-policy" \
  -u "elastic:$ELASTIC_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "min_age": "0ms",
          "actions": {
            "rollover": {
              "max_primary_shard_size": "50gb",
              "max_age": "1d"
            }
          }
        },
        "warm": {
          "min_age": "7d",
          "actions": {
            "forcemerge": {"max_num_segments": 1},
            "shrink": {"number_of_shards": 1}
          }
        },
        "cold": {
          "min_age": "30d",
          "actions": {
            "freeze": {}
          }
        },
        "delete": {
          "min_age": "90d",
          "actions": {
            "delete": {}
          }
        }
      }
    }
  }'

# Security audit logs: longer retention.
# Override: "delete.min_age": "365d" for security-events-* indices.
```

### Step 8: Telemetry

```
elasticsearch_cluster_health_status{cluster}                        gauge
elasticsearch_jvm_memory_used_bytes{node}                           gauge
elasticsearch_indices_docs_total{index}                             gauge
elasticsearch_security_authentication_attempts_total{result, realm} counter
elasticsearch_security_access_denied_total{principal, index}        counter
elasticsearch_audit_events_total{event_type}                        counter
elasticsearch_transport_connections_total{from_node}                counter
```

Alert on:

- `elasticsearch_security_authentication_attempts_total{result="failure"}` spike — credential stuffing or brute-force against Elasticsearch.
- `elasticsearch_security_access_denied_total` — a user is attempting to access indices they are not authorised for.
- Cluster health status RED — data loss risk; shards unassigned.
- Node leaving the cluster unexpectedly — check for network partition or OOM kill.
- Audit log shipping failure — audit trail may have gaps; investigate immediately.

## Expected Behaviour

| Signal | Default Elasticsearch | Hardened Elasticsearch |
|--------|----------------------|----------------------|
| Anonymous API access | All data readable | 401 Unauthorized; TLS required |
| Node-to-node data replication | Plaintext HTTP | TLS transport encryption |
| Log shipper reads all indices | No restrictions | API key limited to write-only on specific indices |
| Security event access by log viewer | All indices accessible | Role restricted to non-security indices |
| Data access by insider | No audit trail | Audit log records user, action, index, and timestamp |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| TLS on all connections | Encrypts all data in transit | Certificate management overhead | Use elasticsearch-certutil; integrate with cert-manager for Kubernetes |
| Fine-grained index RBAC | Principle of least privilege per team | More roles to manage; onboarding complexity | Document role matrix; automate role assignment via IdP groups |
| Audit logging | Complete data access record | Disk space; I/O overhead (~5-10%) | Log to separate cluster; use ILM to rotate audit logs |
| Field-level security | PII fields hidden from non-PII roles | Complex to configure; may miss new PII fields | Define PII fields in a central schema; automate field list maintenance |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| TLS cert expired | All clients fail to connect; TLS handshake error | Cluster health alert; connection errors | Rotate certificates; restart Elasticsearch nodes |
| Role too restrictive for Kibana | Kibana shows "access denied" for dashboard | User complaint; Kibana error log | Add missing index privilege to role; no restart required |
| Audit log disk fills | Audit logging stops silently | Audit log file size; disk space alert | ILM policy for audit index; increase storage |
| Built-in password not set | `elastic` user has no password; security not activated | First `curl` returns 200 without auth | Run `elasticsearch-setup-passwords`; enable security configuration |
| API key not rotated | Old key still in use after service account change | API key age metric | Rotate API keys annually; alert at 300 days |

## Related Articles

- [Loki Security Hardening](/articles/observability/loki-security-hardening/)
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [Audit Log Pipeline](/articles/observability/audit-log-pipeline/)
- [Log Integrity](/articles/observability/log-integrity/)
- [SIEM Cost Optimisation](/articles/observability/siem-cost-optimization/)
