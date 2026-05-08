---
title: "Datadog Security Configuration Hardening"
description: "The Datadog Agent runs with broad system access by default — reading all container logs, hooking the kernel for APM, and transmitting data to Datadog's intake. Hardening covers Agent privilege reduction, API and app key management, RBAC scoping, sensitive data scrubbing, network configuration, and Datadog's own CSPM and audit trail features."
slug: datadog-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - datadog
  - agent-security
  - api-key-management
  - cspm
  - observability
personas:
  - security-engineer
  - platform-engineer
article_number: 551
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/datadog-security-hardening/
---

# Datadog Security Configuration Hardening

## Problem

The Datadog Agent is a privileged process. To do its job — collecting metrics, tailing container logs, tracing application calls, and inspecting network flows — it needs access that most production processes do not have. By default, the DaemonSet runs as root, mounts the host's `/proc` and `/sys` filesystems, reads every container log on the node, and holds an API key that authorises writing data to your Datadog organisation. Each of those capabilities is also an attack surface.

The threats are not hypothetical. An attacker who compromises a container on a node where the Datadog Agent runs as root, with the host filesystem mounted, has a clear path to host breakout. An API key stored in a Kubernetes Secret or a plain environment variable is readable by any process in the same namespace that has `get secrets` permission — or by any engineer who can run `kubectl exec`. An application key scoped to `timeseries:write` for dashboards but leaked grants an attacker the ability to read metrics from every service in your organisation.

Default Datadog deployments also accumulate problems that compound over time:

- **API keys not rotated.** A single API key is used across every environment and every team. A key that has been in production for three years has almost certainly been seen in CI logs, Slack, and configuration files.
- **Application keys over-permissioned.** An app key created for a dashboard-as-code pipeline has `metrics:read` on every service, including services that carry sensitive business data.
- **Sensitive log data transmitted to Datadog.** Application logs contain passwords, tokens, and PII. Without log scrubbing rules, those fields are transmitted to Datadog's intake and indexed in your organisation.
- **Custom Agent checks run arbitrary Python.** The `conf.d/` and `checks.d/` directories hold code that runs as the Agent user. An attacker with write access to those directories executes code under the Agent's privileges.
- **Tag injection crosses team boundaries.** Tags control which dashboards, monitors, and cost views show which data. An application that emits arbitrary `env:` or `team:` tags can pollute other teams' dashboards or inflate their usage metrics.

**Target systems:** Datadog Agent 7.x (current LTS series); Kubernetes DaemonSet deployments using the Datadog Operator or Helm chart; bare-metal and VM deployments; Datadog SaaS (app.datadoghq.com); Datadog CSPM and Cloud Security Management (CSM).

## Threat Model

- **Adversary 1 — API key exfiltration:** An attacker reads the `DD_API_KEY` environment variable from a running container (via `kubectl exec`, a container escape, or a CI log leak). With the API key they can submit arbitrary metrics and logs to the organisation, poisoning dashboards and triggering false monitors.
- **Adversary 2 — Application key abuse:** An over-permissioned application key is leaked from a configuration repository. The attacker uses the key to read metrics and logs from services across the organisation via the Datadog API, harvesting business data and identifying high-value targets.
- **Adversary 3 — Agent privilege escalation:** The Datadog DaemonSet runs as root with host PID namespace and host filesystem access. An attacker who achieves code execution inside a co-located container uses the Agent's kernel access (eBPF hooks, `/proc` read access) to pivot to the host or enumerate process secrets.
- **Adversary 4 — Custom check code injection:** An attacker with write access to the Agent's `checks.d/` directory deploys a malicious custom check. The check executes under the Agent user on every check interval.
- **Adversary 5 — Log data exfiltration via Datadog:** An application logs credential values or user PII. Without scrubbing, those values are ingested by Datadog and accessible to any Datadog user with log query permissions.
- **Adversary 6 — Tag injection for cost manipulation:** A multi-tenant application writes arbitrary `team:` and `service:` tags to its metrics. The inflated tag cardinality pollutes cost allocation dashboards and can cause other teams' monitors to fire on the injected data.
- **Access level:** Adversaries 1–4 require a foothold in the cluster or CI pipeline. Adversary 5 exploits absent data controls. Adversary 6 requires the ability to emit metrics.
- **Objective:** Host breakout, data exfiltration, monitor poisoning, cost fraud.
- **Blast radius:** A compromised Datadog Agent has root on the node and visibility into every process. A leaked application key provides read access to all metrics, logs, and traces across the organisation.

## Configuration

### Step 1: Run the Agent Without Root

The most impactful Agent privilege reduction is switching from the default root user to a dedicated `dd-agent` system user. The Datadog Agent 7.x supports this natively.

```yaml
# datadog-values.yaml — Helm chart configuration.
datadog:
  # Run the Agent as the dd-agent user, not root.
  securityContext:
    runAsUser: 101     # dd-agent UID created by the package installer.
    runAsGroup: 101

  # Drop all Linux capabilities; add back only what is required.
  # Required capabilities for core Agent functionality:
  #   NET_ADMIN: network performance monitoring (remove if NPM not used).
  #   SYS_PTRACE: APM live process monitoring (remove if not used).
  #   SYS_ADMIN: eBPF for USM/NPM (remove if not used).

  containerSecurityContext:
    capabilities:
      drop:
        - ALL
      add:
        - NET_ADMIN      # Network Performance Monitoring only.
        # Remove SYS_ADMIN and SYS_PTRACE if APM and NPM are not in use.
    readOnlyRootFilesystem: true
    allowPrivilegeEscalation: false

  # Mount host paths read-only.
  # The Agent reads /proc and /sys for metrics; it does not need to write them.
  hostPaths:
    - name: procdir
      hostPath: /proc
      mountPath: /host/proc
      readOnly: true        # Explicit read-only mount.
    - name: cgroups
      hostPath: /sys/fs/cgroup
      mountPath: /host/sys/fs/cgroup
      readOnly: true
```

For bare-metal and VM installations, configure the Agent user in `/etc/datadog-agent/datadog.yaml`:

```yaml
# /etc/datadog-agent/datadog.yaml
# The installer creates dd-agent:dd-agent. Run the Agent under this user.
# Confirm with: ps aux | grep datadog
# The systemd unit should specify User=dd-agent.

# Restrict custom check file permissions.
# checks.d/ must be owned by root, not writable by dd-agent.
# chmod 755 /etc/datadog-agent/checks.d/
# chown root:dd-agent /etc/datadog-agent/checks.d/
```

Verify the effective privileges after deployment:

```bash
# Confirm the Agent process is not running as root.
kubectl exec -n datadog ds/datadog -- id
# Expected: uid=101(dd-agent) gid=101(dd-agent) groups=101(dd-agent)

# Confirm no unexpected capabilities.
kubectl exec -n datadog ds/datadog -- cat /proc/1/status | grep Cap
# CapEff should not include CAP_SYS_ADMIN unless NPM/USM is required.
```

### Step 2: API Key and Application Key Management

**API keys** authenticate the Agent to Datadog's intake. **Application keys** authenticate API requests for reading and writing Datadog configuration, metrics, and logs.

**API key hygiene:**

```bash
# Create per-environment API keys — never share one key across environments.
# Datadog UI: Organization Settings > API Keys > New Key.
# Name keys with environment and purpose: "prod-k8s-agent", "staging-k8s-agent".

# Do NOT pass the key as a plain environment variable in a Pod spec.
# BAD:
#   env:
#   - name: DD_API_KEY
#     value: "abc123..."   # Visible in `kubectl get pod -o yaml` by anyone with pod read.

# GOOD: Reference a Kubernetes Secret.
#   env:
#   - name: DD_API_KEY
#     valueFrom:
#       secretKeyRef:
#         name: datadog-secret
#         key: api-key

# Store the actual key in an external secrets manager.
# Use the External Secrets Operator or Vault Agent Injector to sync:

# ExternalSecret example (ESO):
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: datadog-api-key
  namespace: datadog
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: datadog-secret
    creationPolicy: Owner
  data:
    - secretKey: api-key
      remoteRef:
        key: secret/datadog
        property: api_key
```

**Application key scoping:**

```bash
# Application keys carry user-level permissions. Scope them to the minimum.
# Datadog UI: Organization Settings > Application Keys > New Key.

# Principles:
# 1. One app key per consumer (CI pipeline, Terraform, dashboards-as-code tool).
# 2. Scope each key to the minimum required permissions using fine-grained scopes.
# 3. Store in the secrets manager, not in code or CI environment variables in plain text.

# Common minimum scopes by consumer:
# Dashboard-as-code (Terraform):  dashboards:read, dashboards:write, monitors:read, monitors:write
# Metrics read (SLO tool):        metrics:read, timeseries:query
# Log query (SIEM integration):   logs_read_data, logs_read_index_data
# CSPM read (compliance report):  security_monitoring:read

# Keys scoped to dashboards:write CANNOT read metrics.datadoghq.com — verify.
```

**Key rotation policy:**

```bash
# Rotate API keys on a schedule; rotate application keys on personnel changes.
# Use the Datadog API to automate rotation:

# 1. Create the new key.
NEW_KEY=$(curl -s -X POST "https://api.datadoghq.com/api/v2/api_keys" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"data": {"type": "api_keys", "attributes": {"name": "prod-k8s-agent-rotated"}}}' \
  | jq -r '.data.attributes.key')

# 2. Update the external secret in Vault.
vault kv put secret/datadog api_key="${NEW_KEY}"

# 3. The External Secrets Operator syncs the new key to the Kubernetes Secret.
# 4. The Agent picks up the new key on next restart (or rolling restart if needed).
# 5. Revoke the old key after confirming Agent connectivity.
```

### Step 3: RBAC in Datadog

Datadog's RBAC model uses **roles**, **permission scopes**, and **teams**. Default deployments often grant all engineers the Datadog Standard role, which provides read access to all metrics, logs, and traces organisation-wide.

```bash
# Datadog RBAC is configured in the UI or via Terraform.
# Use the datadog_role and datadog_team Terraform resources.

# Example: Restrict log access to team-owned indexes.

resource "datadog_role" "payments_engineer" {
  name = "Payments Engineer"

  permission {
    id = data.datadog_permissions.all.permissions["logs_read_data"]
  }
  permission {
    id = data.datadog_permissions.all.permissions["logs_read_index_data"]
  }
  # No metrics:write, no monitors:write — read-only for metrics.
  permission {
    id = data.datadog_permissions.all.permissions["metrics_read"]
  }
}

# Restrict which log indexes the role can query using log restriction queries.
resource "datadog_logs_index" "payments" {
  name = "payments"
  filter {
    query = "team:payments"   # Only logs tagged team:payments are in this index.
  }
}

# In the Datadog UI: Logs > Indexes > Restriction Queries.
# Assign the restriction query "team:payments" to the Payments Engineer role.
# Members of this role can only query logs where team:payments is present.
```

**Teams-based access control:**

```
# Datadog Teams (GA in 2023) allow dashboard and monitor ownership by team.
# When a team owns a dashboard, non-members can only view it (not edit or delete).
# Assign teams via the UI or the datadog_team Terraform resource.

# Key boundary: Teams do not restrict metric queries via the Metrics Explorer.
# Use log restriction queries and monitor restriction policies for hard data boundaries.
# For metric isolation across tenants, separate Datadog organisations is the only
# fully enforced boundary — teams provide a management boundary, not a data boundary.
```

**Prevent analysts from accessing sensitive service metrics:**

```bash
# Use Metrics without Limits to block forwarding of sensitive metric tags.
# In Datadog UI: Metrics > Metrics without Limits.
# Strip tags that reveal sensitive service internals before indexing.

# Example: strip the "user_id" and "account_id" custom tags from all metrics.
# These tags were added by an application and should not be queryable.

# Via the Datadog API:
curl -X PUT "https://api.datadoghq.com/api/v1/metrics/gauge.payment.latency/tags/configure" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "tags": ["env", "service", "version", "region"]
  }'
# Only the listed tags are retained; user_id and account_id are dropped at ingestion.
```

### Step 4: Network Security

The Agent transmits data to Datadog's intake endpoints. In environments without direct internet access, all Agent traffic must be routed through an authenticated proxy.

```yaml
# /etc/datadog-agent/datadog.yaml — proxy configuration.

# Route all Agent traffic through a corporate proxy.
proxy:
  http: http://proxy.internal.example.com:3128
  https: http://proxy.internal.example.com:3128
  no_proxy:
    - localhost
    - 127.0.0.1
    # Do not bypass the proxy for Datadog intake — keep all traffic inspectable.

# Datadog intake endpoints used by the Agent (allow these through the proxy/firewall):
# intake.datadoghq.com:443     — metrics, events, service checks
# agent-intake.logs.datadoghq.com:443  — log intake
# trace.agent.datadoghq.com:443        — APM traces
# process.datadoghq.com:443            — live process monitoring
# instrumentation-telemetry-intake.datadoghq.com:443  — telemetry

# Use the Agent proxy health check to verify connectivity:
# datadog-agent status | grep "API Keys status"
```

```yaml
# Kubernetes NetworkPolicy — restrict Agent egress to Datadog intake only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: datadog-agent-egress
  namespace: datadog
spec:
  podSelector:
    matchLabels:
      app: datadog
  policyTypes:
    - Egress
  egress:
    # Allow DNS resolution.
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    # Allow HTTPS to Datadog intake.
    # If using a proxy, restrict egress to the proxy IP only.
    - ports:
        - port: 443
          protocol: TCP
    # Allow Agent-to-Agent communication within the cluster (trace collection).
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: datadog
      ports:
        - port: 8126   # APM trace receiver.
          protocol: TCP
        - port: 8125   # DogStatsD.
          protocol: UDP
```

**Verify Agent-to-intake TLS:**

```bash
# The Agent validates Datadog's TLS certificate by default.
# Do not disable SSL verification in production.
# BAD — disables certificate validation:
#   skip_ssl_validation: true

# If a corporate proxy performs TLS inspection, add its CA to the Agent's trust store:
# /etc/datadog-agent/datadog.yaml:
# ca_bundle: /etc/ssl/certs/corporate-proxy-ca.pem
```

### Step 5: Custom Agent Check Security

Custom checks are Python files placed in `/etc/datadog-agent/checks.d/` and run on every check interval. They execute under the Agent's user account.

```bash
# File permission requirements for custom checks.

# The checks.d/ directory must not be writable by the dd-agent user.
# The Agent refuses to load checks not owned by root or dd-agent.
chmod 755 /etc/datadog-agent/checks.d/
chown root:root /etc/datadog-agent/checks.d/
chmod 644 /etc/datadog-agent/checks.d/my_custom_check.py
chown root:root /etc/datadog-agent/checks.d/my_custom_check.py

# Verify the Agent enforces this — a check owned by a non-root/non-dd-agent user
# will be logged as a warning and skipped.

# Code review requirements for custom checks:
# 1. No subprocess calls to shell commands with user-controlled input.
# 2. No network connections except to the monitored service endpoint (defined in conf.yaml).
# 3. No file reads outside /etc/datadog-agent/ or the monitored service's log path.
# 4. No credentials hardcoded in the check file — use conf.yaml init_config or secrets.
# 5. All dependencies must be approved and pinned in requirements-agent-release.txt.
```

```yaml
# /etc/datadog-agent/conf.d/my_custom_check.d/conf.yaml
# Store credentials in conf.yaml, not in the check Python file.
# Use ENC[] syntax for secrets (Datadog Agent secrets management):

init_config:
  # The value is fetched from an external secrets backend at Agent startup.
  db_password: ENC[my_custom_check_db_password]

instances:
  - host: db.internal.example.com
    port: 5432
    username: datadog_monitor
    password: ENC[my_custom_check_db_password]
```

```bash
# Configure the Agent secrets backend.
# /etc/datadog-agent/datadog.yaml:
# secret_backend_command: /usr/local/bin/dd-secrets
# The secrets backend script is called by the Agent to resolve ENC[] values.
# The script must be owned by root, not writable by dd-agent:
chmod 700 /usr/local/bin/dd-secrets
chown root:root /usr/local/bin/dd-secrets
```

### Step 6: Sensitive Data Scrubbing

Datadog provides two mechanisms for scrubbing sensitive data before it leaves the host: log scrubbing rules in `datadog.yaml` and the Sensitive Data Scanner in the Datadog app.

**Agent-side scrubbing (runs before data leaves the host):**

```yaml
# /etc/datadog-agent/datadog.yaml

logs_config:
  # Scrub patterns from log messages before transmission.
  # Uses Go regex syntax. The replacement string replaces the matched group.
  scrubbing_rules:
    # Scrub Bearer tokens from Authorization headers in HTTP access logs.
    - name: "bearer_token"
      pattern: "Bearer\\s+[A-Za-z0-9\\-_=+/]+"
      replacement: "Bearer [REDACTED]"

    # Scrub AWS secret access keys.
    - name: "aws_secret_key"
      pattern: "(?i)(aws_secret_access_key|secretaccesskey)[\\s=:]+([A-Za-z0-9/+=]{40})"
      replacement: "aws_secret_access_key=[REDACTED]"

    # Scrub credit card numbers (basic Luhn pattern — tune for your log format).
    - name: "credit_card"
      pattern: "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b"
      replacement: "[CARD_REDACTED]"

    # Scrub email addresses from user-facing error logs.
    - name: "email_address"
      pattern: "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"
      replacement: "[EMAIL_REDACTED]"

# Scrub sensitive tags from metrics and traces.
# Tags listed here are removed from all data before transmission.
scrubbing:
  additional_keys:
    - password
    - passwd
    - token
    - secret
    - api_key
    - auth
    - credential
```

**APM trace scrubbing:**

```yaml
# /etc/datadog-agent/datadog.yaml

# Scrub query strings from HTTP spans (removes ?api_key=... from URL tags).
apm_config:
  obfuscation:
    http:
      remove_query_string: true        # Remove ?query=... from HTTP resource names.
      remove_paths_with_digits: false  # Keep /api/v2/orders/123 readable.
    redis:
      enabled: true                    # Obfuscate Redis command values.
    memcached:
      enabled: true
    elasticsearch:
      enabled: true
      keep_values: []                  # Do not retain any query parameter values.
    mongodb:
      enabled: true
      keep_values: []

  # Replace specific span tag values with redacted placeholders.
  replace_tags:
    - name: "http.url"
      pattern: "(token|api_key|secret|password)=[^&]*"
      repl: "$1=[REDACTED]"
    - name: "db.statement"
      pattern: "password\\s*=\\s*'[^']*'"
      repl: "password='[REDACTED]'"
```

**Datadog Sensitive Data Scanner (in-app, post-ingestion):**

The Sensitive Data Scanner scans logs, APM events, and RUM events after ingestion. Configure scanning groups in **Organization Settings > Sensitive Data Scanner**.

```
Recommended scanning rules to enable:
- Credit Card Numbers (PCI DSS)
- US Social Security Numbers
- AWS Access Key IDs and Secret Keys
- Basic Auth credentials in URLs
- Private Key material (RSA, EC, PGP)
- API key patterns (generic high-entropy strings)

Scanning group configuration:
- Apply to indexes: all-logs (or restrict to indexes known to contain PII)
- Action on match: Redact (replaces matched value with [REDACTED])
  - Use "Hash" instead of "Redact" for fields needed for correlation (e.g., user IDs)
  - Use "Partially Redact" for fields where format matters (e.g., last 4 digits of card)
- Alert on: new rule matches to detect uncontrolled PII sources
```

### Step 7: Datadog CSPM and Cloud Security Management

Datadog Cloud Security Posture Management (CSPM) and Cloud Security Management (CSM) are distinct from Agent hardening — they use Datadog as a detection platform for cloud misconfigurations and runtime threats.

```yaml
# Enable CSPM in the Datadog Operator configuration.
datadog:
  securityAgent:
    compliance:
      enabled: true       # CSPM: continuous cloud config assessment.
      checkInterval: 20m  # How often to re-evaluate posture rules.
    runtime:
      enabled: true       # CSM Threats: runtime anomaly detection via eBPF.
      syscallMonitor:
        enabled: true     # Monitor syscall patterns for container escapes.
```

```bash
# CSPM evaluates your cloud accounts against CIS Benchmarks and Datadog's own rules.
# Key findings to prioritise:
# - S3 buckets with public access
# - IAM roles with * actions
# - Security groups open to 0.0.0.0/0 on sensitive ports
# - Unencrypted EBS volumes and RDS instances
# - CloudTrail logging disabled
# - MFA not enforced for IAM console access

# CSPM findings appear in Security > Posture Management.
# Export findings to a SIEM via the Datadog webhook integration or the Events API:
curl "https://api.datadoghq.com/api/v2/posture_management/findings" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -G --data-urlencode "filter[status]=failed" \
  --data-urlencode "filter[severity]=critical"
```

**CSM Threats — runtime detection policies:**

```yaml
# Example Datadog Security Rule (YAML format for import).
# Detect a shell spawned inside a container that should not have one.
# Rules > New Rule > Workload Security.
id: custom-shell-in-container
name: "Shell Spawned in Non-Interactive Container"
enabled: true
type: workload_security
query: exec.file.name in ["sh", "bash", "zsh", "dash"] && container.id != ""
  && !process.ancestors.file.name in ["entrypoint.sh", "docker-entrypoint.sh"]
threshold: 1
window: 5m
severity: high
actions:
  - type: alert
    targets:
      - "@security-team"
```

### Step 8: Audit Trail

Datadog Audit Trail records API and UI actions taken by users and service accounts. Enable it in **Organization Settings > Audit Trail**.

```bash
# Audit Trail covers:
# - API key created, deleted, or revoked
# - Application key created, deleted, or modified
# - Dashboard created, modified, or deleted
# - Monitor created, muted, or deleted
# - User invited, role changed, or removed
# - Log index configuration changed
# - Sensitive Data Scanner rule modified
# - RBAC role or permission changed

# Query Audit Trail via the Logs product (audit events are in the _datadog index).
# Example query in Datadog Logs:
# source:datadog @action:modified @resource_type:dashboard

# Forward Audit Trail events to a SIEM.
# Organisation Settings > Audit Trail > Archive to S3/Azure Blob/GCS.
# Or use a Datadog log forwarding rule to route _datadog-sourced logs to an archive.
```

Critical audit events to alert on:

```
@action:deleted @resource_type:api_key              — API key deleted (check for key revocation as cover for activity)
@action:created @resource_type:application_key      — New app key created (verify authorised requestor)
@action:modified @resource_type:user @attribute:role — Role escalation (Viewer to Admin)
@action:modified @resource_type:logs_index          — Log index filter changed (could hide events)
@action:deleted @resource_type:monitor              — Monitor deleted (check for silencing detection)
@action:modified @resource_type:sensitive_data_scanner — Scrubbing rule disabled
```

### Step 9: Tag Security and Injection Prevention

Tags are Datadog's primary dimension for routing, filtering, and cost allocation. Unbounded tag emission from applications creates two risks: tag injection (an application emits tags belonging to another team) and cardinality explosion (high-cardinality tags like `request_id` generate billions of tag combinations, inflating cost).

```yaml
# /etc/datadog-agent/datadog.yaml

# Global tags applied to all data from this Agent.
# These override conflicting tags from applications.
tags:
  - env:production
  - region:us-east-1
  - cluster:prod-k8s-01
  - owner:platform-team    # Authoritative ownership tag, set by the Agent.

# Prevent applications from emitting tags that override Agent-set tags.
# For DogStatsD metrics from applications:
dogstatsd_config:
  # Tag cardinality limits per metric.
  # This does not prevent injection but limits blast radius.
  dogstatsd_tag_cardinality: orchestrator  # low | orchestrator | high

# For Kubernetes pod tags — use allowlists to control which pod labels
# become metric tags. Broad label extraction can expose internal labels.
kubernetes_pod_labels_as_tags:
  app: service          # Map the "app" label to the "service" tag.
  version: version      # Map "version" label to "version" tag.
  team: team            # Map "team" label to "team" tag.
  # Do NOT add: "*": "*" — this maps all labels, including internal ones.

kubernetes_pod_annotations_as_tags:
  ad.datadoghq.com/tags: dd_tags  # Only extract Datadog-specific annotations.
```

```bash
# For multi-tenant environments, restrict DogStatsD tag emission at the Agent.
# Use the origin detection feature to attribute DogStatsD metrics to the
# originating container, preventing cross-namespace tag spoofing.

# /etc/datadog-agent/datadog.yaml:
# dogstatsd_origin_detection: true
# dogstatsd_origin_detection_client: true
#
# When origin detection is enabled, the Agent validates that the container
# emitting the metric matches the container identified by the socket credentials.
# Tags emitted by the application that conflict with Agent-authoritative tags
# (env, service, version from DD_ENV/DD_SERVICE/DD_VERSION) are overridden.
```

### Step 10: Telemetry and Alerting

```
# Datadog Agent self-monitoring metrics (available as standard Agent metrics):
datadog.agent.running{*}                    gauge   — 0 means Agent is down
datadog.dogstatsd.udp_packets_received      counter — DogStatsD traffic volume
datadog.agent.collector.error_count{*}      gauge   — check collection errors
datadog.logs_agent.bytes_sent              counter  — log bytes transmitted

# Custom monitors to add:
```

Alert on:

- `datadog.agent.running` = 0 for any node — Agent gap creates a blind spot in security coverage.
- Audit Trail: `@action:created @resource_type:application_key` outside of approved change window — unauthorised key creation.
- Audit Trail: `@action:modified @resource_type:sensitive_data_scanner` — scrubbing rule disabled or weakened.
- Sensitive Data Scanner match spike — application change is emitting a new PII field.
- API key usage from unexpected source IP — key may be in use by an unauthorised party (check Audit Trail for the key's last use origin).

## Expected Behaviour

| Signal | Default Datadog Deployment | Hardened Datadog Deployment |
|--------|---------------------------|----------------------------|
| Agent process user | root | dd-agent (UID 101); no privilege escalation |
| Host filesystem mounts | Read-write in some configurations | Read-only for /proc, /sys, /var/log |
| API key storage | DD_API_KEY env var in Pod spec | External Secrets Operator from Vault; never in Pod YAML |
| Application key scope | All permissions (Admin key used for everything) | One key per consumer, scoped to minimum permissions |
| Log PII in Datadog | Transmitted and indexed | Scrubbed at Agent before transmission; Scanner catches residual |
| Custom checks | Any user can write to checks.d/ | checks.d/ owned by root; code review required |
| Tag emission | Unlimited; apps can override env/team tags | Origin detection active; Agent-authoritative tags override app tags |
| Audit Trail | Not enabled or not monitored | Enabled; forwarded to SIEM; alerting on key events |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Drop SYS_ADMIN capability | Eliminates eBPF-based host attack surface | Network Performance Monitoring and USM require SYS_ADMIN | Evaluate whether NPM/USM value justifies the capability; use dedicated nodes |
| Per-environment API keys | Limits blast radius of key compromise | More keys to manage and rotate | Automate rotation with Vault + External Secrets Operator |
| Agent-side log scrubbing | PII never leaves the host | Regex performance overhead on high-volume log streams | Profile on staging before enabling in production; use specific patterns, not .* |
| Log restriction queries | Analysts see only their team's logs | Configuration overhead; teams must tag logs consistently | Enforce `team:` tag via Agent config; validate in CI |
| CSPM and CSM | Continuous posture assessment | Additional Datadog cost; requires cloud account permissions | Prioritise critical and high findings; suppress known accepted risks |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| API key rotated but Agent not restarted | Agent stops sending data after old key revoked | `datadog.agent.running` = 0; missing metric gaps | Automate rolling restart after External Secret sync; use Agent readiness probe |
| Overly broad scrubbing regex | Legitimate log content redacted; alert noise | Logs show `[REDACTED]` where data is needed for triage | Use anchored patterns with specific context; test on sample data before deploying |
| Custom check with syntax error | Check silently skipped; metric gap | `datadog.agent.collector.error_count` spike | Validate check syntax before deploy: `datadog-agent check my_custom_check` |
| CSPM permissions too narrow | CSPM shows no findings (false green) | Expected findings absent; compare against manual audit | Review IAM role attached to Datadog AWS integration; CSPM requires SecurityAudit at minimum |
| Origin detection breaks legacy StatsD | Metrics from legacy StatsD clients stop arriving | DogStatsD drops unverifiable packets | Migrate clients to Datadog StatsD client with container ID support; or exempt specific pods |

## Related Articles

- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
- [Prometheus Security Metrics](/articles/observability/prometheus-security-metrics/)
- [Grafana Security Hardening](/articles/observability/grafana-security-hardening/)
- [Loki Security Hardening](/articles/observability/loki-security-hardening/)
- [Kubernetes Secrets Management](/articles/kubernetes/secrets-management/)
- [eBPF Security with Tetragon](/articles/observability/ebpf-tetragon/)
