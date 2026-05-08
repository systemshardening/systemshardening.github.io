---
title: "Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch"
description: "Linux audit logs are the ground truth for security investigation. auditd captures kernel-level events that no userspace tool can see: file access by..."
slug: "audit-log-pipeline"
date: 2026-01-13
lastmod: 2026-01-13
category: "observability"
tags: ["auditd", "logging", "elasticsearch", "loki", "security-monitoring", "audit"]
personas: ["security-engineer", "sre"]
article_number: 62
difficulty: "advanced"
estimated_reading_time: 22
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Axiom"
    id: 112
    category: "observability"
  - name: "Better Stack"
    id: 113
    category: "observability"
premium_pack: "auditd-rule-collection"
published: true
layout: article.njk
permalink: "/articles/observability/audit-log-pipeline/index.html"
---

# Building a Security Audit Log Pipeline That Scales: [auditd](https://github.com/linux-audit/audit-userspace) to [Elasticsearch](https://www.elastic.co/elasticsearch)

## Problem

Linux audit logs are the ground truth for security investigation. auditd captures kernel-level events that no userspace tool can see: file access by any process, syscall execution, user command logging, privilege changes, and authentication events. But auditd's raw output is cryptic multi-line records, high-volume (1-5GB per host per day under standard rules), and local to each host. Without a pipeline that collects, normalises, ships, and indexes these logs centrally, they are useless for incident response and invisible to security monitoring.

The specific challenges:

- **Raw format is unreadable.** auditd produces multi-line records with numeric syscall codes and hex-encoded arguments. Searching for "who read /etc/shadow" requires joining multiple record types (SYSCALL + PATH + CWD + PROCTITLE) by audit ID.
- **Volume grows fast.** Standard CIS-level audit rules generate 1-5GB per host per day. A 20-host fleet produces 20-100GB per day. Without retention management, storage costs are unbounded.
- **Local logs are useless for central monitoring.** auditd writes to `/var/log/audit/audit.log` on each host. If the host is compromised, the attacker deletes the local logs. If you need to search across hosts, you log into each one individually.
- **Self-managed Elasticsearch is a full-time job.** Running Elasticsearch for security logs requires index lifecycle management, shard sizing, capacity planning, cluster health monitoring, and backup, effectively a dedicated engineering role at scale.

This article provides the complete pipeline: auditd rules → log shipping → structured transformation → centralized storage → security alerting.

**Target systems:** Ubuntu 24.04 LTS, RHEL 9, any Linux with auditd. [Vector](https://vector.dev) or [Fluentd](https://www.fluentd.org) for shipping. Elasticsearch, [Loki](https://grafana.com/oss/loki/), or managed backend for storage.

## Threat Model

- **Adversary:** Any attacker operating on Linux hosts. Audit logs detect: privilege escalation (sudo, setuid), unauthorized file access (shadow, SSH keys), user creation/modification, suspicious process execution, and network connections from unexpected processes.
- **Blast radius:** Without centralized audit logs, attacker deletes local logs after compromise, leaving zero evidence. With centralized logs shipped in near-real-time, forensic evidence is preserved off-host before the attacker can destroy it.

## Configuration

### auditd Rule Design

```bash
# /etc/audit/rules.d/hardening.rules
# Security-relevant audit rules for production hosts.
# Applied with: sudo augenrules --load

# --- Rule ordering for performance ---
# Exit rules are evaluated first. Put high-frequency exclusions at the top
# to reduce processing overhead.

# Exclude high-volume, low-value events
-a always,exclude -F msgtype=CWD
-a always,exclude -F msgtype=EOE

# --- File access monitoring ---
# Monitor reads/writes to sensitive files.
-w /etc/shadow -p rwa -k shadow_access
-w /etc/passwd -p rwa -k passwd_access
-w /etc/group -p rwa -k group_access
-w /etc/sudoers -p rwa -k sudoers_access
-w /etc/ssh/sshd_config -p rwa -k sshd_config
-w /root/.ssh -p rwa -k root_ssh
-w /etc/crontab -p rwa -k cron_access
-w /etc/cron.d -p rwa -k cron_access
-w /var/spool/cron -p rwa -k cron_access

# --- User/group changes ---
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification

# --- Privilege escalation ---
# Monitor execve with setuid/setgid bits
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid!=0 -F auid!=4294967295 -k privilege_escalation

# Monitor su and sudo usage
-w /usr/bin/su -p x -k su_usage
-w /usr/bin/sudo -p x -k sudo_usage

# --- Process execution logging ---
# Log all process execution (WARNING: high volume on busy systems)
# Enable selectively or use a lower-volume alternative below.
# -a always,exit -F arch=b64 -S execve -k exec_log

# Lower-volume alternative: log execution only by non-system users
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k user_exec

# --- Kernel module loading ---
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b64 -S delete_module -k module_unload

# --- Network connections (optional - high volume) ---
# Log outbound connections from non-standard processes
# -a always,exit -F arch=b64 -S connect -F a0!=10 -k network_connect

# --- Make rules immutable (must reboot to change) ---
# Uncomment after testing is complete:
# -e 2
```

### auditd.conf Tuning

```ini
# /etc/audit/auditd.conf - tuned for production
# Prevent audit event loss under high load.

# Buffer size: number of events to buffer before writing.
# Default is 8192. Increase for busy systems.
max_log_file_action = rotate
max_log_file = 50
num_logs = 10

# Backlog limit: kernel buffer for audit events.
# If this fills, events are LOST (or system hangs, depending on failure_mode).
# 8192 is the minimum for production. 32768 for busy systems.
backlog_limit = 32768

# What happens when the disk is full:
space_left = 100
space_left_action = email
admin_space_left = 50
admin_space_left_action = halt
# 'halt' stops the system when audit can't log. Use 'syslog' if availability > audit integrity.

# Flush frequency: higher = less data loss on crash, more I/O.
freq = 50
```

```bash
# Apply rules and verify:
sudo augenrules --load
sudo auditctl -l  # List active rules
sudo auditctl -s  # Show audit status (check 'lost' counter = 0)

# If 'lost' > 0: increase backlog_limit and restart auditd.
```

### Log Shipping with Vector

Vector (by Datadog, Apache 2.0 licensed) is recommended over Fluentd for new deployments: lower memory usage, faster processing, and native structured log support.

```yaml
# /etc/vector/vector.yaml
# Ship audit logs from auditd to centralized backend.

sources:
  audit_logs:
    type: journald
    include_units:
      - auditd.service
    # Alternative: read from file directly
    # type: file
    # include:
    #   - /var/log/audit/audit.log

transforms:
  parse_audit:
    type: remap
    inputs:
      - audit_logs
    source: |
      # Parse auditd log format into structured fields
      . = parse_key_value!(.message, key_value_delimiter: "=", field_delimiter: " ")
      .timestamp = now()
      .host = get_hostname!()
      .source = "auditd"

  enrich:
    type: remap
    inputs:
      - parse_audit
    source: |
      # Add environment metadata
      .environment = "production"
      .cluster = "web-fleet"

sinks:
  # Option 1: Elasticsearch
  elasticsearch:
    type: elasticsearch
    inputs:
      - enrich
    endpoints:
      - "https://elasticsearch.example.com:9200"
    index: "audit-logs-%Y.%m.%d"
    auth:
      strategy: basic
      user: "${ES_USER}"
      password: "${ES_PASSWORD}"

  # Option 2: Grafana Cloud Loki
  # loki:
  #   type: loki
  #   inputs:
  #     - enrich
  #   endpoint: "https://logs-prod-us-central1.grafana.net"
  #   auth:
  #     strategy: basic
  #     user: "${LOKI_USER}"
  #     password: "${LOKI_API_KEY}"
  #   labels:
  #     host: "{{ host }}"
  #     source: "auditd"
  #     environment: "{{ environment }}"

  # Option 3: Axiom
  # axiom:
  #   type: axiom
  #   inputs:
  #     - enrich
  #   dataset: "audit-logs"
  #   token: "${AXIOM_API_TOKEN}"
```

### Security Alert Rules

```yaml
# Prometheus alert rules (via Elasticsearch exporter or Loki alerting)
# These detect the most critical security events in audit logs.

groups:
  - name: audit-security-alerts
    rules:
      - alert: ShadowFileAccessed
        expr: count_over_time({source="auditd"} |= "shadow_access" [5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "/etc/shadow was accessed"
          runbook: "Investigate: which process, which user, from which host. Check for unauthorized access."

      - alert: UserCreatedOrModified
        expr: count_over_time({source="auditd"} |= "user_modification" [5m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "User account created or modified"
          runbook: "Verify this was an authorised change. Check for attacker persistence (new user account)."

      - alert: KernelModuleLoaded
        expr: count_over_time({source="auditd"} |= "module_load" [5m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "Kernel module loaded"
          runbook: "Verify the module is expected. Unexpected module loading may indicate rootkit installation."

      - alert: PrivilegeEscalation
        expr: count_over_time({source="auditd"} |= "privilege_escalation" [5m]) > 5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Multiple privilege escalation events detected"
          runbook: "Check for brute-force sudo/su attempts or exploitation of setuid binaries."
```

## Expected Behaviour

- Audit logs from all hosts arrive in centralized storage within 30 seconds of generation
- `auditctl -s` shows `lost = 0` (no events dropped)
- Security queries return results within 5 seconds for the 30-day retention window
- Alert fires within 2 minutes of a security event (shadow access, user creation, privilege escalation)
- No audit event loss under sustained load (verified with auditctl status)
- 30-day retention minimum for investigation; 12-month archival for compliance

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Comprehensive audit rules (CIS-level) | 1-5GB/host/day log volume | Storage costs grow linearly with fleet size; auditd adds 1-3% CPU overhead | Exclude high-volume, low-value events. Ship to cost-effective storage (Loki over Elasticsearch). |
| Elasticsearch backend | Full-text search, mature alerting ecosystem | Cluster management is a full-time job past 20 hosts | **This is the primary transition trigger**. switch to managed backend when ES management exceeds available engineering time. |
| Loki backend | 5-10x cheaper than Elasticsearch; simpler operations | Label-based queries only (no full-text search across log content) | Use Loki for cost-effective retention; supplement with Grafana dashboards for common security queries. |
| Real-time shipping (Vector) | Sub-30-second delivery; attacker cannot delete logs before shipping | Network bandwidth (1-5GB/host/day); Vector resource usage (50-100MB RAM) | Vector's disk buffer prevents loss during network outages. |
| `backlog_limit = 32768` | Prevents audit event loss on busy systems | Higher kernel memory usage (~256KB) | Negligible on modern systems. Monitor `auditctl -s` lost counter. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| auditd buffer overflow | Events lost; `auditctl -s` shows `lost > 0` | Monitor `lost` counter via Prometheus node_exporter textfile | Increase `backlog_limit` in auditd.conf. Reduce rule scope for non-critical hosts. |
| Vector crashes | Logs buffer on disk but don't ship | Vector health check fails; log delivery delay metric increases | Restart Vector. Disk buffer replays missed events automatically. Check Vector logs for the crash cause. |
| Elasticsearch cluster unhealthy | New logs rejected; queries fail or timeout | ES cluster health API shows yellow/red; Prometheus ES exporter alerts | Fix shard allocation; add nodes; or migrate to managed backend (Grafana Cloud #108, Axiom #112). |
| Attacker deletes local logs before shipping | Gap in centralized logs for the compromised host (if shipping delay > attacker speed) | Log gap detection: expected log rate per host drops to zero | Minimize shipping delay (sub-30-second with Vector). Use `af_unix` audisp plugin for lowest possible latency. Ship to immutable storage (Backblaze #161 B2 with write-only IAM). |
| Audit rules too broad | High volume; disk fills; performance degradation | Disk usage alerts; auditd CPU usage; host performance metrics | Disable `exec_log` rule (highest volume). Use `user_exec` (logs only non-system users). Exclude specific high-frequency programs. |

## When to Consider a Managed Alternative

**This is the primary observability conversion article.** Audit log pain is universal and the transition trigger is clear:

- Self-managed Elasticsearch cluster management is a full-time job past 20 hosts (index lifecycle, shard management, capacity planning, version upgrades, backup verification).
- Storage costs for audit logs grow to terabytes within months for a fleet of any size.
- Query performance degrades without continuous index optimisation.

**Recommended providers:**

- **[Grafana Cloud](https://grafana.com/cloud):** Managed Loki for log storage, Prometheus-style alerting, native Grafana dashboards. Start free (50GB logs/month), scale as needed. Loki's label-based query model covers 80% of security queries.
- **[Axiom](https://axiom.co):** 500GB/month free ingestion, unlimited retention, serverless query (zero cluster management). Best for teams that want to ingest everything and query later without managing infrastructure.
- **[Better Stack](https://betterstack.com):** Integrated logging + uptime monitoring + incident management. Good for teams that want observability and incident response in one platform.
- **[Backblaze](https://www.backblaze.com) B2 / [Wasabi](https://wasabi.com):** For long-term immutable archival. Ship a copy of all audit logs to write-only object storage for 12-month compliance retention at $0.006/GB/month.

**What you still control:** auditd rule design (what to log), Vector/Fluentd pipeline configuration (how to ship), and alert rule logic (what to alert on). The managed provider handles storage, indexing, query infrastructure, and retention management.

**Premium content pack:** auditd rule collection. rules for CIS Level 1, CIS Level 2, SOC 2, and NIST 800-53 AU controls. Includes Vector pipeline configurations for each managed backend and Grafana dashboard templates for security investigation.


## Related Articles

- [Centralized Logging Architecture for Security: Fluentd, Vector, and Loki Compared](/articles/observability/centralized-logging/)
- [Kubernetes Audit Log Pipeline Design: From API Server to SIEM](/articles/observability/k8s-audit-log-design/)
- [OpenTelemetry for Security: Distributed Tracing of Authentication and Authorization Flows](/articles/observability/otel-security-tracing/)
- [Security Dashboards That Engineers Actually Use: Grafana Designs for Hardening Verification](/articles/observability/security-dashboards/)
- [Incident Response Runbooks: Structured Procedures for Common Security Events](/articles/observability/incident-response-runbooks/)
