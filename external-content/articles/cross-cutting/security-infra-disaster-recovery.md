---
title: "Security Infrastructure Disaster Recovery: Vault, PKI, and SIEM Failover"
description: "When your security infrastructure fails, you are flying blind. If Vault is down, applications cannot retrieve secrets and new deployments stall."
slug: "security-infra-disaster-recovery"
date: 2026-02-24
lastmod: 2026-02-24
category: "cross-cutting"
tags: ["disaster-recovery", "vault", "pki", "siem", "observability", "resilience"]
personas: ["sre", "security-engineer"]
article_number: 93
difficulty: "advanced"
estimated_reading_time: 15
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
  - name: "Incident.io"
    id: 175
    category: "incident-management"
  - name: "FireHydrant"
    id: 176
    category: "incident-management"
premium_pack: "security-dr-runbook-templates"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/security-infra-disaster-recovery/index.html"
---

# Security Infrastructure Disaster Recovery: Vault, PKI, and SIEM Failover

## Problem

When your security infrastructure fails, you are flying blind. If Vault is down, applications cannot retrieve secrets and new deployments stall. If your PKI is unavailable, certificate renewal fails and mTLS connections start breaking. If your SIEM or log pipeline is down, an attacker operating during the outage has unlimited dwell time with zero detection.

The "who watches the watchers" problem is real. Most teams monitor their applications with [Prometheus](https://prometheus.io), [Grafana](https://grafana.com), and centralised logging. But what monitors Prometheus? What alerts you when Grafana is down? What detects an attacker when your detection system is offline?

Security infrastructure is the foundation that every other security control depends on. A Vault outage is not just a secret management problem. It cascades: services cannot authenticate, certificates cannot rotate, new pods cannot start, and incident response teams cannot access credentials needed to investigate the outage itself.

**Target systems:** HashiCorp Vault (secrets management). Internal PKI ([cert-manager](https://cert-manager.io), SPIRE, or custom CA). SIEM/log pipeline (Prometheus, [Loki](https://grafana.com/oss/loki/), [Elasticsearch](https://www.elastic.co/elasticsearch), or managed equivalents). Alerting systems (Alertmanager, PagerDuty, Opsgenie).

## Threat Model

- **Adversary:** An attacker who triggers or exploits a security infrastructure outage. This could be intentional (DDoS against your monitoring stack, corrupting Vault storage) or opportunistic (attacking during an unrelated outage when detection is impaired).
- **Objective:** Operate with impunity during the monitoring blind spot. Exfiltrate data, establish persistence, or destroy evidence while detection systems are offline.
- **Blast radius:** A monitoring outage does not cause a breach directly. It makes every other breach undetectable for the duration of the outage. A 4-hour SIEM outage means 4 hours of unmonitored activity across every system that depends on centralised logging.

## Configuration

### Vault Disaster Recovery

```hcl
# vault-config.hcl
# Vault with integrated storage (Raft) and auto-unseal
storage "raft" {
  path    = "/vault/data"
  node_id = "vault-0"

  retry_join {
    leader_api_addr = "https://vault-0.vault-internal:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-1.vault-internal:8200"
  }
  retry_join {
    leader_api_addr = "https://vault-2.vault-internal:8200"
  }
}

# Auto-unseal prevents manual intervention after restart
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc123"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/tls.crt"
  tls_key_file  = "/vault/tls/tls.key"
}
```

```bash
# Vault snapshot automation (run daily via cron)
#!/bin/bash
set -euo pipefail

SNAPSHOT_DIR="/vault/snapshots"
DATE=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=30

# Take Raft snapshot
vault operator raft snapshot save "${SNAPSHOT_DIR}/vault-${DATE}.snap"

# Verify snapshot is valid
vault operator raft snapshot inspect "${SNAPSHOT_DIR}/vault-${DATE}.snap"

# Upload to remote storage (separate from Vault's own storage)
aws s3 cp "${SNAPSHOT_DIR}/vault-${DATE}.snap" \
  "s3://vault-dr-backups/vault-${DATE}.snap" \
  --sse aws:kms \
  --sse-kms-key-id "arn:aws:kms:us-east-1:123456789012:key/backup-key"

# Clean up old local snapshots
find "${SNAPSHOT_DIR}" -name "vault-*.snap" -mtime +${RETENTION_DAYS} -delete

echo "Vault snapshot completed: vault-${DATE}.snap"
```

### Vault Recovery Procedure

```bash
# Vault recovery from Raft snapshot
# Run on a fresh Vault cluster

# 1. Start Vault server (it will be uninitialized)
vault server -config=/vault/config/vault.hcl

# 2. Restore from snapshot
vault operator raft snapshot restore \
  -force \
  /vault/snapshots/vault-20260422-020000.snap

# 3. Vault auto-unseals via KMS
# 4. Verify secrets are accessible
vault kv get secret/test

# 5. Verify dynamic secret engines are functional
vault read database/creds/readonly
```

### Monitoring the Monitors

```yaml
# prometheus-self-monitoring.yaml
# Prometheus monitors itself and a secondary Prometheus monitors the primary
groups:
  - name: monitoring-health
    rules:
      - alert: PrometheusDown
        expr: up{job="prometheus"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Prometheus instance down"
          description: "Primary Prometheus is unreachable. Security alerting is impaired."

      - alert: AlertmanagerDown
        expr: up{job="alertmanager"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Alertmanager down. Alerts will not be delivered."

      - alert: VaultDown
        expr: up{job="vault"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Vault is unreachable. Secret retrieval and certificate rotation will fail."

      - alert: VaultSealed
        expr: vault_core_unsealed == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Vault is sealed. All secret operations are blocked."

      - alert: LogPipelineDown
        expr: >
          rate(fluentbit_output_records_total[5m]) == 0
          and rate(fluentbit_input_records_total[5m]) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Log pipeline receiving data but not shipping. Logs are being dropped."

      - alert: CertificateRenewalFailing
        expr: >
          certmanager_certificate_ready_status{condition="False"} == 1
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.name }} renewal failing for 30 minutes"
```

### Dual-Ship Log Pipeline

Send logs to two independent backends so that a single backend failure does not create a monitoring blind spot.

```yaml
# fluent-bit-dual-ship.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: logging
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         5
        Log_Level     info
        Parsers_File  parsers.conf

    [INPUT]
        Name              tail
        Path              /var/log/containers/*.log
        Parser            cri
        Tag               kube.*
        Refresh_Interval  5
        Mem_Buf_Limit     10MB

    # Primary backend
    [OUTPUT]
        Name              loki
        Match             *
        Host              loki.monitoring.svc.cluster.local
        Port              3100
        Labels            job=fluent-bit
        Auto_Kubernetes_Labels on

    # Secondary backend (independent infrastructure)
    [OUTPUT]
        Name              http
        Match             *
        Host              logs.backup-region.example.com
        Port              443
        URI               /api/v1/push
        Format            json
        Header            Authorization Bearer ${BACKUP_LOG_TOKEN}
        TLS               On

    # Local filesystem buffer (survives both backend outages)
    [OUTPUT]
        Name              file
        Match             *
        Path              /var/log/fluent-bit-buffer/
        Format            plain
```

### Degraded-Mode Detection

When centralised monitoring is unavailable, these host-level tools continue operating.

```bash
# degraded-mode-detection.sh
# Run on every host. No dependency on centralised systems.
# Deploy as a systemd timer that runs every 5 minutes.

#!/bin/bash
set -euo pipefail

LOG_FILE="/var/log/security/degraded-mode.log"
ALERT_FILE="/var/log/security/alerts.log"

timestamp() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Check for unexpected processes
UNEXPECTED_PROCS=$(ps aux | grep -E '(xmrig|cryptonight|minerd|stratum)' | grep -v grep || true)
if [ -n "${UNEXPECTED_PROCS}" ]; then
  echo "$(timestamp) CRITICAL: Suspected crypto miner detected: ${UNEXPECTED_PROCS}" >> "${ALERT_FILE}"
fi

# Check for unexpected network listeners
UNEXPECTED_LISTENERS=$(ss -tlnp | grep -vE ':(22|80|443|8080|8443|9090|9100|6443) ' | grep LISTEN || true)
if [ -n "${UNEXPECTED_LISTENERS}" ]; then
  echo "$(timestamp) WARNING: Unexpected network listeners: ${UNEXPECTED_LISTENERS}" >> "${ALERT_FILE}"
fi

# Check for unexpected cron jobs
CRON_CHANGES=$(find /etc/cron* /var/spool/cron -newer /var/log/security/.cron-baseline -type f 2>/dev/null || true)
if [ -n "${CRON_CHANGES}" ]; then
  echo "$(timestamp) WARNING: Cron files modified since last baseline: ${CRON_CHANGES}" >> "${ALERT_FILE}"
fi

# Check Vault accessibility
if ! curl -sf -o /dev/null "https://vault.example.com:8200/v1/sys/health"; then
  echo "$(timestamp) CRITICAL: Vault health check failed" >> "${ALERT_FILE}"
fi

# Ship alerts via alternative channel if centralised logging is down
if [ -s "${ALERT_FILE}" ] && ! curl -sf -o /dev/null "http://loki.monitoring.svc.cluster.local:3100/ready"; then
  # Logging is down, send alerts directly via webhook
  curl -sf -X POST "${EMERGENCY_WEBHOOK}" \
    -H "Content-Type: application/json" \
    -d "{\"text\": \"DEGRADED MODE ALERT from $(hostname): $(cat ${ALERT_FILE})\"}" || true
fi
```

```ini
# /etc/systemd/system/degraded-detection.timer
[Unit]
Description=Degraded mode security detection

[Timer]
OnBootSec=60
OnUnitActiveSec=300
RandomizedDelaySec=30

[Install]
WantedBy=timers.target
```

### DR Drill Procedure

```bash
# quarterly-dr-drill.sh
# Test security infrastructure recovery quarterly

echo "=== Security Infrastructure DR Drill ==="
echo "Date: $(date)"
echo ""

echo "1. Vault Recovery Test"
echo "   - Restoring from latest snapshot to DR cluster..."
# vault operator raft snapshot restore -force /path/to/latest.snap
echo "   - Verifying secret access..."
# vault kv get secret/dr-test
echo "   - Expected: secrets readable within 5 minutes of restore start"
echo ""

echo "2. Log Pipeline Failover Test"
echo "   - Stopping primary Loki..."
# kubectl scale statefulset loki --replicas=0 -n monitoring
echo "   - Verifying logs appear in secondary backend within 30 seconds..."
echo "   - Restarting primary Loki..."
# kubectl scale statefulset loki --replicas=3 -n monitoring
echo ""

echo "3. Certificate Renewal Under CA Failure"
echo "   - Simulating cert-manager CA unavailability..."
echo "   - Verifying existing certificates remain valid..."
echo "   - Verifying renewal recovers when CA returns..."
echo ""

echo "4. Alerting Pipeline Test"
echo "   - Firing test alert..."
# amtool alert add --alertmanager.url=http://alertmanager:9093 \
#   alertname="DR_DRILL_TEST" severity="critical"
echo "   - Verifying alert delivered to on-call..."
echo ""

echo "Record results and update DR runbook with any findings."
```

## Expected Behaviour

- Vault runs in a 3-node Raft cluster with auto-unseal. Daily snapshots stored in a separate region.
- Vault recovery from snapshot completes within 15 minutes
- Log pipeline ships to two independent backends. If primary fails, secondary continues receiving.
- Host-level degraded-mode detection runs independently of centralised monitoring
- Monitoring-of-monitoring alerts fire within 2 minutes of any component failure
- DR drills run quarterly with documented results

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Dual-ship logs | Doubles log storage cost | Log backends may diverge (different retention, different query capabilities) | Treat secondary as a DR backend with shorter retention (7 days vs 30 days). Use primary for day-to-day operations. |
| Auto-unseal via KMS | Vault recovers without manual intervention | KMS outage prevents Vault from starting | Use a KMS in a different region than Vault. If total KMS failure, fall back to Shamir unseal keys stored offline. |
| Host-level degraded detection | Works when everything else is down | Limited detection capability compared to centralised SIEM | This is the last line of defence, not the first. It catches obvious indicators only. |
| Quarterly DR drills | Validates recovery procedures work | Drills require 2-4 hours of engineering time per quarter | Schedule during low-traffic periods. Automate as much as possible. The cost of not testing is a failed recovery during a real incident. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vault snapshot corrupted | Restore fails with integrity error | Snapshot inspect during backup verifies integrity | Retry with previous day's snapshot. Investigate storage corruption. |
| Both log backends fail simultaneously | Complete monitoring blind spot | Host-level degraded detection script fires; no logs arriving at either backend | Logs buffer on [Fluent Bit](https://fluentbit.io) local filesystem. Investigate root cause (shared dependency like DNS or network). |
| Auto-unseal KMS unavailable | Vault cannot start after restart | Vault logs show KMS connection failure | Use Shamir unseal keys as fallback. KMS in a separate region reduces shared failure risk. |
| DR drill reveals outdated runbook | Recovery takes longer than expected or fails | Drill results document the gap | Update runbook immediately. Schedule follow-up drill to verify the fix. |
| Certificate chain breaks during CA recovery | Services reject mTLS connections | TLS handshake errors across services; cert-manager events show issuance failure | Verify CA certificate in cert-manager ClusterIssuer. If CA was rebuilt, distribute new root CA to all trust stores. |

## When to Consider a Managed Alternative

Managed observability providers handle their own HA: [Grafana Cloud](https://grafana.com/cloud), [Axiom](https://axiom.co), [Better Stack](https://betterstack.com). This is the strongest argument for managed observability. When your self-hosted Prometheus goes down, you have no metrics. When Grafana Cloud goes down, their SRE team responds. [Incident.io](https://incident.io) and [FireHydrant](https://firehydrant.com) for incident management during DR scenarios, providing structured incident response when your internal tools are compromised.

**Premium content pack:** Security DR runbook templates. Vault backup and restore scripts, Fluent Bit dual-ship configuration, degraded-mode detection scripts, quarterly DR drill checklist, and monitoring-of-monitoring Prometheus rules.


## Related Articles

- [Migrating from Self-Hosted Prometheus to Grafana Cloud: Preserving Dashboards, Alerts, and History](/articles/cross-cutting/migrate-prometheus-grafana-cloud/)
- [Incident Response Hardening Playbook: From Detection to Post-Mortem](/articles/cross-cutting/incident-response-hardening-playbook/)
- [Multi-Cloud Hardening: Consistent Security Posture Across Providers](/articles/cross-cutting/multi-cloud-hardening/)
- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
