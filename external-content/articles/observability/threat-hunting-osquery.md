---
title: "Threat Hunting with Osquery: Fleet Queries, Detection Packs, and IOC Sweeps"
description: "Osquery turns your fleet into a queryable database. Scheduled queries surface persistence mechanisms, lateral movement artefacts, and IOCs across thousands of hosts simultaneously."
slug: "threat-hunting-osquery"
date: 2026-04-29
lastmod: 2026-04-29
category: "observability"
tags: ["osquery", "threat-hunting", "detection", "fleet", "ioc"]
personas: ["security-engineer", "sre", "platform-engineer"]
article_number: 243
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/observability/threat-hunting-osquery/index.html"
---

# Threat Hunting with Osquery: Fleet Queries, Detection Packs, and IOC Sweeps

## Problem

Most detection controls are reactive: a SIEM correlates events after they arrive; Falco fires on syscall patterns as they happen. Threat hunting is deliberately proactive — a security engineer forms a hypothesis about attacker behaviour and queries the environment for evidence of it, regardless of whether an alert has fired.

Osquery makes proactive hunting tractable at scale. It exposes operating system state — running processes, network connections, installed packages, cron jobs, SSH keys, kernel modules, user accounts, file integrity — as SQL tables. A single query returns results from every host in the fleet simultaneously.

The gap in most security programmes:

- Hunting is manual and ad-hoc; no structured query library.
- Detection packs (community query sets targeting specific threat categories) are never deployed.
- IOC sweeps during an incident require logging into each host individually.
- Scheduled queries run but alerts are not actionable — no baseline, no diff, no response playbook.
- Osquery is deployed for compliance collection only; the security team has never written a hunting query.

By 2026, mature security teams run osquery on every host (Linux, macOS, Windows) and maintain a library of scheduled queries covering persistence mechanisms, lateral movement indicators, credential access artefacts, and supply chain compromise patterns.

**Target systems:** Osquery 5.10+, Fleet (osquery management) 4.46+ or Kolide Fleet; Linux (systemd hosts), macOS 13+, Kubernetes nodes with osquery DaemonSet.

## Threat Model

- **Adversary 1 — Persistence via cron or systemd:** An attacker establishes persistence by adding a cron job or systemd service unit. Standard detection misses it if no audit rule covers `/etc/cron.d` writes. An osquery scheduled query finds it on every host.
- **Adversary 2 — Lateral movement via SSH keys:** An attacker adds an SSH authorised key to a privileged user's account to maintain access across password changes. Osquery surfaces all `~/.ssh/authorized_keys` entries fleet-wide.
- **Adversary 3 — Process injection or unusual parent:** Malware spawns from an unexpected parent (e.g., `nginx` spawning `bash`). An osquery query against the `processes` table filtered by unusual parent-child relationships surfaces the anomaly.
- **Adversary 4 — Supply chain implant in installed package:** A compromised package installs a backdoored binary. Osquery can sweep for file hashes that match known-bad IOCs across the entire fleet.
- **Adversary 5 — Living-off-the-land binary (LOLBin) abuse:** An attacker uses trusted system binaries (`curl`, `python3`, `nc`) for C2. Osquery's `socket_events` and `process_open_sockets` tables surface unexpected network connections from these processes.
- **Access level:** Adversaries 1–3 have root access. Adversary 4 has package manager access. Adversary 5 has any code execution.
- **Objective:** Establish or maintain access, move laterally, exfiltrate data, avoid detection by signature-based tools.
- **Blast radius:** Without hunting, sophisticated attackers dwell for months (median dwell time without EDR: 24 days; with EDR and hunting: ~3 days). Osquery queries return results from every host; a single hunting hypothesis covers the entire fleet.

## Configuration

### Step 1: Deploy Osquery via DaemonSet (Kubernetes)

```yaml
# osquery-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: osquery
  namespace: security
spec:
  selector:
    matchLabels:
      name: osquery
  template:
    metadata:
      labels:
        name: osquery
    spec:
      hostPID: true        # Required for process-level visibility.
      hostNetwork: true    # Required for network connection visibility.
      containers:
        - name: osquery
          image: osquery/osquery:5.10.2
          securityContext:
            privileged: true   # Osquery requires privileged access to host OS tables.
          args:
            - --flagfile=/etc/osquery/osquery.flags
            - --config_plugin=filesystem
            - --config_path=/etc/osquery/osquery.conf
            - --logger_plugin=filesystem
            - --logger_path=/var/log/osquery
            - --disable_events=false
            - --audit_allow_config=true
          volumeMounts:
            - name: osquery-config
              mountPath: /etc/osquery
            - name: host-root
              mountPath: /host
              readOnly: true
            - name: log
              mountPath: /var/log/osquery
      volumes:
        - name: osquery-config
          configMap:
            name: osquery-config
        - name: host-root
          hostPath:
            path: /
        - name: log
          emptyDir: {}
      tolerations:
        - operator: Exists   # Run on all nodes including tainted ones.
```

### Step 2: Core osquery Configuration

```json
// /etc/osquery/osquery.conf
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_events": "false",
    "events_expiry": "3600",
    "enable_file_events": "true",
    "enable_process_events": "true",
    "enable_socket_events": "true",
    "audit_allow_config": "true",
    "audit_allow_sockets": "true",
    "audit_allow_process_events": "true"
  },

  "schedule": {
    "process_events": {
      "query": "SELECT pid, parent, name, cmdline, cwd, on_disk, uid, gid, start_time FROM processes WHERE on_disk = 0 OR name IN ('nc', 'ncat', 'netcat', 'socat');",
      "interval": 60
    },

    "suid_binaries": {
      "query": "SELECT * FROM suid_bin;",
      "interval": 3600
    },

    "startup_items": {
      "query": "SELECT * FROM startup_items;",
      "interval": 3600
    },

    "crontab": {
      "query": "SELECT * FROM crontab;",
      "interval": 3600
    },

    "listening_ports": {
      "query": "SELECT pid, port, protocol, family, address FROM listening_ports WHERE port NOT IN (22, 80, 443, 8080, 9090);",
      "interval": 300
    },

    "users_with_sudo": {
      "query": "SELECT username, user_comment FROM users JOIN sudoers USING (username);",
      "interval": 3600
    }
  },

  "packs": {
    "incident-response": "/etc/osquery/packs/incident-response.conf",
    "it-compliance": "/etc/osquery/packs/it-compliance.conf",
    "osquery-monitoring": "/etc/osquery/packs/osquery-monitoring.conf"
  },

  "file_paths": {
    "configuration": [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/sudoers",
      "/etc/ssh/sshd_config",
      "/etc/cron.d/%%",
      "/etc/cron.daily/%%",
      "/root/.ssh/authorized_keys"
    ],
    "binaries": [
      "/usr/bin/%%",
      "/usr/sbin/%%"
    ]
  }
}
```

### Step 3: Persistence Hunting Queries

Queries targeting the most common persistence mechanisms:

```sql
-- New cron jobs added since last check (diff-mode query in Fleet).
SELECT command, path, minute, hour, day_of_month, month, day_of_week
FROM crontab
WHERE path NOT IN (SELECT path FROM crontab WHERE 1=1);
-- Scheduled hourly; alerts on new entries.

-- Systemd units not owned by any installed package.
SELECT id, description, sub_state, unit_file_path
FROM systemd_units
WHERE unit_file_path NOT LIKE '/lib/systemd/system/%'
  AND unit_file_path NOT LIKE '/usr/lib/systemd/system/%'
  AND unit_file_path NOT LIKE '/run/systemd/%%'
  AND sub_state = 'running';

-- SSH authorised keys for all users (hunt for unexpected entries).
SELECT u.username, u.uid, a.key, a.key_type, a.comment
FROM users u
JOIN authorized_keys a ON a.uid = u.uid
WHERE u.uid >= 1000 OR u.username IN ('root', 'ubuntu', 'ec2-user');

-- LD_PRELOAD in /etc/ld.so.preload (common rootkit persistence).
SELECT * FROM file
WHERE path = '/etc/ld.so.preload'
  AND size > 0;

-- Kernel modules not in expected list.
SELECT name, used_by, status
FROM kernel_modules
WHERE name NOT IN (
  -- Allowlist of expected modules for this host type.
  'ext4', 'overlay', 'br_netfilter', 'ip_tables', 'iptable_filter',
  'nf_conntrack', 'nf_nat', 'veth', 'dummy'
)
AND status = 'Live';
```

### Step 4: Lateral Movement Detection Queries

```sql
-- Unexpected shell spawned by a non-shell parent.
SELECT p.pid, p.name, p.cmdline, p.uid,
       pp.name AS parent_name, pp.cmdline AS parent_cmdline
FROM processes p
JOIN processes pp ON pp.pid = p.parent
WHERE p.name IN ('bash', 'sh', 'zsh', 'fish', 'dash')
  AND pp.name NOT IN (
    'bash', 'sh', 'zsh', 'sshd', 'login', 'su', 'sudo',
    'tmux', 'screen', 'systemd', 'init', 'cron'
  );

-- Network connections from processes that shouldn't have them.
SELECT p.name, p.pid, p.cmdline, c.remote_address, c.remote_port, c.state
FROM processes p
JOIN process_open_sockets c ON c.pid = p.pid
WHERE p.name IN ('python3', 'python', 'perl', 'ruby', 'lua')
  AND c.state = 'ESTABLISHED'
  AND c.remote_address NOT LIKE '127.%'
  AND c.remote_address NOT LIKE '10.%'
  AND c.remote_address != '::1';

-- Processes running from /tmp or /dev/shm (common malware staging).
SELECT pid, name, path, cmdline, uid
FROM processes
WHERE path LIKE '/tmp/%'
   OR path LIKE '/dev/shm/%'
   OR path LIKE '/var/tmp/%';

-- Users who have logged in recently but aren't in expected list.
SELECT username, host, time, type
FROM last
WHERE type = 7   -- Login type.
  AND username NOT IN (
    SELECT username FROM users WHERE uid < 1000
  )
  AND host NOT LIKE '10.%'
  AND host NOT LIKE '172.%'
  AND host NOT LIKE '192.168.%';
```

### Step 5: IOC Sweep — Hash-Based Hunt

During an incident, sweep the fleet for known-bad file hashes:

```sql
-- Sweep for files matching known-bad SHA256 hashes.
-- Replace hashes with actual IOC list from your threat intelligence feed.
SELECT path, sha256, size, mtime, ctime
FROM hash
WHERE path IN (
  SELECT path FROM file
  WHERE (path LIKE '/tmp/%' OR path LIKE '/usr/local/bin/%')
)
AND sha256 IN (
  'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899',
  '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
);

-- Sweep for known-bad process names or cmdline patterns.
SELECT pid, name, cmdline, path, uid, start_time
FROM processes
WHERE name IN ('mimikatz', 'meterpreter', 'cobalt_strike', 'empire')
   OR cmdline LIKE '%powershell%encodedcommand%'
   OR cmdline LIKE '%base64 -d%|%bash%'
   OR cmdline LIKE '%-c "import base64%';

-- Sweep for network connections to known-bad IPs.
-- Replace with current C2 IP list.
SELECT p.name, p.pid, c.remote_address, c.remote_port
FROM processes p
JOIN process_open_sockets c ON c.pid = p.pid
WHERE c.remote_address IN (
  '198.51.100.100',
  '203.0.113.200'
);
```

In Fleet, IOC sweeps are run as live queries across the entire fleet:

```bash
# Fleet CLI: run a live query against all online hosts.
fleet query \
  --query "SELECT path, sha256 FROM hash WHERE path IN (SELECT path FROM file WHERE path LIKE '/tmp/%') AND sha256 IN ('aabb...')" \
  --targets all \
  --timeout 60s
```

### Step 6: Detection Packs from Palantir and Uptycs

Use community-maintained detection packs rather than writing every query from scratch:

```bash
# Palantir's osquery-configuration (widely used reference).
git clone https://github.com/palantir/osquery-configuration.git
ls osquery-configuration/packs/
# incident-response.conf, it-compliance.conf, security-monitoring.conf, ...

# Copy packs to osquery config directory.
cp osquery-configuration/packs/*.conf /etc/osquery/packs/
```

Key packs from Palantir:

| Pack | Queries it includes |
|------|-------------------|
| `incident-response` | Process, socket, user account, cron, startup items, kernel modules |
| `security-monitoring` | File integrity, SSH keys, sudoers, listening ports |
| `it-compliance` | Password policy, disk encryption, firewall state |

Add custom packs alongside community packs:

```json
// /etc/osquery/packs/custom-hunting.conf
{
  "queries": {
    "reverse_shells": {
      "query": "SELECT p.name, p.pid, p.cmdline, c.remote_address, c.remote_port FROM processes p JOIN process_open_sockets c ON c.pid = p.pid WHERE p.name IN ('bash','sh','zsh') AND c.remote_port NOT IN (22, 80, 443) AND c.state = 'ESTABLISHED';",
      "interval": 300,
      "description": "Detect potential reverse shells from interactive processes."
    }
  }
}
```

### Step 7: Fleet-Level Alert Routing

In Fleet, configure query-level alerts:

```yaml
# fleet-queries.yml (Fleet GitOps configuration)
- name: "Cron persistence detected"
  query: |
    SELECT command, path, minute, hour
    FROM crontab
    WHERE path LIKE '/etc/cron.%/%'
  interval: 3600
  automations_enabled: true
  webhook_url: "https://security-alerts.internal/osquery"
  alert_threshold: 1   # Alert on any result.
  description: "Unexpected cron job detected on a host."
  platform: linux
```

For Fleet webhook payloads, route to your SIEM:

```python
# Security alert receiver for Fleet query results.
@app.post("/osquery")
async def osquery_alert(payload: dict):
    host = payload.get("host", {})
    rows = payload.get("rows", [])
    query_name = payload.get("query_name", "unknown")

    if rows:
        send_to_siem({
            "source": "osquery",
            "host": host.get("hostname"),
            "query": query_name,
            "results": rows,
            "severity": "high",
            "timestamp": time.time(),
        })
```

### Step 8: Telemetry

```
osquery_host_count{platform, status}               gauge
osquery_query_result_rows_total{query_name}        counter
osquery_schedule_drift_seconds{host, query}        histogram
osquery_logger_events_total{event_type}            counter
osquery_ioc_matches_total{query_name, host}        counter
```

Alert on:

- `osquery_ioc_matches_total` non-zero — IOC match on a host; immediate investigation.
- `osquery_host_count{status="offline"}` increasing — hosts going offline could indicate tampering with osquery daemon (adversary removing visibility).
- Any result from the `reverse_shells`, `kernel_modules`, `ld_preload` queries — treat as high-priority.

## Expected Behaviour

| Signal | Without osquery hunting | With osquery scheduled queries |
|--------|------------------------|-------------------------------|
| New cron job added fleet-wide | Detected only on hosts with auditd watching cron paths | Detected on all hosts within 1 hour |
| Malware in `/tmp` running | Detected only if EDR fires | Query fires within 60s; results on all hosts |
| Unexpected SSH key added | Discovered in next compliance scan (weeks) | Detected within 1 hour by scheduled `authorized_keys` query |
| IOC sweep during incident | Manual SSH per host (hours to complete) | Live query returns results fleet-wide in < 60s |
| Dwell time reduction | Days to weeks | Hours |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `privileged: true` in DaemonSet | Full host OS visibility | Osquery pod has broad host access | Constrain to read-only host mounts where possible; restrict osquery's network egress. |
| Frequent scheduling (60s intervals) | Near-real-time visibility | CPU and IO overhead on high-event hosts | Profile; increase interval for expensive queries; use event-based tables (process_events) instead of polling. |
| Hash-based IOC sweeps | Precise file-level detection | Hash computation is CPU-intensive for large directories | Scope sweeps to high-risk directories; run as live queries during incidents rather than continuously. |
| Community packs (Palantir) | Maintained by experts; broad coverage | Some queries may not apply to your environment | Review and prune queries that generate noise; keep relevant packs. |
| Fleet GitOps for query management | Query changes reviewed; auditable | Adds change management overhead | Worth it for any fleet > 100 hosts; query changes should be reviewed like code. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Osquery daemon killed by attacker | Host goes offline in Fleet | `osquery_host_count{status="offline"}` alert | Monitor DaemonSet pod health; restart via systemd or DaemonSet controller. |
| Query too expensive, causes CPU spike | Host performance degraded; osquery watchdog restarts process | Host CPU metrics; osquery logs show watchdog restart | Increase `schedule_timeout`; split query into smaller pieces; reduce frequency. |
| Fleet webhook fails | Query results not alerting | Webhook delivery failures in Fleet logs | Implement retry logic; use Fleet's built-in webhook retry. |
| Shadow IT process not in allowlist | False positives on legitimate processes | High alert volume for a specific process name | Add to allowlist; document the exception with justification. |
| osquery not on all nodes | Coverage gaps; blind spots on unhardened nodes | Fleet shows hosts without recent check-in | Deploy via DaemonSet with `tolerations: operator: Exists` to cover all nodes. |
| IOC hashes stale | Sweeps miss new malware variants | New incident; hash not in IOC set | Subscribe to threat intelligence feeds; automate IOC list updates. |

## Related Articles

- [Detection Rules and Sigma Correlation](/articles/observability/detection-rules/)
- [eBPF and Tetragon Runtime Detection](/articles/observability/ebpf-tetragon/)
- [Lateral Movement Detection](/articles/observability/lateral-movement-detection/)
- [Falco Runtime Security](/articles/kubernetes/falco-runtime-security/)
- [Honeypot and Deception Technology in Kubernetes](/articles/observability/honeypot-deception-kubernetes/)
