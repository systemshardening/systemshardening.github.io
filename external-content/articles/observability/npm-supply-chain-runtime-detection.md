---
title: "Runtime Detection of npm Supply Chain RAT Behaviour: Observing the Axios Attack Pattern"
description: "The Axios RAT executed, phoned home, and erased its traces within seconds of npm install. Build runtime detection across process tree monitoring, network telemetry, and file system events — and a Sigma rule for the Axios IOC pattern."
slug: npm-supply-chain-runtime-detection
date: 2026-05-03
lastmod: 2026-05-03
category: observability
tags:
  - supply-chain
  - npm
  - sigma
  - runtime-detection
  - process-monitoring
personas:
  - security-engineer
  - platform-engineer
article_number: 419
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/npm-supply-chain-runtime-detection/
---

# Runtime Detection of npm Supply Chain RAT Behaviour: Observing the Axios Attack Pattern

## The Problem

The Axios RAT executed in a sequence that lasted approximately 10–30 seconds from `npm install` to evidence erasure. On March 31 2026, North Korean threat actor Sapphire Sleet used a stolen maintainer npm token to publish a malicious version of Axios that included a phantom dependency: `plain-crypto-js`. When a developer or CI pipeline ran `npm install`, the `postinstall` hook in `plain-crypto-js` executed a Node.js script, made an outbound connection to a command-and-control server, downloaded a second-stage payload, and then replaced its own source files with clean decoys — all before the install process returned to the shell prompt.

The attack sequence in order:

1. `npm install` resolves Axios and its transitive dependencies, including `plain-crypto-js`.
2. npm runs the `postinstall` lifecycle hook defined in `plain-crypto-js/package.json`.
3. The hook script opens a TCP connection to an attacker-controlled IP on port 443.
4. A second-stage payload is received and written to a temp directory or the user's home directory.
5. The `plain-crypto-js` source files are overwritten with clean, benign content. The malicious hook is erased.

By the time a developer notices anything unusual — if they notice at all — the RAT has established persistence and destroyed the forensic evidence in `node_modules`. Standard antivirus misses this entirely. The malicious component is a Node.js script, not a binary executable, and the individual behaviour (a Node.js process making an HTTPS request) is indistinguishable from the normal operation of thousands of legitimate packages that download platform-specific binaries during postinstall. The malicious intent becomes visible only when you correlate the process tree, the network event, and the file system mutation into a single composite signal.

The defence is layered runtime observability. Three independent data streams converge on the same 30-second window: the process tree shows `npm` spawning an unexpected child; network telemetry shows an outbound connection from `node` to a non-allowlisted address; file system events show files written to `node_modules/` then immediately deleted. Each signal alone is ambiguous. Together, they constitute a high-confidence indicator of supply chain compromise that fires before step 5 — before the evidence erasure is complete.

This article covers osquery process tree monitoring, auditd network connection monitoring, inotifywait and Falco file system monitoring, a composite Sigma rule for the Axios IOC pattern, and an OpenSearch correlation rule that stitches all three into a PagerDuty-triggering alert.

**Target systems:** Linux (auditd, inotifywait), osquery 5.10+, Falco 0.38+, sigma-cli 1.x, OpenSearch 2.x.

## Threat Model

- **Process tree — first observable signal:** The RAT executes as a child process of the `npm` process that ran the lifecycle hook. The process tree at time of compromise shows `npm` → `node` (the postinstall script) → optionally `sh` or `curl` for the C2 connection. Processes with names like `curl`, `wget`, `python3`, `sh`, or `bash` whose ancestor chain contains `npm` are anomalous: npm install should not be spawning interactive shells or download utilities.

- **Network connection — most reliable signal:** The outbound TCP connection to the C2 server is the most actionable signal. It occurs within 5–15 seconds of `npm install` starting and is made by a `node` process whose parent is `npm`. Legitimate Node.js application processes also make network connections, but they do so during application runtime, not during package installation. A `node` process whose ancestor is `npm install` making a connection to a non-RFC1918 address is a high-fidelity indicator.

- **File system — write-then-unlink pattern:** Legitimate npm packages are written to `node_modules/` and stay there for the lifetime of the project. A file written to `node_modules/some-package/` and then deleted within 60 seconds has no legitimate explanation. The Axios RAT used this pattern precisely to destroy its own forensic footprint. The write-then-unlink sequence in `node_modules` is the signal.

- **Second-stage payload outside the project directory:** The second-stage payload is written to `/tmp/`, `/var/tmp/`, or the home directory (`~/.config/`, `~/.local/share/`). File creation in these directories from a process whose ancestor is `npm install` is anomalous. The payload may be a cron job, a systemd unit file, or a modification to a shell RC file.

- **Persistence mechanism:** The second-stage payload establishes persistence. The Sapphire Sleet implant used a cron job entry and a `.bashrc` modification. Detecting the persistence write requires watching the persistence locations — `/etc/cron.d/`, `/var/spool/cron/crontabs/`, `~/.bashrc`, `~/.profile`, systemd unit directories — for writes whose originating process chain includes `npm`.

- **Access level required:** No elevated privileges. The RAT executes as the user running `npm install`, which on a developer workstation is the developer's account and on CI is the runner's service account. Supply chain compromise scales to every developer and every CI pipeline that installs the affected package.

- **Blast radius without detection:** The RAT establishes persistence on every machine that ran `npm install` during the exposure window. On a team of 20 engineers, that is potentially 20 compromised developer workstations. On a CI platform running 500 builds per day, that is 500 environments. The second-stage payload exfiltrates credentials, source code, and cloud provider tokens. Detection within the 30-second install window limits blast radius to one machine; detection hours or days later means all affected machines have been compromised for the full dwell period.

## Hardening Configuration

### 1. Process Tree Telemetry with osquery

osquery's `processes` table exposes the full process tree in real time. The key query joins `processes` on `parent` to walk the ancestor chain and flag any process with a suspicious name whose ancestry includes `npm`.

```sql
SELECT
  child.pid,
  child.name        AS child_name,
  child.cmdline     AS child_cmdline,
  child.uid,
  child.start_time,
  parent.name       AS parent_name,
  parent.cmdline    AS parent_cmdline,
  grandparent.name  AS grandparent_name
FROM processes AS child
JOIN processes AS parent       ON parent.pid = child.parent
JOIN processes AS grandparent  ON grandparent.pid = parent.parent
WHERE child.name IN ('curl', 'wget', 'python3', 'sh', 'bash', 'nc', 'python')
  AND (
    parent.name IN ('node', 'npm', 'npx')
    OR grandparent.name IN ('node', 'npm', 'npx')
  );
```

Register this as a scheduled query in `/etc/osquery/osquery.conf`. The default schedule interval is 60 seconds; reduce it to 15 seconds for process monitoring to catch the RAT before the evidence erasure step completes. A 60-second interval is too slow: the Axios RAT completed its entire execution cycle in 10–30 seconds.

```json
{
  "schedule": {
    "npm_suspicious_child_process": {
      "query": "SELECT child.pid, child.name AS child_name, child.cmdline AS child_cmdline, child.uid, parent.name AS parent_name, grandparent.name AS grandparent_name FROM processes AS child JOIN processes AS parent ON parent.pid = child.parent JOIN processes AS grandparent ON grandparent.pid = parent.parent WHERE child.name IN ('curl','wget','python3','sh','bash','nc') AND (parent.name IN ('node','npm','npx') OR grandparent.name IN ('node','npm','npx'));",
      "interval": 15,
      "description": "Alert on shells or download utilities spawned from npm/node ancestry."
    },
    "node_to_tmp_processes": {
      "query": "SELECT pid, name, path, cmdline, uid, start_time FROM processes WHERE (path LIKE '/tmp/%' OR path LIKE '/var/tmp/%' OR path LIKE '/dev/shm/%') AND uid >= 1000;",
      "interval": 15,
      "description": "Detect second-stage payloads running from temp directories."
    }
  }
}
```

For Fleet-managed osquery deployments, configure the query with `automations_enabled: true` and a webhook to your SIEM so any result immediately creates a high-priority alert. osquery query results are empty when nothing matches; a non-empty result set is the alert.

### 2. Network Connection Monitoring

auditd captures the `connect(2)` syscall and includes the process name (`comm`) in the event record. The following auditd rules record all TCP `connect` calls made by processes named `node`, then a watch rule correlates that with an active `npm` process:

```bash
auditctl -a always,exit -F arch=b64 -S connect \
  -F comm=node \
  -F key=node_outbound_connect

auditctl -a always,exit -F arch=b64 -S execve \
  -F comm=npm \
  -F key=npm_exec
```

Add these to `/etc/audit/rules.d/npm-supply-chain.rules` to persist across reboots:

```bash
-a always,exit -F arch=b64 -S connect -F comm=node -F key=node_outbound_connect
-a always,exit -F arch=b64 -S execve -F comm=npm -F key=npm_exec
-a always,exit -F arch=b64 -S execve -F comm=npx -F key=npm_exec
```

The audit log entries can be forwarded to your SIEM. A SIEM query that joins `node_outbound_connect` events with `npm_exec` events within a 60-second window on the same host identifies the Axios pattern precisely: `npm` running, then `node` making an outbound connection shortly after.

For Zeek-based network monitoring, enrich DNS and conn logs with the process name by deploying Zeek on the host with `zeek-af_packet` capturing the loopback and primary interface, then use a Zeek script to log the initiating PID alongside each connection. This is more complex but gives you destination hostname resolution at the time of the connection, which auditd does not provide.

### 3. File System Event Monitoring with inotifywait

`inotifywait` from the `inotify-tools` package monitors file system events at the kernel level with negligible overhead for small directory trees. The following script watches `node_modules/` and alerts on the write-then-delete pattern — files that are created and then removed within 60 seconds:

```bash
#!/usr/bin/env bash

WATCH_DIR="${1:-node_modules}"
ALERT_WINDOW=60
declare -A created_times

inotifywait -m -r -e create -e delete --format '%T %e %w%f' \
  --timefmt '%s' "$WATCH_DIR" 2>/dev/null |
while read -r timestamp event filepath; do
  if [[ "$event" == "CREATE" ]]; then
    created_times["$filepath"]="$timestamp"
  elif [[ "$event" == "DELETE" ]]; then
    if [[ -n "${created_times[$filepath]}" ]]; then
      age=$(( timestamp - created_times[$filepath] ))
      if (( age <= ALERT_WINDOW )); then
        echo "ALERT: write-then-delete in node_modules within ${age}s: $filepath"
        logger -t npm-rat-detect -p security.warning \
          "write-then-delete in node_modules: $filepath (${age}s)"
      fi
      unset 'created_times[$filepath]'
    fi
  fi
done
```

Run this script in the background before executing `npm install` in CI pipelines. The `logger` call forwards the alert to syslog, from which it can be picked up by your log forwarder and routed to the SIEM.

For production environments and Kubernetes nodes, use Falco with an eBPF driver instead of `inotifywait`. `inotifywait` watching `node_modules/` trees with 10,000+ files adds measurable CPU overhead on CI runners. The Falco rule equivalent:

```yaml
- rule: npm_node_modules_write_then_delete
  desc: >
    A file in node_modules was written and then deleted within 60 seconds.
    This pattern matches the Axios RAT evidence-erasure step.
  condition: >
    (evt.type = unlinkat or evt.type = unlink)
    and fd.name contains "node_modules/"
    and proc.aname[2] = "npm"
  output: >
    File deleted in node_modules by npm descendant
    (file=%fd.name proc=%proc.name pid=%proc.pid
     parent=%proc.pname gparent=%proc.aname[2]
     user=%user.name)
  priority: WARNING
  tags: [supply-chain, npm, file-integrity]
```

### 4. Sigma Rule for the Axios RAT Pattern

The composite Sigma rule fires when all three signals appear within a 30-second window on the same host: a suspicious child process spawned from an `npm` ancestor, a network connection from `node` to a non-allowlisted address, and a file deletion in `node_modules`. The rule targets auditd log events forwarded to a SIEM.

```yaml
title: npm Supply Chain RAT — Axios Attack Pattern
id: a3f2b1c4-9d8e-4a7f-b623-d1e5f8a09c3b
status: experimental
description: >
  Detects the three-signal composite pattern characteristic of a supply chain
  RAT executing during npm install: unexpected child process from npm ancestry,
  outbound network connection from node, and file deletion in node_modules.
  Based on the Axios RAT (Sapphire Sleet, March 31 2026).
references:
  - https://systemshardening.com/articles/observability/npm-supply-chain-runtime-detection/
author: security-team
date: 2026-05-03
tags:
  - attack.execution
  - attack.t1059.006
  - attack.command_and_control
  - attack.t1071.001
  - attack.defense_evasion
  - attack.t1070.004
logsource:
  product: linux
  service: auditd
detection:
  suspicious_child_from_npm:
    type: EXECVE
    key: npm_exec
    comm|contains:
      - npm
      - npx
    child_comm|contains:
      - curl
      - wget
      - python3
      - bash
      - sh

  node_outbound_connect:
    type: SYSCALL
    syscall: connect
    key: node_outbound_connect
    comm: node
    remote_addr|not_contains:
      - '10.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.20.'
      - '172.21.'
      - '172.22.'
      - '172.23.'
      - '172.24.'
      - '172.25.'
      - '172.26.'
      - '172.27.'
      - '172.28.'
      - '172.29.'
      - '172.30.'
      - '172.31.'
      - '192.168.'
      - '127.'

  node_modules_file_deletion:
    type: SYSCALL
    syscall|contains:
      - unlink
      - unlinkat
    exe|contains: node_modules

  timeframe: 30s
  condition: >
    suspicious_child_from_npm
    and node_outbound_connect
    and node_modules_file_deletion

falsepositives:
  - Node.js packages that legitimately download platform-specific binaries
    during postinstall (e.g., esbuild, puppeteer). Tune by adding an allowlist
    of known-good package names matched against the parent cmdline.
  - CI environments that run npm install and curl in rapid succession for
    unrelated reasons. Correlate with the specific node_modules deletion signal
    to reduce false positives.
level: high
fields:
  - comm
  - exe
  - pid
  - ppid
  - remote_addr
  - remote_port
  - key
```

Convert the Sigma rule to your SIEM's native query language:

```bash
sigma convert \
  -t opensearch \
  -p ecs_linux \
  rules/linux/auditd/npm-supply-chain-rat.yml \
  -o npm-rat-opensearch.json
```

### 5. SIEM Correlation Rule (OpenSearch)

The OpenSearch alerting monitor joins auditd `execve` events, `connect` events, and inotify `DELETE` events within a 30-second rolling window. The monitor runs every 15 seconds and triggers a PagerDuty notification on a match.

```json
{
  "name": "npm-supply-chain-rat-composite",
  "type": "monitor",
  "monitor_type": "query_level_monitor",
  "enabled": true,
  "schedule": {
    "period": {
      "interval": 15,
      "unit": "SECONDS"
    }
  },
  "inputs": [
    {
      "search": {
        "indices": ["auditd-*"],
        "query": {
          "size": 0,
          "query": {
            "bool": {
              "filter": [
                {
                  "range": {
                    "@timestamp": {
                      "gte": "now-30s"
                    }
                  }
                }
              ]
            }
          },
          "aggs": {
            "by_host": {
              "terms": {
                "field": "host.name",
                "size": 100
              },
              "aggs": {
                "has_npm_child": {
                  "filter": {
                    "bool": {
                      "must": [
                        { "term": { "auditd.data.syscall": "execve" } },
                        { "terms": { "process.parent.name": ["npm", "npx", "node"] } },
                        { "terms": { "process.name": ["curl", "wget", "bash", "sh", "python3"] } }
                      ]
                    }
                  }
                },
                "has_node_connect": {
                  "filter": {
                    "bool": {
                      "must": [
                        { "term": { "auditd.data.syscall": "connect" } },
                        { "term": { "process.name": "node" } }
                      ],
                      "must_not": [
                        { "prefix": { "destination.ip": "10." } },
                        { "prefix": { "destination.ip": "192.168." } },
                        { "prefix": { "destination.ip": "127." } }
                      ]
                    }
                  }
                },
                "has_node_modules_delete": {
                  "filter": {
                    "bool": {
                      "must": [
                        { "terms": { "auditd.data.syscall": ["unlink", "unlinkat"] } },
                        { "wildcard": { "file.path": "*node_modules*" } }
                      ]
                    }
                  }
                },
                "all_three_signals": {
                  "bucket_script": {
                    "buckets_path": {
                      "npm_child": "has_npm_child._count",
                      "node_conn": "has_node_connect._count",
                      "modules_del": "has_node_modules_delete._count"
                    },
                    "script": "params.npm_child > 0 && params.node_conn > 0 && params.modules_del > 0 ? 1 : 0"
                  }
                }
              }
            }
          }
        }
      }
    }
  ],
  "triggers": [
    {
      "query_trigger": {
        "name": "all-three-signals-present",
        "severity": "1",
        "condition": {
          "script": {
            "source": "ctx.results[0].aggregations.by_host.buckets.stream().anyMatch(b -> b.all_three_signals.value == 1)",
            "lang": "painless"
          }
        },
        "actions": [
          {
            "name": "pagerduty-alert",
            "destination_id": "PAGERDUTY_DESTINATION_ID",
            "message_template": {
              "source": "npm supply chain RAT composite alert on host {{ctx.results[0].aggregations.by_host.buckets[0].key}}. All three signals present within 30s: npm child process, node outbound connect, node_modules deletion. Isolate immediately."
            },
            "action_execution_policy": {
              "action_execution_scope": {
                "per_alert": {
                  "actionable_alerts": ["DEDUPED", "NEW"]
                }
              }
            }
          }
        ]
      }
    }
  ]
}
```

The alert message includes the hostname, making it actionable immediately: the responder knows which machine to isolate without pivoting through dashboards.

## Expected Behaviour After Hardening

**After osquery alert:** Within 15 seconds of the `postinstall` script spawning `curl` or `sh`, the osquery scheduled query with a 15-second interval fires. If the result set is non-empty, the Fleet webhook fires and creates a SIEM alert. The total latency from RAT execution to SIEM alert is under 30 seconds — before the evidence erasure step completes.

**After Sigma rule:** A test install of the Axios malicious version in an isolated sandbox environment (network-egress-allowed, auditd enabled, file system events forwarded to SIEM) triggers all three signals. The composite alert fires within 30 seconds of `npm install` starting. Validate by running `sigma convert` against the rule and replaying auditd log fixtures from the test environment through the converted query.

**After SIEM correlation:** The PagerDuty alert body includes the process tree (parent `npm`, child `node`, grandchild `bash`), the destination IP address and port from the `connect` syscall event, and the file path that was deleted in `node_modules/`. The responder has enough context to isolate the affected machine and begin forensic collection without needing to log into the host first.

In a test scenario with the malicious Axios version installed on an Ubuntu 22.04 host with the full telemetry stack enabled, the sequence is:

1. `npm install` starts — osquery picks up the `npm` process.
2. `postinstall` fires `plain-crypto-js/install.js` — osquery sees `node` as a child of `npm`.
3. `node` opens a connection to `203.0.113.45:443` — auditd `connect` event logged.
4. Second-stage payload written to `/tmp/.update-service` — file creation event logged.
5. `plain-crypto-js/install.js` unlinks itself — auditd `unlinkat` event logged with path containing `node_modules`.
6. OpenSearch correlation sees all three events within the 30-second window → PagerDuty fires.

Total time from step 1 to PagerDuty notification: 28 seconds in the test environment.

## Trade-offs and Operational Considerations

**osquery interval reduction has a cost.** Reducing the scheduled query interval from 60 seconds to 15 seconds increases query frequency fourfold. On a fleet of 1,000 hosts, profile the CPU impact before deploying. Process table queries are relatively cheap (they read `/proc`, not disk), but multiplied across a large fleet the aggregate overhead is non-trivial. Use event-based tables (`process_events` with `enable_process_events: true`) rather than polling the `processes` table where possible — event-based tables stream data as events occur rather than scanning the entire process list on an interval.

**`inotifywait` does not scale to large `node_modules/` trees.** Watching a `node_modules/` directory with 10,000+ files adds measurable CPU overhead on CI runners, particularly on inotify systems that must track each file descriptor. Use Falco with the eBPF driver for production hosts and Kubernetes nodes. Reserve `inotifywait` for developer workstations and small CI environments. The Falco rule provides equivalent coverage with kernel-level efficiency.

**The Sigma rule correlation window generates false positives from legitimate postinstall scripts.** Several widely-used npm packages make outbound HTTP requests during installation to download platform-specific binaries: `esbuild`, `puppeteer`, `sharp`, `canvas`. These packages will trigger the `node_outbound_connect` signal. Tune by adding an allowlist of known-good package names matched against the `cmdline` of the parent `node` process (which includes the path to the install script). Maintain the allowlist in a separate config file and reference it from the Sigma rule's `falsepositives` condition.

**The SIEM correlation rule requires all three telemetry pipelines to be functioning.** If auditd events are not being forwarded, or if the file system event source is down, the composite rule will not fire even when all three events occur. Validate the full pipeline end-to-end before relying on it: run a controlled test install of a package whose postinstall makes a network request and creates then deletes a file in `node_modules/`, and verify the alert fires. Instrument the pipeline health — alert if any of the three event types has a zero event rate for more than 5 minutes on a host that is otherwise active.

**Developer workstation coverage is harder than CI coverage.** CI runners are ephemeral and uniform; installing the telemetry stack is a pipeline step. Developer workstations are heterogeneous, long-lived, and often not managed centrally. Require osquery via the endpoint management platform (Jamf, Puppet, Ansible) and validate coverage weekly via Fleet's host count.

## Failure Modes

**osquery not installed on CI runners.** The process tree telemetry gap means the first signal is absent. CI pipelines are the highest-risk environment — they run `npm install` constantly and their output artifacts (Docker images, deployed binaries) propagate the compromise to production. Make osquery installation a CI runner AMI/base image requirement, not an optional add-on.

**Sigma rule fires but the alert is routed to a low-priority SIEM queue.** If the security team has configured all rule-level `high` alerts to go into a triage queue reviewed daily, the PagerDuty path is bypassed. The RAT will have been running for 24 hours before anyone sees the alert. Map `level: high` Sigma alerts from the supply chain rule category to an immediate PagerDuty notification, not the daily triage queue. Document the routing decision explicitly so it survives team changes.

**File system monitoring watching `node_modules/` but not temp directories.** The second-stage payload is written to `/tmp/` or `~/.config/`, not `node_modules/`. Monitoring only `node_modules/` catches the evidence erasure signal but misses the payload deployment signal. Add temp directory monitoring to the Falco ruleset and to the inotifywait watch list. The combination of both file system signals (deletion in `node_modules/` plus creation in a temp directory from an `npm` ancestor) is a higher-fidelity indicator than either alone.

**Correlation window too wide.** Setting the SIEM correlation window to 5 minutes instead of 30 seconds means that a developer running `npm install` in a terminal and separately running a `curl` command five minutes later, in an unrelated activity, will match the pattern. Alert fatigue sets in within days of deploying the rule, and the SOC disables it. Keep the correlation window at 30 seconds. If false positives remain, narrow them by requiring the `node` process making the outbound connection to be a descendant of the specific `npm` process identified in the first signal, not just any `node` process on the host.

**auditd rules not loaded after a reboot.** `auditctl` commands applied at the CLI are not persistent. If the rules are not written to `/etc/audit/rules.d/npm-supply-chain.rules` and loaded by `augenrules --load`, a host reboot silently drops the telemetry. Include an auditd rule validation step in the configuration management playbook and alert on hosts where the `npm_exec` and `node_outbound_connect` audit keys are absent from `auditctl -l` output.

## Related Articles

- [Application Security Logging](/articles/observability/application-security-logging/)
- [Detection Rules](/articles/observability/detection-rules/)
- [Threat Hunting Osquery](/articles/observability/threat-hunting-osquery/)
- [npm Postinstall Kernel Detection](/articles/linux/npm-postinstall-kernel-detection/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
