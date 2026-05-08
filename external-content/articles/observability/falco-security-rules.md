---
title: "Falco Runtime Security: Writing Effective Detection Rules and Deploying Falco Securely"
description: "Falco is the de facto standard for Linux runtime security monitoring. This guide covers its syscall-based detection model, writing custom rules for privilege escalation, container escapes, and credential access, tuning rules to eliminate false positives, securing falco.yaml, routing alerts through Falcosidekick, and automating response with Falco Talon."
slug: falco-security-rules
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - falco
  - runtime-security
  - detection-rules
  - kubernetes
  - syscall-monitoring
personas:
  - security-engineer
  - platform-engineer
article_number: 543
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/falco-security-rules/
---

# Falco Runtime Security: Writing Effective Detection Rules and Deploying Falco Securely

## Problem

Most runtime security monitoring is either too shallow (audit logs only, no syscall visibility) or too expensive to run at production scale. [Falco](https://falco.org) occupies the right middle ground: it attaches a probe to the Linux kernel, streams every relevant syscall event, and evaluates them against a rule set in near-real-time. The gap between "we have Falco installed" and "Falco is actually detecting attacks" is wider than most teams realize.

The specific problems:

- **Default rules generate noise.** The FalcoSecurity upstream rule set is broad by design. Without tuning, production environments see hundreds of false positives per day for legitimate CI pipelines, package installs, and debug tooling.
- **Custom rules require understanding the Falco condition language.** Writing `evt.type = execve and proc.name = bash` is easy. Writing a rule that accurately distinguishes attacker shells from legitimate bash usage is a two-week calibration exercise if you do not understand macros, lists, and field inheritance.
- **Deployment security is neglected.** Falco itself runs as a privileged DaemonSet with kernel-level visibility. A misconfigured Falco instance that sends alerts over unauthenticated HTTP, or that uses the kernel module driver in a production cluster, introduces new risk rather than reducing it.

This article covers: the eBPF probe vs kernel module tradeoff, the complete Falco rule anatomy, custom rules for the five most important attack categories, tuning approaches, securing `falco.yaml`, routing alerts with [Falcosidekick](https://github.com/falcosecurity/falcosidekick), automated response with [Falco Talon](https://docs.falco-talon.org), and testing rules before deploying them.

**Target systems:** Kubernetes 1.28+ with Falco 0.39+. Falcosidekick 2.29+. Falco Talon 0.2+.

## Threat Model

- **Adversary:** An attacker who has compromised a workload (via application vulnerability, supply chain attack, or stolen credentials) and is attempting to escalate privileges, access credentials, escape the container, or move laterally to other services.
- **Detection window:** Falco detects at the syscall level, meaning it can alert on the first `execve` call of a privilege-escalation attempt before the binary has a chance to run. This is earlier than any log-based detection.
- **Blind spots:** Falco does not detect attacks that happen entirely in userspace without syscalls (pure memory attacks), attacks that compromise the Falco process itself, or attacks that begin before Falco is running. Address blind spots with complementary controls: immutable container images, OPA admission policies, and network policy.

## Configuration

### eBPF Probe vs Kernel Module

Falco supports three driver modes: kernel module (`kmod`), eBPF probe (`ebpf`), and modern eBPF (`modern_ebpf`). Always use `modern_ebpf` or `ebpf` in production. Never use `kmod` in new deployments.

**Why the kernel module is high risk:**

The kernel module (`falco.ko`) runs as a loadable kernel module with the highest privilege level on the system. A bug in the module can kernel-panic the node. The module must be recompiled for every kernel version, and a mismatch causes a crash at load time. It bypasses all the safety guarantees that eBPF provides: the eBPF verifier, bounded loops, checked memory accesses. In a production Kubernetes cluster, a kernel panic on a node means all pods on that node are evicted simultaneously, potentially triggering cascading failures.

The `modern_ebpf` driver (Falco 0.35+, kernel 5.8+) requires no kernel headers, no module compilation, and passes the eBPF verifier on every load. Use it:

```yaml
# values.yaml for Falco Helm chart
driver:
  kind: modern_ebpf

# Explicitly disable kernel module loading
falco:
  # Do not load kernel module
  load_plugins: []
```

For kernels 4.14–5.7 where `modern_ebpf` is unavailable, use the classic `ebpf` probe (requires kernel headers on the host):

```yaml
driver:
  kind: ebpf
  ebpf:
    path: ""           # Auto-detect from kernel version
    leastPrivileged: false  # Still requires CAP_SYS_PTRACE, CAP_SYS_ADMIN
```

### Falco Rule Anatomy

Every Falco rule file uses three building blocks: lists, macros, and rules.

**Lists** are named arrays of strings used in conditions:

```yaml
# A list of shells considered "attacker-worthy."
# Used in conditions with the `in` operator.
- list: shell_binaries
  items: [bash, sh, dash, zsh, ksh, fish, tcsh, csh]

# Package managers that should never run in production containers.
- list: package_manager_binaries
  items: [apt, apt-get, yum, dnf, apk, pip, pip3, npm, gem]

# Privileged binaries that perform setuid operations.
- list: setuid_binaries
  items: [su, sudo, newgrp, sg, passwd, chfn, gpasswd]
```

**Macros** are named condition fragments that can be composed:

```yaml
# True when the event originates inside a container (not on the host).
- macro: container
  condition: container.id != host

# True for the process that is the container entrypoint (PID 1 in the container).
# Used to suppress false positives: PID 1 is allowed to exec shells;
# child processes generally should not.
- macro: container_entrypoint
  condition: proc.vpid = 1

# True when the spawning process is a known CI/CD agent.
# Extend this list to match your environment.
- macro: spawned_by_ci
  condition: >
    proc.aname[2] in (jenkins, gitlab-runner, drone-runner, buildkitd, kaniko)
    or proc.aname[3] in (jenkins, gitlab-runner, drone-runner, buildkitd, kaniko)

# True when the process runs in a namespace explicitly labeled for development.
- macro: dev_namespace
  condition: k8s.ns.name in (dev, development, staging, test, qa)
```

**Rules** combine conditions with output formatting:

```yaml
- rule: Unexpected Shell Spawned in Container
  desc: >
    A shell was spawned inside a container by a process that is not the
    container entrypoint. This is a strong indicator of an interactive
    session opened by an attacker.
  condition: >
    container
    and evt.type = execve
    and evt.dir = <
    and proc.name in (shell_binaries)
    and not container_entrypoint
    and not spawned_by_ci
  output: >
    Shell spawned in container
    (shell=%proc.name pid=%proc.pid parent=%proc.pname
     container_id=%container.id image=%container.image.repository
     k8s_pod=%k8s.pod.name k8s_ns=%k8s.ns.name
     cmdline=%proc.cmdline user=%user.name)
  priority: WARNING
  tags: [shell, container, mitre_execution]
```

Key fields in every rule:
- `condition`: Boolean expression evaluated against the syscall event stream.
- `output`: Alert message. Include all fields needed for triage. Do not omit `container.id` and `k8s.pod.name`.
- `priority`: `DEBUG`, `INFORMATIONAL`, `NOTICE`, `WARNING`, `ERROR`, `CRITICAL`, `ALERT`, `EMERGENCY`. Map `CRITICAL` and above to PagerDuty; `WARNING` and above to Slack.
- `tags`: Arbitrary strings. Use MITRE ATT&CK tactic tags (`mitre_execution`, `mitre_privilege_escalation`, etc.) so your SIEM can auto-tag events.

### Detecting Privilege Escalation

The `su` and `sudo` binaries perform setuid privilege escalation. They are legitimately called by humans at a terminal, but not by application processes inside containers.

```yaml
# Detect any process executing su or sudo from within a container,
# unless the parent is an interactive terminal session (tty attached).
- rule: Privilege Escalation via su or sudo in Container
  desc: >
    su or sudo executed inside a container. Application code should not
    require privilege escalation. Attacker may be attempting to gain root.
  condition: >
    container
    and evt.type = execve
    and evt.dir = <
    and proc.name in (setuid_binaries)
    and not proc.tty != 0     # Allow interactive terminal sessions (humans debugging)
    and not container_entrypoint
  output: >
    Privilege escalation attempt in container
    (binary=%proc.name pid=%proc.pid parent=%proc.pname ppid=%proc.ppid
     container=%container.id image=%container.image.repository
     pod=%k8s.pod.name ns=%k8s.ns.name user=%user.name tty=%proc.tty)
  priority: ERROR
  tags: [privilege_escalation, mitre_privilege_escalation, container]

# Detect setuid bit on a newly written executable inside a container.
# Attackers plant setuid binaries to leave a persistent escalation path.
- rule: Setuid Binary Written in Container
  desc: A file with the setuid bit set was written inside a container.
  condition: >
    container
    and evt.type in (open, openat, openat2)
    and evt.dir = <
    and (evt.arg.flags contains O_CREAT or evt.arg.flags contains O_WRONLY)
    and fd.name glob "/usr/*"
    and evt.arg.mode contains S_ISUID
  output: >
    Setuid binary written in container
    (file=%fd.name pid=%proc.pid cmdline=%proc.cmdline
     container=%container.id image=%container.image.repository
     pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [privilege_escalation, mitre_persistence]
```

### Detecting Container Escape Attempts

Container escapes rely on a small set of kernel primitives: namespace manipulation via `nsenter` or `unshare`, host filesystem access via mounts, and `/proc` filesystem abuse.

```yaml
# Detect mount syscall from inside a container.
# Containers should not need to mount filesystems. Legitimate use cases
# (CSI drivers, privileged DaemonSets) must be explicitly allowed.
- list: known_privileged_images
  items:
    - falcosecurity/falco-driver-loader
    - kindest/node
    - rancher/local-path-provisioner
    - openebs/provisioner-localpv

- rule: Mount Syscall in Container
  desc: >
    A mount syscall was issued from inside a container. This is a key
    indicator of a container escape attempt via namespace/filesystem manipulation.
  condition: >
    container
    and evt.type = mount
    and not container.image.repository in (known_privileged_images)
    and not container_entrypoint
  output: >
    Mount syscall in container
    (target=%evt.arg.target flags=%evt.arg.flags
     pid=%proc.pid cmdline=%proc.cmdline
     container=%container.id image=%container.image.repository
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: CRITICAL
  tags: [container_escape, mitre_privilege_escalation]

# Detect nsenter or unshare execution from a container.
# Both tools manipulate Linux namespaces and are the primary mechanism
# for escaping container isolation.
- rule: Namespace Escape Tools Executed in Container
  desc: >
    nsenter or unshare was executed inside a container. These tools
    are used to enter host namespaces or create new namespaces to
    escape container isolation.
  condition: >
    container
    and evt.type = execve
    and evt.dir = <
    and proc.name in (nsenter, unshare)
    and not spawned_by_ci
  output: >
    Namespace escape tool executed
    (binary=%proc.name args=%proc.args pid=%proc.pid
     container=%container.id image=%container.image.repository
     pod=%k8s.pod.name ns=%k8s.ns.name user=%user.name)
  priority: CRITICAL
  tags: [container_escape, mitre_privilege_escalation]
```

### Detecting Credential Access

Attackers inside a container target two credential stores: `/etc/shadow` (local password hashes) and `/proc/<PID>/mem` (process memory, which may contain live secrets).

```yaml
# Detect reads of /etc/shadow.
# Shadow file access should only occur during PAM authentication, not
# from application processes. An unexpected open of shadow is credential theft.
- macro: allowed_shadow_readers
  condition: >
    proc.name in (passwd, unix_chkpwd, sshd, login, su, sudo, cron)

- rule: Shadow File Read
  desc: >
    /etc/shadow was opened for reading by a process that is not a standard
    PAM authentication binary. Indicates credential harvesting.
  condition: >
    evt.type in (open, openat, openat2)
    and evt.dir = <
    and fd.name = /etc/shadow
    and not allowed_shadow_readers
    and not proc.name startswith python  # Python package installs check shadow
  output: >
    Shadow file read
    (proc=%proc.name pid=%proc.pid parent=%proc.pname
     user=%user.name container=%container.id
     pod=%k8s.pod.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [credential_access, mitre_credential_access]

# Detect /proc/<PID>/mem access from a non-ptrace-authorized process.
# Reading another process's memory is used to extract secrets from
# application memory without triggering file-based detection.
- rule: Process Memory Read via /proc
  desc: >
    A process opened /proc/<PID>/mem for reading. This bypasses normal
    file access controls and is used to extract credentials from running
    processes (e.g., database passwords in application heap memory).
  condition: >
    evt.type in (open, openat, openat2)
    and evt.dir = <
    and fd.name glob /proc/*/mem
    and not proc.name in (gdb, strace, lldb, perf)
  output: >
    Process memory read via /proc
    (proc=%proc.name pid=%proc.pid target_path=%fd.name
     container=%container.id pod=%k8s.pod.name user=%user.name)
  priority: CRITICAL
  tags: [credential_access, mitre_credential_access]
```

### Detecting Lateral Movement

Unexpected outbound connections from containers that normally do not make external network calls are a reliable signal for command-and-control establishment or data exfiltration.

```yaml
# Detect outbound connections from containers to unexpected destinations.
# This rule is most effective on tightly-scoped workloads (databases,
# batch processors) that have a known, stable set of network peers.
- list: internal_cidrs
  items:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"

# Detect development or data containers making unexpected TCP connections
# to public IP ranges.
- rule: Unexpected Outbound Connection from Data Container
  desc: >
    A container whose name suggests a database or data-processing role
    made an outbound TCP connection to a public IP address. Data containers
    should only communicate within the cluster.
  condition: >
    container
    and evt.type = connect
    and evt.dir = <
    and fd.typechar = 4    # IPv4
    and fd.rip_net not in (internal_cidrs)
    and fd.l4proto = tcp
    and (
      container.name glob *postgres* or
      container.name glob *mysql* or
      container.name glob *redis* or
      container.name glob *mongo* or
      container.name glob *kafka*
    )
  output: >
    Unexpected outbound connection from data container
    (proc=%proc.name dest_ip=%fd.rip dest_port=%fd.rport
     container=%container.id image=%container.image.repository
     pod=%k8s.pod.name ns=%k8s.ns.name)
  priority: ERROR
  tags: [lateral_movement, mitre_command_and_control, exfiltration]
```

### Rule Tuning: Reducing False Positives

The most common sources of false positives and how to eliminate them without weakening detection:

**Pattern 1: Init containers and job pods trigger rules on startup.** Use `container_entrypoint` to suppress:

```yaml
# The container_entrypoint macro is true when proc.vpid = 1.
# PID 1 in a container legitimately execs shells, installs packages,
# and mounts volumes during initialization. Allow it explicitly.
- macro: container_entrypoint
  condition: proc.vpid = 1
```

**Pattern 2: Specific images are flagged by broad rules.** Maintain per-rule exception lists and document why each exception exists:

```yaml
# Append exceptions to existing rules without modifying the original rule.
# Use the append: true directive to extend the condition.
- rule: Unexpected Shell Spawned in Container
  condition: >
    and not container.image.repository in (
      "our-registry.example.com/debug-toolbox",
      "bitnami/kubectl"
    )
  append: true
  # Reason: debug-toolbox is a pre-approved break-glass image.
  # kubectl image execs sh during readiness probes.
```

**Pattern 3: Specific Kubernetes namespaces have different risk profiles.** Use namespace-based exceptions for dev environments only:

```yaml
# Exempt the dev namespace from the outbound connection rule.
# Dev containers routinely connect to external APIs.
- rule: Unexpected Outbound Connection from Data Container
  condition: and not dev_namespace
  append: true
```

**Pattern 4: Known CI/CD tooling triggers execution rules.** Use ancestor process name matching (`proc.aname[N]`) to trace the process tree:

```yaml
# Allow package installs when the grandparent or great-grandparent
# is a recognized build agent. proc.aname[2] = grandparent process name.
- macro: spawned_by_ci
  condition: >
    proc.aname[1] in (make, gradle, maven)
    or proc.aname[2] in (jenkins, gitlab-runner, drone-runner)
    or proc.aname[3] in (jenkins, gitlab-runner, drone-runner)
```

### Securing falco.yaml

The `falco.yaml` configuration file controls how Falco processes and outputs events. Default configuration is not production-ready.

```yaml
# /etc/falco/falco.yaml — hardened production configuration.

# 1. Use the modern eBPF driver.
engine:
  kind: modern_ebpf

# 2. Set the minimum rule priority to suppress DEBUG and INFORMATIONAL noise.
# In most environments, WARNING is the right minimum for actionable alerts.
priority: warning

# 3. Disable the default JSON stdout output (use structured outputs only).
stdout_output:
  enabled: false

# 4. Send alerts to Falcosidekick over gRPC (preferred) or HTTP.
# gRPC provides TLS mutual authentication; prefer it over HTTP.
grpc:
  enabled: true
  bind_address: "unix:///run/falco/falco.sock"
  threadiness: 8

grpc_output:
  enabled: true

# 5. If you must use HTTP output, always use HTTPS with a valid certificate.
# Never send alerts to an unauthenticated HTTP endpoint.
http_output:
  enabled: true
  url: "https://falcosidekick.monitoring.svc.cluster.local:2801"
  user_agent: "falcosecurity/falco"
  # mTLS is preferred over simple TLS; set client cert if Falcosidekick
  # requires client authentication.

# 6. Rate-limit outputs to avoid flooding alert channels during an incident.
# A single exploit attempt can generate thousands of syscall events per second.
outputs:
  rate: 1
  max_burst: 1000

# 7. Restrict Falco's own file descriptor table to prevent information leakage.
outputs_queue:
  capacity: 0     # Unbounded queue is the default; set a limit in memory-constrained environments.

# 8. Disable syscall event drops reporting to stderr (redirect to structured output).
syscall_event_drops:
  actions:
    - log
    - alert
  rate: 0.03333
  max_burst: 10

# 9. Falco loads rules in the order listed. Place custom rules AFTER upstream rules
# so that append: true directives work correctly.
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d
```

### Falcosidekick for Alert Routing

[Falcosidekick](https://github.com/falcosecurity/falcosidekick) receives Falco webhook output and fans alerts out to any combination of downstream destinations. Run it as a Deployment (not DaemonSet) behind a ClusterIP Service.

```yaml
# falcosidekick-config.yaml — mounted as ConfigMap
[DEFAULT]

# Slack: send WARNING and above to general security channel,
# CRITICAL and above to paging channel.
[slack]
webhookurl = https://hooks.slack.com/services/YOUR/WEBHOOK/URL
channel = #security-alerts
minimumpriority = warning
messageformat = long    # Include all fields in the message.

# PagerDuty: only page on CRITICAL and above.
[pagerduty]
routingkey = YOUR_PAGERDUTY_INTEGRATION_KEY
minimumpriority = critical

# Elasticsearch: send all events at NOTICE and above for SIEM correlation.
[elasticsearch]
hostport = https://elasticsearch.logging.svc.cluster.local:9200
index = falco-events
minimumpriority = notice
username = falcosidekick
password_env = ELASTICSEARCH_PASSWORD    # Read from environment variable.
# mutualtls: true    # Enable mTLS for production Elasticsearch clusters.
```

Helm deployment:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --create-namespace \
  --set config.slack.webhookurl="${SLACK_WEBHOOK_URL}" \
  --set config.slack.minimumpriority=warning \
  --set config.pagerduty.routingkey="${PAGERDUTY_KEY}" \
  --set config.pagerduty.minimumpriority=critical \
  --set config.elasticsearch.hostport="https://elasticsearch.logging.svc:9200" \
  --set config.elasticsearch.minimumpriority=notice \
  --set webui.enabled=true \
  --set replicaCount=2
```

### Falco Talon for Automated Response

[Falco Talon](https://docs.falco-talon.org) is a response engine that subscribes to Falcosidekick and takes automated actions when specific rules fire. The primary use case: kill a container immediately on a `CRITICAL` rule match, before the attacker can complete their objective.

```yaml
# talon-rules.yaml

# Action set: terminate the offending container.
- action: Terminate Pod
  actionner: kubernetes:terminate
  parameters:
    grace_period_seconds: 0     # Kill immediately, no graceful shutdown.

# Action set: label the pod for forensic collection before termination.
- action: Label Suspicious Pod
  actionner: kubernetes:label
  parameters:
    labels:
      security.example.com/incident: "true"
      security.example.com/falco-rule: "{{ .RuleName }}"
      security.example.com/incident-time: "{{ .Time }}"

# Response plan: on container escape or credential access, label then terminate.
- rule: Container Escape Response
  match:
    rules:
      - Mount Syscall in Container
      - Namespace Escape Tools Executed in Container
      - Process Memory Read via /proc
  actions:
    - action: Label Suspicious Pod
    - action: Terminate Pod

# Response plan: on privilege escalation, label only (do not auto-terminate
# to avoid disrupting stateful workloads; require human confirmation).
- rule: Privilege Escalation Response
  match:
    rules:
      - Privilege Escalation via su or sudo in Container
      - Setuid Binary Written in Container
  actions:
    - action: Label Suspicious Pod
```

Deploy Talon alongside Falcosidekick and configure Falcosidekick to forward to the Talon webhook:

```bash
helm install falco-talon falcosecurity/falco-talon \
  --namespace falco \
  --set listenPort=2803

# Add Talon as a Falcosidekick output target:
helm upgrade falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --reuse-values \
  --set config.webhook.address=http://falco-talon.falco.svc:2803 \
  --set config.webhook.minimumpriority=critical
```

### The FalcoSecurity Rules Library and Plugins

The [falcosecurity/rules](https://github.com/falcosecurity/rules) repository is the official upstream rules library. It is separate from the Falco binary, versioned independently, and updated more frequently than Falco releases.

Key rule files to be aware of:

- `falco_rules.yaml`: Core syscall rules for container escapes, shell spawning, file writes.
- `falco-incubating_rules.yaml`: Higher false-positive rules that are useful in controlled environments.
- `falco-sandbox_rules.yaml`: Experimental rules under development. Do not enable in production.

[Falco plugins](https://falco.org/docs/plugins/) extend Falco beyond syscall monitoring. The most useful security plugins:

- **k8saudit**: Parses Kubernetes audit log events. Detects `exec` into pods, role bindings, secret access — all from audit logs rather than syscalls.
- **cloudtrail**: Parses AWS CloudTrail events. Detects IAM changes, S3 access, and EC2 modifications.
- **github**: Monitors GitHub webhook events for repository changes.

Enable the k8saudit plugin alongside the syscall engine:

```yaml
# falco.yaml additions for k8saudit plugin.
plugins:
  - name: k8saudit
    library_path: libk8saudit.so
    init_config:
      maxEventSize: 262144
      webhookMaxBatchSize: 12582912
    open_params: "http://:9765/k8s-audit"

  - name: json
    library_path: libjson.so

load_plugins: [k8saudit, json]
```

### Testing Rules Before Deploying

Never deploy new Falco rules to production without testing. Two approaches:

**1. Dry-run validation** checks rule syntax and field references without processing live events:

```bash
# Validate rule file syntax.
falco --dry-run \
  -r /etc/falco/falco_rules.yaml \
  -r /etc/falco/custom-rules.yaml

# The exit code is non-zero if any rule contains syntax errors or
# references invalid field names. Run this in CI before merging rule changes.
```

**2. Event injection with `falco-tester`** replays synthetic syscall traces against the rule set:

```bash
# Install falco-tester (part of the falcosecurity/testing repo).
git clone https://github.com/falcosecurity/testing
cd testing

# Run the built-in test suite against your rules.
make test RULES_DIR=/path/to/your/rules

# Test a specific rule by triggering the relevant syscall in a container.
# Example: trigger the "Shadow File Read" rule.
docker run --rm \
  -v /etc/shadow:/etc/shadow:ro \
  alpine:latest \
  cat /etc/shadow

# Falco running on the host should fire the "Shadow File Read" rule.
# Check Falco output:
sudo journalctl -u falco -f
```

**3. Use `pdig` (ptrace-based event capture)** to replay real syscall traces in isolation:

```bash
# Record a syscall trace of a suspicious command.
pdig -j -p $(pgrep -n suspicious-process) > trace.json

# Replay the trace against your rules without running on a live cluster.
falco --dry-run -e trace.json -r custom-rules.yaml
```

## Verification

After deploying Falco with your custom rules, verify the full pipeline:

```bash
# 1. Confirm Falco is running with the modern_ebpf driver.
kubectl exec -n falco -it $(kubectl get pods -n falco -l app=falco -o name | head -1) -- \
  falco --version

# 2. Trigger a test rule (spawn a shell in a running pod).
kubectl exec -n default deploy/test-app -- sh -c "id"

# 3. Verify the alert appears in Falco logs.
kubectl logs -n falco -l app=falco --tail=50 | grep "Shell spawned"

# 4. Verify the alert reached Falcosidekick.
kubectl logs -n falco -l app=falcosidekick --tail=50 | grep "Shell spawned"

# 5. Confirm the alert appeared in your Slack channel and Elasticsearch index.
# In Elasticsearch:
curl -s "https://elasticsearch.logging.svc:9200/falco-events/_search?q=rule:*Shell*&size=1" \
  | jq '.hits.hits[0]._source'

# 6. Measure syscall event drop rate (drops mean Falco cannot keep up with load).
kubectl exec -n falco -it $(kubectl get pods -n falco -l app=falco -o name | head -1) -- \
  cat /proc/$(pgrep falco)/net/dev
# Or via the Falco metrics endpoint if enabled:
curl http://falco-metrics.falco.svc:8765/metrics | grep falco_drops
```

A drop rate above 0.1% means Falco is losing events. Remediation options: increase `syscall_buf_size_preset` in `falco.yaml`, reduce the number of active rules, or increase the DaemonSet CPU limit.

## Key Points

- Use `modern_ebpf` or `ebpf` driver. Never use the kernel module (`kmod`) in production: a bug panics the node.
- Rules have three building blocks: lists (string arrays), macros (condition fragments), and rules (condition + output + priority). Compose them aggressively; do not duplicate conditions.
- The `container_entrypoint` macro (`proc.vpid = 1`) is your primary false-positive suppressor for init container activity.
- Use `append: true` to add exceptions to upstream rules rather than copying and modifying them. This makes upstream rule upgrades safe.
- Secure `falco.yaml`: disable stdout output, enable gRPC or HTTPS HTTP output, rate-limit outputs, and never send alerts to unauthenticated endpoints.
- Falcosidekick fan-out: route `WARNING`+ to Slack, `CRITICAL`+ to PagerDuty, `NOTICE`+ to Elasticsearch.
- Falco Talon enables automated response: label pods for forensics and terminate them on `CRITICAL` rules. Do not auto-terminate stateful workloads without a human approval gate.
- Validate all rule changes with `falco --dry-run` in CI before merging. Test with synthetic workloads before enabling in production namespaces.
- Monitor the syscall event drop rate. Drops mean missed detections; remediate by tuning the buffer size or reducing rule complexity before an incident occurs.
