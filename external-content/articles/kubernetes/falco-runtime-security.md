---
title: "Runtime Security with Falco on Kubernetes: Rules, Tuning, and Response Automation"
description: "Prevention-only security has a binary failure mode: either the control holds and the attacker is stopped, or the control fails and the attacker..."
slug: "falco-runtime-security"
date: 2026-04-02
lastmod: 2026-04-02
category: "kubernetes"
tags: ["falco", "runtime-security", "ebpf", "detection", "kubernetes", "falcosidekick"]
personas: ["security-engineer", "platform-engineer"]
article_number: 29
difficulty: "advanced"
estimated_reading_time: 22
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Aqua"
    id: 123
    category: "runtime-security"
premium_pack: "falco-rule-collection"
published: true
layout: article.njk
permalink: "/articles/kubernetes/falco-runtime-security/index.html"
---

# Runtime Security with [Falco](https://falco.org) on [Kubernetes](https://kubernetes.io): Rules, Tuning, and Response Automation

## Problem

Prevention-only security has a binary failure mode: either the control holds and the attacker is stopped, or the control fails and the attacker operates undetected. Network policies block lateral movement, until the attacker finds a pod with an overly permissive egress rule. Seccomp blocks dangerous syscalls, until the attacker uses an allowed syscall in an unexpected way. Admission control blocks bad workloads, until the attacker compromises a signed, legitimate image at runtime.

Runtime detection is the safety net that catches what prevention misses. It monitors process execution, file access, network connections, and syscalls inside running containers, detecting container escapes, reverse shells, crypto mining, credential theft, and data exfiltration as they happen.

Falco (CNCF) is the most widely deployed runtime security tool for Kubernetes. But out of the box, it generates 50-200 alerts per day on a moderately busy cluster. Most are false positives, benign processes that match generic detection patterns. Without tuning and response automation, Falco creates noise, not security. The team learns to ignore alerts, and real attacks go unnoticed in the flood.

This article covers deployment, custom rule writing based on container identity (not generic patterns), tuning for false positive reduction, and automated response via [Falcosidekick](https://github.com/falcosecurity/falcosidekick).

**Target systems:** Kubernetes 1.29+ with kernel 5.8+ (for eBPF driver). Falco 0.38+, Falcosidekick 2.29+.

## Threat Model

- **Adversary:** Attacker with code execution inside a container, post-exploitation phase. Prevention has failed or been bypassed. The attacker is now operating inside a running pod.
- **Access level:** Process running as the application user inside the container. May have access to the default service account token if not disabled ([Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)(/articles/cross-cutting/complete-kubernetes-hardening/)).
- **Objective:** Container escape (nsenter, unshare, mount manipulation). Reverse shell establishment. Crypto mining deployment. Credential theft (service account tokens, environment variables, mounted secrets). Data exfiltration. Persistence (create new pods, modify existing workloads).
- **Blast radius:** Without runtime detection, attacker operates for days or weeks before discovery (via outage, cost spike, or external notification). With Falco, detection within seconds, containment within minutes through automated response.

## Configuration

### Deployment

Deploy Falco as a DaemonSet with the eBPF driver (no kernel module loading required):

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --set driver.kind=ebpf \
  --set collectors.containerd.enabled=true \
  --set collectors.containerd.socket=/run/containerd/containerd.sock \
  --set falcosidekick.enabled=true \
  --set falcosidekick.webui.enabled=true \
  --set falcosidekick.config.slack.webhookurl="${SLACK_WEBHOOK_URL}" \
  --set falcosidekick.config.slack.minimumpriority="warning" \
  --set resources.requests.cpu=100m \
  --set resources.requests.memory=256Mi \
  --set resources.limits.cpu=1000m \
  --set resources.limits.memory=512Mi \
  --set tolerations[0].operator=Exists
```

```bash
# Verify Falco is running on all nodes:
kubectl get pods -n falco -o wide
# Expected: one Falco pod per node, all STATUS=Running

# Check Falco is receiving events:
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=5
# Expected: Falco output lines showing syscall events
```

### Default Rules: What to Keep, Disable, and Tune

Falco ships with hundreds of default rules. Many generate excessive noise in containerised environments.

**Rules to KEEP (high-value, low false-positive):**

```yaml
# These rules detect real attacks and rarely fire on legitimate activity:
# - Terminal shell in container (detect interactive shells)
# - Read sensitive file untrusted (detect /etc/shadow, /etc/passwd reads)
# - Write below binary dir (detect binary injection into /usr/bin, /usr/local/bin)
# - Contact K8S API Server From Container (detect API server abuse)
# - Modify Shell Configuration File (detect persistence via .bashrc, .profile)
```

**Rules to DISABLE (high false-positive in container environments):**

```yaml
# falco-overrides.yaml - ConfigMap for Falco overrides
# Disable rules that fire constantly in containerised environments:

- rule: Read sensitive file trusted after startup
  enabled: false
  # Reason: Many containers read /etc/passwd during startup (getent, NSS).

- rule: Write below etc
  enabled: false
  # Reason: Some containers legitimately write to /etc (resolv.conf, hosts).
  # Replace with more specific rules per container image.

- rule: Change thread namespace
  enabled: false
  # Reason: Container runtimes legitimately use namespace operations.
  # Replace with rules specific to container escape techniques.
```

### Custom Rules Based on Container Identity

The key to reducing false positives: write rules based on what SPECIFIC containers should and should not do, not generic rules that apply to all containers.

```yaml
# custom-rules.yaml - rules based on container image identity

# Rule: NGINX containers should never spawn a shell.
# This is always suspicious - NGINX does not need interactive shells.
- rule: Shell in NGINX Container
  desc: A shell was spawned inside an NGINX container.
  condition: >
    spawned_process
    and container
    and container.image.repository endswith "nginx"
    and proc.name in (bash, sh, dash, zsh, csh, ksh, fish)
  output: >
    Shell spawned in NGINX container
    (container_id=%container.id container_name=%container.name
     image=%container.image.repository:%container.image.tag
     process=%proc.name parent=%proc.pname cmdline=%proc.cmdline
     user=%user.name namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: WARNING
  tags: [container, shell, nginx, behavioural]

# Rule: Database containers should never make outbound connections
# to external IPs (only to replication peers and internal services).
- rule: Database External Connection
  desc: A database container connected to an external IP.
  condition: >
    evt.type = connect
    and evt.dir = <
    and container
    and (container.image.repository endswith "postgres"
         or container.image.repository endswith "mysql"
         or container.image.repository endswith "redis"
         or container.image.repository endswith "mongo")
    and fd.typechar = 4
    and not fd.sip in (rfc_1918_addresses)
    and not fd.sip = "127.0.0.1"
  output: >
    Database container connecting to external IP
    (container_name=%container.name image=%container.image.repository
     dest=%fd.sip:%fd.sport process=%proc.name
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, network, exfiltration, database]

# Rule: Detect crypto mining by known binary names.
- rule: Crypto Miner Detected
  desc: A known crypto mining binary was executed.
  condition: >
    spawned_process
    and container
    and proc.name in (xmrig, minerd, cpuminer, cgminer, bfgminer,
                       ethminer, stratum, cryptonight, randomx)
  output: >
    Crypto miner detected in container
    (binary=%proc.name container_name=%container.name
     image=%container.image.repository namespace=%k8s.ns.name
     pod=%k8s.pod.name cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [container, crypto, mining]

# Rule: Detect container escape via nsenter.
- rule: Container Escape via nsenter
  desc: nsenter was executed inside a container (namespace escape attempt).
  condition: >
    spawned_process
    and container
    and proc.name = nsenter
  output: >
    nsenter executed inside container (ESCAPE ATTEMPT)
    (container_name=%container.name image=%container.image.repository
     cmdline=%proc.cmdline user=%user.name
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, escape, nsenter]

# Rule: Detect reading Kubernetes service account tokens.
- rule: K8s Service Account Token Read
  desc: A process read the Kubernetes service account token file.
  condition: >
    open_read
    and container
    and fd.name = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    and not proc.name in (kube-proxy, kubelet, coredns, calico-node, cilium-agent)
  output: >
    Service account token read by unexpected process
    (process=%proc.name container=%container.name
     image=%container.image.repository
     namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: WARNING
  tags: [container, credential, k8s]
```

### Falcosidekick: Response Automation

Configure Falcosidekick to take automated action on high-confidence detections:

```yaml
# falcosidekick-config - relevant section of Helm values

falcosidekick:
  config:
    # Alert to Slack for all warnings and above
    slack:
      webhookurl: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      minimumpriority: "warning"
      messageformat: |
        *{{ .Priority }}*: {{ .Rule }}
        Namespace: {{ index .OutputFields "k8s.ns.name" }}
        Pod: {{ index .OutputFields "k8s.pod.name" }}
        Image: {{ index .OutputFields "container.image.repository" }}
        Process: {{ index .OutputFields "proc.name" }}

    # Forward to Grafana Cloud Loki for centralized storage
    loki:
      hostport: "https://logs-prod-us-central1.grafana.net"
      user: "${LOKI_USER}"
      apikey: "${LOKI_API_KEY}"
      minimumpriority: "notice"

    # Automated Kubernetes response for critical alerts
    kubernetes:
      # Label the pod for quarantine (NetworkPolicy blocks all traffic)
      - action: label
        parameters:
          minimumpriority: critical
          labels:
            quarantine: "true"
```

**Quarantine NetworkPolicy** (automatically applied to labelled pods):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-deny-all
  namespace: production
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []
```

### Tuning Workflow

The goal: reduce from 50-200 alerts/day (default) to under 10 false positives/day within 2-4 weeks.

```bash
# Week 1: Deploy in alert-only mode. Collect all alerts.
# Identify the top 10 rules by alert volume:
kubectl logs -n falco -l app.kubernetes.io/name=falco --since=24h | \
  grep -oP '"rule":"[^"]*"' | sort | uniq -c | sort -rn | head -10

# Week 2: For each high-volume rule:
# 1. Review alerts - are any real? (Almost certainly not for the top generators)
# 2. Add exceptions for known-good behaviour per container image
# 3. Or disable the rule and replace with a container-specific version

# Week 3-4: Verify false positive rate is below 10/day.
# Enable automated response for rules with near-zero false positives:
# - Crypto miner detection (known binary names → nearly zero FP)
# - nsenter in container (always suspicious → near-zero FP)

# Ongoing: Review new alerts weekly. Add exceptions as needed.
```

## Expected Behaviour

- Falco DaemonSet running on all nodes (pod count = node count)
- Custom rules detecting: shell in web containers, database external connections, crypto miners, container escape attempts, service account token access
- False positive rate below 10 per day after 2-4 week tuning period
- Automated quarantine for critical detections (crypto mining, container escape)
- All alerts forwarded to Slack and centralized logging (Grafana Cloud #108 or Axiom #112)
- Performance overhead below 2% CPU per node

```bash
# Verify detection (trigger a test alert):
kubectl exec -n production deploy/nginx -- /bin/sh -c "whoami"
# Check Falco logs within 5 seconds:
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=3 | grep "Shell"
# Expected: "Shell in NGINX Container" alert
```

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| eBPF driver (not kernel module) | No kernel module loading needed; works on more hosts | Requires kernel 5.8+; slightly fewer syscall hooks than kernel module | Check kernel version before deployment. Use kernel module driver on older kernels. |
| Automated pod quarantine | Instant containment for confirmed threats | False positive quarantines a legitimate pod → service disruption | Only auto-quarantine for near-zero-FP detections (crypto mining, nsenter). Alert-only for everything else. |
| Container-specific rules (not generic) | Much lower false positive rate | Must write rules for each application type | Start with the most common images (nginx, postgres, redis, node). Add as you deploy new workload types. |
| High rule count (many custom rules) | Better coverage | Higher CPU usage; more events to process | Profile CPU usage. Disable low-value rules. Target: 50-100 active rules. |
| Alert forwarding to managed backend | Centralized visibility; long-term retention | Cost of managed logging service; network egress for alert data | [Grafana Cloud](https://grafana.com/cloud) free tier handles moderate alert volumes. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Falco DaemonSet not running on a node | No detection on that node. blind spot | DaemonSet pod count < node count; [Prometheus](https://prometheus.io) `falco_running` metric missing for a node | Check tolerations (must tolerate all taints). Check resource limits (may be OOMKilled on small nodes). |
| eBPF driver fails to load | Falco pod crashloops | Pod logs show "error loading eBPF program"; `kubectl describe pod` shows backoff | Check kernel version (need 5.8+). Check seccomp/[AppArmor](https://apparmor.net) is not blocking BPF. Try kernel module driver as fallback. |
| Alert fatigue (>50 alerts/day) | Team stops investigating Falco alerts | Alert volume metrics show high count; no incident created from Falco alerts in 30 days | Follow the tuning workflow. Disable noisy default rules. Write container-specific rules. |
| Automated quarantine triggers on FP | Legitimate pod loses all network access | Service monitoring detects pod unreachable; pod has `quarantine: true` label | Remove the label: `kubectl label pod <name> quarantine-`. Tune the rule that triggered. Increase confidence threshold for auto-response. |
| Falcosidekick webhook fails | Alerts generated but never delivered | Falcosidekick metrics show delivery failures; no alerts in Slack/Loki | Check webhook URL and credentials. Verify network egress from falco namespace. Check Falcosidekick pod logs. |

## When to Consider a Managed Alternative

**Transition point:** Falco OSS generates 50-200 alerts/day out of the box. Tuning to under 10/day takes 2-4 weeks of dedicated effort. Managing custom rules across 3+ clusters requires centralised rule distribution that OSS does not provide. Keeping detection rules current with emerging attack techniques requires ongoing security research.

**[Sysdig](https://sysdig.com)** is the commercial evolution of Falco, built by the same team:

- Managed detection rules updated automatically for new attack techniques (including AI-generated variants, see [How AI Is Compressing the Attacker Timeline: What Defenders Need to Change Now](/articles/ai-landscape/ai-compressing-attacker-timeline/)(/articles/ai-landscape/ai-compressing-attacker-timeline/))
- UI for rule management, alert triage, and investigation
- Multi-cluster visibility (one dashboard for all clusters)
- Compliance reporting (CIS, SOC 2, PCI-DSS mapping)
- ML-powered anomaly detection (behavioural baselines per container image)

This is the strongest free-to-paid bridge on the site. Teams that start with Falco OSS and invest in custom rules eventually reach a scale where managed rule updates, multi-cluster visibility, and compliance reporting justify Sysdig's cost.

**[Aqua](https://www.aquasec.com)** provides runtime protection with a different approach, agent-based enforcement that can block attacks in addition to detecting them. [Wazuh](https://wazuh.com) provides free OSS SIEM/XDR with file integrity monitoring as a complement to Falco's syscall-level detection.

**Premium content pack:** Falco rule collection. 30+ tested, tuned rules for common workload types (web servers, databases, message queues, AI inference, CI/CD runners) with per-image exceptions and known-good behaviour documentation. Includes Falcosidekick response configuration for each rule.


## Related Articles

- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes Audit Log Analysis: What to Log, How to Query, and What to Alert On](/articles/kubernetes/audit-log-analysis/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
- [Kubernetes API Server Hardening: Flags, Authentication, and Audit Logging](/articles/kubernetes/api-server-hardening/)
