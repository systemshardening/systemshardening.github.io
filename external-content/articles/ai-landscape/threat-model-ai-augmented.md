---
title: "The Threat Model Has Changed: Rewriting Security Assumptions for an AI-Augmented World"
description: "Every security architecture is built on assumptions about what attackers can do, how fast they can do it, and at what scale."
slug: "threat-model-ai-augmented"
date: 2026-02-17
lastmod: 2026-02-17
category: "ai-landscape"
tags: ["threat-modelling", "ai-security", "zero-trust", "fido2", "behavioural-detection", "stride"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 109
difficulty: "advanced"
estimated_reading_time: 20
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Tailscale"
    id: 40
    category: "identity"
  - name: "Vanta"
    id: 169
    category: "compliance"
premium_pack: "threat-model-templates"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/threat-model-ai-augmented/index.html"
---

# The Threat Model Has Changed: Rewriting Security Assumptions for an AI-Augmented World

## Problem

Every security architecture is built on assumptions about what attackers can do, how fast they can do it, and at what scale. Four of these foundational assumptions are now wrong:

**Assumption 1: Reconnaissance takes time.**
Traditional: An attacker takes days to weeks to map your exposed attack surface, subdomains, open ports, technology fingerprints, exposed APIs, software versions.
Reality: AI-powered scanning tools enumerate your entire exposed surface in minutes. Subdomain brute-forcing combined with service fingerprinting and CVE correlation runs at API speed, not human speed.

**Assumption 2: Exploit development requires specialist skill.**
Traditional: Turning a CVE advisory into a working exploit requires weeks of skilled reverse engineering. This created a natural patch window.
Reality: LLMs generate working exploit code from vulnerability descriptions. The skill barrier has dropped from "specialist researcher" to "prompt engineer with API access." The patch window has collapsed from weeks to hours.

**Assumption 3: Social engineering does not scale.**
Traditional: Targeted phishing requires per-victim research and crafting. Bulk phishing is generic and recognisable. The trade-off between targeting and scale limited the attacker.
Reality: AI produces personalised phishing at volume, thousands of unique, contextually relevant messages per hour. Each references real projects, real colleagues, real recent events. The targeting-vs-scale trade-off no longer exists.

**Assumption 4: Persistence uses known patterns.**
Traditional: C2 (command and control) communication uses recognisable protocols, patterns, and destinations. IDS/IPS signature matching detects and blocks known C2 frameworks.
Reality: AI adapts C2 communication in real time. After a pattern is detected and blocked, the AI generates a new communication method, different protocol, different timing, different encoding. Signature-based C2 detection becomes a game of whack-a-mole that the defender cannot win.

Organisations that have not updated their threat models in the past 12 months are defending against an adversary that no longer exists.

## Threat Model

This article does not have a traditional threat model section because the article *is* the threat model. It defines the AI-augmented adversary profile that should be the baseline assumption for every security decision.

### The AI-Augmented Adversary Profile

| Attribute | Traditional Adversary | AI-Augmented Adversary |
|-----------|----------------------|------------------------|
| Reconnaissance speed | Days to weeks | Minutes to hours |
| Exploit development | Requires specialist skill; weeks | LLM-generated from CVE description; hours |
| Social engineering scale | Tens of targeted emails/day | Thousands of unique, personalised messages/hour |
| Payload uniqueness | Reuses known payloads (signature-matchable) | Every payload is unique (polymorphic by default) |
| Persistence adaptation | Static C2 patterns (detectable by signatures) | Real-time adaptation to evade detection |
| Cost per attack | High (skilled human time: $100-1000/hour) | Low (LLM API calls: $0.01-1.00 per attempt) |
| Availability | Nation-states and organised crime | Anyone with API access or a local GPU |

### What Has NOT Changed

AI changes the speed, scale, and cost of attacks. It does not change the fundamentals of defence:

- Defence in depth still works, multiple layers of control, each covering a different failure mode.
- Least privilege still works, an attacker who compromises a service with minimal permissions has minimal blast radius.
- Network segmentation still works, microsegmentation limits lateral movement regardless of how fast the attacker operates.
- Encryption still works, mTLS, TLS 1.3, and encryption at rest protect data regardless of the attacker's tooling.

The controls are the same. The urgency, thresholds, and detection approach must change.

## Configuration

### Updated Defensive Posture for Each Assumption

#### Assumption 1 Response: Minimise Exposed Surface, Assume Constant Scanning

Since reconnaissance is now instant, you must assume your entire exposed surface is mapped. The defensive response is not "detect scanning faster"; it is "reduce what there is to scan."

```yaml
# Kubernetes: Default-deny ingress on every namespace.
# Only expose what is explicitly needed.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

```yaml
# Kubernetes: Default-deny egress. Allowlist only known destinations.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
```

Place an edge layer (Cloudflare #29, free tier) in front of all internet-facing services. This absorbs reconnaissance traffic before it reaches your infrastructure and provides a baseline WAF without configuration.

#### Assumption 2 Response: 24-Hour Patch SLA, Runtime Detection During Gap

Since exploits are generated within hours of disclosure, your patch SLA must be under 24 hours for critical vulnerabilities.

```yaml
# Prometheus alert: vulnerability scanner found a critical CVE
# in a running container. This starts the 24-hour clock.
groups:
  - name: vulnerability-sla
    rules:
      - alert: CriticalCVEInProduction
        expr: trivy_vulnerability_count{severity="CRITICAL"} > 0
        for: 0m  # Alert immediately
        labels:
          severity: critical
          sla: "24h"
        annotations:
          summary: "Critical CVE detected in {{ $labels.image }}"
          runbook: |
            1. Check Trivy results for CVE details.
            2. Determine if a patch is available.
            3. If patch available: create patched image, deploy via canary, full rollout.
            4. If no patch: apply virtual patch (WAF rule, network policy, or seccomp restriction).
            5. Target: resolved within 24 hours of this alert.
```

While the patch is being deployed, runtime detection provides coverage:

```yaml
# Falco rule: detect exploitation of common vulnerability classes.
# This catches the attack even if the specific exploit is AI-generated
# and has no matching signature.
- rule: Unexpected File Write by Web Process
  desc: >
    A web server process wrote to a path outside its expected write set.
    This detects post-exploitation file drops (webshells, backdoors)
    regardless of the specific exploit used.
  condition: >
    evt.type in (open, openat)
    and evt.is_open_write=true
    and container
    and container.image.repository in (nginx, httpd, node, python, ruby, java)
    and not fd.name startswith /tmp
    and not fd.name startswith /var/log
    and not fd.name startswith /dev/null
  output: >
    Web process wrote to unexpected path
    (file=%fd.name container=%container.name image=%container.image.repository
     process=%proc.name user=%user.name)
  priority: WARNING
```

#### Assumption 3 Response: Phishing-Resistant Authentication

Since AI-generated phishing is indistinguishable from legitimate communication, authentication that can be phished is broken. The only defence is authentication that is cryptographically bound to the origin.

**FIDO2/WebAuthn** authenticates by proving possession of a hardware key to the specific domain the user is visiting. A phishing site on a different domain cannot trigger the authentication; the key refuses to respond because the origin does not match.

```bash
# Require FIDO2 keys for all SSH access.
# OpenSSH 8.2+ supports FIDO2 natively.

# Generate a resident FIDO2 key (stored on the hardware key):
ssh-keygen -t ed25519-sk -O resident -O verify-required -f ~/.ssh/id_ed25519_sk

# Add to authorised keys on the server:
cat ~/.ssh/id_ed25519_sk.pub >> ~/.ssh/authorized_keys

# Disable password authentication entirely:
# In /etc/ssh/sshd_config:
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
```

**Out-of-band verification for sensitive operations:**

AI-generated phishing can convincingly impersonate colleagues in email and Slack. For sensitive operations (credential resets, wire transfers, infrastructure access grants), require verification through a different channel than the request arrived on.

```
# Policy (document and enforce):
# 1. Credential reset requested via email → verify via Slack video call
# 2. Access grant requested via Slack → verify via email to manager + requester
# 3. Wire transfer requested via any channel → verify via phone call to a known number
# 4. Infrastructure change requested via ticket → verify via Slack thread with the requestor
#
# The key: the verification channel must be DIFFERENT from the request channel.
# AI can impersonate on one channel. Impersonating on two simultaneously is harder.
```

#### Assumption 4 Response: Behavioural Detection Over Signatures

Since C2 adapts to evade signatures, detect by behaviour, not by pattern.

```yaml
# Prometheus alert: detect data exfiltration through anomalous egress volume.
# This catches C2 communication regardless of the protocol or encoding used.
groups:
  - name: exfiltration-detection
    rules:
      # Alert when a service sends 10x its normal daily egress.
      - alert: AnomalousEgressVolume
        expr: >
          rate(container_network_transmit_bytes_total[1h])
          > 10 * avg_over_time(rate(container_network_transmit_bytes_total[1h])[7d:1h])
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "{{ $labels.pod }} is sending 10x normal egress volume"
          runbook: |
            1. Check if a deployment or migration is in progress (expected spike).
            2. If no expected activity: investigate the pod's network connections.
            3. Use Hubble: hubble observe --pod {{ $labels.pod }} --verdict FORWARDED
            4. Look for connections to unusual IPs or high-volume transfers to single destinations.

      # Detect DNS tunnelling: unusually high DNS query rate from a single pod.
      - alert: PossibleDNSTunnelling
        expr: >
          rate(coredns_dns_requests_total{zone="cluster.local."}[5m])
          > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High DNS query rate from cluster, possible DNS tunnelling"
          runbook: |
            1. Identify the source pod from CoreDNS query logs.
            2. Check for unusually long subdomain queries (>50 chars = likely tunnelling).
            3. Check for queries to rare/new domains not seen in baseline.
```

### Updated STRIDE Worksheet

STRIDE is the most widely used threat modelling framework. Here it is updated for AI-augmented adversaries:

| STRIDE Category | Traditional Assumption | AI-Updated Assumption | Updated Control | Verification |
|----------------|----------------------|----------------------|----------------|--------------|
| **Spoofing** | Phishing requires crafted emails that trained users can detect | AI phishing is indistinguishable from legitimate communication | FIDO2/WebAuthn for all authentication. Out-of-band verification for sensitive operations. | Quarterly phishing simulation. 100% FIDO2 coverage for admin accounts. |
| **Tampering** | Exploit development takes weeks; patch window is 7-14 days | Exploits generated in hours; patch window is 24-48 hours | 24-hour patch SLA for critical CVEs. Runtime detection during patch gap. Automated canary deployment. | Patch deployment time metric. Mean time to remediate (MTTR) < 24h. |
| **Repudiation** | Audit logs are reviewed by humans on a weekly/monthly basis | AI attacks operate at machine speed; logs must be analysed in real time | Real-time log analysis with automated alerting. Immutable log storage (attacker cannot cover tracks). | Alert latency metric < 2 minutes. Log integrity verification. |
| **Information Disclosure** | Reconnaissance takes days, giving time to detect and respond to scanning | Reconnaissance completes in minutes; no time to detect before exploitation | Minimise exposed surface. Default-deny network policies. Edge layer absorbs scanning traffic. | External attack surface scan (quarterly). Open port audit. |
| **Denial of Service** | DDoS requires botnets that are expensive to operate | AI can generate diverse DDoS patterns that evade rate limiting | Edge provider (Cloudflare #29) for volumetric DDoS absorption. Behavioural rate limiting (not just per-IP). | DDoS simulation (annual). Rate limit effectiveness testing. |
| **Elevation of Privilege** | Privilege escalation requires specific exploit knowledge | LLMs generate escalation techniques from public vulnerability data | Least privilege everywhere. Seccomp profiles. Network microsegmentation. Runtime detection of escalation attempts. | [kube-bench](https://aquasecurity.github.io/kube-bench/) CIS score > 90%. Seccomp coverage for all workloads. |

## Expected Behaviour

After updating your threat model and implementing the controls in this article:

- All internet-facing services sit behind an edge layer that absorbs reconnaissance and volumetric attacks
- Default-deny network policies are in place for all Kubernetes namespaces (ingress and egress)
- Critical CVEs are patched in production within 24 hours of detection
- All admin accounts use FIDO2/WebAuthn authentication (zero reliance on passwords for infrastructure access)
- Behavioural detection baselines established for all production workloads within 30 days
- Anomaly alerts (egress volume, process execution, DNS patterns) fire within 2 minutes of threshold breach
- STRIDE worksheet completed and reviewed quarterly with updated AI-adversary assumptions

## Trade-offs

| Updated Control | Cost | Risk | Mitigation |
|----------------|------|------|------------|
| 24-hour patch SLA | Requires automated testing, canary deployment, and CI/CD maturity. Cannot be achieved with manual processes. | Automated patches that break production if test coverage is insufficient. | Invest in test coverage first. Canary deployment with automated rollback. Break-glass procedure for zero-days. |
| FIDO2-only authentication | $25-90 per hardware key per user. Backup key logistics. Recovery process. | Key loss locks the user out. Recovery must be secure (not email-based, or you've re-introduced phishing risk). | Two keys per user. Backup key in a secure physical location. Recovery requires in-person identity verification. |
| Default-deny egress | Every service needs an explicit egress policy. Breaks "it works in dev" patterns. | Legitimate outbound connections blocked until allowlisted. New external API integrations require egress policy updates. | Maintain an egress allowlist per namespace. CI check that verifies egress policies exist for all services. |
| Behavioural detection | 30-90 day baseline period. Ongoing tuning. Alert fatigue during deployments. | False positives during deployments. False negatives for slow-and-low attacks that stay within baseline. | Deployment-window suppression. Correlation across multiple signal types to increase confidence. |
| Edge layer (Cloudflare) | Free tier covers basics. Pro ($20/month) for WAF and bot management. | Single vendor dependency for edge security. | Cloudflare free tier has no contractual SLA. Evaluate risk tolerance. Use Pro for production workloads. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| 24-hour patch SLA missed | Critical CVE in production for >24 hours | Vulnerability age metric exceeds SLA threshold; alert fires | Escalate to incident. Deploy with break-glass procedure. Post-mortem on why the SLA was missed (missing tests? CI failure? human bottleneck?). |
| FIDO2 key lost | User locked out of all admin systems | User reports inability to authenticate; MFA challenge fails | Issue replacement from pre-registered backup key. If no backup: in-person identity verification + new key registration with two approvers. |
| Egress allowlist too restrictive | Application feature fails (cannot reach external API) | Application error logs show connection timeout or refused; monitoring shows 5xx spike correlated with new egress policy | Add the external API endpoint to the egress allowlist. Deploy updated network policy. Document the new dependency. |
| Behavioural baseline drift | Gradually increasing false positive rate over weeks | Alert volume trending upward without corresponding incidents; on-call fatigue | Re-baseline affected workloads. Adjust detection thresholds. Exclude deployment windows from baseline calculation. |
| Edge layer outage | All internet-facing traffic fails or degrades | Synthetic monitoring detects elevated error rate; Cloudflare status page shows incident | If edge provider is down: DNS failover to direct-to-origin (pre-configured, tested quarterly). Accept reduced security during failover. |

## When to Consider a Managed Alternative

Implementing the full updated threat model requires changes across multiple infrastructure layers. For teams under 10 engineers, implementing everything simultaneously is unrealistic. Prioritise based on the highest-impact assumptions:

**Priority 1. Edge layer (addresses Assumption 1: reconnaissance):**
[Cloudflare](https://www.cloudflare.com) free tier provides basic DDoS protection, DNS, and WAF. Single afternoon to set up. Immediately reduces your exposed attack surface.

**Priority 2. Phishing-resistant authentication (addresses Assumption 3: social engineering):**
[YubiKey](https://www.yubico.com) hardware keys + FIDO2 configuration. $25-90 per key, 1-2 hours to deploy per user. Eliminates phishing risk entirely for protected accounts.

**Priority 3. Managed observability (addresses Assumption 4: persistence):**
[Grafana Cloud](https://grafana.com/cloud) or [Axiom](https://axiom.co) for centralized metrics, logs, and traces with retention. Enables behavioural baselines and anomaly detection without managing Prometheus/[Loki](https://grafana.com/oss/loki/) at scale.

**Priority 4. Runtime detection (addresses Assumption 2: fast exploitation):**
[Sysdig](https://sysdig.com) for ML-powered runtime detection built on Falco. Managed detection rules automatically updated for emerging attack techniques. Replaces the manual Falco rule tuning burden.

**Compliance alignment:**
[Vanta](https://www.vanta.com) or [Drata](https://drata.com) for continuous compliance monitoring that tracks whether your security posture matches the updated threat model. Useful for SOC 2 or ISO 27001 where you need to demonstrate that your controls match your documented threat model.

**Link to:** [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/): Security Hardening for Small Teams](/articles/cross-cutting/hardening-small-teams/) for a prioritised hardening roadmap specific to teams of 1-5 engineers.


## Related Articles

- [How AI Is Compressing the Attacker Timeline: What Defenders Need to Change Now](/articles/ai-landscape/ai-compressing-attacker-timeline/)
- [Detecting AI-Generated Attacks: Moving from Signatures to Behavioural Baselines](/articles/ai-landscape/detecting-ai-attacks/)
- [AI-Powered Vulnerability Discovery: What Automated Code Analysis Means for Your Patch Cycle](/articles/ai-landscape/ai-vulnerability-discovery/)
- [Using AI to Harden Systems: Automated Configuration Review and Remediation](/articles/ai-landscape/ai-assisted-hardening/)
- [Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems](/articles/ai-landscape/agent-to-agent-trust/)
