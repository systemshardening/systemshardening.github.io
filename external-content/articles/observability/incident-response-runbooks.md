---
title: "Incident Response Runbooks: Structured Procedures for Common Security Events"
description: "Detection without documented response is security theatre. Most teams have alerts that fire at 3 AM, but no written procedure for what the on-call..."
slug: "incident-response-runbooks"
date: 2026-01-19
lastmod: 2026-01-19
category: "observability"
tags: ["incident-response", "runbooks", "alerting", "automation", "security-operations"]
personas: ["sre", "security-engineer"]
article_number: 69
difficulty: "intermediate"
estimated_reading_time: 17
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Better Stack"
    id: 113
    category: "observability"
premium_pack: "incident-response-runbook-templates"
published: true
layout: article.njk
permalink: "/articles/observability/incident-response-runbooks/index.html"
---

# Incident Response Runbooks: Structured Procedures for Common Security Events

## Problem

Detection without documented response is security theatre. Most teams have alerts that fire at 3 AM, but no written procedure for what the on-call engineer should do when they fire. The result: inconsistent triage, slow containment, missed steps, and post-mortems that say "we should have done X sooner."

The specific problems:

- **Response knowledge lives in people's heads.** The senior security engineer knows exactly what to do when a brute force alert fires. When they are on holiday and the junior SRE gets the page, the response is slow and incomplete.
- **Every incident is treated as novel.** Without runbooks, each incident starts from scratch. The same investigation steps are repeated. The same containment actions are discovered through trial and error.
- **Automated response has no guardrails.** Teams want to automate containment (kill the compromised pod, block the IP), but without documented decision criteria, automation either does too much (kills legitimate workloads) or too little (sends a notification nobody reads).
- **Runbooks rot.** Even teams with runbooks find them outdated within months. Infrastructure changes, new services are deployed, and the runbook still references the old alerting system.

This article provides a runbook structure, templates for common security events, integration with alerting systems, and a maintenance process that keeps runbooks current.

**Target systems:** Any alerting system (Alertmanager, PagerDuty, Opsgenie). [Falcosidekick](https://github.com/falcosecurity/falcosidekick) for automated response. Git-based runbook storage for version control.

## Threat Model

- **Adversary:** Any attacker whose activity triggers a detection alert. The threat model for runbooks is not the attacker but the response gap: the time between detection and effective containment.
- **Blast radius:** Without runbooks, mean time to respond (MTTR) is 2-4 hours for security events. With practiced runbooks, MTTR drops to 15-30 minutes. Every hour of delayed response gives the attacker time to escalate privileges, exfiltrate data, and establish persistence.

## Configuration

### Runbook Structure

Every runbook follows the same six-section format:

```markdown
# Runbook: [Alert Name]

## Trigger Condition
What alert fires and what thresholds activate this runbook.

## Severity Classification
How to determine if this is P1 (active compromise), P2 (suspicious activity),
or P3 (informational anomaly).

## Triage Steps (first 5 minutes)
Ordered checklist of investigation steps to determine if this is a true
positive or false positive.

## Containment Actions
What to do if the event is confirmed as a true positive. Specific commands
and procedures, not general guidance.

## Remediation and Recovery
Steps to restore normal operation after containment.

## Post-Incident
What to document, who to notify, and how to update this runbook based on
what was learned.
```

### Runbook: Brute Force Detected

```markdown
# Runbook: BruteForceDetected

## Trigger Condition
Alert: BruteForceDetected
Threshold: auth failure rate > 5x 7-day baseline from a single source IP,
sustained for 2+ minutes.

## Severity Classification
- P1 if: source IP is internal OR target is admin/root account
- P2 if: source IP is external AND rate > 100 failures/minute
- P3 if: source IP is external AND rate < 100 failures/minute

## Triage Steps (first 5 minutes)
1. Check source IP:
   - Internal IP? Check if it is a known service (password rotation, CI/CD).
     Run: kubectl get pods -A -o wide | grep <IP>
   - External IP? Check threat intel:
     Run: curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=<IP>" \
       -H "Key: ${ABUSEIPDB_KEY}" | jq '.data.abuseConfidenceScore'
2. Check target account:
   - Is it a service account? Check recent credential rotation:
     Run: kubectl get secret <service-account>-token -o jsonpath='{.metadata.creationTimestamp}'
   - Is it a user account? Contact the user (Slack DM) to confirm it is not them.
3. Check recent deployments:
   - Any deployment in the last 30 minutes that might cause auth failures?
     Run: kubectl get events --sort-by='.lastTimestamp' | grep -i deploy | head -5

## Containment Actions (if confirmed P1/P2)
1. Block the source IP at the ingress controller:
   kubectl annotate ingress <ingress-name> \
     nginx.ingress.kubernetes.io/deny-list=<SOURCE_IP> --overwrite
2. Force password reset for targeted accounts:
   Run: ./scripts/force-password-reset.sh <username>
3. Revoke active sessions:
   Run: ./scripts/revoke-sessions.sh <username>

## Remediation and Recovery
1. Verify the block is effective (check logs for continued attempts).
2. Monitor for attacks from adjacent IP ranges (same /24).
3. If targeted account was compromised, audit all actions taken by that
   account in the last 7 days.

## Post-Incident
- Document: source IP, target accounts, duration, whether credentials
  were compromised.
- Update: IP blocklist if the source is a known attack infrastructure.
- Review: are rate limits configured on the auth endpoint?
```

### Runbook: Compromised Pod

```markdown
# Runbook: CorrelatedCompromiseIndicator

## Trigger Condition
Alert: CorrelatedCompromiseIndicator
Condition: pod has BOTH unexpected process execution AND anomalous network
behaviour (exfiltration or new destination).

## Severity Classification
- Always P1. Correlated process + network anomaly is high-confidence compromise.

## Triage Steps (first 5 minutes)
1. Identify the pod and its workload:
   Run: kubectl describe pod <pod-name> -n <namespace>
2. Check the unexpected process:
   Run: kubectl exec <pod-name> -n <namespace> -- ps aux
   (If the pod is still running. Do NOT exec into a compromised pod
   unless necessary; you may trigger attacker's detection of investigation.)
3. Check network destinations:
   Run: hubble observe --from-pod <namespace>/<pod-name> --last 30m
4. Capture forensic snapshot BEFORE containment:
   Run: kubectl logs <pod-name> -n <namespace> --all-containers > /tmp/forensic-logs.txt
   Run: kubectl get pod <pod-name> -n <namespace> -o yaml > /tmp/forensic-pod-spec.txt

## Containment Actions
1. Quarantine the pod (apply network isolation):
   kubectl label pod <pod-name> -n <namespace> security.quarantine=true
   (This triggers the CiliumNetworkPolicy that drops all traffic.)
2. Scale down the parent deployment to prevent new compromised pods:
   kubectl scale deployment <deployment-name> -n <namespace> --replicas=0
3. Preserve the container filesystem:
   kubectl cp <namespace>/<pod-name>:/tmp /tmp/forensic-tmp/

## Remediation and Recovery
1. Identify the attack vector (CVE, misconfiguration, stolen credentials).
2. Patch the vulnerability or rotate compromised credentials.
3. Rebuild the container image from a clean base.
4. Redeploy with the fix. Monitor for 24 hours.

## Post-Incident
- Incident report: attack vector, timeline, blast radius, data accessed.
- Update Falco rules if the attack used a new technique.
- Review: was the pod running with unnecessary privileges?
```

### Linking Runbooks to Alerts

```yaml
# Alertmanager configuration: include runbook URLs in every alert.
# This ensures the on-call engineer has one click to reach the procedure.
route:
  receiver: security-team
  routes:
    - match:
        detection_type: brute_force
      receiver: security-team
      continue: true
    - match:
        detection_type: correlated
      receiver: security-team-critical
      continue: true

receivers:
  - name: security-team
    slack_configs:
      - api_url: "${SLACK_WEBHOOK}"
        channel: "#security-alerts"
        title: '{{ .GroupLabels.alertname }}'
        text: >
          {{ range .Alerts }}
          *Summary:* {{ .Annotations.summary }}
          *Runbook:* {{ .Annotations.runbook_url }}
          *False Positive Notes:* {{ .Annotations.false_positive_notes }}
          {{ end }}

  - name: security-team-critical
    pagerduty_configs:
      - routing_key: "${PAGERDUTY_KEY}"
        description: '{{ .GroupLabels.alertname }}: {{ .CommonAnnotations.summary }}'
        details:
          runbook: '{{ .CommonAnnotations.runbook_url }}'
```

### Automated Response with Falcosidekick

```yaml
# Falcosidekick configuration: trigger automated containment for
# high-confidence events.
config:
  webhook:
    # Webhook to the response automation service.
    address: "http://response-automation:8080/falco"
    minimumpriority: "critical"

  # Only auto-respond to specific, high-confidence rules.
  customfields:
    auto_response: "true"

---
# Response automation service (simplified webhook handler).
# Receives Falco events and executes containment based on rule name.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: response-automation
spec:
  replicas: 1
  template:
    spec:
      serviceAccountName: response-automation
      containers:
        - name: handler
          image: ghcr.io/internal/response-automation:v1.2
          env:
            - name: ACTIONS
              value: |
                {
                  "CorrelatedCompromiseIndicator": ["quarantine-pod"],
                  "CryptoMiningDetected": ["kill-pod", "alert-critical"],
                  "ContainerEscapeAttempt": ["quarantine-pod", "alert-critical"]
                }
```

### Tabletop Exercise Schedule

```yaml
# quarterly-tabletop-schedule.yaml
# Run tabletop exercises to validate runbooks work under pressure.
exercises:
  - name: "Compromised Pod"
    frequency: quarterly
    scenario: |
      A developer reports that a staging pod is making unusual network
      connections. The CorrelatedCompromiseIndicator alert fired 10 minutes
      ago but was acknowledged without investigation.
    objectives:
      - On-call follows the runbook without prior knowledge of the scenario
      - Containment actions are executed within 15 minutes
      - Forensic evidence is preserved before pod termination
    participants: [on-call-sre, security-team-lead]

  - name: "Credential Stuffing"
    frequency: quarterly
    scenario: |
      BruteForceDetected alert fires for an external IP targeting the
      admin login endpoint. Rate is 500 failures/minute and rising.
    objectives:
      - Triage correctly identifies this as P2 (external, high rate)
      - Source IP is blocked within 5 minutes
      - Targeted account is checked for compromise
    participants: [on-call-sre]
```

## Expected Behaviour

- Every security alert includes a `runbook_url` annotation linking to the relevant procedure
- On-call engineers can begin triage within 2 minutes of receiving an alert (no searching for documentation)
- Containment actions for confirmed P1 incidents completed within 15 minutes
- Automated response triggers for high-confidence events (correlated alerts, confirmed crypto mining)
- Tabletop exercises conducted quarterly; findings incorporated into runbook updates
- Runbooks updated after every incident that reveals a gap or outdated step

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Structured runbook format (6 sections) | Consistent response regardless of who is on-call | Rigid format may not fit every incident type | Allow appendices for edge cases. The core structure covers 90% of scenarios. |
| Automated containment for high-confidence alerts | Seconds-to-containment for confirmed threats | Auto-response can disrupt legitimate workloads on false positive | Require correlated (multi-signal) alerts before auto-response triggers. Single-signal alerts page only. |
| Runbook links in alert annotations | One-click access to procedure from alert | Broken links if runbook URL changes | Use stable URL paths (not file-based). Test runbook links in CI pipeline. |
| Quarterly tabletop exercises | Validates runbooks work under pressure; reveals gaps | Time investment (2-4 hours per exercise per quarter) | Keep exercises focused (one scenario per session, 60-90 minutes). Rotate scenarios across teams. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Runbook outdated | On-call engineer follows steps that reference removed infrastructure | Post-incident review reveals runbook steps were wrong | Add a "last validated" date to each runbook. Review quarterly. Flag runbooks not validated in 6 months. |
| Runbook link broken | On-call clicks link, gets 404 | Automated link checker in CI runs weekly | Use redirect rules for moved runbooks. Never delete, only redirect. |
| Auto-response too aggressive | Legitimate pod quarantined; service outage | Service health check failures correlate with auto-response event | Add a 60-second grace period: auto-response labels the pod, waits 60 seconds, checks if alert is still firing, then quarantines. |
| No runbook for a new alert type | On-call has no procedure; escalates blindly to management | Alert fires with empty `runbook_url` annotation | CI check: fail deployment if an alert rule has no `runbook_url`. Require a runbook for every new alert rule. |
| Tabletop exercises skipped | Runbook gaps not discovered until real incident | Calendar check: no exercise recorded in 6 months | Assign exercise ownership to a specific team member. Track completion as an OKR metric. |

## When to Consider a Managed Alternative

Self-managed incident response requires runbook authoring, alerting integration, automated response infrastructure, and quarterly tabletop exercises (8-12 hours/month across the team).

- **[Grafana Cloud](https://grafana.com/cloud):** [Grafana](https://grafana.com) OnCall with integrated runbook links. Escalation policies and on-call scheduling. Alert routing based on labels.
- **[Better Stack](https://betterstack.com):** Incident management with status pages, on-call scheduling, and runbook integration. Combines alerting and incident workflow in one platform.

**Premium content pack:** Incident response runbook template collection. 20+ runbook templates covering brute force, credential stuffing, compromised pods, data exfiltration, DNS tunnelling, privilege escalation, certificate expiry, container escape, and crypto mining. Each template includes triage checklists, containment commands, and post-incident report templates.


## Related Articles

- [Security-Relevant Prometheus Metrics: What to Collect, How to Alert, When to Page](/articles/observability/prometheus-security-metrics/)
- [Building Detection Rules That Don't Cry Wolf: Alert Design for Security Events](/articles/observability/detection-rules/)
- [Building a Security Audit Log Pipeline That Scales: auditd to Elasticsearch](/articles/observability/audit-log-pipeline/)
- [Centralized Logging Architecture for Security: Fluentd, Vector, and Loki Compared](/articles/observability/centralized-logging/)
- [Lateral Movement Detection: Network Patterns, Authentication Anomalies, and Alert Correlation](/articles/observability/lateral-movement-detection/)
