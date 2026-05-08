---
title: "Incident Response Hardening Playbook: From Detection to Post-Mortem"
description: "During an active security incident, hardening is reactive: isolate the compromised system, contain the blast radius, preserve evidence, and stop the.."
slug: "incident-response-hardening-playbook"
date: 2026-03-02
lastmod: 2026-03-02
category: "cross-cutting"
tags: ["incident-response", "containment", "forensics", "post-mortem", "hardening", "falco"]
personas: ["security-engineer", "sre"]
article_number: 100
difficulty: "intermediate"
estimated_reading_time: 15
provider_bridges:
  - name: "Incident.io"
    id: 175
    category: "incident-management"
  - name: "FireHydrant"
    id: 176
    category: "incident-management"
  - name: "Rootly"
    id: 177
    category: "incident-management"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Vanta"
    id: 169
    category: "compliance"
premium_pack: "incident-response-hardening-templates"
published: true
layout: article.njk
permalink: "/articles/cross-cutting/incident-response-hardening-playbook/index.html"
---

# Incident Response Hardening Playbook: From Detection to Post-Mortem

## Problem

During an active security incident, hardening is reactive: isolate the compromised system, contain the blast radius, preserve evidence, and stop the bleeding. After the incident, hardening is preventive: translate findings into permanent controls that ensure the same attack path never works again. Most teams lack a structured approach for either.

The typical incident response is chaotic. An alert fires. Someone investigates. Credentials get rotated, maybe. The compromised pod gets deleted (destroying evidence). A week later, life continues and no permanent hardening happens. The same attack path remains open. The post-mortem (if one happens) produces action items that sit in a ticket queue for months.

This playbook provides step-by-step procedures for containment during an incident and a structured process for converting incident findings into permanent hardening controls afterward.

**Target systems:** [Kubernetes](https://kubernetes.io) clusters. Linux servers. Any infrastructure where security incidents require both immediate response and long-term hardening.

## Threat Model

- **Adversary:** Active attacker with some level of access. The specific attack type is unknown at the start of incident response. The playbook must work regardless of whether the incident is a container escape, a compromised credential, a data exfiltration, or a supply chain compromise.
- **Objective (attacker):** Maintain access, exfiltrate data, escalate privileges, or cause destruction.
- **Objective (defender):** Contain the attacker's access, preserve forensic evidence, restore service, and close the attack path permanently.
- **Blast radius:** Depends on time to containment. Every minute between detection and isolation is a minute the attacker can escalate. The playbook's goal is to reduce this window from hours to minutes.

## Configuration

### Phase 1: Network Isolation (First 5 Minutes)

Isolate the compromised workload immediately. Do not delete it. Isolation preserves evidence while stopping lateral movement.

```yaml
# quarantine-network-policy.yaml
# Apply to isolate a compromised pod
# This blocks ALL ingress and egress while keeping the pod running
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-pod
  namespace: production  # Target namespace
spec:
  podSelector:
    matchLabels:
      quarantine: "true"  # Label the compromised pod
  policyTypes:
    - Ingress
    - Egress
  ingress: []   # Deny all ingress
  egress: []    # Deny all egress
```

```bash
#!/bin/bash
# quarantine.sh - Isolate a compromised pod
# Usage: ./quarantine.sh <namespace> <pod-name>
set -euo pipefail

NAMESPACE=$1
POD=$2
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

echo "[${TIMESTAMP}] INCIDENT: Quarantining pod ${POD} in ${NAMESPACE}"

# Step 1: Label the pod for quarantine network policy
kubectl label pod "${POD}" -n "${NAMESPACE}" quarantine=true --overwrite

# Step 2: Apply quarantine network policy
kubectl apply -f quarantine-network-policy.yaml -n "${NAMESPACE}"

# Step 3: Verify isolation
echo "Verifying network isolation..."
kubectl exec "${POD}" -n "${NAMESPACE}" -- \
  timeout 5 curl -s http://kubernetes.default.svc 2>&1 || echo "Network isolated: cannot reach API server"

# Step 4: Record the quarantine event
kubectl annotate pod "${POD}" -n "${NAMESPACE}" \
  "incident.quarantined-at=${TIMESTAMP}" \
  "incident.quarantined-by=${USER}" \
  --overwrite

echo "[${TIMESTAMP}] Pod ${POD} quarantined. Do NOT delete this pod. Evidence preservation required."
```

### Phase 2: Credential Rotation (First 15 Minutes)

Assume all credentials accessible to the compromised workload are compromised.

```bash
#!/bin/bash
# rotate-credentials.sh
# Usage: ./rotate-credentials.sh <namespace> <service-account>
set -euo pipefail

NAMESPACE=$1
SA=$2
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

echo "[${TIMESTAMP}] Rotating credentials for ${SA} in ${NAMESPACE}"

# 1. Delete and recreate service account tokens
echo "Revoking Kubernetes service account tokens..."
kubectl get secrets -n "${NAMESPACE}" -o json | \
  jq -r ".items[] | select(.metadata.annotations[\"kubernetes.io/service-account.name\"]==\"${SA}\") | .metadata.name" | \
  xargs -I{} kubectl delete secret {} -n "${NAMESPACE}"

# 2. Rotate Vault tokens (if applicable)
echo "Revoking Vault leases for ${SA}..."
vault lease revoke -prefix "auth/kubernetes/login" || true

# 3. Rotate cloud provider credentials (IRSA/Workload Identity)
# These are short-lived by default (1h for IRSA), but rotate the role binding
echo "Verify IRSA/Workload Identity role has not been modified..."
# Check IAM role policy for unexpected changes

# 4. Rotate database credentials
echo "Rotating database credentials..."
vault write -f database/rotate-root/production

# 5. Invalidate active sessions
echo "Invalidating active sessions..."
# Application-specific: clear session store, invalidate JWTs

# 6. Rotate API keys
echo "Rotating external API keys..."
# Provider-specific rotation (see Article #82)

echo "[${TIMESTAMP}] Credential rotation complete. Verify application functionality."
```

### Phase 3: Evidence Preservation (First 30 Minutes)

Capture forensic evidence before anything is cleaned up.

```bash
#!/bin/bash
# preserve-evidence.sh
# Usage: ./preserve-evidence.sh <namespace> <pod-name>
set -euo pipefail

NAMESPACE=$1
POD=$2
EVIDENCE_DIR="/evidence/incident-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${EVIDENCE_DIR}"

echo "Preserving evidence for ${POD} in ${NAMESPACE}"

# 1. Pod description and status
kubectl get pod "${POD}" -n "${NAMESPACE}" -o yaml > "${EVIDENCE_DIR}/pod.yaml"
kubectl describe pod "${POD}" -n "${NAMESPACE}" > "${EVIDENCE_DIR}/pod-describe.txt"

# 2. Container logs (all containers including init and sidecar)
for CONTAINER in $(kubectl get pod "${POD}" -n "${NAMESPACE}" -o jsonpath='{.spec.containers[*].name}'); do
  kubectl logs "${POD}" -n "${NAMESPACE}" -c "${CONTAINER}" > "${EVIDENCE_DIR}/logs-${CONTAINER}.txt" 2>&1 || true
  kubectl logs "${POD}" -n "${NAMESPACE}" -c "${CONTAINER}" --previous > "${EVIDENCE_DIR}/logs-${CONTAINER}-previous.txt" 2>&1 || true
done

# 3. Process list inside the container
kubectl exec "${POD}" -n "${NAMESPACE}" -- ps auxww > "${EVIDENCE_DIR}/processes.txt" 2>&1 || true

# 4. Network connections
kubectl exec "${POD}" -n "${NAMESPACE}" -- ss -tlnp > "${EVIDENCE_DIR}/network-listeners.txt" 2>&1 || true
kubectl exec "${POD}" -n "${NAMESPACE}" -- ss -tnp > "${EVIDENCE_DIR}/network-connections.txt" 2>&1 || true

# 5. Filesystem modifications (compare against image)
NODE=$(kubectl get pod "${POD}" -n "${NAMESPACE}" -o jsonpath='{.spec.nodeName}')
CONTAINER_ID=$(kubectl get pod "${POD}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|containerd://||')
echo "Container ID: ${CONTAINER_ID} on node ${NODE}" > "${EVIDENCE_DIR}/container-info.txt"

# 6. Events from the namespace
kubectl get events -n "${NAMESPACE}" --sort-by='.lastTimestamp' > "${EVIDENCE_DIR}/events.txt"

# 7. Network policy state
kubectl get networkpolicy -n "${NAMESPACE}" -o yaml > "${EVIDENCE_DIR}/network-policies.yaml"

# 8. Copy to immutable storage
tar czf "${EVIDENCE_DIR}.tar.gz" "${EVIDENCE_DIR}"
aws s3 cp "${EVIDENCE_DIR}.tar.gz" "s3://incident-evidence/$(basename ${EVIDENCE_DIR}).tar.gz" \
  --sse aws:kms

echo "Evidence preserved at ${EVIDENCE_DIR} and uploaded to S3."
echo "DO NOT delete the quarantined pod until investigation is complete."
```

### Phase 4: Close the Attack Path (Post-Incident)

After the immediate incident is resolved, implement permanent fixes.

```yaml
# Example: if the incident was caused by overly permissive RBAC
# Fix: replace cluster-admin with least-privilege role

# Before (incident root cause)
# apiVersion: rbac.authorization.k8s.io/v1
# kind: ClusterRoleBinding
# metadata:
#   name: deploy-bot
# roleRef:
#   kind: ClusterRole
#   name: cluster-admin     # <-- This was the problem
# subjects:
#   - kind: ServiceAccount
#     name: deploy-bot
#     namespace: ci-cd

# After (permanent fix)
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deploy-bot-role
  namespace: production  # Scoped to single namespace
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "patch", "update"]
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list"]
    # No create, no delete, no access to other namespaces
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: deploy-bot-binding
  namespace: production
roleRef:
  kind: Role
  name: deploy-bot-role
subjects:
  - kind: ServiceAccount
    name: deploy-bot
    namespace: ci-cd
```

### Phase 5: Strengthen Detection

Write detection rules for the specific attack pattern observed during the incident.

```yaml
# falco-rule-from-incident.yaml
# Example: incident revealed that the attacker used kubectl exec
# to establish a reverse shell from a production pod

- rule: Reverse Shell in Production
  desc: >
    Outbound connection from a production container to a non-standard port,
    combined with shell execution. Derived from incident INC-2026-042.
  condition: >
    spawned_process
    and container
    and k8s.ns.name = "production"
    and proc.name in (bash, sh, dash)
    and evt.type = connect
    and fd.sip != "0.0.0.0"
    and not fd.sip in (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  output: >
    Reverse shell detected in production
    (pod=%k8s.pod.name ns=%k8s.ns.name process=%proc.name
     dest=%fd.sip:%fd.sport user=%user.name)
  priority: CRITICAL
  tags: [incident-derived, reverse-shell, INC-2026-042]

- rule: Kubectl Exec to Production Pod
  desc: >
    kubectl exec into a production pod outside of approved maintenance windows.
    Derived from incident INC-2026-042.
  condition: >
    kevt
    and kcreate
    and k8s.ns.name = "production"
    and ka.verb = "create"
    and ka.target.subresource = "exec"
  output: >
    kubectl exec to production pod
    (pod=%ka.target.name ns=%ka.target.namespace user=%ka.user.name)
  priority: WARNING
  tags: [incident-derived, exec, INC-2026-042]
```

### Phase 6: Incident-to-Hardening Conversion Template

```yaml
# incident-hardening-template.yaml
# Fill this out for every security incident to convert findings into permanent controls
incident:
  id: "INC-2026-042"
  date: "2026-04-22"
  severity: "high"
  summary: "Attacker used compromised CI/CD service account to exec into production pod and exfiltrate database credentials"

findings:
  - finding: "CI/CD service account had cluster-admin privileges"
    root_cause: "Default RBAC from initial cluster setup was never tightened"
    control: "Least-privilege RBAC for all service accounts"
    article_reference: "Article #27 - RBAC Hardening"
    implementation:
      status: "completed"
      pr: "https://github.com/org/infra/pull/847"
      deployed: "2026-04-23"

  - finding: "No detection for kubectl exec in production"
    root_cause: "Falco rules did not cover exec subresource"
    control: "Falco rule for production exec events"
    article_reference: "Article #29 - Falco Rules"
    implementation:
      status: "completed"
      pr: "https://github.com/org/infra/pull/848"
      deployed: "2026-04-23"

  - finding: "Database credentials stored as Kubernetes Secret (not Vault)"
    root_cause: "Migration to Vault was incomplete for this service"
    control: "All database credentials managed by Vault with dynamic secrets"
    article_reference: "Article #52 - Secret Management"
    implementation:
      status: "in-progress"
      ticket: "SEC-2026-089"
      target_date: "2026-05-01"

verification:
  - test: "Attempt kubectl exec to production pod with CI/CD service account"
    expected: "Denied by RBAC"
    result: "Verified 2026-04-24"
  - test: "Falco alert fires on kubectl exec to production"
    expected: "CRITICAL alert within 30 seconds"
    result: "Verified 2026-04-24"
```

## Expected Behaviour

- Compromised pod is network-isolated within 5 minutes of detection
- All credentials accessible to the compromised workload are rotated within 15 minutes
- Forensic evidence is captured and stored in immutable storage within 30 minutes
- Attack path is closed with a permanent fix within 48 hours
- New detection rules for the observed attack pattern are deployed within 48 hours
- Incident-to-hardening template is completed within 1 week
- All hardening actions from the incident have a tracking ticket and a target date

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Quarantine (not delete) | Preserves evidence but leaves compromised pod running (isolated) | Resource consumption; team anxiety about "leaving the bad pod" | Network isolation eliminates the risk. The pod cannot communicate. Delete only after evidence is preserved. |
| Immediate credential rotation | Stops the attacker from using stolen credentials | May disrupt legitimate services using the same credentials | Verify service health after rotation. Accept brief disruption in exchange for containment. |
| Post-incident hardening required | Every incident produces permanent security improvement | Additional work after the incident is already resolved; team fatigue | Build the conversion template into the post-mortem process. No post-mortem is complete without hardening actions. |
| Incident-derived Falco rules | Detection rules based on real attacks, not theoretical ones | Rules may be too specific (only catches exact replay of this attack) | Write rules at the technique level (reverse shell, unauthorized exec), not the exact payload level. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Quarantine network policy not applied | Compromised pod continues lateral movement | Network monitoring shows continued connections from quarantined pod | Verify network policy controller ([Cilium](https://cilium.io)/[Calico](https://www.tigera.io/project-calico/)) is running. Apply policy to node-level firewall as fallback. |
| Evidence destroyed (pod deleted prematurely) | No forensic data available for investigation | Evidence directory empty or missing | Recover what is possible from centralised logs and node-level audit logs. Update playbook to emphasise "do not delete." |
| Credential rotation misses a credential | Attacker retains access through a credential that was not rotated | Continued attacker activity after rotation | Audit all credentials the service account had access to. Check Vault audit logs, cloud IAM access advisor, and API key usage logs. |
| Post-incident hardening stalls | Tickets created but never completed | Hardening tickets older than 30 days without progress | Assign hardening actions to specific owners with deadlines. Review in weekly security standup. Escalate after 30 days. |

## When to Consider a Managed Alternative

[Incident.io](https://incident.io), [FireHydrant](https://firehydrant.com), and [Rootly](https://rootly.com) for structured incident management with automated workflows, Slack/Teams integration, and post-mortem templates. [Sysdig](https://sysdig.com) for runtime detection that feeds directly into incident response with container forensics. [Grafana Cloud](https://grafana.com/cloud) for log analysis during incidents with fast query across all infrastructure. [Vanta](https://www.vanta.com) and [Drata](https://drata.com) for post-incident compliance documentation showing that findings were remediated.

**Premium content pack:** Incident response hardening templates. Quarantine scripts, credential rotation runbook, evidence preservation procedures, Falco rule templates for common incident types, and the incident-to-hardening conversion template.


## Related Articles

- [Hardening a Complete Kubernetes Platform: From Cluster Bootstrap to Production-Ready](/articles/cross-cutting/complete-kubernetes-hardening/)
- [Security Hardening for Small Teams: Prioritising Controls When You Cannot Do Everything](/articles/cross-cutting/hardening-small-teams/)
- [Security Infrastructure Disaster Recovery: Vault, PKI, and SIEM Failover](/articles/cross-cutting/security-infra-disaster-recovery/)
- [The Hardening Scorecard: Measuring and Tracking Security Posture](/articles/cross-cutting/hardening-scorecard/)
- [Compliance-as-Code: Mapping CIS Benchmarks to Automated Checks with InSpec and Kube-bench](/articles/cross-cutting/compliance-as-code/)
