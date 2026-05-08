---
title: "Verifying AI Agent Output: Deterministic Checks, Human-in-the-Loop Gates, and Rollback Safety"
description: "AI agents generate infrastructure configurations, database migrations, deployment manifests, and shell commands. It passes a casual review."
slug: "ai-agent-output-verification"
date: 2026-03-18
lastmod: 2026-03-18
category: "ai-landscape"
tags: ["ai-agents", "output-verification", "dry-run", "rollback", "human-in-the-loop", "validation"]
personas: ["platform-engineer", "sre", "security-engineer", "ai-ml-engineer"]
article_number: 115
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Incident.io"
    id: 175
    category: "incident-response"
premium_pack: "agent-output-verification-pack"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-agent-output-verification/index.html"
---

# Verifying AI Agent Output: Deterministic Checks, Human-in-the-Loop Gates, and Rollback Safety

## Problem

AI agents generate infrastructure configurations, database migrations, deployment manifests, and shell commands. They produce output that looks correct. It passes a casual review. Then it breaks production because it changed a resource limit by 10x, removed a security context, or added an ingress rule that exposes an internal service to the internet. The agent does not know the difference between a correct configuration and a plausible one. It optimizes for coherence, not correctness. Every agent-generated artefact must pass through deterministic validation before it touches production. Every change must be reversible. The alternative is trusting a language model to never make a mistake, and that is not a security posture.

## Threat Model

- **Adversary:** (1) Agent generating subtly incorrect configurations due to hallucination or context misinterpretation. (2) Prompt injection that causes the agent to produce configurations with hidden backdoors (extra ports opened, security contexts weakened, new service accounts created). (3) Agent operating on stale context and producing changes that conflict with recent manual changes.
- **Blast radius:** Every resource the agent-generated configuration modifies. A bad [Kubernetes](https://kubernetes.io) deployment manifest can take down a service. A bad network policy can expose internal services. A bad database migration can corrupt data irreversibly.

## Configuration

### Pre-Apply Validation of Agent-Generated Configs

Run every agent-generated Kubernetes manifest through schema validation, policy checks, and security scanning before it can be applied.

```bash
#!/bin/bash
# validate-agent-output.sh
# Runs a validation pipeline on agent-generated Kubernetes manifests.
# Exits non-zero if any check fails. Agent cannot apply until all pass.

set -euo pipefail

MANIFEST_PATH="${1:?Usage: validate-agent-output.sh <manifest-path>}"
RESULTS_DIR="/tmp/validation-results"
mkdir -p "$RESULTS_DIR"

echo "=== Validating agent-generated manifest: $MANIFEST_PATH ==="

# Step 1: YAML syntax validation
echo "[1/5] YAML syntax check..."
python3 -c "
import yaml, sys
try:
    list(yaml.safe_load_all(open('$MANIFEST_PATH')))
    print('  PASS: Valid YAML')
except yaml.YAMLError as e:
    print(f'  FAIL: Invalid YAML: {e}')
    sys.exit(1)
"

# Step 2: Kubernetes schema validation with kubeconform
echo "[2/5] Kubernetes schema validation..."
kubeconform \
  -strict \
  -summary \
  -output json \
  "$MANIFEST_PATH" > "$RESULTS_DIR/kubeconform.json"

if [ $? -ne 0 ]; then
    echo "  FAIL: Schema validation errors found"
    cat "$RESULTS_DIR/kubeconform.json"
    exit 1
fi
echo "  PASS: Valid Kubernetes schema"

# Step 3: Security policy check with OPA/conftest
echo "[3/5] Security policy check..."
conftest test \
  --policy /etc/agent-policies/ \
  --output json \
  "$MANIFEST_PATH" > "$RESULTS_DIR/conftest.json"

if [ $? -ne 0 ]; then
    echo "  FAIL: Security policy violations"
    cat "$RESULTS_DIR/conftest.json"
    exit 1
fi
echo "  PASS: Security policies satisfied"

# Step 4: Diff against current state
echo "[4/5] Diff against current cluster state..."
kubectl diff -f "$MANIFEST_PATH" > "$RESULTS_DIR/diff.txt" 2>&1 || true
echo "  Diff saved to $RESULTS_DIR/diff.txt"

# Step 5: Dry-run against API server
echo "[5/5] Server-side dry-run..."
kubectl apply --dry-run=server -f "$MANIFEST_PATH" -o json > "$RESULTS_DIR/dryrun.json"

if [ $? -ne 0 ]; then
    echo "  FAIL: Server-side dry-run failed"
    cat "$RESULTS_DIR/dryrun.json"
    exit 1
fi
echo "  PASS: Server-side dry-run succeeded"

echo ""
echo "=== All validation checks passed ==="
echo "Diff for review:"
cat "$RESULTS_DIR/diff.txt"
```

OPA policies for agent-generated manifests:

```rego
# policy/agent-output-security.rego
# Policies that every agent-generated manifest must satisfy.

package agent.output.security

# Deny containers running as root
deny[msg] {
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container '%v' must set runAsNonRoot: true", [container.name])
}

# Deny containers without resource limits
deny[msg] {
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%v' must have memory limits set", [container.name])
}

# Deny privilege escalation
deny[msg] {
    container := input.spec.template.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true
    msg := sprintf("Container '%v' must not allow privilege escalation", [container.name])
}

# Deny hostNetwork
deny[msg] {
    input.spec.template.spec.hostNetwork == true
    msg := "Agent-generated manifests must not use hostNetwork"
}

# Deny new ServiceAccount creation (agents should not create SAs)
deny[msg] {
    input.kind == "ServiceAccount"
    msg := "Agent-generated manifests must not create ServiceAccounts"
}

# Deny ClusterRole or ClusterRoleBinding creation
deny[msg] {
    input.kind == "ClusterRole"
    msg := "Agent-generated manifests must not create ClusterRoles"
}

deny[msg] {
    input.kind == "ClusterRoleBinding"
    msg := "Agent-generated manifests must not create ClusterRoleBindings"
}

# Deny resource limits exceeding safety thresholds
deny[msg] {
    container := input.spec.template.spec.containers[_]
    memory_limit := container.resources.limits.memory
    # Block if memory limit exceeds 8Gi
    endswith(memory_limit, "Gi")
    value := to_number(trim_suffix(memory_limit, "Gi"))
    value > 8
    msg := sprintf(
        "Container '%v' memory limit %v exceeds 8Gi maximum for agent-generated configs",
        [container.name, memory_limit]
    )
}
```

### Dry-Run Verification

Every agent action must be dry-run first. The dry-run output is compared against expected outcomes before the real action proceeds.

```python
# dry_run_verifier.py
# Executes dry-run for agent-generated changes and verifies the output.

import subprocess
import json
import yaml

class DryRunVerifier:
    def __init__(self, manifest_path: str):
        self.manifest_path = manifest_path
        self.dry_run_result = None
        self.diff_result = None

    def run_server_dry_run(self) -> dict:
        """Execute server-side dry-run and return the result."""
        result = subprocess.run(
            ["kubectl", "apply", "--dry-run=server", "-f", self.manifest_path, "-o", "json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return {"valid": False, "error": result.stderr}

        self.dry_run_result = json.loads(result.stdout)
        return {"valid": True, "result": self.dry_run_result}

    def compute_diff(self) -> dict:
        """Compute diff between current state and proposed change."""
        result = subprocess.run(
            ["kubectl", "diff", "-f", self.manifest_path],
            capture_output=True, text=True, timeout=30
        )
        self.diff_result = result.stdout
        # kubectl diff exits 0 (no diff) or 1 (has diff) or >1 (error)
        if result.returncode > 1:
            return {"has_diff": False, "error": result.stderr}
        return {
            "has_diff": result.returncode == 1,
            "diff": self.diff_result,
            "diff_lines": len(self.diff_result.splitlines()),
        }

    def check_safety_bounds(self) -> list[str]:
        """Check if the proposed changes stay within safety bounds."""
        violations = []

        if not self.diff_result:
            self.compute_diff()

        diff_lines = self.diff_result.splitlines() if self.diff_result else []

        # Flag large diffs (more than 50 lines changed)
        changed_lines = [l for l in diff_lines if l.startswith("+") or l.startswith("-")]
        if len(changed_lines) > 50:
            violations.append(
                f"Large diff: {len(changed_lines)} lines changed. "
                f"Requires human review."
            )

        # Flag replica count changes
        for line in diff_lines:
            if "replicas:" in line and line.startswith("+"):
                violations.append(
                    f"Replica count change detected: {line.strip()}. "
                    f"Requires human review."
                )

        return violations
```

### Human-in-the-Loop Diff Review Gates

For changes that exceed safety bounds or modify critical resources, pause and send the diff to a human reviewer.

```python
# review_gate.py
# Sends agent-generated diffs to Slack for human review.
# Agent cannot proceed until a human approves or rejects.

import requests
import time
import json
import hashlib

SLACK_WEBHOOK = ""  # Loaded from Vault
APPROVAL_API = "https://agent-gateway.internal/v1/approvals"

def request_human_review(
    agent_id: str,
    manifest_path: str,
    diff_text: str,
    safety_violations: list[str],
    timeout_minutes: int = 30,
) -> bool:
    """Send diff to Slack for review. Block until approved or rejected."""

    review_id = hashlib.sha256(
        f"{agent_id}-{manifest_path}-{time.time()}".encode()
    ).hexdigest()[:12]

    # Post to Slack
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Agent Review Request [{review_id}]"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Agent:* `{agent_id}`\n"
                        f"*Manifest:* `{manifest_path}`\n"
                        f"*Safety flags:* {len(safety_violations)}"
                    )
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```\n{diff_text[:2900]}\n```"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": f"approve-{review_id}"
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject"},
                        "style": "danger",
                        "action_id": f"reject-{review_id}"
                    }
                ]
            }
        ]
    }

    requests.post(SLACK_WEBHOOK, json=message)

    # Poll for approval
    deadline = time.time() + (timeout_minutes * 60)
    while time.time() < deadline:
        response = requests.get(
            f"{APPROVAL_API}/{review_id}",
            timeout=5
        )
        status = response.json().get("status")
        if status == "approved":
            return True
        if status == "rejected":
            return False
        time.sleep(10)

    # Timeout: default to rejection
    return False
```

### Automated Rollback on Unexpected State Changes

After applying a change, monitor the affected resources. If the state diverges from expectations (pods crashing, health checks failing), automatically roll back.

```bash
#!/bin/bash
# apply-with-rollback.sh
# Applies an agent-generated manifest and monitors for failures.
# Automatically rolls back if pods enter CrashLoopBackOff or health checks fail.

set -euo pipefail

MANIFEST="${1:?Usage: apply-with-rollback.sh <manifest>}"
NAMESPACE="${2:-production}"
ROLLBACK_TIMEOUT="${3:-120}"  # seconds to monitor after apply

# Capture current state for rollback
echo "[rollback] Capturing current state..."
RESOURCE_KIND=$(yq '.kind' "$MANIFEST")
RESOURCE_NAME=$(yq '.metadata.name' "$MANIFEST")
kubectl get "$RESOURCE_KIND" "$RESOURCE_NAME" \
  -n "$NAMESPACE" \
  -o yaml > "/tmp/rollback-${RESOURCE_NAME}.yaml" 2>/dev/null || true

# Apply the change
echo "[rollback] Applying manifest..."
kubectl apply -f "$MANIFEST" -n "$NAMESPACE"

# Monitor for failures
echo "[rollback] Monitoring for ${ROLLBACK_TIMEOUT}s..."
START_TIME=$(date +%s)

while true; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    if [ "$ELAPSED" -ge "$ROLLBACK_TIMEOUT" ]; then
        echo "[rollback] Monitoring period complete. No issues detected."
        exit 0
    fi

    # Check for CrashLoopBackOff
    CRASH_PODS=$(kubectl get pods -n "$NAMESPACE" \
        -l "app=${RESOURCE_NAME}" \
        --field-selector=status.phase!=Running \
        -o json 2>/dev/null | \
        python3 -c "
import json, sys
data = json.load(sys.stdin)
crash = 0
for pod in data.get('items', []):
    for cs in pod.get('status', {}).get('containerStatuses', []):
        waiting = cs.get('state', {}).get('waiting', {})
        if waiting.get('reason') in ('CrashLoopBackOff', 'Error', 'ImagePullBackOff'):
            crash += 1
print(crash)
" 2>/dev/null || echo "0")

    if [ "$CRASH_PODS" -gt 0 ]; then
        echo "[rollback] FAILURE DETECTED: $CRASH_PODS pods in error state"
        echo "[rollback] Initiating rollback..."

        if [ -f "/tmp/rollback-${RESOURCE_NAME}.yaml" ]; then
            kubectl apply -f "/tmp/rollback-${RESOURCE_NAME}.yaml" -n "$NAMESPACE"
            echo "[rollback] Rolled back to previous state"
        else
            echo "[rollback] No previous state found. Manual intervention required."
        fi

        # Log the rollback event
        echo "{\"event\":\"agent.rollback\",\"resource\":\"${RESOURCE_NAME}\",\"namespace\":\"${NAMESPACE}\",\"reason\":\"crash_detected\",\"crash_pods\":${CRASH_PODS}}"
        exit 1
    fi

    sleep 5
done
```

### Confidence Scoring for Agent Actions

Assign a confidence score to each agent action based on the complexity and risk of the change. Route low-confidence actions to human review automatically.

```python
# confidence_scorer.py
# Scores agent-generated changes based on risk factors.
# Low-confidence changes are routed to human review.

from dataclasses import dataclass

@dataclass
class ConfidenceScore:
    score: float           # 0.0 (no confidence) to 1.0 (full confidence)
    factors: list[str]     # Reasons that affected the score
    requires_review: bool  # True if score is below threshold

def score_agent_change(
    diff_lines: int,
    resource_kind: str,
    namespace: str,
    changes_security_context: bool,
    changes_network_policy: bool,
    changes_rbac: bool,
    changes_replicas: bool,
    is_new_resource: bool,
) -> ConfidenceScore:
    """Score an agent-generated change based on risk factors."""
    score = 1.0
    factors = []

    # Large diffs reduce confidence
    if diff_lines > 100:
        score -= 0.3
        factors.append(f"Large diff: {diff_lines} lines")
    elif diff_lines > 50:
        score -= 0.15
        factors.append(f"Medium diff: {diff_lines} lines")

    # Production namespace reduces confidence
    if namespace == "production":
        score -= 0.1
        factors.append("Target namespace: production")

    # Security-sensitive changes reduce confidence
    if changes_security_context:
        score -= 0.25
        factors.append("Modifies securityContext")
    if changes_network_policy:
        score -= 0.25
        factors.append("Modifies NetworkPolicy")
    if changes_rbac:
        score -= 0.4
        factors.append("Modifies RBAC resources")

    # Replica changes need review
    if changes_replicas:
        score -= 0.15
        factors.append("Changes replica count")

    # New resources are riskier
    if is_new_resource:
        score -= 0.1
        factors.append("Creates new resource")

    # High-risk resource kinds
    high_risk_kinds = {"ClusterRole", "ClusterRoleBinding", "NetworkPolicy", "Ingress"}
    if resource_kind in high_risk_kinds:
        score -= 0.2
        factors.append(f"High-risk resource kind: {resource_kind}")

    score = max(0.0, score)
    requires_review = score < 0.6

    return ConfidenceScore(
        score=round(score, 2),
        factors=factors,
        requires_review=requires_review,
    )
```

```yaml
# Prometheus alert for low-confidence agent changes
groups:
  - name: agent-output-verification
    rules:
      - alert: AgentLowConfidenceApplied
        expr: >
          agent_change_confidence_score < 0.6
          and agent_change_applied == 1
        labels:
          severity: critical
        annotations:
          summary: "Low-confidence agent change applied without review"
          runbook: "A change with confidence score {{ $value }} was applied. Check if review gate was bypassed."

      - alert: AgentRollbackTriggered
        expr: >
          increase(agent_rollback_total[10m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "Agent-generated change was rolled back in {{ $labels.namespace }}"
          runbook: "Investigate the rolled-back change. Check agent context and input for issues."

      - alert: AgentValidationFailureRate
        expr: >
          rate(agent_validation_failures_total[30m])
          / rate(agent_validation_total[30m]) > 0.3
        labels:
          severity: warning
        annotations:
          summary: "Agent {{ $labels.agent_id }} failing validation >30% of the time"
          runbook: "Agent is producing invalid output too frequently. Review agent prompts and context."
```

## Expected Behaviour

- Every agent-generated manifest passes YAML validation, schema validation, OPA security policy, and server-side dry-run before apply
- Changes to security contexts, RBAC, or network policies are blocked by OPA policy for agent-generated manifests
- Diffs exceeding 50 lines or changes to critical resources are routed to human review via Slack
- Applied changes are monitored for 120 seconds; automatic rollback triggers on CrashLoopBackOff or health check failures
- Changes with confidence scores below 0.6 require human approval
- Agent-generated manifests cannot create ServiceAccounts, ClusterRoles, or ClusterRoleBindings
- Rollback events and low-confidence applies trigger alerts

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Full validation pipeline | 30-60 second delay before every apply | Slows agent response time for simple changes | Cache validation results for identical manifests. Skip schema validation for manifests that passed within the last 5 minutes. |
| Human-in-the-loop for large diffs | Agent blocks waiting for human approval | Approval delay for time-sensitive changes during incidents | Set shorter timeout (5 minutes) during declared incidents. Allow pre-approved change templates that skip review. |
| 120-second rollback monitoring | Agent is blocked for 2 minutes after every apply | Cascading delays in multi-step deployments | Reduce monitoring period for known-safe resource types. Run monitoring asynchronously for low-risk changes. |
| Confidence scoring | Subjective scoring may not reflect actual risk | Low-risk changes scored as high-risk (false positives) | Tune scoring weights based on historical rollback data. Review and adjust thresholds quarterly. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Validation pipeline crash | Agent-generated changes bypass all checks | No validation log entries for applied changes | Add a Kubernetes admission webhook as a final backstop. Changes without a validation pass annotation are rejected. |
| Rollback to stale state | Rollback restores a version that is also broken | Service remains unhealthy after rollback | Capture multiple rollback points. If rollback fails, alert on-call and block further agent changes. |
| Review gate bypassed | Agent applies changes without human approval | Audit log shows apply without corresponding approval entry | Enforce approval via admission webhook that checks for an approval annotation signed by a human reviewer. |
| Confidence scorer miscalibrated | High-risk changes scored as safe and applied without review | Post-incident: change that caused outage had a high confidence score | Retrain scoring weights against historical incident data. Add resource-specific overrides for known high-risk patterns. |

## When to Consider a Managed Alternative

Building output verification infrastructure requires OPA/conftest for policy, a review workflow, and rollback automation.

- **[Sysdig](https://sysdig.com):** Runtime monitoring with automated response when agent-applied changes cause container anomalies.
- **[Grafana Cloud](https://grafana.com/cloud):** Dashboards tracking agent validation pass rates, confidence score distributions, and rollback frequency.
- **[Incident.io](https://incident.io):** Automated incident creation when agent rollbacks trigger, with full context from the agent's audit trail.

**Premium content pack:** Agent output verification pack. OPA policy library for agent-generated manifests, validation pipeline scripts, Slack review gate integration, rollback wrapper scripts, confidence scoring module, and Prometheus alert rules for agent output monitoring.


## Related Articles

- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [Sandboxing AI Agent Tool Use: Filesystem, Network, and Process Isolation for Autonomous Actions](/articles/ai-landscape/agent-tool-use-sandboxing/)
- [Agent-to-Agent Trust: Authentication, Delegation, and Capability Boundaries in Multi-Agent Systems](/articles/ai-landscape/agent-to-agent-trust/)
- [AI Credential Delegation: Short-Lived Tokens, Scope Narrowing, and Audit Trails for Agent Access](/articles/ai-landscape/ai-credential-delegation/)
- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
