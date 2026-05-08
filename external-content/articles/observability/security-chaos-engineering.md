---
title: "Security Chaos Engineering: Testing Detection and Response Capabilities"
description: "If you haven't tested that your detection rules fire and alerts route correctly, you don't know if they work. Security chaos engineering injects controlled attacks to validate the detection stack before a real attacker does."
slug: "security-chaos-engineering"
date: 2026-04-30
lastmod: 2026-04-30
category: "observability"
tags: ["chaos-engineering", "detection-testing", "atomic-red-team", "purple-team", "validation"]
personas: ["security-engineer", "sre", "platform-engineer"]
article_number: 267
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/observability/security-chaos-engineering/index.html"
---

# Security Chaos Engineering: Testing Detection and Response Capabilities

## Problem

Most security teams build detection rules, configure alerts, and write runbooks — then assume they work. Assumptions are not tested until a real incident occurs, which is the worst possible time to discover that:

- A Falco rule wasn't deployed to the nodes where the attack occurred.
- The PagerDuty integration stopped routing alerts three weeks ago after a configuration change.
- The SIEM ingestion pipeline silently stopped processing audit logs from a specific source.
- The runbook references a tool that was decommissioned six months ago.

Security chaos engineering deliberately and safely injects attack techniques into production or staging environments to validate that detection fires, alerts route, and response procedures work — before a real attacker tests them. This is the security analog of chaos engineering for reliability (Chaos Monkey, Gremlin): you learn about failures by inducing them under controlled conditions rather than discovering them during incidents.

The practice is sometimes called purple teaming (combining red team attack techniques with blue team detection validation), but automation and scheduled testing make it a continuous engineering discipline rather than a quarterly exercise.

Specific gaps without detection testing:

- New detection rules are never validated against actual attacker behaviour.
- Falco rules are deployed but coverage of all production nodes is unverified.
- Alert routing configuration changes silently break pager integrations.
- Log pipeline changes stop delivering security events to the SIEM.
- Detection rules are tuned so aggressively to reduce noise that real attacks no longer trigger them.

**Target systems:** Atomic Red Team (Invoke-AtomicRedTeam, atomics); Stratus Red Team (cloud-focused attack techniques); Caldera (adversary emulation platform); Falco, SIEM, PagerDuty/Opsgenie for alert validation; Kubernetes and Linux production or staging environments.

## Threat Model

This article addresses internal quality failures rather than external adversaries. The risks are:

- **Risk 1 — Silent detection failure:** A rule that used to fire no longer does (log format change, agent update, rule misconfiguration). Attackers who use the covered technique go undetected.
- **Risk 2 — Alert routing failure:** A pager integration breaks after a configuration change. Security events are logged but nobody is notified.
- **Risk 3 — Coverage gap:** A new cluster, node pool, or service is spun up without deploying the detection agent. Attacks on those systems produce no alerts.
- **Risk 4 — Runbook rot:** A runbook references tools, endpoints, or procedures that have changed. An incident responder following the runbook fails.
- **Risk 5 — False confidence from alert counts:** Metrics show N alerts per day, creating confidence. But those N alerts are all for low-severity events; the high-severity rules are broken.

## Configuration

### Step 1: Atomic Red Team on Linux Hosts

Atomic Red Team provides hundreds of pre-built attack technique implementations mapped to MITRE ATT&CK:

```bash
# Install Invoke-AtomicRedTeam (requires PowerShell or run via the bash atomics directly).
# For Linux, use the bash-based atomics directly.

# Clone the atomics repository.
git clone https://github.com/redcanaryco/atomic-red-team.git /opt/atomic-red-team

# Run a specific technique to test detection.
# T1059.004: Command and Scripting Interpreter — Unix Shell
cd /opt/atomic-red-team/atomics/T1059.004
bash T1059.004.yaml  # Runs the test; your Falco/auditd rules should fire.

# T1070.004: Indicator Removal — File Deletion
# Tests whether log deletion attempts are detected.
bash /opt/atomic-red-team/atomics/T1070.004/T1070.004.yaml

# T1055: Process Injection
# Tests whether ptrace or /proc/*/mem write is detected.
bash /opt/atomic-red-team/atomics/T1055/T1055.yaml
```

Build a controlled test runner:

```bash
#!/bin/bash
# run-detection-tests.sh
# Runs a curated set of atomics and checks for corresponding alerts.

TECHNIQUES=(
  "T1059.004"   # Unix shell
  "T1070.004"   # File deletion in /var/log
  "T1105"       # Ingress tool transfer (curl/wget)
  "T1082"       # System information discovery
  "T1057"       # Process discovery
)

SIEM_QUERY_URL="https://siem.internal/api/query"
LOOKBACK_SECONDS=120

for tech in "${TECHNIQUES[@]}"; do
  echo "Running technique: $tech"
  start_time=$(date +%s)

  bash /opt/atomic-red-team/atomics/$tech/$tech.yaml 2>/dev/null

  sleep 30   # Allow time for event to propagate to SIEM.

  # Query SIEM for alerts from this technique in the last 2 minutes.
  alert_count=$(curl -s -X POST "$SIEM_QUERY_URL" \
    -H "Authorization: Bearer $SIEM_TOKEN" \
    -d "{\"query\": \"mitre_technique:$tech AND timestamp:>$(date -d '-2 minutes' --iso-8601=seconds)\", \"size\": 1}" \
    | jq '.hits.total.value')

  if [[ $alert_count -gt 0 ]]; then
    echo "PASS: $tech — $alert_count alert(s) detected"
  else
    echo "FAIL: $tech — no alerts detected in SIEM"
    FAILURES+=("$tech")
  fi
done

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  echo "Detection failures: ${FAILURES[*]}"
  exit 1
fi
```

### Step 2: Stratus Red Team for Cloud Attack Techniques

Stratus Red Team provides AWS, GCP, and Azure-specific attack techniques:

```bash
# Install Stratus Red Team.
go install github.com/datadog/stratus-red-team/v2/cmd/stratus@latest

# List available techniques.
stratus list --platform aws

# Detonate a specific cloud attack technique.
# AWS-IAM-1: Create an IAM backdoor user.
stratus detonate aws.iam.backdoor-iam-user

# AWS-S3-1: Exfiltrate S3 objects to external account.
stratus detonate aws.s3.backdoor-s3-policy

# AWS-EC2-1: Download credentials from Instance Metadata Service (IMDS).
stratus detonate aws.credential-access.ec2-steal-instance-credentials

# After the test, clean up resources.
stratus cleanup aws.iam.backdoor-iam-user
```

Each Stratus technique validates a detection hypothesis. For `aws.iam.backdoor-iam-user`:

- Expected detection: CloudTrail `CreateUser` event with a suspicious username → alert fires.
- Expected response: Security team receives PagerDuty alert within 5 minutes.

```bash
# Validate CloudTrail captured the event.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time $(date -d '-10 minutes' --iso-8601=seconds) \
  | jq '.Events[].CloudTrailEvent | fromjson | {user: .requestParameters.userName, time: .eventTime}'
```

### Step 3: Kubernetes Detection Validation with Falco

Validate that Falco rules fire for specific attack patterns on Kubernetes nodes:

```yaml
# detection-test-pod.yaml
# A test pod that runs atomic techniques inside the cluster.
apiVersion: v1
kind: Pod
metadata:
  name: detection-test
  namespace: security-testing
spec:
  containers:
    - name: test
      image: ubuntu:22.04
      command: ["/bin/bash", "-c", "sleep 3600"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
  restartPolicy: Never
```

```bash
# Run detection tests inside the pod.
kubectl exec -n security-testing detection-test -- bash -c "
  # T1059: spawn a shell from a unexpected process.
  python3 -c 'import subprocess; subprocess.run([\"bash\", \"-c\", \"id\"])'
"
# Expected Falco rule: 'Shell Spawned by Non-Shell' should fire.

# T1611: Escape to host via /proc mount.
kubectl exec -n security-testing detection-test -- bash -c "
  ls /proc/1/ns/
"
# Expected Falco rule: 'Container Escape via /proc' should fire.

# T1552: Read credentials from filesystem.
kubectl exec -n security-testing detection-test -- bash -c "
  cat /var/run/secrets/kubernetes.io/serviceaccount/token
"
# Expected Falco rule: 'Service Account Token Read' should fire.
```

Validate that Falco is actually running on all nodes:

```bash
# Check Falco DaemonSet coverage.
kubectl get daemonset falco -n falco -o jsonpath='{.status}' | jq '{desired: .desiredNumberScheduled, ready: .numberReady}'
# desired should equal ready.

# Check Falco is capturing events (not crashed or silently failing).
kubectl logs -n falco -l app=falco --tail=20 | grep -E "Starting|engine|version"

# Inject a known-detectable event and check Falco logs within 10 seconds.
kubectl exec -n security-testing detection-test -- bash -c "nmap 10.0.0.1" 2>/dev/null || true
sleep 10
kubectl logs -n falco -l app=falco --since=15s | grep -i "nmap\|network"
```

### Step 4: Alert Routing Validation

Test the full alert pipeline: detection → SIEM → Alertmanager → PagerDuty.

```python
# alert-routing-test.py
# Injects a synthetic test alert and verifies it reaches the on-call engineer.

import requests
import time
import json

ALERTMANAGER_URL = "https://alertmanager.internal"
PAGERDUTY_EVENTS_API = "https://events.pagerduty.com/v2/enqueue"
TEST_RUNBOOK_URL = "https://runbooks.internal/test-detection-fire"

def inject_test_alert():
    """Send a synthetic security alert directly to Alertmanager."""
    alert = [{
        "labels": {
            "alertname": "SecurityChaosTestFire",
            "severity": "critical",
            "team": "security",
            "test": "true",   # Tag as test; route to test channel, not pager.
        },
        "annotations": {
            "summary": "Security chaos test: validate detection pipeline",
            "description": "This is a controlled test alert. If you receive this, the pipeline is working.",
            "runbook_url": TEST_RUNBOOK_URL,
        },
    }]
    resp = requests.post(
        f"{ALERTMANAGER_URL}/api/v2/alerts",
        json=alert,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.status_code

def verify_alert_received(expected_within_seconds: int = 300) -> bool:
    """Poll for the test alert having been acknowledged or received."""
    # Check PagerDuty incidents for the test alert.
    deadline = time.time() + expected_within_seconds
    while time.time() < deadline:
        incidents = requests.get(
            "https://api.pagerduty.com/incidents",
            headers={"Authorization": f"Token token={PD_API_KEY}"},
            params={"urgency": "low", "statuses[]": ["triggered", "acknowledged"]},
        ).json().get("incidents", [])

        for incident in incidents:
            if "SecurityChaosTestFire" in incident.get("title", ""):
                return True

        time.sleep(30)

    return False

if __name__ == "__main__":
    print("Injecting test alert...")
    inject_test_alert()

    print("Waiting for alert to reach PagerDuty (up to 5 minutes)...")
    if verify_alert_received(300):
        print("PASS: Alert routing pipeline working")
    else:
        print("FAIL: Alert not received in PagerDuty within 5 minutes")
        exit(1)
```

### Step 5: Scheduled Detection Tests in CI

Run detection tests on a weekly schedule:

```yaml
# .github/workflows/detection-validation.yml
name: Detection Validation

on:
  schedule:
    - cron: "0 3 * * 2"   # Every Tuesday at 3am.
  workflow_dispatch:       # Manual trigger for ad-hoc testing.

jobs:
  atomic-tests:
    runs-on: self-hosted   # Must run on a host with access to the test environment.
    environment: staging   # Staging cluster only; never run on production.
    steps:
      - uses: actions/checkout@v4

      - name: Run atomic detection tests
        run: |
          ./scripts/run-detection-tests.sh \
            --techniques T1059.004,T1070.004,T1105,T1082 \
            --siem-url ${{ vars.SIEM_URL }} \
            --siem-token ${{ secrets.SIEM_TOKEN }} \
            --fail-on-missing-detection
        timeout-minutes: 30

      - name: Validate alert routing
        run: python3 scripts/alert-routing-test.py
        env:
          PD_API_KEY: ${{ secrets.PAGERDUTY_API_KEY }}

      - name: Report results
        if: failure()
        run: |
          gh issue create \
            --title "Detection validation failure: $(date +%Y-%m-%d)" \
            --body "Weekly detection test failed. See workflow run: $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" \
            --label "security,detection"
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Step 6: Runbook Validation

Detection tests expose broken detection rules; runbook tests expose broken response procedures:

```python
# runbook-validator.py
# Checks that tools and endpoints referenced in runbooks are available.

import yaml
import requests
import subprocess
import re

def validate_runbook(runbook_path: str) -> list[str]:
    failures = []
    content = open(runbook_path).read()

    # Check all URLs referenced in the runbook.
    urls = re.findall(r'https?://[^\s\'"]+', content)
    for url in urls:
        try:
            resp = requests.head(url, timeout=5, allow_redirects=True)
            if resp.status_code >= 400:
                failures.append(f"Broken URL: {url} -> {resp.status_code}")
        except requests.RequestException as e:
            failures.append(f"Unreachable URL: {url} -> {e}")

    # Check all CLI tools referenced in code blocks.
    tools = re.findall(r'```(?:bash|shell)\n(.*?)```', content, re.DOTALL)
    for block in tools:
        commands = [line.strip().split()[0] for line in block.splitlines()
                    if line.strip() and not line.startswith('#')]
        for cmd in commands:
            if subprocess.run(['which', cmd], capture_output=True).returncode != 0:
                failures.append(f"Tool not found: {cmd}")

    return failures

# Validate all runbooks in the docs directory.
import glob
all_failures = {}
for runbook in glob.glob("docs/runbooks/**/*.md", recursive=True):
    failures = validate_runbook(runbook)
    if failures:
        all_failures[runbook] = failures

if all_failures:
    for runbook, failures in all_failures.items():
        print(f"\n{runbook}:")
        for f in failures:
            print(f"  - {f}")
    exit(1)
print("All runbooks validated successfully.")
```

### Step 7: Telemetry

```
detection_test_pass_total{technique, environment}          counter
detection_test_fail_total{technique, environment}          counter
alert_routing_latency_seconds{route, destination}          histogram
alert_routing_failure_total{route, destination}            counter
runbook_validation_failure_total{runbook, failure_type}    counter
falco_node_coverage_pct{cluster}                           gauge
siem_ingestion_lag_seconds{source}                         gauge
```

Alert on:

- `detection_test_fail_total` non-zero — a detection rule is broken; immediate investigation required.
- `alert_routing_failure_total` — alert pipeline broken; detection is happening but nobody is being paged.
- `falco_node_coverage_pct` < 100% — some nodes are not running the detection agent.
- `siem_ingestion_lag_seconds` > 300 — SIEM is not receiving logs from a source; events are being lost.

## Expected Behaviour

| Signal | No detection testing | With security chaos engineering |
|--------|---------------------|--------------------------------|
| Detection rule deployment broken | Discovered during real incident | Caught by weekly atomic test |
| Alert routing failure | Discovered when nobody responds to real alert | Caught by routing validation test |
| Falco missing on a new node | Never discovered until an attack | Coverage metric alert within hours |
| Runbook references decommissioned tool | Discovered under incident pressure | Caught by runbook validator |
| New detection rule quality | Unknown until it either fires or doesn't | Validated immediately against the technique it covers |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Running atomics in staging not production | No production risk | Staging may differ from production | Run a subset of low-risk atomics in production (read-only techniques); save destructive tests for staging. |
| Scheduled automated tests | Regular validation; no manual effort | False test failures (SIEM lag, tool version) | Add retry logic to SIEM queries; test multiple times before marking failure. |
| Alert routing synthetic alerts | Validates full pipeline | On-call receives test pages | Tag test alerts clearly; route to a test channel during business hours; only route to pager outside hours. |
| Runbook URL validation | Catches broken links | Internal URLs may be behind VPN | Run runbook validator from within the internal network; check public URLs from external CI. |
| Automating Stratus Red Team | Cloud detection coverage | AWS/GCP costs from created resources | Use `stratus cleanup` immediately after each test; costs are minimal (< $1 per test run). |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Atomic test triggers real alert before SIEM check | On-call paged for a test technique | Real alert fires; team responds | Coordinate test timing with on-call; use test-tagged alerts; communicate before running tests. |
| SIEM lag causes false detection failure | Technique fires but SIEM query times out before event arrives | Test reports failure; manual check shows event present | Increase SIEM query lookback window; add retry logic with backoff. |
| Test contaminates production logs | Detection testing events appear in production SIEM searches | Test events visible in real incident investigation | Tag all test events with a `security_test: true` field; filter them from default SIEM views. |
| Atomic requires root; test host lacks permissions | Atomic fails to run; no detection to validate | Atomic returns error; test not conclusive | Run restricted atomics that don't require root; use a dedicated root-capable test host for privileged atomics. |
| Stratus resource cleanup fails | Test resources persist; costs accumulate | Cloud cost alert; resource appears in inventory | Always run `stratus cleanup` in a post-test hook, even on failure; or use a TTL cleanup Lambda. |

## Related Articles

- [Detection Rules and Sigma Correlation](/articles/observability/detection-rules/)
- [Falco Runtime Security](/articles/kubernetes/falco-runtime-security/)
- [eBPF and Tetragon Runtime Detection](/articles/observability/ebpf-tetragon/)
- [Incident Response Runbooks](/articles/observability/incident-response-runbooks/)
- [Honeypot and Deception Technology in Kubernetes](/articles/observability/honeypot-deception-kubernetes/)
