---
title: "Running AI-Powered Security Assessments on Your Own Infrastructure: Using Frontier Models Before Attackers Do"
description: "If Anthropic's Mythos can find your vulnerabilities, so can every attacker with API access. The only rational response is to find them first. This article covers how to run systematic AI-powered security assessments across your code, infrastructure-as-code, and runtime configuration."
slug: "ai-powered-security-assessments"
date: 2026-04-23
lastmod: 2026-04-23
category: "ai-landscape"
tags: ["ai-security", "mythos", "security-assessment", "code-review", "iac-review", "audit", "semgrep", "claude"]
personas: ["security-engineer", "platform-engineer", "devops-engineer"]
article_number: 154
difficulty: "advanced"
estimated_reading_time: 24
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
  - name: "Semgrep"
    id: 157
    category: "static-analysis"
  - name: "Wiz"
    id: 155
    category: "cloud-security"
premium_pack: "ai-security-assessment-pipeline"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-powered-security-assessments/index.html"
---

# Running AI-Powered Security Assessments on Your Own Infrastructure: Using Frontier Models Before Attackers Do

## Problem

[Anthropic](https://www.anthropic.com) announced that [Mythos](https://www.anthropic.com) is significantly better at discovering cyber vulnerabilities than previous AI models. Every security team should interpret this announcement through a simple lens: if Mythos can find vulnerabilities in your infrastructure, so can every adversary with API access to a frontier model. The capability is symmetric. The asymmetry is in who uses it first.

Most organisations lack the security headcount to audit their full stack. A mid-size company with 40 microservices, 200 Kubernetes manifests, 50 Terraform modules, and 300,000 lines of application code cannot perform comprehensive manual security review more than once per year, if that. Between reviews, vulnerabilities accumulate. Configuration drifts. New services are deployed with insufficient review. The attack surface grows unchecked.

AI-powered security assessment changes the economics. A frontier model can review an entire Terraform module in seconds, trace authentication logic across a microservice boundary in minutes, and identify network policy gaps across a cluster in a single pass. The cost is API tokens. The constraint is building a systematic pipeline that runs these assessments continuously, scopes the model's access appropriately, and produces actionable findings rather than noise.

This article covers how to build that pipeline: systematic AI-powered security assessments across application code, infrastructure-as-code, runtime configuration, and network architecture.

## Threat Model

- **Adversary:** Any attacker with access to frontier AI models. The specific risk is that the adversary uses AI-assisted review against your publicly accessible code, container images, API surfaces, and infrastructure configuration before you do.
- **Access level (adversary):** External. Public repositories, public container registries, exposed API endpoints, DNS records, TLS certificates. No initial access required for discovery-phase assessment.
- **Access level (defender):** Internal. You have full access to source code, infrastructure-as-code, runtime configurations, network policies, and cluster state. This is your asymmetric advantage.
- **Objective:** Find vulnerabilities before the adversary does. Convert the time gap between "vulnerability exists" and "vulnerability is discovered" from the adversary's advantage to yours.
- **Blast radius of inaction:** Every week without systematic assessment is a week where AI-discoverable vulnerabilities exist in production, waiting for the first adversary who points a frontier model at your infrastructure.

## Configuration

### 1. AI-Assisted Code Review for Security Vulnerabilities

Traditional static analysis (Semgrep, CodeQL) catches pattern-based vulnerabilities: SQL injection, XSS, hardcoded secrets. AI models catch what pattern-based tools miss: logic flaws, incorrect authorisation checks, race conditions, and business logic vulnerabilities.

**Set up AI security review in CI:**

```yaml
# .github/workflows/ai-security-review.yml
# Run AI-assisted security review on every pull request.
# Reviews only the changed files to control cost and focus findings.
name: AI Security Review
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  ai-review:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changed
        run: |
          FILES=$(git diff --name-only origin/${{ github.base_ref }}...HEAD -- '*.go' '*.py' '*.js' '*.ts' '*.java' '*.rs')
          echo "files<<EOF" >> "$GITHUB_OUTPUT"
          echo "$FILES" >> "$GITHUB_OUTPUT"
          echo "EOF" >> "$GITHUB_OUTPUT"

      - name: Run AI security review
        if: steps.changed.outputs.files != ''
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          python3 scripts/ai-security-review.py \
            --files "${{ steps.changed.outputs.files }}" \
            --output findings.json \
            --severity-threshold medium

      - name: Post findings to PR
        if: steps.changed.outputs.files != ''
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          python3 scripts/post-findings.py \
            --findings findings.json \
            --pr-number ${{ github.event.pull_request.number }}
```

**The AI security review script:**

```python
#!/usr/bin/env python3
# scripts/ai-security-review.py
# Sends changed files to an AI model for security review.
# Produces structured findings with severity, location, and remediation.

import argparse
import json
import os
import sys

import anthropic


SECURITY_REVIEW_PROMPT = """You are a security engineer reviewing code changes for vulnerabilities.

Review the following code for security issues. Focus on:
1. Authentication and authorisation flaws (missing checks, incorrect logic, privilege escalation)
2. Input validation gaps (unsanitised user input reaching sensitive operations)
3. Injection vulnerabilities (SQL, command, LDAP, template injection)
4. Cryptographic issues (weak algorithms, hardcoded keys, insufficient entropy)
5. Race conditions and TOCTOU vulnerabilities
6. Information disclosure (error messages, debug output, stack traces)
7. Business logic flaws (bypasses, incorrect state transitions, missing rate limits)

For each finding, provide:
- severity: critical, high, medium, or low
- file: the file path
- line: the approximate line number
- title: one-line summary
- description: what the vulnerability is and why it matters
- remediation: specific fix recommendation

Respond ONLY with a JSON array of findings. If no issues are found, respond with an empty array [].
Do not include markdown formatting or code fences in your response.

Code to review:
"""


def review_files(file_list: list[str], severity_threshold: str) -> list[dict]:
    """Send files to AI model for security review."""
    client = anthropic.Anthropic()
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threshold_value = severity_order.get(severity_threshold, 2)

    all_findings = []

    for file_path in file_list:
        if not os.path.exists(file_path):
            continue

        with open(file_path, "r") as f:
            content = f.read()

        # Skip files over 500 lines to control token usage
        if content.count("\n") > 500:
            # Split into chunks of 500 lines
            lines = content.split("\n")
            chunks = ["\n".join(lines[i:i + 500]) for i in range(0, len(lines), 500)]
        else:
            chunks = [content]

        for chunk_index, chunk in enumerate(chunks):
            prompt_content = f"File: {file_path}\n"
            if len(chunks) > 1:
                prompt_content += f"Chunk {chunk_index + 1} of {len(chunks)}\n"
            prompt_content += f"\n```\n{chunk}\n```"

            message = client.messages.create(
                model="claude-sonnet-4-6-20250514",
                max_tokens=4096,
                messages=[
                    {
                        "role": "user",
                        "content": SECURITY_REVIEW_PROMPT + prompt_content,
                    }
                ],
            )

            response_text = message.content[0].text.strip()
            findings = json.loads(response_text)

            # Filter by severity threshold
            for finding in findings:
                finding_severity = severity_order.get(finding.get("severity", "low"), 3)
                if finding_severity <= threshold_value:
                    all_findings.append(finding)

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="AI-powered security code review")
    parser.add_argument("--files", required=True, help="Newline-separated list of files to review")
    parser.add_argument("--output", required=True, help="Output JSON file for findings")
    parser.add_argument("--severity-threshold", default="medium", help="Minimum severity to report")
    args = parser.parse_args()

    file_list = [f.strip() for f in args.files.strip().split("\n") if f.strip()]

    if not file_list:
        print("No files to review.")
        with open(args.output, "w") as f:
            json.dump([], f)
        sys.exit(0)

    findings = review_files(file_list, args.severity_threshold)

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Found {len(findings)} security findings.")

    # Exit with non-zero status if critical or high findings exist
    critical_or_high = [f for f in findings if f.get("severity") in ("critical", "high")]
    if critical_or_high:
        print(f"  {len(critical_or_high)} critical/high severity findings. Failing build.")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### 2. Infrastructure-as-Code Security Assessment

AI models understand the relationships between Terraform resources, Kubernetes manifests, and cloud configurations that pattern-based tools cannot reason about: a security group that is technically restrictive but allows access from a compromised subnet, a Kubernetes RBAC role that grants escalation through a chain of permissions, or a Terraform module that creates a public S3 bucket because a variable default was never overridden.

**Terraform security review script:**

```bash
#!/bin/bash
# scripts/ai-iac-review.sh
# Review Terraform modules for security issues using AI.
# Exports the plan as JSON and sends it for analysis.

set -e

TERRAFORM_DIR="${1:-.}"
OUTPUT_FILE="${2:-iac-findings.json}"

echo "=== Terraform Security Assessment ==="
echo "Directory: ${TERRAFORM_DIR}"

# Generate Terraform plan in JSON format
cd "${TERRAFORM_DIR}"
terraform init -backend=false -input=false
terraform plan -out=tfplan -input=false
terraform show -json tfplan > tfplan.json

# Extract resource configurations for review
jq '{
  planned_values: .planned_values,
  resource_changes: [.resource_changes[] | {
    address: .address,
    type: .type,
    change: {
      actions: .change.actions,
      after: .change.after
    }
  }],
  variables: .variables
}' tfplan.json > tfplan-summary.json

# Send to AI for security review
python3 "$(dirname "$0")/ai-iac-review.py" \
  --plan tfplan-summary.json \
  --output "${OUTPUT_FILE}"

echo "=== Results written to ${OUTPUT_FILE} ==="

# Clean up
rm -f tfplan tfplan.json tfplan-summary.json
```

```python
#!/usr/bin/env python3
# scripts/ai-iac-review.py
# AI-powered infrastructure-as-code security review.

import argparse
import json
import sys

import anthropic


IAC_REVIEW_PROMPT = """You are an infrastructure security engineer reviewing a Terraform plan for security issues.

Review the following Terraform plan JSON for:
1. Overly permissive security groups or firewall rules (0.0.0.0/0 ingress, unnecessary ports)
2. Public exposure of resources that should be private (S3 buckets, databases, APIs)
3. Missing encryption (at rest and in transit)
4. Overly permissive IAM policies (wildcard actions, wildcard resources)
5. Missing logging and monitoring configuration
6. Default credentials or missing authentication
7. Network segmentation issues (resources in public subnets that should be private)
8. Missing backup or disaster recovery configuration for stateful resources

For each finding, provide:
- severity: critical, high, medium, or low
- resource: the Terraform resource address
- title: one-line summary
- description: what the issue is and the security impact
- remediation: specific Terraform configuration change

Respond ONLY with a JSON array of findings. If no issues are found, respond with an empty array [].
Do not include markdown formatting or code fences in your response.

Terraform plan:
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with open(args.plan) as f:
        plan_content = f.read()

    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-4-6-20250514",
        max_tokens=4096,
        messages=[
            {
                "role": "user",
                "content": IAC_REVIEW_PROMPT + plan_content,
            }
        ],
    )

    response_text = message.content[0].text.strip()
    findings = json.loads(response_text)

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)

    critical_count = sum(1 for finding in findings if finding.get("severity") in ("critical", "high"))
    print(f"Found {len(findings)} findings ({critical_count} critical/high).")

    if critical_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### 3. Kubernetes Configuration Assessment

Export live cluster state and assess security posture across namespaces, RBAC, network policies, and workload configurations.

```bash
#!/bin/bash
# scripts/k8s-security-assessment.sh
# Export Kubernetes cluster security-relevant configuration and assess with AI.

set -e

OUTPUT_DIR="${1:-k8s-assessment}"
mkdir -p "${OUTPUT_DIR}"

echo "=== Kubernetes Security Assessment ==="
echo "Cluster: $(kubectl config current-context)"

# Export security-relevant resources
echo "Exporting cluster state..."

kubectl get clusterroles -o json > "${OUTPUT_DIR}/clusterroles.json"
kubectl get clusterrolebindings -o json > "${OUTPUT_DIR}/clusterrolebindings.json"
kubectl get networkpolicies -A -o json > "${OUTPUT_DIR}/networkpolicies.json"
kubectl get pods -A -o json | jq '{items: [.items[] | {
  namespace: .metadata.namespace,
  name: .metadata.name,
  serviceAccount: .spec.serviceAccountName,
  containers: [.spec.containers[] | {
    name: .name,
    image: .image,
    securityContext: .securityContext,
    ports: .ports
  }],
  hostNetwork: .spec.hostNetwork,
  hostPID: .spec.hostPID,
  hostIPC: .spec.hostIPC
}]}' > "${OUTPUT_DIR}/pods-security.json"

kubectl get services -A -o json | jq '{items: [.items[] | {
  namespace: .metadata.namespace,
  name: .metadata.name,
  type: .spec.type,
  ports: .spec.ports,
  selector: .spec.selector
}]}' > "${OUTPUT_DIR}/services.json"

kubectl get ingress -A -o json > "${OUTPUT_DIR}/ingress.json"

# Check which namespaces lack network policies
echo ""
echo "=== Namespaces without NetworkPolicies ==="
for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
  count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "  WARNING: ${ns} has no NetworkPolicies (default-allow all traffic)"
  fi
done

# Check for privileged pods
echo ""
echo "=== Privileged Pods ==="
kubectl get pods -A -o json | jq -r '
  .items[] |
  .metadata as $meta |
  .spec.containers[] |
  select(.securityContext.privileged == true) |
  "  WARNING: \($meta.namespace)/\($meta.name) container \(.name) is privileged"
'

# Check for pods running as root
echo ""
echo "=== Pods Running as Root ==="
kubectl get pods -A -o json | jq -r '
  .items[] |
  .metadata as $meta |
  .spec.containers[] |
  select(.securityContext.runAsNonRoot != true and (.securityContext.runAsUser == 0 or .securityContext.runAsUser == null)) |
  "  WARNING: \($meta.namespace)/\($meta.name) container \(.name) may run as root"
'

echo ""
echo "=== Sending to AI for comprehensive assessment ==="

# Combine all exports into a single assessment payload
python3 "$(dirname "$0")/ai-k8s-review.py" \
  --input-dir "${OUTPUT_DIR}" \
  --output "${OUTPUT_DIR}/assessment-results.json"

echo "=== Assessment complete. Results in ${OUTPUT_DIR}/assessment-results.json ==="
```

```python
#!/usr/bin/env python3
# scripts/ai-k8s-review.py
# AI-powered Kubernetes security assessment.

import argparse
import json
import os
import sys

import anthropic


K8S_REVIEW_PROMPT = """You are a Kubernetes security engineer performing a cluster security assessment.

Review the following Kubernetes cluster configuration for security issues:
1. RBAC: overly permissive roles, wildcard permissions, unnecessary cluster-admin bindings
2. Network policies: namespaces with no policies (default-allow), overly broad allow rules
3. Workload security: privileged containers, host namespaces, missing security contexts, running as root
4. Service exposure: LoadBalancer or NodePort services that should be ClusterIP, unnecessary external exposure
5. Ingress: missing TLS, overly broad path rules, exposed internal paths
6. Service accounts: pods using default service account, service accounts with unnecessary permissions

For each finding, provide:
- severity: critical, high, medium, or low
- resource: namespace/resource-name
- title: one-line summary
- description: what the issue is and the security impact
- remediation: specific kubectl command or YAML change

Respond ONLY with a JSON array of findings. If no issues are found, respond with an empty array [].
Do not include markdown formatting or code fences in your response.

Cluster configuration:
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    # Combine all exported files into a single context
    combined = {}
    for filename in os.listdir(args.input_dir):
        if filename.endswith(".json") and filename != os.path.basename(args.output):
            filepath = os.path.join(args.input_dir, filename)
            with open(filepath) as f:
                combined[filename.replace(".json", "")] = json.load(f)

    # Truncate to avoid exceeding token limits
    context = json.dumps(combined, indent=2)
    if len(context) > 100000:
        context = context[:100000] + "\n... (truncated for token limits)"

    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-4-6-20250514",
        max_tokens=8192,
        messages=[
            {
                "role": "user",
                "content": K8S_REVIEW_PROMPT + context,
            }
        ],
    )

    response_text = message.content[0].text.strip()
    findings = json.loads(response_text)

    with open(args.output, "w") as f:
        json.dump(findings, f, indent=2)

    # Summary
    severity_counts = {}
    for finding in findings:
        sev = finding.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"Total findings: {len(findings)}")
    for sev in ["critical", "high", "medium", "low"]:
        if sev in severity_counts:
            print(f"  {sev}: {severity_counts[sev]}")

    if severity_counts.get("critical", 0) > 0 or severity_counts.get("high", 0) > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
```

### 4. Network Architecture Assessment

Export firewall rules, network policies, and routing configuration for AI analysis. AI models identify attack paths that span multiple network segments and trust boundaries.

```bash
#!/bin/bash
# scripts/network-assessment.sh
# Export network configuration for AI-powered assessment.

set -e

OUTPUT_DIR="${1:-network-assessment}"
mkdir -p "${OUTPUT_DIR}"

echo "=== Network Architecture Assessment ==="

# Kubernetes network policies
kubectl get networkpolicies -A -o json > "${OUTPUT_DIR}/networkpolicies.json"

# Cilium network policies (if using Cilium)
kubectl get ciliumnetworkpolicies -A -o json 2>/dev/null > "${OUTPUT_DIR}/cilium-policies.json" || true

# Services and their exposure types
kubectl get services -A -o json | jq '{items: [.items[] | {
  namespace: .metadata.namespace,
  name: .metadata.name,
  type: .spec.type,
  clusterIP: .spec.clusterIP,
  externalIPs: .spec.externalIPs,
  loadBalancerIP: .status.loadBalancer.ingress,
  ports: [.spec.ports[] | {port: .port, targetPort: .targetPort, protocol: .protocol, nodePort: .nodePort}]
}]}' > "${OUTPUT_DIR}/services-exposure.json"

# Ingress resources with TLS configuration
kubectl get ingress -A -o json | jq '{items: [.items[] | {
  namespace: .metadata.namespace,
  name: .metadata.name,
  tls: .spec.tls,
  rules: .spec.rules
}]}' > "${OUTPUT_DIR}/ingress-config.json"

# Cloud firewall rules (AWS example)
if command -v aws &> /dev/null; then
  echo "Exporting AWS security groups..."
  aws ec2 describe-security-groups --output json > "${OUTPUT_DIR}/aws-security-groups.json" 2>/dev/null || true
fi

# Cloud firewall rules (GCP example)
if command -v gcloud &> /dev/null; then
  echo "Exporting GCP firewall rules..."
  gcloud compute firewall-rules list --format=json > "${OUTPUT_DIR}/gcp-firewall-rules.json" 2>/dev/null || true
fi

echo "Network configuration exported to ${OUTPUT_DIR}/"
echo "Run: python3 scripts/ai-network-review.py --input-dir ${OUTPUT_DIR} --output ${OUTPUT_DIR}/network-findings.json"
```

### 5. Continuous AI Audit Pipeline

Run comprehensive assessments on a schedule, not just on pull requests. Vulnerabilities introduced by configuration drift, infrastructure changes outside of CI, and newly discovered attack patterns require continuous assessment.

```yaml
# .github/workflows/ai-security-audit.yml
# Weekly comprehensive security assessment using AI.
name: Weekly AI Security Audit
on:
  schedule:
    - cron: '0 2 * * 1'  # Every Monday at 02:00 UTC
  workflow_dispatch:

jobs:
  code-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Install dependencies
        run: pip install anthropic

      - name: Full codebase security review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          # Review all application code files, not just changed files
          find . -name '*.go' -o -name '*.py' -o -name '*.js' -o -name '*.ts' \
            | grep -v vendor/ | grep -v node_modules/ | grep -v '.test.' \
            > files-to-review.txt
          python3 scripts/ai-security-review.py \
            --files "$(cat files-to-review.txt)" \
            --output code-findings.json \
            --severity-threshold medium
        continue-on-error: true

      - name: Upload findings
        uses: actions/upload-artifact@v4
        with:
          name: code-security-findings
          path: code-findings.json

  iac-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Install dependencies
        run: pip install anthropic

      - name: Review Terraform modules
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          for dir in $(find . -name '*.tf' -exec dirname {} \; | sort -u); do
            echo "Reviewing: ${dir}"
            bash scripts/ai-iac-review.sh "${dir}" "iac-findings-$(echo ${dir} | tr '/' '-').json" || true
          done

      - name: Upload findings
        uses: actions/upload-artifact@v4
        with:
          name: iac-security-findings
          path: iac-findings-*.json

  k8s-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Install dependencies
        run: pip install anthropic

      - name: Kubernetes security assessment
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          KUBECONFIG: ${{ secrets.KUBECONFIG }}
        run: bash scripts/k8s-security-assessment.sh k8s-findings
        continue-on-error: true

      - name: Upload findings
        uses: actions/upload-artifact@v4
        with:
          name: k8s-security-findings
          path: k8s-findings/

  aggregate-report:
    runs-on: ubuntu-latest
    needs: [code-review, iac-review, k8s-review]
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Download all findings
        uses: actions/download-artifact@v4
        with:
          path: all-findings/

      - name: Generate summary report
        run: |
          echo "# Weekly AI Security Assessment Report" > report.md
          echo "Date: $(date -u +%Y-%m-%d)" >> report.md
          echo "" >> report.md

          total=0
          critical=0
          high=0

          for f in $(find all-findings/ -name '*.json' -type f); do
            count=$(jq 'length' "$f" 2>/dev/null || echo 0)
            crit=$(jq '[.[] | select(.severity == "critical")] | length' "$f" 2>/dev/null || echo 0)
            hi=$(jq '[.[] | select(.severity == "high")] | length' "$f" 2>/dev/null || echo 0)
            total=$((total + count))
            critical=$((critical + crit))
            high=$((high + hi))
          done

          echo "## Summary" >> report.md
          echo "- Total findings: ${total}" >> report.md
          echo "- Critical: ${critical}" >> report.md
          echo "- High: ${high}" >> report.md

          cat report.md

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: security-assessment-report
          path: report.md

      - name: Notify on critical findings
        if: always()
        run: |
          CRITICAL_COUNT=$(find all-findings/ -name '*.json' -exec jq '[.[] | select(.severity == "critical")] | length' {} \; | paste -sd+ | bc)
          if [ "${CRITICAL_COUNT}" -gt 0 ]; then
            echo "CRITICAL FINDINGS DETECTED: ${CRITICAL_COUNT}"
            # Send notification via webhook (Slack, PagerDuty, etc.)
            # curl -X POST -H 'Content-Type: application/json' \
            #   -d "{\"text\": \"Weekly AI security audit found ${CRITICAL_COUNT} critical findings.\"}" \
            #   "${SLACK_WEBHOOK_URL}"
          fi
```

### 6. Scoping AI Access Safely

Giving an AI model access to your infrastructure for assessment creates its own attack surface. Scope access to read-only, use short-lived credentials, and audit every action.

```bash
# Create a read-only Kubernetes service account for AI assessments
kubectl create serviceaccount ai-assessor -n security

# Bind to a read-only cluster role
kubectl create clusterrolebinding ai-assessor-readonly \
  --clusterrole=view \
  --serviceaccount=security:ai-assessor

# Generate a short-lived token (expires in 1 hour)
kubectl create token ai-assessor -n security --duration=1h > /tmp/ai-assessor-token

# Create a kubeconfig that uses this token
kubectl config set-credentials ai-assessor --token="$(cat /tmp/ai-assessor-token)"
kubectl config set-context ai-assessment \
  --cluster="$(kubectl config current-context)" \
  --user=ai-assessor \
  --namespace=security

# Verify read-only access
kubectl auth can-i create pods --as=system:serviceaccount:security:ai-assessor
# Expected output: no

kubectl auth can-i get pods --as=system:serviceaccount:security:ai-assessor
# Expected output: yes

# Clean up token after assessment
rm -f /tmp/ai-assessor-token
```

**For source code access, use read-only deploy keys:**

```bash
# Generate a read-only deploy key for the assessment pipeline
ssh-keygen -t ed25519 -C "ai-security-assessor" -f ai-assessor-key -N ""

# Add as a read-only deploy key in GitHub repository settings
# Settings > Deploy keys > Add deploy key > Allow read access only

# Clean up the private key after adding to CI secrets
rm -f ai-assessor-key
```

**API key management for AI model access:**

```yaml
# Store the AI API key in Vault with a short TTL
# vault-policy-ai-assessor.hcl
path "secret/data/ai-assessor/*" {
  capabilities = ["read"]
}
```

```bash
# Store the API key with metadata
vault kv put secret/ai-assessor/anthropic \
  api_key="${ANTHROPIC_API_KEY}" \
  purpose="security-assessment-pipeline" \
  owner="security-team" \
  ttl="24h"
```

## Expected Behaviour

After implementing the AI-powered assessment pipeline:

- **Pull request reviews:** Every PR with code changes receives AI security review within 5 minutes. Findings posted as PR comments with severity, description, and remediation. Critical/high findings block merge.
- **IaC reviews:** Terraform plans reviewed for security issues before `terraform apply`. Overly permissive security groups, public resource exposure, and missing encryption caught before deployment.
- **Cluster assessments:** Weekly comprehensive assessment of RBAC, network policies, workload security, and service exposure. Findings tracked as issues with severity and remediation.
- **Network assessments:** Firewall rules and network policies reviewed for implicit trust, overly broad allow rules, and attack paths spanning trust boundaries.
- **False positive rate:** Expect 15-25% false positive rate from AI findings in the first month. This drops to 5-10% after tuning prompts and adding context about your architecture. False positives are preferable to false negatives; a false positive costs review time, a false negative costs a breach.
- **Cost:** Approximately $50-200/month in API tokens for a mid-size codebase (300,000 lines, 50 Terraform modules, 3 clusters) with weekly full assessments and per-PR reviews.

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| AI code review on every PR | Adds 2-5 minutes to PR pipeline; costs API tokens per review | False positives slow development velocity; developers learn to ignore findings | Tune severity threshold. Start with critical/high only. Add architectural context to prompts to reduce false positives. |
| Full codebase weekly scan | Comprehensive coverage finds issues missed by diff-based review | High token cost for large codebases; review fatigue from volume of findings | Prioritise by severity. Assign findings to service owners. Track finding-to-fix rate. |
| AI access to cluster state | Assessment requires read access to sensitive configuration (RBAC, secrets metadata) | Compromised AI API key or pipeline could leak cluster configuration | Read-only service account. Short-lived tokens (1 hour). Audit all API calls. No access to secret values (metadata only). |
| AI access to source code | Full codebase sent to external API for analysis | Source code leaves your network boundary | Use self-hosted models for sensitive codebases. Review AI provider data retention policies. Consider on-premise deployment of open-weight models for classified environments. |
| Automated finding creation | Issues created automatically from AI findings | Noise from false positives clutters issue tracker | Human triage step between finding and issue creation. AI-suggested severity + human-confirmed severity. |
| Per-PR blocking on critical findings | Critical AI findings block merge | False positive critical finding blocks a time-sensitive deployment | Override mechanism for security team lead. All overrides logged and reviewed weekly. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| AI model hallucinates vulnerability | Finding describes a vulnerability that does not exist in the code | Manual review of finding; code does not contain the described pattern | Mark as false positive. Add the specific pattern to the prompt's exclusion list. Track hallucination rate. |
| AI misses actual vulnerability | Real vulnerability not reported in findings | Discovered through penetration test, bug bounty, or incident | Add the missed vulnerability class to the prompt. Consider supplementing AI review with traditional SAST (Semgrep, CodeQL) for pattern-based coverage. |
| API rate limit or outage | AI review step times out or returns errors | CI pipeline step fails with API error | Implement retry with exponential backoff. Set pipeline to continue-on-error for AI review step (non-blocking). Alert security team to review manually. |
| Token budget exceeded | Monthly AI API costs exceed budget | Billing alert from AI provider | Reduce scan frequency (weekly instead of daily for full scans). Increase severity threshold. Limit file size per review. |
| Leaked source code via API | Source code stored or logged by AI provider | Audit of data retention; provider security incident disclosure | Use providers with zero-retention data policies. Self-host models for sensitive code. Rotate any credentials that appeared in reviewed code. |
| Over-reliance on AI findings | Team stops manual security review; AI-specific blind spots become systemic | Vulnerabilities found by penetration testers that AI consistently misses | Maintain annual penetration testing. Track vulnerability sources (AI-found, pentest-found, incident-found). AI is a supplement, not a replacement. |

## When to Consider a Managed Alternative

Building and maintaining an AI security assessment pipeline requires prompt engineering, pipeline maintenance, false positive management, and ongoing tuning. For teams without dedicated security engineering capacity, managed solutions provide the same capability with less operational overhead.

- **[Snyk](https://snyk.io):** AI-powered code analysis with reachability analysis. Identifies whether vulnerable code paths are actually reachable from application entry points. Lower false positive rate than general-purpose AI review because the models are fine-tuned for security findings.
- **[Semgrep](https://semgrep.dev):** Rule-based static analysis with AI-assisted rule generation. Combines the precision of pattern matching with AI's ability to understand code context. Managed rule sets updated for emerging vulnerability patterns.
- **[Wiz](https://www.wiz.io):** Agentless cloud security that combines AI-powered analysis with graph-based attack path identification. Maps relationships between cloud resources, Kubernetes workloads, and code to identify exploitable paths that individual tools miss.

**What you still control:** The assessment scope (which repositories, clusters, and cloud accounts are assessed). The severity thresholds and response procedures. The decision of which findings to fix, defer, or accept. Managed tools find the vulnerabilities; your team decides the response.

**Premium content pack:** AI security assessment pipeline templates. Complete GitHub Actions workflows for code, IaC, and Kubernetes assessment. Prompt templates optimised for low false-positive rates. Finding aggregation and reporting scripts. Credential scoping configurations for safe AI access.

## Related Articles

- [Mythos and the Vulnerability Classes AI Finds First: Eliminating Your Highest-Risk Attack Surface](/articles/ai-landscape/mythos-proactive-attack-surface-reduction/)
- [AI-Powered Vulnerability Discovery: What Automated Code Analysis Means for Your Patch Cycle](/articles/ai-landscape/ai-vulnerability-discovery/)
- [Claude for Security Detection: How Large Language Models Find What Scanners Miss](/articles/ai-landscape/claude-security-detection/)
- [Using AI to Harden Systems: Automated Configuration Review and Remediation](/articles/ai-landscape/ai-assisted-hardening/)
- [How AI Is Compressing the Attacker Timeline: What Defenders Need to Change Now](/articles/ai-landscape/ai-compressing-attacker-timeline/)
- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
