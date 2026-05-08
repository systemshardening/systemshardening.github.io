---
title: "kube-bench: CIS Kubernetes Benchmark Automation and Remediation"
description: "The CIS Kubernetes Benchmark defines 200+ controls across the API server, etcd, kubelet, and scheduler. kube-bench automates this check and integrates into CI/CD so benchmark regressions are caught before they reach production."
slug: "kube-bench-cis-benchmark"
date: 2026-05-01
lastmod: 2026-05-01
category: "kubernetes"
tags: ["kube-bench", "cis-benchmark", "compliance", "kubernetes-hardening", "security-posture"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 280
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/kubernetes/kube-bench-cis-benchmark/index.html"
---

# kube-bench: CIS Kubernetes Benchmark Automation and Remediation

## Problem

Kubernetes ships with many components that are insecure by default: anonymous authentication enabled on the API server, insecure ports open on the scheduler and controller manager, audit logging disabled, kubelet read-only port open. The CIS Kubernetes Benchmark documents the correct configuration for all of these. Most clusters fail dozens of checks simply because nobody ran the benchmark after initial setup.

The problems with manual CIS benchmark audits:

- **Point-in-time assessments.** A manual audit captures the cluster state at one moment. Node configuration drift, new worker nodes provisioned from an unhardened image, or a cloud provider upgrade that resets kubelet flags create compliance gaps between audits.
- **No CI/CD integration.** Changes that cause benchmark regressions (updating kube-apiserver flags, modifying kubelet configuration) are merged without a compliance gate. The next audit discovers the regression weeks or months later.
- **Partial coverage.** Manual audits often focus on control plane components and miss worker nodes. A cluster with a hardened API server and misconfigured kubelets passes a partial audit but remains exploitable.
- **No distinction between managed and self-managed controls.** On EKS, GKE, or AKS, some controls are the cloud provider's responsibility and cannot be configured by the operator. Without filtering, the raw benchmark output shows hundreds of failures that cannot be remediated.
- **Remediation guidance not tracked.** A finding with no owner is never fixed. Without a tracking workflow, benchmark results accumulate without driving improvement.

**Target systems:** kube-bench 0.8+ (CIS Kubernetes Benchmark 1.8+); self-managed Kubernetes 1.28+; EKS, GKE, AKS (with managed control plane filtering); kubeadm-provisioned clusters; RKE2/k3s.

## Threat Model

- **Adversary 1 — Anonymous API server access:** The API server has `--anonymous-auth=true` and the system:anonymous user has been bound to a permissive ClusterRole (a common misconfiguration). An attacker accesses the API server without credentials and enumerates or modifies cluster state.
- **Adversary 2 — Kubelet read-only port exploitation:** The kubelet's read-only port (10255) is open and unauthenticated. An attacker on the network queries `/pods` and `/metrics` to enumerate all pods, environment variables, and resource usage on the node — sensitive data without authentication.
- **Adversary 3 — etcd unauthenticated access:** etcd client URLs are bound to `0.0.0.0` without peer or client authentication. An attacker with network access to port 2379 reads all cluster secrets in plaintext.
- **Adversary 4 — Service account token abuse:** `--service-account-lookup=false` means a deleted service account's token remains valid. An attacker who obtained a token before service account deletion continues to use it indefinitely.
- **Adversary 5 — Audit log blind spot:** Audit logging is disabled. An attacker who compromises the cluster has no recorded evidence of their API calls, making forensic investigation impossible.
- **Access level:** Adversaries 1 and 2 need network access to Kubernetes ports. Adversaries 3 and 4 need network access or a compromised pod. Adversary 5 is a detection gap exploited post-compromise.
- **Objective:** Enumerate cluster, extract secrets, establish persistence, evade detection.
- **Blast radius:** etcd access or API server anonymous access gives complete cluster control — equivalent to root on every node.

## Configuration

### Step 1: Run kube-bench

kube-bench auto-detects the cluster component configuration:

```bash
# Run against a kubeadm-provisioned cluster (auto-detects version).
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Or run directly on a control plane node.
kube-bench run --targets master,node,etcd,policies

# Run specific CIS benchmark version.
kube-bench run --benchmark cis-1.8

# Output formats.
kube-bench run --json > kube-bench-results.json
kube-bench run --junit > kube-bench-results.xml   # For CI systems.

# For managed clusters (EKS): use EKS-specific targets.
kube-bench run --targets node,policies --benchmark eks-stig-kubernetes-v2r2
# Or use the managed benchmark (skips control plane — AWS manages it).
kube-bench run --benchmark eks-1.4.0
```

Interpreting results:

```
[INFO] 1 Master Node Security Configuration
[INFO] 1.2 API Server
[PASS] 1.2.1 Ensure that the --anonymous-auth argument is set to false
[FAIL] 1.2.6 Ensure that the --kubelet-certificate-authority argument is set as appropriate
[WARN] 1.2.11 Ensure that the admission control plugin AlwaysAdmit is not set
[INFO] 1.2.12 Ensure that the admission control plugin AlwaysPullImages is set

== Summary master ==
43 checks PASS
7 checks FAIL
10 checks WARN
0 checks INFO
```

- `PASS`: Control is satisfied.
- `FAIL`: Control is not satisfied; remediation required.
- `WARN`: Manual verification required (kube-bench cannot automate this check).
- `INFO`: Informational; review but no action required.

### Step 2: Prioritise and Remediate FAIL Findings

High-priority FAIL checks and their remediation:

```bash
# 1.2.1 — anonymous-auth: disable anonymous API server access.
# /etc/kubernetes/manifests/kube-apiserver.yaml
# Add flag:
# - --anonymous-auth=false
# Note: on EKS/GKE this is managed by the provider.

# 1.2.2 — token-auth-file: ensure static token file is not used.
# Remove --token-auth-file from kube-apiserver flags.

# 1.2.6 — kubelet-certificate-authority: verify kubelet TLS.
# kube-apiserver must verify kubelet certs:
# - --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt

# 1.2.22 — audit-log-path: enable audit logging.
# - --audit-log-path=/var/log/kubernetes/audit.log
# - --audit-log-maxage=30
# - --audit-log-maxbackup=10
# - --audit-log-maxsize=100
# - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
```

```bash
# 4.2.1 — kubelet: disable anonymous authentication.
# /var/lib/kubelet/config.yaml
# authentication:
#   anonymous:
#     enabled: false   # Was true by default on some distros.

# 4.2.2 — kubelet: require Webhook authorization.
# authorization:
#   mode: Webhook   # Not AlwaysAllow.

# 4.2.6 — protect kernel defaults.
# protectKernelDefaults: true
```

```bash
# 2.1 — etcd: peer and client TLS.
# /etc/kubernetes/manifests/etcd.yaml
# - --cert-file=/etc/kubernetes/pki/etcd/server.crt
# - --key-file=/etc/kubernetes/pki/etcd/server.key
# - --client-cert-auth=true
# - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
# - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
# - --peer-client-cert-auth=true
```

For kubeadm clusters, patch the configuration in place:

```bash
# Edit kube-apiserver manifest (kubeadm clusters).
# The API server restarts automatically when the manifest changes.
sudo cp /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/manifests/kube-apiserver.yaml.bak
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml

# Verify the API server came back after edit.
kubectl get nodes
kubectl cluster-info
```

### Step 3: Configuration File for Managed Clusters

Create a kube-bench configuration that skips controls managed by the cloud provider:

```yaml
# kube-bench-config.yaml — for EKS clusters.
# Skip control plane checks (AWS manages the control plane).
skip:
  - "1"    # Master node checks.
  - "2"    # etcd checks.
  - "3"    # Control plane configuration.

# Run only node and policy checks.
targets:
  - node
  - policies
```

```bash
kube-bench run --config kube-bench-config.yaml --benchmark eks-1.4.0
```

For GKE:

```bash
# GKE auto-configures most CIS controls. Run only node-level checks.
kube-bench run --targets node --benchmark gke-1.4.0
```

### Step 4: CI/CD Integration

Run kube-bench automatically on cluster configuration changes:

```yaml
# .github/workflows/cis-benchmark.yml
name: CIS Kubernetes Benchmark

on:
  schedule:
    - cron: "0 6 * * *"      # Daily at 6am.
  push:
    paths:
      - "kubernetes/**"       # Also on k8s config changes.

jobs:
  kube-bench:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Deploy kube-bench job
        run: |
          kubectl apply -f kubernetes/kube-bench-job.yaml
          kubectl wait --for=condition=complete job/kube-bench --timeout=300s

      - name: Collect results
        run: |
          kubectl logs job/kube-bench --all-containers > kube-bench-results.txt
          # Extract FAIL count.
          FAIL_COUNT=$(grep -c '^\[FAIL\]' kube-bench-results.txt || true)
          echo "FAIL checks: $FAIL_COUNT"
          echo "fail_count=$FAIL_COUNT" >> $GITHUB_ENV

      - name: Fail CI on new failures
        run: |
          # Compare against baseline.
          BASELINE=$(cat .kube-bench-baseline)
          if [ "${{ env.fail_count }}" -gt "$BASELINE" ]; then
            echo "REGRESSION: ${{ env.fail_count }} failures (baseline: $BASELINE)"
            cat kube-bench-results.txt | grep '^\[FAIL\]'
            exit 1
          fi
          echo "No new failures."

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: kube-bench-results
          path: kube-bench-results.txt
```

```yaml
# kubernetes/kube-bench-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
  namespace: kube-system
spec:
  template:
    spec:
      hostPID: true
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          effect: NoSchedule
      containers:
        - name: kube-bench
          image: aquasec/kube-bench:v0.8.0
          command: ["kube-bench", "run", "--targets", "master,node,etcd,policies", "--json"]
          volumeMounts:
            - name: var-lib-etcd
              mountPath: /var/lib/etcd
              readOnly: true
            - name: etc-kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
            - name: etc-systemd
              mountPath: /etc/systemd
              readOnly: true
            - name: var-lib-kubelet
              mountPath: /var/lib/kubelet
              readOnly: true
            - name: usr-local-mount-1
              mountPath: /usr/local/mount-from-host/bin
              readOnly: true
      restartPolicy: Never
      volumes:
        - name: var-lib-etcd
          hostPath:
            path: /var/lib/etcd
        - name: etc-kubernetes
          hostPath:
            path: /etc/kubernetes
        - name: etc-systemd
          hostPath:
            path: /etc/systemd
        - name: var-lib-kubelet
          hostPath:
            path: /var/lib/kubelet
        - name: usr-local-mount-1
          hostPath:
            path: /usr/local/bin
```

### Step 5: Tracking Remediation with Exceptions

Not all FAIL checks can be immediately remediated. Track exceptions explicitly:

```yaml
# kube-bench-exceptions.yaml — documented accepted risks.
exceptions:
  - check_id: "1.2.11"
    check_description: "AlwaysPullImages admission plugin"
    reason: "Multi-tenant clusters require this; enabling causes issues with air-gapped nodes"
    owner: "platform-team"
    review_date: "2026-11-01"
    risk_accepted_by: "security-eng"

  - check_id: "4.2.12"
    check_description: "Ensure that the RotateKubeletServerCertificate argument is set to true"
    reason: "Not yet supported by our managed node group upgrade process; tracked in INFRA-4821"
    owner: "infrastructure-team"
    review_date: "2026-08-01"
    risk_accepted_by: "ciso"
```

```python
# kube_bench/filter_results.py
def filter_accepted_exceptions(results: list, exceptions: list) -> list:
    """Remove accepted exceptions from FAIL list before CI gate evaluation."""
    exception_ids = {e["check_id"] for e in exceptions}
    return [r for r in results if r["id"] not in exception_ids or r["status"] != "FAIL"]
```

### Step 6: Node-Level Hardening from Benchmark Findings

The most commonly failed node checks and their remediation:

```yaml
# /var/lib/kubelet/config.yaml — kubelet hardening from CIS.
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration

# 4.2.1: Disable anonymous authentication.
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt

# 4.2.2: Webhook authorization.
authorization:
  mode: Webhook

# 4.2.6: Protect kernel defaults.
protectKernelDefaults: true

# 4.2.7: Make kubelet config file read-only.
# (Set file permissions on /var/lib/kubelet/config.yaml to 644.)

# 4.2.10: TLS cipher restriction.
tlsCipherSuites:
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
tlsMinVersion: VersionTLS12

# 4.2.12: Rotate kubelet server certificates.
serverTLSBootstrap: true
rotateCertificates: true

# 4.2.4: Disable read-only port.
readOnlyPort: 0
```

### Step 7: Scheduled Reporting

Generate trend reports to show compliance improvement over time:

```python
#!/usr/bin/env python3
# kube_bench/report.py
import json
from datetime import datetime
from pathlib import Path

def parse_kube_bench_json(results_file: str) -> dict:
    with open(results_file) as f:
        data = json.load(f)
    
    totals = {"pass": 0, "fail": 0, "warn": 0, "info": 0}
    failures = []
    
    for section in data.get("Controls", []):
        for test in section.get("tests", []):
            for result in test.get("results", []):
                status = result["status"].lower()
                totals[status] = totals.get(status, 0) + 1
                if status == "fail":
                    failures.append({
                        "id": result["test_number"],
                        "description": result["test_desc"],
                        "remediation": result.get("remediation", "")
                    })
    
    return {"totals": totals, "failures": failures, "date": datetime.utcnow().isoformat()}

def write_trend(history_file: str, run_result: dict):
    history = json.loads(Path(history_file).read_text()) if Path(history_file).exists() else []
    history.append(run_result)
    Path(history_file).write_text(json.dumps(history, indent=2))
```

### Step 8: Telemetry

```
kube_bench_fail_total{cluster, section}          gauge
kube_bench_pass_total{cluster, section}          gauge
kube_bench_warn_total{cluster}                   gauge
kube_bench_check_status{cluster, check_id}       gauge (1=pass, 0=fail)
kube_bench_run_timestamp{cluster}                gauge
```

Alert on:

- `kube_bench_fail_total` increases from previous run — a benchmark regression was introduced; review recent configuration changes.
- `kube_bench_check_status{check_id="1.2.1"}` == 0 — anonymous auth is enabled on the API server; critical finding.
- `kube_bench_check_status{check_id="2.1"}` == 0 — etcd is unauthenticated; critical finding.
- No `kube_bench_run_timestamp` update in 25 hours — scheduled benchmark job failed to run.

## Expected Behaviour

| Signal | Unchecked cluster | kube-bench enforced |
|--------|------------------|---------------------|
| Anonymous API server access | Possible if unconfigured | Detected at next scan; CI gate fails on introduction |
| Kubelet read-only port open | Common default | Detected; `readOnlyPort: 0` pushed via kubelet config |
| Audit logging disabled | Default on kubeadm | Detected; audit policy applied |
| Benchmark regressions from config changes | Silent until next audit | CI gate fails; PR blocked |
| Node-to-node benchmark drift | Undetected | Per-node job run detects node-specific failures |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `hostPID: true` for kube-bench job | Required to inspect process args | Privileged pod; only run in kube-system | Restrict job to control plane node; use RBAC to prevent non-admin scheduling |
| Daily scheduled scan | Catches drift | Another cron job to maintain | Use existing monitoring infrastructure; alert on job failure |
| Strict CI gate (fail on any new FAIL) | Prevents regression | May block legitimate changes | Exception mechanism with documented owner and review date |
| CIS benchmark is not threat-specific | Comprehensive baseline | Some checks are low-risk in your environment | Use exceptions for low-risk checks; focus remediation on critical findings |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| kube-bench version mismatch | Checks differ from expected CIS version | Version logged in job output | Pin `--benchmark` flag to specific version; update explicitly |
| Job fails to start on managed cluster | Kubelet read-only volume mounts fail | Job pod pending/crashlooping | Use cloud-provider specific benchmark (EKS/GKE flags); skip host mount checks |
| False positive after distro update | PASS check becomes FAIL after OS package update changes defaults | Benchmark regression alert | Investigate actual config; update baseline if the new state is correct |
| Exception list not updated at review date | Accepted risk still present past agreed remediation date | Automated review date check in CI | Alert when exception review_date < today; require renewal or remediation |

## Related Articles

- [Kubernetes API Server Hardening](/articles/kubernetes/api-server-hardening/)
- [Kubernetes Node Hardening](/articles/kubernetes/node-hardening/)
- [etcd Encryption and Security](/articles/kubernetes/etcd-encryption/)
- [Kubelet Security](/articles/kubernetes/kubelet-security/)
- [Kyverno Policy Development and Testing](/articles/kubernetes/kyverno-policy-development/)
- [Cloud Security Posture Management](/articles/cross-cutting/cloud-security-posture-management/)
