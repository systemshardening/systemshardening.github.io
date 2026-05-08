---
title: "Kubernetes Manifest Validation in CI: Catching Security Issues Before Deployment"
description: "Runtime admission controllers catch bad manifests at deploy time — when it's too late for the developer and too slow for the pipeline. Shift manifest security left with kubesec, Trivy, Conftest, Kyverno CLI, and Polaris in GitHub Actions to fail PRs before anything reaches the cluster."
slug: kubernetes-manifest-validation-ci
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - kubernetes
  - manifest-validation
  - kyverno
  - conftest
  - policy-as-code
personas:
  - security-engineer
  - platform-engineer
article_number: 530
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/kubernetes-manifest-validation-ci/
---

# Kubernetes Manifest Validation in CI: Catching Security Issues Before Deployment

## Problem

Kubernetes admission controllers — Kyverno, OPA Gatekeeper, the built-in PodSecurity admission plugin — are the last line of defence before a workload runs in your cluster. They are not the right place to first discover a security problem. When a deployment fails admission at the cluster gate, a developer has already merged a PR, triggered a deploy job, waited for image builds, and then received a cryptic rejection with no inline code context and no link to the policy they violated.

The gap between YAML authoring and runtime admission is where security debt accumulates:

- **Developers write manifests with no feedback.** `runAsNonRoot: false`, missing `securityContext`, `privileged: true` — these issues are invisible until the manifest hits admission control or, worse, until a workload runs unchallenged in a cluster with no admission controller.
- **Admission controllers only fire at deploy time.** A failed admission check surfaces minutes to hours after the code was written, in a context (a deploy pipeline stage) that is far from the developer's editor and PR.
- **Helm charts mask raw manifests.** Chart authors render templates once to verify they work, not to verify they comply with security policy. Rendered output can differ substantially from the chart's template source, and only the rendered output matters to the cluster.
- **Schema drift causes silent failures.** Manifests using deprecated API versions (`extensions/v1beta1 Ingress`, removed in 1.22) apply successfully in a lenient cluster but fail validation entirely in the target version. Catching this in CI prevents broken deployments.
- **No organisational policy enforcement in development.** Teams have opinionated rules — required labels, banned image registries, mandatory resource limits — that are expressed in admission policies but never visible to developers until a deploy bounces.

**Target systems:** Kubernetes 1.26+; GitHub Actions; Helm 3.x; kubesec 2.x; Trivy 0.50+; Conftest 0.50+; Kyverno CLI 1.12+; Polaris 8.x; kubeconform 0.6+.

## Threat Model

- **Adversary 1 — Misconfigured workload running as root:** A developer submits a Deployment manifest with no `securityContext`. The admission controller is missing or bypassed in a dev cluster. The container runs as UID 0. A vulnerability in the application gives the attacker root-equivalent access inside the container, easing container escape.
- **Adversary 2 — Privileged container via chart default:** A third-party Helm chart ships with `privileged: true` in its default values. Nobody notices because the chart is templated and applied without scanning the rendered output. The container has host-level capabilities.
- **Adversary 3 — Banned image registry in production:** An engineer references a public Docker Hub image in a manifest. The organisation's supply-chain policy requires images to come from the internal registry. No CI check exists; the image reaches production pulling from an uncontrolled source.
- **Adversary 4 — Policy drift between CI and admission:** Admission controller policies are updated but the CI validation linter is not. Manifests pass CI checks that will fail in the cluster. Engineers lose confidence in CI validation and start bypassing it.
- **Adversary 5 — Deprecated API version applied to new cluster:** A manifest uses `policy/v1beta1 PodDisruptionBudget`, removed in Kubernetes 1.25. The cluster is upgraded; the next deployment fails. No CI check caught the incompatibility.
- **Access level:** Adversaries 1–3 require only the ability to merge a Kubernetes manifest or Helm chart. Adversary 4 is an operational failure. Adversary 5 requires a cluster version upgrade event.
- **Objective:** Run privileged workloads, supply-chain compromise, deployment failures during upgrades.
- **Blast radius:** A single unchecked manifest can expose a node, introduce a supply-chain vulnerability, or break a production deployment.

## Configuration

### Step 1: kubesec — Manifest Risk Scoring

kubesec scores individual manifests against a set of security rules, producing a numeric score with per-rule pass/fail detail. Negative score or low score fails the build.

```yaml
# .github/workflows/manifest-security.yml
name: Kubernetes Manifest Security

on:
  pull_request:
    paths:
      - 'k8s/**'
      - 'charts/**'

jobs:
  kubesec-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install kubesec
        run: |
          curl -sSL https://github.com/controlplaneio/kubesec/releases/download/v2.14.2/kubesec_linux_amd64.tar.gz \
            | tar xz kubesec
          sudo mv kubesec /usr/local/bin/

      - name: Scan manifests with kubesec
        run: |
          FAIL=0
          for manifest in $(find k8s/ -name '*.yaml' -o -name '*.yml'); do
            echo "=== Scanning $manifest ==="
            RESULT=$(kubesec scan "$manifest")
            SCORE=$(echo "$RESULT" | jq '.[0].score')
            echo "$RESULT" | jq '.[0].scoring'
            if [ "$SCORE" -lt 0 ]; then
              echo "FAIL: $manifest scored $SCORE (threshold: 0)"
              FAIL=1
            fi
          done
          exit $FAIL
```

kubesec checks that matter most:

| Rule | What it checks | Score impact |
|------|---------------|-------------|
| `RunAsNonRoot` | `securityContext.runAsNonRoot: true` | +1 |
| `ReadOnlyRootFilesystem` | `securityContext.readOnlyRootFilesystem: true` | +1 |
| `CapDropAll` | `capabilities.drop: [ALL]` | +1 |
| `Privileged` | `securityContext.privileged: true` | -30 |
| `AllowPrivilegeEscalation` | `allowPrivilegeEscalation: true` | -7 |
| `HostPID` | `hostPID: true` | -9 |
| `HostNetwork` | `hostNetwork: true` | -9 |

A manifest with `privileged: true` scores below zero immediately, failing the build.

### Step 2: Trivy — Misconfiguration Scanning

Trivy's `--scanners misconfig` mode checks Kubernetes manifests against a built-in rule library covering CIS Kubernetes Benchmark, NSA guidelines, and general best practices.

```yaml
  trivy-misconfig:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy misconfiguration scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: k8s/
          # Fail on HIGH or CRITICAL severity misconfigurations.
          exit-code: '1'
          severity: 'HIGH,CRITICAL'
          format: sarif
          output: trivy-results.sarif

      - name: Upload Trivy SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()   # Upload even if scan failed, for PR annotation.
        with:
          sarif_file: trivy-results.sarif
```

The SARIF upload causes GitHub to annotate the PR diff directly with the finding location — the developer sees the issue on the relevant line without leaving the pull request.

To scan only the manifests changed in the PR, limiting noise:

```bash
# Only scan files changed in this PR.
git diff --name-only origin/main...HEAD -- '*.yaml' '*.yml' \
  | xargs -I{} trivy config --severity HIGH,CRITICAL --exit-code 1 {}
```

### Step 3: Conftest — OPA-Based Organisational Policies

Conftest evaluates Kubernetes manifests against Rego policies. This is where team-specific rules live: required labels, approved image registries, banned capabilities, mandatory resource limits.

```rego
# policy/kubernetes/deny_latest_tag.rego
package kubernetes.deny_latest_tag

import future.keywords.contains
import future.keywords.if

# Deny containers that use the :latest image tag.
deny contains msg if {
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container '%v' uses ':latest' tag — pin to a digest or version", [container.name])
}

deny contains msg if {
  container := input.spec.template.spec.initContainers[_]
  endswith(container.image, ":latest")
  msg := sprintf("initContainer '%v' uses ':latest' tag", [container.name])
}
```

```rego
# policy/kubernetes/require_labels.rego
package kubernetes.require_labels

import future.keywords.contains
import future.keywords.if

required_labels := {"app", "version", "team"}

deny contains msg if {
  provided := {label | input.metadata.labels[label]}
  missing := required_labels - provided
  count(missing) > 0
  msg := sprintf("Missing required labels: %v", [missing])
}
```

```rego
# policy/kubernetes/registry_allowlist.rego
package kubernetes.registry_allowlist

import future.keywords.contains
import future.keywords.if

approved_registries := {
  "registry.internal.example.com",
  "gcr.io/distroless",
}

deny contains msg if {
  container := input.spec.template.spec.containers[_]
  image := container.image
  not any_approved(image)
  msg := sprintf("Container '%v' image '%v' is not from an approved registry", [container.name, image])
}

any_approved(image) if {
  approved_registries[registry]
  startswith(image, registry)
}
```

```rego
# policy/kubernetes/resource_limits.rego
package kubernetes.resource_limits

import future.keywords.contains
import future.keywords.if

deny contains msg if {
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container '%v' has no memory limit", [container.name])
}

deny contains msg if {
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.cpu
  msg := sprintf("Container '%v' has no CPU request", [container.name])
}
```

GitHub Actions step to run Conftest:

```yaml
  conftest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Conftest
        run: |
          curl -sSL https://github.com/open-policy-agent/conftest/releases/download/v0.53.0/conftest_0.53.0_Linux_x86_64.tar.gz \
            | tar xz conftest
          sudo mv conftest /usr/local/bin/

      - name: Run Conftest against Kubernetes manifests
        run: |
          conftest test k8s/ \
            --policy policy/kubernetes/ \
            --output github \
            --all-namespaces
        # --output github: produces GitHub Actions annotation format;
        # violations appear as inline PR comments.
```

The `--output github` flag causes Conftest to emit `::error file=...::` annotations, which GitHub Actions converts to inline PR comments pointing to the exact file and line where the policy was violated.

### Step 4: Kyverno CLI — Offline Policy Testing

Kyverno runs as a Kubernetes admission controller at runtime. The Kyverno CLI replicates that evaluation locally, so the exact same policies enforced at admission are also tested in CI. This eliminates the drift between CI checks and what the cluster actually enforces.

```yaml
# policy/kyverno/require-non-root.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-run-as-non-root
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-run-as-non-root
      match:
        any:
          - resources:
              kinds: [Deployment, StatefulSet, DaemonSet, Job, CronJob]
      validate:
        message: "Containers must not run as root. Set securityContext.runAsNonRoot: true."
        pattern:
          spec:
            template:
              spec:
                securityContext:
                  runAsNonRoot: "true"
```

```yaml
# policy/kyverno/disallow-privileged.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-privileged
      match:
        any:
          - resources:
              kinds: [Deployment, StatefulSet, DaemonSet, Pod]
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            template:
              spec:
                containers:
                  - =(securityContext):
                      =(privileged): "false"
```

```yaml
  kyverno-cli:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Kyverno CLI
        run: |
          curl -sSL https://github.com/kyverno/kyverno/releases/download/v1.12.5/kyverno-cli_v1.12.5_linux_x86_64.tar.gz \
            | tar xz kyverno
          sudo mv kyverno /usr/local/bin/

      - name: Apply Kyverno policies to manifests
        run: |
          kyverno apply policy/kyverno/ \
            --resource k8s/ \
            --detailed-results \
            --table
        # Exit code is non-zero if any Enforce policy fails.
```

Because these policies are the same YAML files deployed to the cluster, there is a single source of truth. Update the policy file, and both CI and admission control update together.

### Step 5: Polaris — Best-Practices Validation

Polaris covers a broader set of Kubernetes best-practice checks beyond security: health checks, image tag pinning, resource requests, and security context completeness. It produces a scored summary and can enforce a minimum score.

```yaml
  polaris:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Polaris
        run: |
          curl -sSL https://github.com/FairwindsOps/polaris/releases/download/8.5.4/polaris_linux_amd64.tar.gz \
            | tar xz polaris
          sudo mv polaris /usr/local/bin/

      - name: Run Polaris audit
        run: |
          polaris audit \
            --audit-path k8s/ \
            --format pretty \
            --set-exit-code-below-score 80 \
            --set-exit-code-on-danger
        # Fails if score < 80 or any "danger" check fails.
```

Polaris checks include:

| Category | Example checks |
|----------|---------------|
| Security | `runAsNonRoot`, `readOnlyRootFilesystem`, `privileged`, `allowPrivilegeEscalation` |
| Reliability | `livenessProbe`, `readinessProbe`, resource requests and limits |
| Efficiency | Resource limits set; no resource waste from oversized limits |
| Images | Not using `latest` tag, not pulling from insecure registries |

### Step 6: Scanning Helm Chart Rendered Output

Helm charts render to Kubernetes YAML at deploy time. The rendered output is what the cluster applies — and the templates may produce quite different manifests depending on values. Always scan rendered output, not template source.

```bash
# Render and scan in one pipeline — no cluster access needed.

# Using kubesec:
helm template my-release ./charts/my-app \
  --values charts/my-app/values-prod.yaml \
  | kubesec scan -
# kubesec reads from stdin when given '-' as the filename.

# Using Conftest (split multi-document YAML into individual documents):
helm template my-release ./charts/my-app \
  --values charts/my-app/values-prod.yaml \
  | conftest test - --policy policy/kubernetes/ --all-namespaces

# Using Trivy:
helm template my-release ./charts/my-app \
  --values charts/my-app/values-prod.yaml \
  > /tmp/rendered.yaml && \
  trivy config --severity HIGH,CRITICAL /tmp/rendered.yaml

# Using Kyverno CLI directly against rendered output:
helm template my-release ./charts/my-app \
  --values charts/my-app/values-prod.yaml \
  > /tmp/rendered.yaml && \
  kyverno apply policy/kyverno/ --resource /tmp/rendered.yaml
```

GitHub Actions job scanning a Helm chart:

```yaml
  helm-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Helm
        uses: azure/setup-helm@v4

      - name: Render and scan Helm chart
        run: |
          # Render to a temp file.
          helm template my-release ./charts/my-app \
            --values charts/my-app/values-prod.yaml \
            > /tmp/rendered.yaml

          echo "--- kubesec ---"
          kubesec scan /tmp/rendered.yaml | jq '.[].score'

          echo "--- conftest ---"
          conftest test /tmp/rendered.yaml \
            --policy policy/kubernetes/ \
            --all-namespaces \
            --output github

          echo "--- kyverno ---"
          kyverno apply policy/kyverno/ \
            --resource /tmp/rendered.yaml \
            --table
```

### Step 7: kubeconform — Schema and API Version Validation

kubeconform validates manifests against the Kubernetes JSON schema for the target version. It catches deprecated or removed API versions, typos in field names, and structural errors that `kubectl apply --dry-run` would miss without cluster access.

```yaml
  kubeconform:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install kubeconform
        run: |
          curl -sSL https://github.com/yannh/kubeconform/releases/download/v0.6.7/kubeconform-linux-amd64.tar.gz \
            | tar xz kubeconform
          sudo mv kubeconform /usr/local/bin/

      - name: Validate schema against target Kubernetes version
        run: |
          kubeconform \
            -kubernetes-version 1.29.0 \
            -strict \
            -summary \
            -output pretty \
            k8s/

      - name: Validate Helm rendered output schema
        run: |
          helm template my-release ./charts/my-app \
            --values charts/my-app/values-prod.yaml \
            | kubeconform \
              -kubernetes-version 1.29.0 \
              -strict \
              -summary
```

`-strict` rejects any fields that do not exist in the schema — including custom annotation typos that would be silently ignored by the API server. Use the target Kubernetes version of the production cluster so that the check catches API removals before the cluster upgrade lands.

For clusters with custom resources (CRDs), supply schemas from the cluster:

```bash
# Export CRD schemas from the cluster for kubeconform.
kubectl get crds -o json \
  | jq -r '.items[].metadata.name' \
  | while read crd; do
      kubectl get crd "$crd" -o json \
        | jq '{
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": .spec.versions[0].schema.openAPIV3Schema.properties
          }' \
        > "schemas/$(echo $crd | tr '.' '_').json"
    done

# Run kubeconform with the exported schemas.
kubeconform \
  -kubernetes-version 1.29.0 \
  -schema-location schemas/ \
  -strict \
  k8s/
```

### Step 8: Complete GitHub Actions Workflow

Assembling all checks into a single workflow that fails the PR with inline annotations:

```yaml
# .github/workflows/manifest-security.yml
name: Kubernetes Manifest Security

on:
  pull_request:
    paths:
      - 'k8s/**'
      - 'charts/**'
      - 'policy/**'

permissions:
  contents: read
  security-events: write   # For SARIF upload.
  pull-requests: write     # For inline PR comments via GitHub annotations.

jobs:
  schema-validation:
    name: Schema (kubeconform)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install kubeconform
        run: |
          curl -sSL https://github.com/yannh/kubeconform/releases/download/v0.6.7/kubeconform-linux-amd64.tar.gz \
            | tar xz && sudo mv kubeconform /usr/local/bin/
      - name: Validate schemas
        run: |
          kubeconform -kubernetes-version 1.29.0 -strict -summary k8s/

  security-score:
    name: Security Score (kubesec)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install kubesec
        run: |
          curl -sSL https://github.com/controlplaneio/kubesec/releases/download/v2.14.2/kubesec_linux_amd64.tar.gz \
            | tar xz && sudo mv kubesec /usr/local/bin/
      - name: Score manifests
        run: |
          FAIL=0
          for f in $(find k8s/ -name '*.yaml'); do
            SCORE=$(kubesec scan "$f" | jq '.[0].score')
            [ "$SCORE" -lt 0 ] && { echo "FAIL: $f scored $SCORE"; FAIL=1; }
          done
          exit $FAIL

  misconfig-scan:
    name: Misconfigurations (Trivy)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aquasecurity/trivy-action@master
        with:
          scan-type: config
          scan-ref: k8s/
          exit-code: '1'
          severity: HIGH,CRITICAL
          format: sarif
          output: trivy-results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-results.sarif

  policy-check:
    name: Policy (Conftest + Kyverno)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Conftest and Kyverno CLI
        run: |
          curl -sSL https://github.com/open-policy-agent/conftest/releases/download/v0.53.0/conftest_0.53.0_Linux_x86_64.tar.gz \
            | tar xz && sudo mv conftest /usr/local/bin/
          curl -sSL https://github.com/kyverno/kyverno/releases/download/v1.12.5/kyverno-cli_v1.12.5_linux_x86_64.tar.gz \
            | tar xz && sudo mv kyverno /usr/local/bin/
      - name: Conftest organisational policies
        run: |
          conftest test k8s/ \
            --policy policy/kubernetes/ \
            --output github \
            --all-namespaces
      - name: Kyverno admission policies
        run: |
          kyverno apply policy/kyverno/ \
            --resource k8s/ \
            --detailed-results \
            --table

  best-practices:
    name: Best Practices (Polaris)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Polaris
        run: |
          curl -sSL https://github.com/FairwindsOps/polaris/releases/download/8.5.4/polaris_linux_amd64.tar.gz \
            | tar xz && sudo mv polaris /usr/local/bin/
      - name: Polaris audit
        run: |
          polaris audit \
            --audit-path k8s/ \
            --format pretty \
            --set-exit-code-below-score 80 \
            --set-exit-code-on-danger

  helm-render-scan:
    name: Helm Rendered Output
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/setup-helm@v4
      - name: Render and scan charts
        run: |
          for chart_dir in charts/*/; do
            chart=$(basename "$chart_dir")
            echo "=== Rendering $chart ==="
            helm template "$chart" "$chart_dir" \
              --values "${chart_dir}values-prod.yaml" \
              > /tmp/rendered-${chart}.yaml

            echo "--- kubesec ---"
            kubesec scan /tmp/rendered-${chart}.yaml \
              | jq '.[].score' | grep -v '^-' || exit 1

            echo "--- conftest ---"
            conftest test /tmp/rendered-${chart}.yaml \
              --policy policy/kubernetes/ \
              --all-namespaces \
              --output github || exit 1
          done
```

### Step 9: Progressive Policy — Warn Before Enforcing

Introducing validation in CI on an existing codebase will produce hundreds of failures on day one. Use a warn-before-enforce progression to build developer trust without blocking all work.

**Phase 1 — Warn only (week 1-2).** Run all checks but do not fail the PR. Collect a baseline of violations.

```yaml
      - name: Conftest (warn only — phase 1)
        run: |
          conftest test k8s/ \
            --policy policy/kubernetes/ \
            --output github \
            --all-namespaces || true   # 'true' swallows exit code; never blocks PR.
        continue-on-error: true
```

**Phase 2 — Fail on new violations (week 3-4).** Use a diff-based scan: only check files changed in the PR. Existing violations are not blocked; new ones are.

```bash
# Only scan manifests changed in this PR.
CHANGED=$(git diff --name-only origin/main...HEAD -- '*.yaml' '*.yml')
if [ -n "$CHANGED" ]; then
  echo "$CHANGED" | xargs conftest test --policy policy/kubernetes/ --output github --all-namespaces
fi
```

**Phase 3 — Fail on all violations (week 5+).** Enable full enforcement. By this point, the baseline violations should have been remediated or granted permanent exceptions via policy annotations.

Kyverno supports `validationFailureAction: Audit` in the policy YAML to produce warnings without blocking. Switch to `Enforce` at Phase 3 — the policy files used in CI match the cluster exactly:

```yaml
# policy/kyverno/require-non-root.yaml
spec:
  validationFailureAction: Audit   # Phase 1: warn.
  # validationFailureAction: Enforce  # Phase 3: block.
```

Because the same files are used in CI and deployed to the cluster, promoting from `Audit` to `Enforce` at CI mirrors the admission controller upgrade — no policy drift.

### Step 10: Telemetry

```
ci_manifest_scan_violations_total{tool, severity, rule, repo}    counter
ci_manifest_scan_duration_seconds{tool, repo}                    histogram
ci_manifest_scan_score{tool, manifest, repo}                     gauge
ci_policy_exceptions_total{policy, namespace, manifest}          counter
ci_helm_render_scan_violations_total{chart, tool, rule}          counter
```

Alert on:

- `ci_manifest_scan_violations_total` rising over a rolling 7-day window — policy compliance is regressing; audit recently merged PRs.
- Any manifest reaching admission control with a violation that should have been caught in CI — indicates a scanner gap or a CI bypass.
- `ci_policy_exceptions_total` for production namespaces — exceptions in production-bound manifests require security review.
- Kyverno admission controller blocking a manifest that passed CI — policy drift; re-sync CI policy files from cluster.

## Expected Behaviour

| Signal | Without CI validation | With CI validation |
|--------|-----------------------|--------------------|
| Manifest with `privileged: true` submitted | Passes PR; bounces at admission (or runs unchallenged if no admission controller) | PR fails with kubesec score below threshold; inline PR annotation |
| Helm chart renders container running as root | Undetected until runtime | `helm template \| conftest` fails policy check in PR |
| Manifest uses deprecated API version | Silent until cluster upgrade; deploy fails | kubeconform catches version incompatibility in PR |
| Image from unapproved registry | Admitted; image pulled from external source | Conftest registry allowlist policy blocks PR |
| Admission controller policy updated without updating CI | CI passes; deploy bounces | Kyverno CLI uses same policy YAML as cluster; CI and admission in sync |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Multiple tools (kubesec + Trivy + Conftest + Kyverno) | Complementary coverage; different rule sets catch different issues | Longer CI runtime; more maintenance | Parallelise jobs; start with two tools and add others incrementally |
| Scanning rendered Helm output | Catches values-dependent misconfigurations | Requires production values to be checked in or generated | Store non-secret values in values-prod.yaml; inject secrets at deploy time |
| Kyverno CLI using cluster policy files | Zero policy drift between CI and admission | Requires policy files to be versioned with application code | Store policies in the same repo or a pinned submodule |
| Progressive warn-before-enforce rollout | Avoids big-bang PR failure on day one | Warn phase gives false sense of safety if not time-bounded | Set a calendar deadline for Phase 3 enforcement; track violation count trend |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Tool version mismatch between CI and cluster | CI passes; cluster admission rejects | Manifest reaches cluster and fails | Pin tool versions in CI workflow; match Kyverno CLI to cluster controller version |
| Conftest policy has incorrect Rego logic | Violations not detected; policy has no effect | conftest test with known-bad fixture passes unexpectedly | Add negative test fixtures (`conftest verify`) alongside policy files |
| kubeconform schema out of date | New API version accepted as unknown; validation skipped | Schema validation passes a removed API | Pin `-kubernetes-version` to the target cluster version; update on each cluster upgrade |
| Helm values differ between CI and deploy | CI scans dev values; prod values introduce violations | Production deploy bounces at admission | Always scan with the same values file used in production deploys |
| CI validation bypassed via direct push to main | Bad manifest merged without check | Admission controller fires; deploy fails | Enforce branch protection requiring CI checks to pass before merge |

## Related Articles

- [Kyverno Policy Development and Testing](/articles/kubernetes/kyverno-policy-development/)
- [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/)
- [Container Build Hardening](/articles/cicd/container-build-hardening/)
- [Kyverno Policy Development](/articles/kubernetes/kyverno-policy-development/)
- [Validating Admission Policies with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [Artifact Integrity in CI/CD](/articles/cicd/artifact-integrity/)
