---
title: "Argo Workflows Controller DoS: Hardening Against CVE-2026-40886"
description: "CVE-2026-40886 crashes the Argo Workflows controller with a single malformed pod annotation. Learn how the silent-patch pattern enabled this and how to harden your cluster against annotation-injection DoS attacks."
slug: argo-workflows-controller-dos
date: 2026-05-03
lastmod: 2026-05-03
category: cicd
tags:
  - argo-workflows
  - denial-of-service
  - annotation
  - cve
  - controller
personas:
  - platform-engineer
  - security-engineer
article_number: 394
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/cicd/argo-workflows-controller-dos/
---

# Argo Workflows Controller DoS: Hardening Against CVE-2026-40886

## The Problem

CVE-2026-40886 allows any user who can create a pod with the annotation `workflows.argoproj.io/pod-gc-strategy` to crash the Argo Workflows controller permanently, halting every workflow running in the cluster. The crash is immediate, deterministic, and self-reinforcing: the controller restarts, scans existing pods, hits the offending annotation again, and panics again — an infinite crash loop that does not resolve without operator intervention.

The root cause is a one-line indexing error in `podGCFromPod()`, the function responsible for reading the pod garbage-collection strategy from a pod annotation. The annotation is expected to carry a value in the form `OnPodCompletion/3600`, where the string to the left of the `/` is the GC strategy name and the string to the right is a timeout in seconds. The code splits the annotation value on `/` and immediately reads index `[1]`:

```go
parts := strings.SplitN(val, "/", 2)
strategy := parts[0]
ttl, _ := strconv.Atoi(parts[1])   // panics if val contains no "/"
```

If the annotation value is `OnPodCompletion` with no delimiter — a value that looks plausible and passes basic string validation — `parts` has length 1, and reading `parts[1]` is an out-of-bounds access. Go panics. The controller process exits. Kubernetes restarts it. The controller rescans existing pods. It reads the annotation again. It panics again.

The crash loop continues until two things happen: the controller pod is manually terminated, and the pod carrying the malformed annotation is deleted or the annotation is removed. Simply restarting the controller is not enough — the bad pod remains in the cluster's pod history, and the controller will find it again on startup.

The fix is a single bounds check before the index access. It was merged to the `release-3.7` branch and the `main` branch. The corrected releases are Argo Workflows 4.0.5 and 3.7.14.

**The silent-patch pattern.** Argo Workflows has a large security surface area and a high volume of CVE reports. The Argo project team's pattern for lower-severity or straightforward fixes is to merge the correction as a routine patch commit and file the GitHub Security Advisory afterward — sometimes days later. The fix for CVE-2026-40886 landed in `release-3.7` before the advisory `GHSA-xxxx` was published. Operators watching GitHub release notes, the Argo changelog, or diff-monitoring their pinned branches would have seen an inconspicuous one-line patch to `workflow_controller.go`. Operators who rely exclusively on dependency scanners and CVE feeds would have seen nothing until the advisory was filed.

This pattern is not unique to Argo. Projects with high CVE volume — Kubernetes, containerd, various CNCF operators — sometimes merge security fixes as ordinary patches to reduce the overhead of coordinated disclosure. The practical consequence is that a researcher watching commits may know about a vulnerability weeks before the broader operator community does. For a DoS with no exploit code required beyond a valid annotation value, that window matters: the information asymmetry is already closed the moment anyone reads the diff.

The implications for operators are two-fold. First, pinned version upgrades driven solely by CVE scanner alerts will lag behind actual fix availability. Second, admission controls that validate annotation values are a meaningful defense-in-depth layer independent of patch cadence — they block the attack vector before the controller ever sees the annotation.

## Threat Model

The vulnerability requires no special cluster access beyond what ordinary workflow users already have.

Any workflow submitter — a developer running `argo submit`, a CI bot with a service account, an automated deployment pipeline — can include a `workflows.argoproj.io/pod-gc-strategy` annotation in a workflow template's pod metadata. Argo Workflows passes that annotation to the pods it creates. The controller reads the annotation during pod GC evaluation. A malformed value crashes the controller.

An external attacker who can reach an exposed Argo Workflows API server — for example, one without IP allowlisting or authentication enforcement — can submit a workflow as an unauthenticated or low-privilege user and achieve the same effect. The Argo Workflows API server is not always treated with the same network isolation as the Kubernetes API server.

The impact is a full workflow halt. Argo Workflows is commonly the critical path for CI/CD pipelines: image builds, test runs, deployment workflows, data engineering jobs. A controller crash loop freezes all of these simultaneously. In clusters where Argo orchestrates production deployments, the DoS is equivalent to a deploy freeze — no new versions can be rolled out, no rollbacks can be executed through the standard pipeline. Recovery requires a human operator with cluster access to delete the offending pod and restart the controller, which may take ten minutes or considerably longer if the on-call rotation is slow to engage.

Pods from already-completed workflows are not exempt. If a pod from a finished workflow carries the malformed annotation — perhaps injected weeks ago by a misconfigured workflow template — it remains in the cluster's pod records and will continue to crash the controller on every restart. The attacker need not submit a new workflow; the damage can persist indefinitely from a single historical submission.

Affected versions: 3.6.5 through 4.0.4, and 3.7.0 through 3.7.13.

## Hardening Configuration

### 1. Upgrade to the Patched Release

The authoritative fix is upgrading to Argo Workflows 4.0.5 or 3.7.14. Check the currently installed version before planning the upgrade window:

```bash
kubectl get deployment workflow-controller -n argo \
  -o jsonpath='{.spec.template.spec.containers[0].image}'

kubectl get pods -n argo -l app=workflow-controller \
  -o jsonpath='{.items[0].spec.containers[0].image}'
```

For Helm-managed installations:

```bash
helm list -n argo
helm get values argo-workflows -n argo
```

Before upgrading, check for pods with the malformed annotation. If any exist, delete them first — upgrading the controller without removing the offending pods means the patched controller will log a warning rather than panic, but the annotation remains a latent issue and could become a problem again if the bounds check is ever regressed:

```bash
kubectl get pods -A \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.annotations.workflows\.argoproj\.io/pod-gc-strategy}{"\n"}{end}' \
  | grep -v $'\t$' \
  | awk -F'\t' '$3 !~ /\//  && $3 != "" {print "BAD ANNOTATION: " $1 "/" $2 " => " $3}'
```

### 2. RBAC — Restrict Workflow Submission

Limit which service accounts and users can submit workflows. A developer who cannot submit workflows cannot inject annotations. Create explicit Roles rather than binding broad cluster permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: workflow-submitter
  namespace: argo-workflows
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["workflows"]
    verbs: ["create", "get", "list", "watch"]
  - apiGroups: ["argoproj.io"]
    resources: ["workflowtemplates", "clusterworkflowtemplates"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: workflow-controller-operator
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["workflows", "workflowtemplates", "cronworkflows"]
    verbs: ["get", "list", "watch", "update", "patch", "delete"]
  - apiGroups: ["argoproj.io"]
    resources: ["workflows/status", "workflows/finalizers"]
    verbs: ["update", "patch"]
  - apiGroups: [""]
    resources: ["pods", "pods/exec", "pods/log"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
```

Bind the submitter Role only to specific service accounts, not to broad groups:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ci-workflow-submitter
  namespace: argo-workflows
subjects:
  - kind: ServiceAccount
    name: ci-pipeline-sa
    namespace: ci-system
roleRef:
  kind: Role
  name: workflow-submitter
  apiGroup: rbac.authorization.k8s.io
```

### 3. Kyverno Annotation Validation Webhook

An admission webhook that rejects pods with a malformed `workflows.argoproj.io/pod-gc-strategy` annotation stops the attack before the controller sees it, regardless of whether the controller is patched. This is defense in depth: the patch fixes the crash; the webhook removes the attack vector entirely.

The valid annotation format is `<StrategyName>/<ttl-seconds>`, where strategy names are `OnPodCompletion`, `OnPodSuccess`, `OnWorkflowCompletion`, and `OnWorkflowSuccess`. The following Kyverno ClusterPolicy enforces that if the annotation is present, it must match this pattern:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: validate-argo-pod-gc-strategy
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: check-pod-gc-strategy-annotation
      match:
        any:
          - resources:
              kinds: ["Pod"]
      preconditions:
        all:
          - key: "{{ request.object.metadata.annotations.\"workflows.argoproj.io/pod-gc-strategy\" || '' }}"
            operator: NotEquals
            value: ""
      validate:
        message: >
          The annotation workflows.argoproj.io/pod-gc-strategy must be in the
          format <Strategy>/<ttl-seconds>, e.g. OnPodCompletion/3600.
          Value '{{ request.object.metadata.annotations."workflows.argoproj.io/pod-gc-strategy" }}'
          is invalid.
        pattern:
          metadata:
            annotations:
              workflows.argoproj.io/pod-gc-strategy: "?(OnPodCompletion|OnPodSuccess|OnWorkflowCompletion|OnWorkflowSuccess)/[0-9]+"
```

Set `validationFailureAction: Enforce` — not `Audit`. In `Audit` mode, invalid annotations are logged but the pod is admitted. The controller still receives the malformed annotation and, on an unpatched version, still crashes.

### 4. Controller Restart Policy and Crash Loop Alerting

The controller deployment should have `restartPolicy: Always` (the default for Deployments) and a readiness probe. Without a readiness probe, Kubernetes marks the restarting controller as Ready between crashes, and alerting based on pod readiness will miss the crash loop. Add a liveness and readiness probe:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: workflow-controller
  namespace: argo
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: workflow-controller
          image: quay.io/argoproj/workflow-controller:v4.0.5
          livenessProbe:
            httpGet:
              path: /healthz
              port: 6060
            initialDelaySeconds: 30
            periodSeconds: 20
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: 6060
            initialDelaySeconds: 10
            periodSeconds: 10
            failureThreshold: 3
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
```

Add a Prometheus alerting rule for crash loop rate. A controller that crashes more than twice in five minutes is in a crash loop:

```yaml
groups:
  - name: argo-workflows-controller
    rules:
      - alert: ArgoWorkflowControllerCrashLoop
        expr: |
          increase(kube_pod_container_status_restarts_total{
            namespace="argo",
            pod=~"workflow-controller-.*"
          }[5m]) > 2
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Argo Workflows controller is crash-looping"
          description: >
            The workflow controller in namespace {{ $labels.namespace }} has
            restarted more than twice in 5 minutes. All workflows are halted.
            Check for pods with a malformed workflows.argoproj.io/pod-gc-strategy
            annotation.
```

### 5. Namespace Isolation with Argo Namespaced Mode

Argo Workflows supports a namespaced installation mode where each namespace runs its own controller instance, scoped to that namespace. A controller crash in one namespace does not halt workflows in others. This is the most effective architectural isolation for multi-team clusters.

Deploy a namespaced controller per team or trust boundary:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: workflow-controller
  namespace: team-a-workflows
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: workflow-controller
          image: quay.io/argoproj/workflow-controller:v4.0.5
          args:
            - "--namespaced"
            - "--managed-namespace"
            - "team-a-workflows"
          env:
            - name: LEADER_ELECTION_NAMESPACE
              value: team-a-workflows
```

With namespaced mode, a malformed annotation submitted by a user in `team-a-workflows` crashes only the `team-a-workflows` controller. The `team-b-workflows` controller continues running. Cluster-wide operational continuity is preserved while the affected namespace is quarantined and recovered.

## Expected Behaviour After Hardening

**After patching to 4.0.5 / 3.7.14.** Submit a workflow with a malformed `pod-gc-strategy` annotation:

```bash
argo submit -n argo-workflows - <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata:
  generateName: gc-test-
spec:
  entrypoint: main
  podMetadata:
    annotations:
      workflows.argoproj.io/pod-gc-strategy: "OnPodCompletion"
  templates:
    - name: main
      container:
        image: alpine:3.19
        command: [sh, -c, "echo done"]
EOF
```

On the patched controller, the log output shows a warning rather than a panic:

```
level=warning msg="invalid pod-gc-strategy annotation, missing delimiter" pod=gc-test-abc12 annotation=OnPodCompletion
```

The controller continues running. No crash. No restart.

**With the Kyverno ClusterPolicy active.** Attempt to create a pod directly with the malformed annotation:

```bash
kubectl run test-pod -n argo-workflows \
  --image=alpine:3.19 \
  --annotations='workflows.argoproj.io/pod-gc-strategy=OnPodCompletion'
```

The admission webhook rejects the request before the pod is created:

```
Error from server: admission webhook "validate.kyverno.svc" denied the request:
resource Pod/argo-workflows/test-pod was blocked due to the following policies
validate-argo-pod-gc-strategy:
  check-pod-gc-strategy-annotation: The annotation workflows.argoproj.io/pod-gc-strategy
  must be in the format <Strategy>/<ttl-seconds>, e.g. OnPodCompletion/3600.
  Value 'OnPodCompletion' is invalid.
```

The controller never receives the annotation. No crash is possible regardless of patch level.

## Trade-offs and Operational Considerations

**Annotation validation webhook latency.** The Kyverno admission webhook adds a round-trip to every pod creation request. For high-throughput Argo workflows that create many short-lived pods, this adds measurable latency to workflow startup. The latency is typically under 10 milliseconds per pod admission when the webhook is co-located in the same cluster. For workflows submitting thousands of pods, the aggregate cost is worth measuring before enabling in production.

**Namespaced controller resource overhead.** Running one controller per namespace multiplies memory and CPU consumption. Each controller instance holds its own watch cache for the pods and workflows in its managed namespace. At 10 namespaces with 100-500 workflows each, the overhead is material. The right sizing decision depends on whether the blast-radius isolation is worth the additional resource cost for your threat model.

**RBAC restriction impact on automated pipelines.** Tightening workflow submission RBAC means that CI service accounts operating with broad permissions will need to be explicitly granted the `workflow-submitter` Role. Any existing automation that submits workflows using default service accounts or cluster-wide permissions will break until the Role and RoleBinding are applied. Plan a grace period for migration, and audit existing service accounts before enforcing the restrictive RBAC.

**Kyverno webhook failure policy.** Kyverno's default `failurePolicy` is `Ignore` for its mutating webhook and configurable for validating webhooks. If the Kyverno webhook pod is unavailable and `failurePolicy` is `Ignore`, pod admissions proceed without validation — the annotation check is skipped, and a malformed annotation can reach the controller. Set the validating webhook's `failurePolicy` to `Fail` for the Argo annotation rule, accepting that Kyverno outages will block pod creation in affected namespaces rather than silently bypass validation.

## Failure Modes

**Patching without removing existing bad-annotation pods.** Upgrading the controller to 4.0.5 or 3.7.14 stops the panic, but the malformed annotation remains on historical pods. If the bounds-check patch is ever reverted — for example, by a botched rollback or a merge conflict — the controller will crash again on those pods. After upgrading, run the annotation audit query from the upgrade section and delete or relabel offending pods to eliminate the latent risk entirely.

**Kyverno webhook in `Ignore` mode.** A validating webhook configured with `failurePolicy: Ignore` is bypassed on webhook timeout. If the Kyverno pod is under memory pressure, restarting, or experiencing network issues, pod admission requests time out and Kubernetes falls back to admitting the pod without validation. The malformed annotation enters the cluster silently. Always set the failure policy for security-critical validation rules to `Fail` and monitor Kyverno availability as a first-class operational metric.

**Not monitoring controller crash loop rate in Prometheus.** The crash loop begins and resolves (through restarts) within seconds for each cycle. Without a Prometheus alert on restart rate, the controller may crash and restart dozens of times before anyone notices. All workflow progress during that window is lost: running pods continue executing but the controller cannot update their status, collect results, or trigger downstream steps. Mean time to detection without monitoring can exceed ten minutes on a quietly-staffed cluster — enough time for deployment pipelines to time out and fail, and for on-call engineers to receive a flood of downstream alerts before the root cause is identified.

## Related Articles

- [Argo CD Security Hardening](/articles/cicd/argocd-security-hardening/)
- [GitOps Security](/articles/cicd/gitops-security/)
- [CI/CD Secret Management](/articles/cicd/cicd-secret-management/)
- [Kubernetes Admission Control](/articles/kubernetes/kubernetes-admission-control/)
- [Kyverno Policy Development](/articles/kubernetes/kyverno-policy-development/)
