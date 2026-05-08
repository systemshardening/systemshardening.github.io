---
title: "Kyverno Policy Development and Testing: Validate, Mutate, and Generate"
description: "Kyverno enforces Kubernetes security policy as YAML. Writing effective validate, mutate, and generate policies — and testing them with Chainsaw — turns admission control from a checkpoint into a continuous guardrail."
slug: "kyverno-policy-development"
date: 2026-04-30
lastmod: 2026-04-30
category: "kubernetes"
tags: ["kyverno", "policy", "admission-control", "validation", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 272
difficulty: "intermediate"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/kubernetes/kyverno-policy-development/index.html"
---

# Kyverno Policy Development and Testing: Validate, Mutate, and Generate

## Problem

Kubernetes admission control stops misconfigured workloads at deployment time. Kyverno implements admission control as YAML policies — no Rego, no webhooks to write, no custom controllers. A security engineer who understands Kubernetes YAML can write Kyverno policies without learning a new programming language.

But effective Kyverno policy authorship requires understanding several non-obvious behaviours:

- **Validate vs enforce.** A `ClusterPolicy` with `validationFailureAction: Audit` logs violations but never blocks anything. Teams often deploy in Audit mode and never flip to Enforce, so the policy provides no actual protection.
- **Pattern matching subtleties.** Kyverno patterns match using an `anchor` system. `?(key): value` is a conditional anchor (only match if the key exists). `^(key): value` is a negation anchor. Getting these wrong produces silent non-enforcement.
- **Context and variables.** Policies that reference `request.object` vs `request.oldObject` behave differently on creates vs updates. Policies that use `context.variables` for external data lookups require understanding Kyverno's JMESPath implementation.
- **Mutation ordering.** Multiple mutate rules apply in sequence. A later rule can undo what an earlier one set. Order matters.
- **Testing is skipped.** Most teams write policies and test by trying to deploy a bad workload manually. This misses edge cases, doesn't catch regressions when policies are updated, and doesn't verify that the policy fires for all intended resource types.

**Target systems:** Kyverno 1.12+; Kubernetes 1.28+; Chainsaw 0.1.9+ (Kyverno's E2E testing tool); kyverno CLI 1.12+ (local policy testing without a cluster).

## Threat Model

- **Adversary 1 — Policy in Audit mode only:** A policy exists to block privileged containers. It was deployed in Audit mode for testing and never switched to Enforce. A developer deploys a privileged container; the policy logs a violation but the container runs.
- **Adversary 2 — Pattern mismatch bypasses policy:** A validate policy checks `spec.containers[*].securityContext.privileged == false`. An attacker deploys a pod with `securityContext.privileged: null` (absent, not false). The pattern match fails to catch the omission.
- **Adversary 3 — Kyverno webhook unavailable:** The Kyverno admission webhook is down during a deployment. If `failurePolicy: Ignore` is set, all admission requests are allowed through. The policy provides no protection during Kyverno downtime.
- **Adversary 4 — Namespace exemption too broad:** A policy excludes namespaces labelled `policy-exempt: true`. A developer adds that label to a production namespace to unblock a deployment, permanently exempting it.
- **Adversary 5 — Generate policy creates overpermissive defaults:** A Kyverno generate rule creates a default NetworkPolicy for new namespaces. The generated policy is overly permissive; all new namespaces inherit a weak posture.
- **Access level:** Adversaries 1–4 have developer access to deploy workloads or modify namespace labels. Adversary 5 is a Kyverno misconfiguration affecting all new namespaces.
- **Objective:** Deploy non-compliant workloads, bypass admission controls, inherit weak security defaults.
- **Blast radius:** An audit-mode-only policy provides zero protection. A misconfigured pattern match leaves the intended gap open. Kyverno in Ignore failure mode means any Kyverno outage = open admission.

## Configuration

### Step 1: Install Kyverno with HA and Fail-Closed

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

helm install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace \
  --set replicaCount=3 \                  # HA: 3 admission controller replicas.
  --set admissionController.replicas=3 \
  --set backgroundController.replicas=2 \
  --set webhookFailurePolicy=Fail \       # CRITICAL: fail-closed if Kyverno is unavailable.
  --set webhookTimeout=15 \               # 15s timeout before failing.
  --set "features.policyExceptions.enabled=true"  # Enable structured exceptions.
```

`webhookFailurePolicy=Fail` means if Kyverno's webhook is unreachable, admission requests are denied rather than allowed. This is the secure default for production.

Verify the webhook is configured correctly:

```bash
kubectl get validatingwebhookconfigurations kyverno-resource-validating-webhook-cfg \
  -o jsonpath='{.webhooks[0].failurePolicy}'
# Expected: Fail
```

### Step 2: Validate Policy — Blocking Privileged Containers

A complete, production-grade validate policy catches both explicit and implicit privileged access:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
  annotations:
    policies.kyverno.io/title: Disallow Privileged Containers
    policies.kyverno.io/description: >
      Privileged containers share the host kernel namespaces and have full
      access to host resources. This policy blocks privileged containers
      and privilege escalation.
spec:
  validationFailureAction: Enforce   # Not Audit — actually blocks.
  background: true                   # Also check existing resources.
  rules:
    - name: no-privileged
      match:
        any:
          - resources:
              kinds: [Pod]
      exclude:
        any:
          - resources:
              namespaces: [kyverno, kube-system]   # Minimal exemptions only.
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            containers:
              # =(key) is a conditional anchor: only check if the key exists.
              # Without this, a missing securityContext would match.
              - =(securityContext):
                  =(privileged): "false | null"
                  =(allowPrivilegeEscalation): "false | null"
            initContainers:
              - =(securityContext):
                  =(privileged): "false | null"
                  =(allowPrivilegeEscalation): "false | null"
            ephemeralContainers:
              - =(securityContext):
                  =(privileged): "false | null"

    - name: require-drop-all
      match:
        any:
          - resources:
              kinds: [Pod]
      exclude:
        any:
          - resources:
              namespaces: [kyverno, kube-system]
      validate:
        message: "Containers must drop ALL capabilities."
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.containers[].securityContext.capabilities.drop[] | contains(@, 'ALL') }}"
                operator: Equals
                value: false
```

### Step 3: Mutate Policy — Enforcing Defaults

Mutate policies add or overwrite fields at admission time, ensuring defaults are applied even when developers omit them:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: add-default-security-context
spec:
  rules:
    - name: set-security-defaults
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      mutate:
        patchStrategicMerge:
          spec:
            securityContext:
              # Set defaults that developers frequently omit.
              # Only sets if not already specified (strategic merge semantics).
              runAsNonRoot: true
              seccompProfile:
                type: RuntimeDefault
            containers:
              - (name): "*"   # Apply to all containers.
                securityContext:
                  allowPrivilegeEscalation: false
                  readOnlyRootFilesystem: true
                  capabilities:
                    drop: [ALL]
```

Mutate with JMESPath for conditional logic:

```yaml
    - name: add-resource-limits-if-missing
      match:
        any:
          - resources:
              kinds: [Pod]
      preconditions:
        any:
          # Only apply if at least one container is missing resource limits.
          - key: "{{ request.object.spec.containers[?!resources.limits] | length(@) }}"
            operator: GreaterThan
            value: "0"
      mutate:
        foreach:
          - list: "request.object.spec.containers"
            patchStrategicMerge:
              spec:
                containers:
                  - name: "{{ element.name }}"
                    resources:
                      limits:
                        memory: "512Mi"
                        cpu: "500m"
```

### Step 4: Generate Policy — Secure Defaults for New Namespaces

Generate policies create resources in response to other resource creation:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: generate-default-network-policy
spec:
  rules:
    - name: default-deny-all
      match:
        any:
          - resources:
              kinds: [Namespace]
      exclude:
        any:
          - resources:
              names: [kube-system, kyverno, monitoring]
      generate:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        name: default-deny-all
        namespace: "{{ request.object.metadata.name }}"
        synchronize: true   # Keep generated resource in sync if policy changes.
        data:
          spec:
            podSelector: {}    # Applies to all pods in the namespace.
            policyTypes: [Ingress, Egress]
            # Empty Ingress/Egress = deny all by default.

    - name: default-allow-dns
      match:
        any:
          - resources:
              kinds: [Namespace]
      exclude:
        any:
          - resources:
              names: [kube-system, kyverno, monitoring]
      generate:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        name: allow-dns-egress
        namespace: "{{ request.object.metadata.name }}"
        synchronize: true
        data:
          spec:
            podSelector: {}
            policyTypes: [Egress]
            egress:
              - to:
                  - namespaceSelector:
                      matchLabels:
                        kubernetes.io/metadata.name: kube-system
                ports:
                  - port: 53
                    protocol: UDP
```

### Step 5: Testing with the Kyverno CLI

Test policies without a cluster:

```bash
# Install Kyverno CLI.
curl -LO https://github.com/kyverno/kyverno/releases/latest/download/kyverno_linux_amd64.tar.gz
tar xzf kyverno_linux_amd64.tar.gz && mv kyverno /usr/local/bin/

# Test a policy against a resource file.
kyverno apply disallow-privileged.yaml --resource pod-privileged.yaml
# Output: PASS count: 0, FAIL count: 1
# [pod-privileged] policy/disallow-privileged-containers/no-privileged FAIL

# Test against a directory of resources.
kyverno apply policies/ --resource resources/

# Test with generate (shows what would be created).
kyverno apply generate-netpol.yaml --resource namespace.yaml
```

### Step 6: Integration Testing with Chainsaw

Chainsaw runs Kyverno policies against a real cluster with declarative test scenarios:

```bash
# Install Chainsaw.
go install github.com/kyverno/chainsaw@latest

# Directory structure for a policy test.
# tests/
#   disallow-privileged/
#     chainsaw-test.yaml
#     manifests/
#       bad-pod.yaml       (should be blocked)
#       good-pod.yaml      (should be allowed)
```

```yaml
# tests/disallow-privileged/chainsaw-test.yaml
apiVersion: chainsaw.kyverno.io/v1alpha1
kind: Test
metadata:
  name: disallow-privileged-containers
spec:
  steps:
    - name: apply-policy
      try:
        - apply:
            file: ../../../../policies/disallow-privileged.yaml

    - name: test-privileged-pod-blocked
      try:
        - apply:
            file: manifests/bad-pod.yaml
            expect:
              - match:
                  apiVersion: v1
                  kind: Pod
                check:
                  ($error != null): true   # Expect the apply to fail.

    - name: test-compliant-pod-allowed
      try:
        - apply:
            file: manifests/good-pod.yaml
        - assert:
            file: manifests/good-pod.yaml

    - name: cleanup
      try:
        - delete:
            file: ../../../../policies/disallow-privileged.yaml
```

```bash
# Run all tests.
chainsaw test tests/

# Output:
# Running tests...
# PASS: disallow-privileged-containers/test-privileged-pod-blocked
# PASS: disallow-privileged-containers/test-compliant-pod-allowed
```

Add Chainsaw tests to CI:

```yaml
# .github/workflows/kyverno-test.yml
name: Kyverno Policy Tests

on:
  push:
    paths: ["kyverno/policies/**", "kyverno/tests/**"]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Create kind cluster
        uses: helm/kind-action@v1

      - name: Install Kyverno
        run: |
          helm install kyverno kyverno/kyverno -n kyverno --create-namespace \
            --set webhookFailurePolicy=Fail

      - name: Run Chainsaw tests
        run: chainsaw test kyverno/tests/ --parallel 4
```

### Step 7: Policy Exceptions — Structured Override

Never use broad namespace exemptions. Use `PolicyException` for specific, auditable overrides:

```yaml
# PolicyException: allow a specific legacy workload to use a privileged container.
apiVersion: kyverno.io/v2beta1
kind: PolicyException
metadata:
  name: legacy-monitoring-agent-exception
  namespace: monitoring   # Exception is namespace-scoped.
  annotations:
    # Justification is mandatory — document why the exception exists.
    policy.exception/justification: >
      The legacy-monitoring-agent requires host PID access for metrics collection.
      Migration to the new agent is tracked in ticket MON-1234.
      Exception expires: 2026-12-01.
    policy.exception/approved-by: "security-team@example.com"
    policy.exception/expires: "2026-12-01"
spec:
  exceptions:
    - policyName: disallow-privileged-containers
      ruleNames:
        - no-privileged
  match:
    any:
      - resources:
          kinds: [Pod]
          names: [legacy-monitoring-agent-*]
          namespaces: [monitoring]
```

Audit all PolicyExceptions periodically:

```bash
kubectl get policyexceptions -A -o json | jq '
  .items[] | {
    name: .metadata.name,
    namespace: .metadata.namespace,
    policy: .spec.exceptions[].policyName,
    justification: .metadata.annotations["policy.exception/justification"],
    expires: .metadata.annotations["policy.exception/expires"]
  }'
```

### Step 8: Telemetry

```
kyverno_policy_results_total{policy, rule, resource_namespace, result}   counter
kyverno_admission_requests_total{resource_kind, operation, result}       counter
kyverno_policy_execution_duration_seconds{policy, rule}                  histogram
kyverno_exceptions_used_total{policy, exception}                         counter
kyverno_controller_reconcile_errors_total                                counter
```

Alert on:

- `kyverno_policy_results_total{result="fail"}` in namespaces where Enforce is expected — someone deployed a non-compliant resource; investigate.
- `kyverno_controller_reconcile_errors_total` non-zero — Kyverno controller is failing; policies may not be applied correctly.
- `kyverno_exceptions_used_total` increasing — exceptions are accumulating; trigger a review.
- Kyverno pods `NotReady` — webhook unavailable; with `failurePolicy=Fail`, all admission requests blocked; urgent.

## Expected Behaviour

| Signal | No Kyverno | Kyverno Audit mode | Kyverno Enforce mode |
|--------|-----------|-------------------|---------------------|
| Privileged container deployed | Allowed | Allowed; violation logged | Blocked; error returned to kubectl |
| Missing resource limits | Allowed | Allowed (violation logged if validate rule) | Set to defaults by mutate rule |
| New namespace created | No default NetworkPolicy | No default NetworkPolicy | NetworkPolicy generated automatically |
| Kyverno webhook down | N/A | All requests allowed (Ignore failurePolicy) | All requests denied (Fail failurePolicy) |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `webhookFailurePolicy=Fail` | No bypass during Kyverno downtime | Kyverno downtime blocks all admission | Run 3 HA replicas; monitor Kyverno pod health with priority alerting. |
| `validationFailureAction: Enforce` | Actually blocks non-compliant workloads | Breaks existing non-compliant workloads on first deploy | Use Audit mode to discover violations; fix before switching to Enforce. |
| Generate with `synchronize: true` | Generated resources stay in sync with policy | Policy change propagates to all existing namespaces | Test policy changes in staging; use `synchronize: false` for break-glass scenarios. |
| PolicyException over namespace exemption | Auditable; specific; time-bounded | More effort than adding a namespace label | The overhead is the point — exceptions should require effort. |
| Chainsaw E2E tests | Catches regression in policy logic | Requires a cluster (even kind) | Use kind in CI; fast spin-up (~60s). |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Kyverno pod OOMKilled | Webhook becomes unavailable | `kyverno_controller_reconcile_errors_total`; pods restarting | Increase Kyverno memory limits; large clusters need more resources. |
| Pattern anchor mismatch | Policy does not block the intended configuration | Chainsaw test reveals the gap | Fix the anchor syntax; use `kyverno apply` locally to test specific resources. |
| `synchronize: true` deletes a manually-created resource | A manually created NetworkPolicy is deleted when Kyverno generates one | Resource disappears; application connectivity breaks | Check `synchronize: true` policies after any generate-policy change. |
| Exception not expired when due | Expired exception still grants access | PolicyException list shows past `expires` annotation | Automate exception expiry checks via a weekly job; delete or renew exceptions on schedule. |
| Mutate rule breaks existing workload | Pod fails health check after mutation changes a setting | Pod fails; logs show unexpected configuration | Add `preconditions` to the mutate rule; only apply when a specific condition is met. |

## Related Articles

- [Kubernetes Admission Control and OPA/Gatekeeper](/articles/kubernetes/kubernetes-admission-control/)
- [Validating Admission Policy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [Pod Security Context and Seccomp Profiles](/articles/kubernetes/seccomp-profiles/)
- [Cilium Network Policy](/articles/kubernetes/cilium-network-policy/)
