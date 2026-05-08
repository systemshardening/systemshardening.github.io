---
title: "Custom CodeQL Queries for Kubernetes Security: Scanning for RBAC Misconfigs, Pod Security Gaps, and Helm Secrets"
description: "The default CodeQL query packs don't cover Kubernetes-specific vulnerabilities — RBAC wildcard rules in Go controller code, unencrypted Kubernetes Secrets in Helm values, privileged container specs baked into application manifests. This guide writes custom CodeQL queries for Kubernetes controllers, operator code, and Helm chart generation that surface misconfigurations at the source code level."
slug: codeql-kubernetes-security-queries
date: 2026-05-08
lastmod: 2026-05-08
category: kubernetes
tags:
  - codeql
  - kubernetes-security
  - sast
  - rbac
  - code-scanning
personas:
  - security-engineer
  - platform-engineer
article_number: 642
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/kubernetes/codeql-kubernetes-security-queries/
---

# Custom CodeQL Queries for Kubernetes Security: Scanning for RBAC Misconfigs, Pod Security Gaps, and Helm Secrets

## Problem

CodeQL's built-in query packs for Go, Java, and Python are written by engineers who understand generic application security — SQL injection, command injection, insecure deserialization, use of weak cryptographic primitives, path traversal. Those queries are well-maintained and catch real bugs. They are also completely blind to Kubernetes-specific failure modes.

When a Go operator constructs an `rbacv1.PolicyRule` with `Verbs: []string{"*"}`, that is not a generic injection vulnerability. CodeQL's default Go pack has no model of the Kubernetes API types, no understanding that `Verbs: []string{"*"}` grants every operation on every resource in the target API group, and no reason to flag it. The same blindspot applies to `v1.SecurityContext` fields, `v1.PodSpec` construction, Helm template generation, and the `client-go` patterns that operators use to create resources at runtime.

This leaves a structural gap. A significant fraction of Kubernetes misconfigurations do not originate in YAML files written by hand — they originate in code. Controllers reconcile cluster state by constructing API objects programmatically. Helm chart generators build templates in Go. GitOps scaffolding tools emit manifests from templates. All of this code can be scanned with CodeQL, but only if someone writes queries that understand Kubernetes semantics.

**Three failure patterns that standard CodeQL misses:**

1. **RBAC escalation in operator code.** An operator author writes a function that generates `ClusterRole` objects for tenant workloads. The function is passed a `permissions` struct. In one code path — the default case when `permissions` is nil — the function falls back to `Verbs: []string{"*"}`. The code ships, the operator runs, every tenant gets a wildcard ClusterRole, and Falco never fires because the operator has permission to create those roles. The bug lives in a Go source file that no admission webhook ever sees.

2. **Privileged mode defaults in Helm chart templates.** A Helm chart has a `values.yaml` that sets `podSecurityContext.privileged: true` as a convenience default for local development. The chart template passes this value through to `securityContext.privileged` without any override guard. The same chart is deployed to production with `helm install --values prod-values.yaml`, but the `prod-values.yaml` was generated from a script that omits `podSecurityContext.privileged`. The default wins. The container runs privileged.

3. **Plaintext secrets in generated Helm values.** A platform tooling repository has a Go function that generates `values.yaml` files from a configuration database and writes them to a Git repository for Flux to apply. The function writes a database password directly into the `values.yaml` as a plain string under a key named `postgresql.password`. The generated `values.yaml` is consumed by a Helm chart that passes `{{ .Values.postgresql.password }}` into a Kubernetes `Secret`'s `data` field — but `Secret.data` requires base64-encoded values, so the chart template base64-encodes it inline with `b64enc`. The actual password is still in cleartext in the `values.yaml` in Git. Kubernetes Secrets are already base64 (not encrypted), so anything in `.Values` is trivially readable.

**Why catching these at code review time matters.** Runtime detection tools — Falco, OPA Gatekeeper admission webhooks, kube-bench — are a necessary layer but a late layer. By the time Falco fires an alert about a privileged container, the container has already started. By the time Gatekeeper rejects a ClusterRole, the CI/CD pipeline has already failed at apply time. Catching the bug in the Go source file or the Helm template at pull request review, before the CI pipeline even reaches the cluster, compresses the time-to-remediation from hours (alert → triage → trace back to source → fix → redeploy) to minutes (pull request comment → fix before merge).

## Threat Model

**Adversary 1 — Developer accidentally generating an overprivileged ClusterRole.** A platform engineer is building an operator that provisions tenant RBAC. They add a helper function with a `default` branch that grants `Verbs: []string{"*"}` to simplify initial testing. They forget to remove it. The PR passes review because reviewers don't trace the code path to the `default` branch. The operator ships. Every tenant namespace it manages has a wildcard ClusterRole bound to the tenant's service account. An attacker who compromises any tenant workload can now read, write, and delete resources cluster-wide in the scoped API group.

**Adversary 2 — Helm chart template conditionally enabling privileged mode with a true default.** A storage plugin chart uses `{{ if .Values.plugin.privileged }}` and the default in `values.yaml` is `true`. The chart is added to an internal Helm repository. Teams that install the chart without overriding the default run privileged containers. An attacker with container escape ability (kernel vulnerability, container runtime CVE) can break out to the node. No admission webhook catches this because the chart ships with valid YAML that passes schema validation and the privileged context is explicitly set.

**Adversary 3 — Go code constructing pod specs without security context.** An operator reconciles `Job` objects for batch workloads. The function that constructs the `PodSpec` never sets `SecurityContext.RunAsNonRoot`. All Jobs run as UID 0 inside the container. An RCE in the batch workload code runs as root, making container escape significantly easier. The operator has been in production for two years and nobody reviewed the `PodSpec` construction code against the CIS Kubernetes Benchmark.

## Configuration / Implementation

### Repository Structure and CodeQL Setup

Custom CodeQL queries live in a QL pack — a directory with a `qlpack.yml` manifest that declares the pack name, version, dependencies, and default suite. For Kubernetes security queries targeting Go and YAML, you need two packs: one for Go queries and one for YAML queries.

```
.github/
  codeql/
    codeql-config.yml
  workflows/
    codeql.yml
codeql/
  kubernetes-go-queries/
    qlpack.yml
    src/
      RbacWildcardRule.ql
      MissingRunAsNonRoot.ql
      PrivilegedContainerGeneration.ql
    test/
      RbacWildcardRule/
        test.go
        RbacWildcardRule.expected
  kubernetes-yaml-queries/
    qlpack.yml
    src/
      HelmSecretPlaintext.ql
    test/
      HelmSecretPlaintext/
        template.yaml
        HelmSecretPlaintext.expected
```

The `qlpack.yml` for the Go query pack:

```yaml
name: myorg/kubernetes-go-queries
version: 1.0.0
dependencies:
  codeql/go-all: "*"
defaultSuiteFile: kubernetes-go-queries.qls
```

The default suite file `kubernetes-go-queries.qls` references all queries:

```yaml
- queries: src
  from: myorg/kubernetes-go-queries
```

The GitHub Actions workflow that runs custom queries alongside the standard CodeQL Go pack:

```yaml
# .github/workflows/codeql.yml
name: CodeQL Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    strategy:
      matrix:
        language: [go]

    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          config-file: .github/codeql/codeql-config.yml

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

The CodeQL configuration file at `.github/codeql/codeql-config.yml` combines the standard pack with the custom pack:

```yaml
# .github/codeql/codeql-config.yml
name: Kubernetes Security CodeQL Config

queries:
  - uses: security-and-quality          # standard Go pack
  - uses: ./codeql/kubernetes-go-queries # custom pack (relative path)

paths-ignore:
  - vendor/
  - "**/*_test.go"                      # exclude test helpers that deliberately construct bad objects
```

---

### Query 1 — Detecting RBAC Wildcard Rules in Go Code

The target is code like this in an operator:

```go
func buildClusterRole(name string, perms *Permissions) *rbacv1.ClusterRole {
    verbs := []string{"get", "list", "watch"}
    if perms == nil {
        verbs = []string{"*"}   // <-- this is the bug
    }
    return &rbacv1.ClusterRole{
        Rules: []rbacv1.PolicyRule{
            {
                Verbs:     verbs,
                Resources: []string{"*"},
                APIGroups: []string{"*"},
            },
        },
    }
}
```

The CodeQL query detects `StringLit` nodes with value `"*"` used in slice literals that are assigned to fields of `rbacv1.PolicyRule` composite literals:

```ql
/**
 * @name RBAC wildcard rule generation
 * @description Detects code that creates RBAC rules with wildcard verbs or resources,
 *              which grants overly broad permissions to the bound subject.
 * @kind problem
 * @problem.severity error
 * @id go/kubernetes-rbac-wildcard
 * @tags security kubernetes rbac
 */
import go

/**
 * Holds if `lit` is a composite literal constructing an rbacv1.PolicyRule.
 */
predicate isPolicyRuleLiteral(CompositeLit lit) {
  lit.getType().(NamedType).getName() = "PolicyRule" and
  lit.getType().(NamedType).getPackage().getPath().matches("%rbac%")
}

/**
 * Holds if `sliceLit` is a slice literal that contains the wildcard string.
 */
predicate containsWildcard(SliceLit sliceLit) {
  exists(StringLit s |
    s = sliceLit.getAnElement() and
    s.getValue() = "*"
  )
}

from CompositeLit policyRule, KeyValueExpr kv, SliceLit verbSlice
where
  isPolicyRuleLiteral(policyRule) and
  kv = policyRule.getAField() and
  kv.getKey().(Ident).getName() in ["Verbs", "Resources", "APIGroups"] and
  verbSlice = kv.getValue() and
  containsWildcard(verbSlice)
select verbSlice,
  "RBAC PolicyRule sets '" + kv.getKey().(Ident).getName() +
  "' to [\"*\"] — grant specific permissions instead of wildcards"
```

This query will also surface cases where the wildcard is conditionally assigned through a variable, as long as the slice literal is inline. For the case where `verbs` is a `var` that might be assigned `[]string{"*"}` in one branch, the query needs data flow.

---

### Query 2 — Missing `runAsNonRoot` in Pod Spec Construction

This query uses CodeQL's data flow library to track `PodSpec` objects from construction site to API call. The simpler version looks for composite literals where no `RunAsNonRoot` field is set:

```ql
/**
 * @name Pod spec constructed without RunAsNonRoot
 * @description A PodSecurityContext or SecurityContext that does not set RunAsNonRoot: true
 *              allows the container to run as root (UID 0).
 * @kind problem
 * @problem.severity warning
 * @id go/kubernetes-missing-run-as-non-root
 * @tags security kubernetes pod-security
 */
import go

/**
 * Holds if `lit` constructs a SecurityContext or PodSecurityContext.
 */
predicate isSecurityContextLiteral(CompositeLit lit) {
  exists(NamedType t | t = lit.getType() |
    t.getName() in ["SecurityContext", "PodSecurityContext"] and
    t.getPackage().getPath().matches("%k8s.io/api/core%")
  )
}

/**
 * Holds if `lit` has a RunAsNonRoot field explicitly set.
 */
predicate setsRunAsNonRoot(CompositeLit lit) {
  exists(KeyValueExpr kv |
    kv = lit.getAField() and
    kv.getKey().(Ident).getName() = "RunAsNonRoot"
  )
}

from CompositeLit sc
where
  isSecurityContextLiteral(sc) and
  not setsRunAsNonRoot(sc)
select sc,
  "SecurityContext constructed without setting RunAsNonRoot — container may run as UID 0"
```

The predicate `isSecurityContextLiteral` narrows to the `k8s.io/api/core/v1` package path to avoid flagging unrelated structs named `SecurityContext` in non-Kubernetes code. Adjust the path match if your codebase vendors Kubernetes at a different module path.

For the data flow variant that catches pod specs assembled across multiple functions, extend the query with `DataFlow::Configuration`:

```ql
import DataFlow

class PodSpecFlow extends DataFlow::Configuration {
  PodSpecFlow() { this = "PodSpecFlow" }

  override predicate isSource(DataFlow::Node src) {
    exists(CompositeLit lit |
      lit.getType().(NamedType).getName() = "PodSpec" and
      src.asExpr() = lit
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(CallExpr call |
      // Matches client.Create(ctx, podSpec) or similar
      call.getAnArgument() = sink.asExpr() and
      call.getCallee().(SelectorExpr).getSelector().getName() in ["Create", "Update", "Patch"]
    )
  }
}
```

The data flow configuration lets you then check whether any `PodSpec` reaching a Kubernetes API call was constructed without `RunAsNonRoot`. This trades query simplicity for coverage of multi-function construction patterns, at the cost of higher analysis time.

---

### Query 3 — Helm Template Plaintext Secrets

YAML CodeQL queries use the `yaml` library. The target is a Helm template like:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
data:
  password: {{ .Values.postgresql.password | b64enc | quote }}
```

The `b64enc` filter encodes at template render time, but the actual value lives in `values.yaml` as plaintext and in Git history. The query targets `Secret` YAML nodes where the `data` field contains a Helm template expression that references `.Values`:

```ql
/**
 * @name Helm Secret data references .Values directly
 * @description A Kubernetes Secret data field populated from .Values passes the value
 *              through base64 encoding but stores it as plaintext in values.yaml and Git.
 *              Use ExternalSecrets or Sealed Secrets instead.
 * @kind problem
 * @problem.severity warning
 * @id yaml/helm-secret-plaintext-values
 * @tags security kubernetes secrets helm
 */
import yaml

from YamlDocument doc, YamlMapping secretRoot, YamlMapping dataMap, YamlScalar dataValue
where
  // Document is a Kubernetes Secret
  secretRoot = doc.getNode() and
  exists(YamlScalar kind |
    kind = secretRoot.lookup("kind") and
    kind.getValue() = "Secret"
  ) and
  // data field exists
  dataMap = secretRoot.lookup("data") and
  // Any value under data contains a .Values reference
  dataValue = dataMap.getAValueNode() and
  dataValue.getValue().matches("%{{ .Values.%")
select dataValue,
  "Helm Secret data field references .Values directly — the plaintext value is stored in values.yaml. " +
  "Use ExternalSecretOperator or SealedSecrets to avoid plaintext secrets in Git."
```

This query will fire on the `b64enc` pattern as well as raw `{{ .Values.foo }}` patterns. That is intentional — base64 encoding is not encryption, and the security concern is about the source value being in `values.yaml`, not about the encoding of the output.

---

### Query 4 — Privileged Container Generation

The target pattern in Go operator code:

```go
func boolPtr(b bool) *bool { return &b }

container := v1.Container{
    SecurityContext: &v1.SecurityContext{
        Privileged: boolPtr(true),
    },
}
```

```ql
/**
 * @name Privileged container security context
 * @description Go code that constructs a container SecurityContext with Privileged set to true.
 *              Privileged containers have unrestricted access to host kernel capabilities.
 * @kind problem
 * @problem.severity error
 * @id go/kubernetes-privileged-container
 * @tags security kubernetes container-security
 */
import go

/**
 * Holds if `call` is a call to a helper like boolPtr(true) or ptr.To(true)
 * that returns *bool pointing to true.
 */
predicate isBoolPtrTrue(CallExpr call) {
  call.getAnArgument().(BoolLit).getBoolValue() = true and
  call.getCallee().(Ident).getName() in ["boolPtr", "BoolPtr", "To", "Bool"]
}

from CompositeLit sc, KeyValueExpr kv
where
  // SecurityContext composite literal
  sc.getType().(NamedType).getName() = "SecurityContext" and
  sc.getType().(NamedType).getPackage().getPath().matches("%k8s.io/api/core%") and
  // Has a Privileged field
  kv = sc.getAField() and
  kv.getKey().(Ident).getName() = "Privileged" and
  // Field value is a call to a bool pointer helper with argument true
  isBoolPtrTrue(kv.getValue())
select kv,
  "Container SecurityContext sets Privileged: true — remove this unless the workload " +
  "is a system daemon with documented kernel access requirements"
```

The `isBoolPtrTrue` predicate covers the most common patterns (`boolPtr`, the `k8s.io/utils/pointer.BoolPtr`, and `ptr.To` from `k8s.io/utils/ptr`). Add additional function names to the `in` list to match your codebase's helper conventions.

---

### Writing and Testing CodeQL Queries

**Development environment.** Install the [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases) and the [CodeQL extension for VS Code](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql). Create a CodeQL database from your Kubernetes operator or chart generator repository:

```bash
codeql database create ./codeql-db \
  --language=go \
  --source-root=. \
  --command="go build ./..."
```

Run a specific query against the database:

```bash
codeql query run \
  --database=./codeql-db \
  ./codeql/kubernetes-go-queries/src/RbacWildcardRule.ql
```

**Unit tests.** Each query should have a test case directory alongside the `.ql` file. The test directory contains a Go source file that exercises both the positive case (code the query should flag) and the negative case (code the query should not flag), plus an `.expected` file listing the expected findings:

```
codeql/kubernetes-go-queries/test/RbacWildcardRule/
  test.go
  RbacWildcardRule.expected
```

The `test.go` file:

```go
package test

import rbacv1 "k8s.io/api/rbac/v1"

// GOOD: specific verbs
func goodRole() *rbacv1.ClusterRole {
    return &rbacv1.ClusterRole{
        Rules: []rbacv1.PolicyRule{
            {Verbs: []string{"get", "list", "watch"}},
        },
    }
}

// BAD: wildcard verbs
func badRole() *rbacv1.ClusterRole {
    return &rbacv1.ClusterRole{
        Rules: []rbacv1.PolicyRule{
            {Verbs: []string{"*"}}, // $ RbacWildcardRule
        },
    }
}
```

The `$ RbacWildcardRule` inline annotation marks the expected finding location. The `.expected` file lists findings in the format CodeQL test output produces. Run tests with:

```bash
codeql test run ./codeql/kubernetes-go-queries/test/RbacWildcardRule/
```

**Evaluating false positive rate.** Run the query against a large Go codebase (the Kubernetes controller-runtime source, or a collection of public operators) and manually inspect the first 50 findings. For the `MissingRunAsNonRoot` query, expect false positives from test helpers, mock objects, and partial constructors that are completed in a separate function. Adjust the query predicates to exclude paths containing `_test.go` suffix, or add a suppression comment convention (`// codeql[go/kubernetes-missing-run-as-non-root]: test helper`).

---

### Integrating Custom Queries into GitHub Advanced Security

**Uploading the query pack to GitHub Packages.** Authenticate the CodeQL CLI against the registry and publish the pack:

```bash
codeql pack publish \
  --registry=https://ghcr.io \
  ./codeql/kubernetes-go-queries/
```

This makes the pack available as `ghcr.io/myorg/kubernetes-go-queries@1.0.0`.

**Referencing the published pack in the CodeQL init step:**

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: go
    packs: |
      security-and-quality
      myorg/kubernetes-go-queries@1.0.0
```

**Per-repository configuration using code scanning configs.** For repositories that should run only a subset of the custom queries (for example, a repository that has no Helm chart generation code and should skip `HelmSecretPlaintext.ql`), create a `.github/codeql/codeql-config.yml` in that repository:

```yaml
name: Kubernetes Security CodeQL Config

queries:
  - uses: security-and-quality
  - uses: myorg/kubernetes-go-queries/src/RbacWildcardRule.ql
  - uses: myorg/kubernetes-go-queries/src/MissingRunAsNonRoot.ql
  - uses: myorg/kubernetes-go-queries/src/PrivilegedContainerGeneration.ql
  # HelmSecretPlaintext excluded — no Helm generation in this repo
```

The init step picks up this file automatically if `config-file: .github/codeql/codeql-config.yml` is set, or if the GitHub Advanced Security default configuration is enabled for the repository.

## Expected Behaviour

| Kubernetes Security Issue | CodeQL Query | Detection Mechanism | False Positive Risk |
|---|---|---|---|
| RBAC wildcard verb in PolicyRule | `RbacWildcardRule.ql` | Composite literal field value matching `"*"` | Low — very specific to `rbacv1.PolicyRule` struct |
| Missing `RunAsNonRoot` in SecurityContext | `MissingRunAsNonRoot.ql` | Absence of `RunAsNonRoot` field in composite literal | Medium — fires on partial constructors and test helpers |
| Helm template `.Values` reference in Secret data | `HelmSecretPlaintext.ql` | YAML scalar value matching `{{ .Values.%` in Secret `data` | Low — specific to `kind: Secret` with data fields |
| Privileged container SecurityContext | `PrivilegedContainerGeneration.ql` | Composite literal `Privileged` field set via `boolPtr(true)` | Low — unless the codebase uses uncommon bool pointer helpers |
| PodSpec reaching API call without SecurityContext | `MissingRunAsNonRoot.ql` (data flow variant) | Data flow from `PodSpec` construction to `client.Create` | High on first run — requires tuning to exclude test paths |

## Trade-offs

**Query writing time investment.** Each query takes a meaningful amount of time to write correctly: understanding the QL type system for Go composite literals, testing against real operator code, calibrating predicates to reduce false positives. Budget 2–4 hours per query for an engineer new to CodeQL QL, dropping to 30–60 minutes per query once the team has written a dozen. The Kubernetes-specific queries in this article are starting points, not production-ready queries — they need testing against your actual codebase.

**False positive rates for structural queries.** The `MissingRunAsNonRoot` query is the most prone to false positives because absence-of-field detection fires on every SecurityContext that doesn't set the field, including test fixtures, partial builders, and structs that are completed downstream. Expect 30–50% false positives on initial run in a mature operator codebase. Accept this as the cost of using absence detection rather than data flow, or invest in the data flow variant which is significantly more expensive to write but has a lower false positive rate.

**Maintaining queries as Kubernetes API versions change.** The Kubernetes Go client package paths change across API versions. A query targeting `k8s.io/api/core/v1` will stop working if the operator migrates to a vendor fork or an alternative client library. Build version-checking into the qlpack CI by running the test suite against a fresh database whenever the `go.mod` Kubernetes dependency version changes. Track the CodeQL Go library release notes for changes to how struct types and package paths are modelled — the underlying QL models occasionally change in ways that break custom queries.

**Query pack distribution overhead.** Maintaining a published CodeQL query pack in GitHub Packages adds an artifact to the organization's registry with versioned releases. This is low operational overhead, but it requires a process: bump the version in `qlpack.yml`, publish the pack, update the pack reference in the repositories that consume it. Treat the query pack like a library: semver, a CHANGELOG, and a test suite that runs in CI.

## Failure Modes

**Queries not finding issues due to indirect construction patterns.** The composite literal queries rely on finding the struct construction inline. If an operator uses a builder pattern — `NewSecurityContext().WithPrivileged(true)` — the queries will not fire. CodeQL's method call tracking can model this, but it requires extending the queries to follow method calls on the builder struct and inspect the final built value. Audit your operator code for builder patterns and constructor functions before concluding the queries provide full coverage.

**CodeQL QL type system limitations for Kubernetes API structs.** CodeQL models Go types by package path and struct name. When code uses `interface{}` or `runtime.Object` to hold Kubernetes API objects (common in generic controller code and admission webhook handlers), the type predicates in these queries will not resolve correctly. The query sees an `interface{}` value being passed to the API, not a concrete `PodSpec`. This is a structural limitation: CodeQL's Go type analysis handles concrete types well but loses type information at interface boundaries. For controller-runtime controllers that use `client.Object`, the actual concrete type is only recoverable through more sophisticated type flow analysis.

**Query performance timeout on large codebases.** The data flow variant of `MissingRunAsNonRoot` can time out on large operator repositories (100k+ lines of Go) if the `isSource` and `isSink` predicates are too broad. CodeQL imposes a default query timeout of 15 minutes in GitHub Actions. If a query consistently times out, restrict the source predicate to specific packages (`src.getFile().getRelativePath().matches("pkg/controllers/%")`), add `isBarrier` predicates to stop data flow at function boundaries you know are safe, or fall back to the simpler composite literal version which does not use data flow and has much lower analysis cost.

**Silent failures in YAML queries.** CodeQL YAML analysis depends on the file being valid, parseable YAML. Helm templates with complex Go template syntax (`{{- range .Values.items }}`) can produce YAML that is not valid before template rendering. CodeQL will skip these files silently. For repositories where all YAML files are Helm templates (as opposed to rendered output), consider running the YAML queries against rendered Helm output (`helm template .`) rather than the raw templates. This requires a build step in the GitHub Actions workflow before the CodeQL analyze step.
