---
title: "Mythos and the Vulnerability Classes AI Finds First: Eliminating Your Highest-Risk Attack Surface"
description: "Frontier AI models like Anthropic's Mythos find vulnerability classes that traditional scanners miss: logic flaws, implicit trust, hardcoded secrets, configuration drift. The defensive response is not faster patching. It is eliminating these classes before they are discovered."
slug: "mythos-proactive-attack-surface-reduction"
date: 2026-04-23
lastmod: 2026-04-23
category: "ai-landscape"
tags: ["ai-security", "mythos", "attack-surface", "hardening", "secrets-management", "network-policy", "opa", "gatekeeper"]
personas: ["security-engineer", "platform-engineer", "sre"]
article_number: 153
difficulty: "advanced"
estimated_reading_time: 22
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
  - name: "Wiz"
    id: 155
    category: "cloud-security"
  - name: "HashiCorp Vault"
    id: 65
    category: "secrets"
  - name: "Styra"
    id: 156
    category: "policy-engine"
premium_pack: "ai-attack-surface-reduction"
published: true
layout: article.njk
permalink: "/articles/ai-landscape/mythos-proactive-attack-surface-reduction/index.html"
---

# Mythos and the Vulnerability Classes AI Finds First: Eliminating Your Highest-Risk Attack Surface

## Problem

[Anthropic](https://www.anthropic.com) announced that [Mythos](https://www.anthropic.com), their frontier AI model, is significantly better at discovering cyber vulnerabilities than any previous AI system. This is not incremental improvement. Mythos identifies vulnerability classes that traditional static analysis, dynamic testing, and even prior AI models consistently miss: logic flaws in authentication flows, implicit trust assumptions between services, hardcoded credentials buried in configuration, race conditions in concurrent code, and misconfigured default-allow network policies that expose internal services.

The standard defensive response to faster vulnerability discovery is faster patching (see [AI-Powered Vulnerability Discovery: What Automated Code Analysis Means for Your Patch Cycle](/articles/ai-landscape/ai-vulnerability-discovery/)). That response is necessary but insufficient. Patching faster treats the symptom. The systemic response is eliminating the vulnerability classes that AI finds most effectively, so that when Mythos (or an adversary using equivalent capability) examines your infrastructure, the most dangerous classes of finding simply do not exist.

This article covers proactive attack surface reduction: eliminating the six vulnerability classes that frontier AI models discover with the highest reliability and the greatest impact.

### The six classes AI finds first

1. **Hardcoded secrets and credentials** in source code, configuration files, and container images. AI models parse entire repositories contextually and identify secrets that regex-based scanners miss (e.g., API keys constructed from concatenated variables, credentials in test fixtures that mirror production values).
2. **Implicit trust between services.** Default-allow network policies, services that accept unauthenticated requests from within the cluster, and internal APIs that assume callers are trusted because they are "internal."
3. **Configuration drift from security baselines.** Infrastructure that was hardened at deployment but has drifted over time: disabled audit logging, relaxed RBAC permissions added during incident response and never reverted, debug endpoints left enabled.
4. **Unnecessary attack surface.** Services exposing admin interfaces, debug endpoints, health check pages with detailed system information, unnecessary ports, and development tooling left in production images.
5. **Input validation gaps at system boundaries.** AI models trace data flow from ingress to processing and identify where untrusted input reaches sensitive operations without validation, sanitisation, or type enforcement.
6. **Dependency chains with transitive vulnerabilities.** AI models map the full dependency graph and identify paths where a vulnerability in a transitive dependency is reachable from application code, not just present in the tree.

## Threat Model

- **Adversary:** Any attacker with access to frontier AI models (commercial API access or self-hosted open-weight models). This is not limited to nation-state actors. The cost of running AI-assisted vulnerability discovery against a target is measured in tens of dollars, not thousands.
- **Access level:** External. The adversary examines publicly accessible code repositories, scans exposed services, analyses container images pulled from public registries, and probes network boundaries. No initial foothold required for discovery of most vulnerability classes.
- **Objective:** Identify exploitable vulnerabilities in the target's infrastructure faster than the target can find and fix them. AI reduces the cost and time of discovery to near zero for the classes listed above.
- **Blast radius:** Depends on the vulnerability class. Hardcoded credentials provide direct access to the systems those credentials protect. Implicit trust between services enables lateral movement from any compromised service to every service that trusts it. Configuration drift creates gaps in detection and audit coverage that mask post-compromise activity.

**The key shift:** The question is no longer "will someone find this?" It is "how quickly will AI find this?" For the six classes above, the answer is minutes.

## Configuration

### 1. Eliminate Hardcoded Secrets

Secrets in source code are the highest-signal finding for AI models. Every hardcoded credential is a direct path to compromise.

**Scan existing repositories with Gitleaks:**

```bash
# Install Gitleaks
# https://github.com/gitleaks/gitleaks
brew install gitleaks  # macOS
# or: apt-get install gitleaks  # Debian/Ubuntu

# Scan the full git history of a repository
gitleaks detect --source /path/to/repo --verbose --report-format json --report-path gitleaks-report.json

# Scan only staged changes (for pre-commit hook)
gitleaks protect --staged --verbose
```

**Block secrets from entering repositories with a pre-commit hook:**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
```

```bash
# Install and activate pre-commit hooks
pip install pre-commit
pre-commit install
```

**Enforce secret scanning in CI:**

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scan
on:
  push:
    branches: [main]
  pull_request:

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          fetch-depth: 0  # Full history for comprehensive scan

      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Migrate existing secrets to a secrets manager:**

```bash
# Example: migrate a database password from environment variable to Vault
# Step 1: Store the secret in Vault
vault kv put secret/production/database password="$(openssl rand -base64 32)"

# Step 2: Configure application to read from Vault (using vault-agent sidecar in Kubernetes)
```

```yaml
# vault-agent-sidecar.yaml
# Inject secrets from Vault into the application container at runtime.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "app"
        vault.hashicorp.com/agent-inject-secret-db-password: "secret/data/production/database"
        vault.hashicorp.com/agent-inject-template-db-password: |
          {{- with secret "secret/data/production/database" -}}
          {{ .Data.data.password }}
          {{- end -}}
    spec:
      serviceAccountName: app
      containers:
        - name: app
          image: registry.example.com/app:latest
          env:
            - name: DB_PASSWORD_FILE
              value: /vault/secrets/db-password
```

```bash
# Apply the deployment
kubectl apply -f vault-agent-sidecar.yaml
```

### 2. Eliminate Implicit Trust Between Services

Default-allow network policies mean that any compromised service can reach every other service in the cluster. AI models identify these trust relationships by mapping service communication patterns and finding paths from external-facing services to sensitive backends.

**Deploy default-deny network policies:**

```yaml
# default-deny-all-namespaces.yaml
# Apply to every namespace. This blocks all ingress and egress
# unless explicitly allowed by a service-specific policy.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # Applies to all pods in the namespace
  policyTypes:
    - Ingress
    - Egress
  ingress: []   # Deny all ingress
  egress: []    # Deny all egress
```

```yaml
# allow-app-to-database.yaml
# Explicit policy: only the app service can reach the database, on port 5432 only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-database
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: backend
      ports:
        - protocol: TCP
          port: 5432
```

```yaml
# allow-app-egress.yaml
# Explicit egress: app can reach database and DNS only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

```bash
# Apply all network policies
kubectl apply -f default-deny-all-namespaces.yaml
kubectl apply -f allow-app-to-database.yaml
kubectl apply -f allow-app-egress.yaml
```

**Require mutual TLS between services:**

```yaml
# istio-strict-mtls.yaml
# Enforce mTLS for all service-to-service communication.
# No service can communicate without a valid certificate.
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
```

```bash
# Apply mTLS policy
kubectl apply -f istio-strict-mtls.yaml
```

### 3. Detect and Correct Configuration Drift

Infrastructure that was hardened at deployment drifts over time. AI models compare running configurations against known-good baselines and find every deviation. Automated policy enforcement ensures drift is detected and blocked before it reaches production.

**Enforce security baselines with OPA Gatekeeper:**

```yaml
# constraint-template-privileged-containers.yaml
# Block privileged containers in all namespaces except kube-system.
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sBlockPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockprivileged

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged == true
          msg := sprintf("Privileged container not allowed: %v", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          container.securityContext.privileged == true
          msg := sprintf("Privileged init container not allowed: %v", [container.name])
        }
```

```yaml
# constraint-block-privileged.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockPrivileged
metadata:
  name: block-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]
```

```yaml
# constraint-template-required-labels.yaml
# Ensure all deployments have required security labels for policy enforcement.
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        violation[{"msg": msg}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
```

```bash
# Apply Gatekeeper constraint templates and constraints
kubectl apply -f constraint-template-privileged-containers.yaml
kubectl apply -f constraint-block-privileged.yaml
kubectl apply -f constraint-template-required-labels.yaml
```

**Continuous drift detection with scheduled audit:**

```yaml
# .github/workflows/drift-detection.yml
# Run OPA policy checks against live cluster state every 6 hours.
name: Configuration Drift Detection
on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Install conftest
        run: |
          wget -q https://github.com/open-policy-agent/conftest/releases/download/v0.56.0/conftest_0.56.0_Linux_x86_64.tar.gz
          tar xzf conftest_0.56.0_Linux_x86_64.tar.gz
          sudo mv conftest /usr/local/bin/

      - name: Export live cluster state
        run: |
          kubectl get deployments -A -o json > deployments.json
          kubectl get networkpolicies -A -o json > networkpolicies.json
          kubectl get pods -A -o json > pods.json

      - name: Check against security policies
        run: |
          conftest test deployments.json --policy policies/
          conftest test networkpolicies.json --policy policies/
          conftest test pods.json --policy policies/
```

### 4. Remove Unnecessary Attack Surface

Every exposed endpoint, debug interface, and unnecessary service is a target that AI can map and probe. Minimise what exists, not just what is reachable.

**Audit and remove debug endpoints:**

```bash
#!/bin/bash
# audit-debug-endpoints.sh
# Find debug and admin endpoints exposed in Kubernetes services.

echo "=== Services with debug/admin ports ==="
kubectl get services -A -o json | jq -r '
  .items[] |
  select(.spec.ports[]? |
    (.name // "" | test("debug|admin|profiling|pprof|metrics-debug"; "i")) or
    (.port == 6060 or .port == 8081 or .port == 9090 and .name != "prometheus")
  ) |
  "\(.metadata.namespace)/\(.metadata.name): \([.spec.ports[] | "\(.name // "unnamed"):\(.port)"] | join(", "))"
'

echo ""
echo "=== Ingress resources exposing internal paths ==="
kubectl get ingress -A -o json | jq -r '
  .items[] |
  .metadata as $meta |
  .spec.rules[]? |
  .host as $host |
  .http.paths[]? |
  select(.path | test("debug|admin|internal|actuator|health/detail"; "i")) |
  "\($meta.namespace)/\($meta.name): \($host)\(.path)"
'
```

```bash
# Run the audit
chmod +x audit-debug-endpoints.sh
./audit-debug-endpoints.sh
```

**Strip unnecessary tools from production container images:**

```dockerfile
# Dockerfile - multi-stage build, production image has no shell, no package manager
FROM golang:1.23 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .

# Production image: distroless, no shell, no package manager, no debugging tools
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]
```

**Enforce read-only root filesystems:**

```yaml
# security-context-readonly.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
  namespace: production
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.example.com/app:latest
          securityContext:
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65534
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
```

```bash
# Apply the hardened deployment
kubectl apply -f security-context-readonly.yaml
```

### 5. Harden Input Validation at System Boundaries

AI models trace data flow paths through applications and identify where untrusted input reaches sensitive operations. Close these paths at the boundary.

**Deploy an API gateway with strict schema validation:**

```yaml
# api-gateway-validation.yaml
# Kong or similar gateway: reject requests that do not match the OpenAPI schema.
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: request-validator
  namespace: production
config:
  body_schema: |
    {
      "type": "object",
      "required": ["action", "target"],
      "properties": {
        "action": {
          "type": "string",
          "enum": ["create", "read", "update", "delete"]
        },
        "target": {
          "type": "string",
          "pattern": "^[a-zA-Z0-9_-]{1,128}$"
        }
      },
      "additionalProperties": false
    }
  allowed_content_types:
    - "application/json"
  verbose_response: false
plugin: request-validator
```

**Rate limit API endpoints to slow automated probing:**

```yaml
# rate-limiting.yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: rate-limit
  namespace: production
config:
  minute: 60
  hour: 1000
  policy: redis
  redis_host: redis.production.svc.cluster.local
  redis_port: 6379
  fault_tolerant: true
  hide_client_headers: false
plugin: rate-limiting
```

### 6. Reduce Dependency Attack Surface

AI models map transitive dependency trees and identify reachable vulnerabilities. Reduce the tree size and pin every dependency.

**Generate and audit an SBOM:**

```bash
# Generate SBOM using Syft
syft registry.example.com/app:latest -o spdx-json > sbom.json

# Scan the SBOM for known vulnerabilities
grype sbom:sbom.json --fail-on critical

# List all dependencies (direct and transitive)
syft registry.example.com/app:latest -o table
```

**Pin all dependency versions (Go example):**

```bash
# Verify dependency checksums
go mod verify

# List all dependencies with their hashes
go mod download -json | jq '{path: .Path, version: .Version, hash: .Sum}'

# Remove unused dependencies
go mod tidy
```

**Enforce SBOM generation in CI:**

```yaml
# .github/workflows/sbom.yml
name: SBOM Generation
on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Build image
        run: docker build -t app:${{ github.sha }} .

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: app:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Scan SBOM for vulnerabilities
        uses: anchore/scan-action@v4
        with:
          sbom: sbom.spdx.json
          fail-build: true
          severity-cutoff: high

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json
```

## Expected Behaviour

After implementing all six classes of attack surface reduction:

- **Secrets:** No hardcoded credentials in any repository. Pre-commit hooks block new secrets from being committed. CI pipeline fails on any secret detection. All application secrets served at runtime via Vault sidecar injection.
- **Network trust:** Default-deny network policies in every namespace. Each service-to-service communication path has an explicit allow policy. mTLS enforced for all inter-service communication. No service accepts unauthenticated requests from within the cluster.
- **Configuration drift:** Gatekeeper blocks privileged containers, missing security labels, and other policy violations at admission time. Scheduled drift detection runs every 6 hours and alerts on any deviation from baseline.
- **Attack surface:** Production images are distroless with no shell or package manager. Read-only root filesystems enforced. Debug and admin endpoints removed or blocked at the ingress layer. No unnecessary ports exposed.
- **Input validation:** API gateway rejects malformed requests before they reach application code. Rate limiting active on all external endpoints. Schema validation enforced against OpenAPI specification.
- **Dependencies:** SBOM generated for every build. Transitive vulnerability scanning blocks builds with critical or high findings. Unused dependencies removed. All versions pinned with hash verification.

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Default-deny network policies | Breaks any service communication not explicitly allowed | Legitimate service calls fail silently if policy is missing | Map all service communication paths before applying. Use [Hubble](https://docs.cilium.io/en/stable/observability/hubble/) (Cilium) to observe actual traffic flows and generate policies from observed behaviour. |
| Distroless production images | Cannot exec into container for debugging | Debugging production issues requires alternative approach | Use ephemeral debug containers (`kubectl debug`) or ship logs and metrics to external systems. |
| Read-only root filesystem | Applications that write to disk fail | Application crashes at startup | Identify all write paths (temp files, caches, uploads) and mount writable `emptyDir` volumes at those paths only. |
| Strict input validation at gateway | Legitimate requests that do not match the schema are rejected | Users experience 400 errors for valid but unexpected input | Comprehensive schema testing. Log rejected requests for analysis. Gradual rollout (log-only mode before enforcement). |
| Gatekeeper admission control | Blocks deployments that violate policy, including during incidents | Emergency deployments blocked by policy constraints | Break-glass namespace with relaxed policies for emergency use. All break-glass deployments require post-hoc review within 24 hours. |
| Aggressive dependency pruning | Fewer dependencies means less available functionality | Removing a dependency breaks a feature that uses it indirectly | Run full test suite after dependency removal. Identify all import paths before removing. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Network policy blocks legitimate traffic | Service-to-service calls fail with connection timeout | Application error rates spike; Hubble flow logs show DROPPED verdicts | Identify the missing policy from Hubble flow logs. Add explicit allow policy. Apply immediately. |
| Gatekeeper blocks valid deployment | `kubectl apply` returns admission webhook denial | Deployment pipeline fails; error message contains Gatekeeper constraint name | Review the constraint. If deployment is legitimate: update the manifest to comply. If emergency: deploy to break-glass namespace with post-hoc review. |
| Secret scanner false positive blocks CI | PR build fails on a string that looks like a credential but is not | CI pipeline fails with Gitleaks finding on non-secret content | Add the specific pattern to `.gitleaksignore` with a comment explaining why it is not a secret. |
| Distroless image missing required library | Application crashes at startup with "shared library not found" | Container enters CrashLoopBackOff; logs show library load failure | Add required library to build stage. Copy only the specific library (not the full OS layer) into the distroless image. |
| mTLS breaks during certificate rotation | Service-to-service calls fail with TLS handshake errors | Application error rates spike; Istio proxy logs show certificate validation failures | Check Istio certificate authority status. Restart affected Istio sidecars. If CA is compromised: rotate the root CA and all workload certificates. |
| Rate limiting blocks legitimate burst traffic | Users receive 429 responses during peak usage | 429 response rate exceeds threshold; user complaints | Increase rate limits for affected endpoints. Implement client-side retry with exponential backoff. Consider per-customer rate limits instead of global limits. |

## When to Consider a Managed Alternative

Implementing all six classes of attack surface reduction across a fleet of 50+ services, 200+ containers, and 10+ clusters is operationally intensive. The scanning, policy enforcement, drift detection, and dependency analysis require dedicated tooling and continuous maintenance.

- **[Snyk](https://snyk.io):** Reachability analysis determines whether a vulnerable dependency is actually executed by your code (not just present in the tree). Reduces false positives by 80%+ compared to tree-presence scanning. Automated fix PRs for vulnerable dependencies.
- **[Wiz](https://www.wiz.io):** Agentless cloud security posture management. Scans running infrastructure for misconfigurations, exposed secrets, overly permissive network policies, and drift from security baselines. Correlates findings across cloud accounts, clusters, and repositories to identify attack paths.
- **[HashiCorp Vault](https://www.hashicorp.com/products/vault):** Centralised secrets management with dynamic credentials (short-lived, automatically rotated). Eliminates the entire class of hardcoded secrets. Audit logging for every secret access.
- **[Styra](https://www.styra.com) (OPA/Gatekeeper managed):** Managed policy-as-code. Pre-built policy libraries for Kubernetes, Terraform, and cloud APIs. Continuous compliance monitoring and drift detection at scale.

**What you still control:** Network policy design (which services can communicate with which). Container image build pipeline. API schema definitions and validation rules. Dependency selection and pruning decisions. These are architectural decisions that managed tools enforce but cannot make for you.

**Premium content pack:** AI attack surface reduction templates. Gitleaks configuration with custom rules for infrastructure secrets, Gatekeeper constraint templates for the six vulnerability classes, network policy generators from Hubble flow logs, and SBOM pipeline configurations with automated vulnerability blocking.

## Related Articles

- [AI-Powered Vulnerability Discovery: What Automated Code Analysis Means for Your Patch Cycle](/articles/ai-landscape/ai-vulnerability-discovery/)
- [How AI Is Compressing the Attacker Timeline: What Defenders Need to Change Now](/articles/ai-landscape/ai-compressing-attacker-timeline/)
- [Detecting AI-Generated Attacks: Moving from Signatures to Behavioural Baselines](/articles/ai-landscape/detecting-ai-attacks/)
- [The Threat Model Has Changed: Rewriting Security Assumptions for an AI-Augmented World](/articles/ai-landscape/threat-model-ai-augmented/)
- [Hardening the AI Control Plane: Kill Switches, Rate Limits, and Human-in-the-Loop Gates](/articles/ai-landscape/ai-control-plane/)
- [AI Supply Chain Attack Surface: Models, Datasets, and Inference Dependencies](/articles/ai-landscape/ai-supply-chain-attack-surface/)
