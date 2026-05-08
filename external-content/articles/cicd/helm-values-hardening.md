---
title: "Hardening Helm Values: Schema Validation, Secret Injection, and Security Defaults"
description: "Helm values files control security-critical Kubernetes fields like security contexts, image references, and resource limits. Without schema validation, a single misconfigured value can deploy a privileged container or pull an unscanned image."
slug: "helm-values-hardening"
date: 2026-03-18
lastmod: 2026-03-18
category: "cicd"
tags: ["helm", "kubernetes", "schema-validation", "external-secrets", "security-contexts"]
personas: ["devops-engineer", "platform-engineer"]
article_number: 150
difficulty: "intermediate"
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/cicd/helm-values-hardening/index.html"
---

# Hardening Helm Values: Schema Validation, Secret Injection, and Security Defaults

## Problem

Helm values files are the primary interface for configuring Kubernetes workloads, and they control security-critical fields with no built-in validation:

- **No enforcement that containers run as non-root.** A developer sets `securityContext.runAsNonRoot: false` in their values file, or omits the field entirely, and the chart deploys a root container. Nothing in the Helm workflow catches this before it reaches the cluster.
- **Secrets hardcoded in values files.** Database passwords, API keys, and TLS certificates are stored directly in `values.yaml` or passed via `--set`. These end up in Helm release secrets (base64-encoded in the cluster), in Git history, and in CI logs.
- **No image tag format validation.** Values files accept `image.tag: latest` or `image.tag: ""`, resulting in mutable tags that can be replaced with a compromised image. There is no schema rule that requires a digest or a semver tag.
- **Resource limits are optional.** Charts without default resource limits allow a single misbehaving pod to consume all node resources. Values files that omit `resources.limits` pass Helm validation because there is no schema to enforce them.
- **No pre-deployment validation.** `helm install` renders templates and applies them in one step. If the rendered manifests contain security violations, you discover them only after they hit the API server or, worse, after they are running.

These gaps exist because Helm treats values as arbitrary YAML with no type checking or constraint enforcement. The `values.schema.json` feature exists but is rarely used because teams do not know about it or consider it optional.

**Target systems:** Teams deploying to [Kubernetes](https://kubernetes.io) with Helm, using internal or third-party charts. Applicable to any chart where values control security contexts, images, resource limits, or network policies.

## Threat Model

- **Adversary:** Developer who accidentally weakens security settings. Insider who intentionally deploys a privileged container. Attacker who compromises a values file in a Git repository. CI pipeline that leaks secrets from `--set` arguments in process listings.
- **Access level:** Write access to the Git repository containing values files. Access to the CI pipeline that runs `helm install`. kubectl access to the target namespace.
- **Objective:** Deploy a container running as root with host network access. Extract secrets from values files stored in Git or Helm release secrets. Replace an image tag with a compromised version. Remove resource limits to enable resource exhaustion attacks.
- **Blast radius:** A privileged container can escape to the host node. Leaked secrets compromise external systems (databases, APIs). An unrestricted pod can starve other workloads on the same node.

## Configuration

### values.schema.json for Security Enforcement

Helm supports JSON Schema validation through a `values.schema.json` file in the chart root. This schema runs during `helm install`, `helm upgrade`, and `helm lint`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["image", "securityContext", "resources"],
  "properties": {
    "image": {
      "type": "object",
      "required": ["repository", "tag"],
      "properties": {
        "repository": {
          "type": "string",
          "pattern": "^registry\\.internal\\.company\\.com/",
          "description": "Image must come from the internal registry"
        },
        "tag": {
          "type": "string",
          "pattern": "^(v[0-9]+\\.[0-9]+\\.[0-9]+|sha256:[a-f0-9]{64})$",
          "description": "Tag must be semver (v1.2.3) or a sha256 digest. 'latest' is not allowed."
        },
        "pullPolicy": {
          "type": "string",
          "enum": ["IfNotPresent", "Never"],
          "description": "Always is not permitted in production"
        }
      },
      "additionalProperties": false
    },
    "securityContext": {
      "type": "object",
      "required": ["runAsNonRoot", "runAsUser"],
      "properties": {
        "runAsNonRoot": {
          "type": "boolean",
          "const": true,
          "description": "Containers must run as non-root"
        },
        "runAsUser": {
          "type": "integer",
          "minimum": 1000,
          "description": "UID must be 1000 or higher"
        },
        "allowPrivilegeEscalation": {
          "type": "boolean",
          "const": false,
          "description": "Privilege escalation must be disabled"
        },
        "readOnlyRootFilesystem": {
          "type": "boolean",
          "const": true,
          "description": "Root filesystem must be read-only"
        },
        "capabilities": {
          "type": "object",
          "properties": {
            "drop": {
              "type": "array",
              "contains": {
                "const": "ALL"
              },
              "description": "Must drop ALL capabilities"
            },
            "add": {
              "type": "array",
              "maxItems": 2,
              "items": {
                "type": "string",
                "enum": ["NET_BIND_SERVICE", "CHOWN"],
                "description": "Only NET_BIND_SERVICE and CHOWN may be added"
              }
            }
          }
        }
      }
    },
    "resources": {
      "type": "object",
      "required": ["limits", "requests"],
      "properties": {
        "limits": {
          "type": "object",
          "required": ["cpu", "memory"],
          "properties": {
            "cpu": {
              "type": "string",
              "pattern": "^[0-9]+(m|\\.[0-9]+)?$"
            },
            "memory": {
              "type": "string",
              "pattern": "^[0-9]+(Mi|Gi)$"
            }
          }
        },
        "requests": {
          "type": "object",
          "required": ["cpu", "memory"],
          "properties": {
            "cpu": {
              "type": "string"
            },
            "memory": {
              "type": "string"
            }
          }
        }
      }
    },
    "networkPolicy": {
      "type": "object",
      "properties": {
        "enabled": {
          "type": "boolean",
          "const": true,
          "description": "Network policy must be enabled in production"
        }
      },
      "required": ["enabled"]
    },
    "serviceAccount": {
      "type": "object",
      "properties": {
        "automountServiceAccountToken": {
          "type": "boolean",
          "const": false,
          "description": "Do not automount service account token unless required"
        }
      }
    }
  }
}
```

### Security-Focused Default Values

The chart's `values.yaml` should ship with secure defaults so that omitting a value results in a hardened configuration, not an open one:

```yaml
# values.yaml - Secure defaults for the payments-api chart

image:
  repository: registry.internal.company.com/payments-api
  tag: "v1.0.0"  # Overridden per environment; 'latest' fails schema
  pullPolicy: IfNotPresent

replicaCount: 2

securityContext:
  runAsNonRoot: true
  runAsUser: 65534  # nobody
  runAsGroup: 65534
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

podSecurityContext:
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault

resources:
  limits:
    cpu: "500m"
    memory: "256Mi"
  requests:
    cpu: "100m"
    memory: "128Mi"

networkPolicy:
  enabled: true
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: envoy-proxy
      ports:
        - port: 8443
          protocol: TCP

serviceAccount:
  create: true
  automountServiceAccountToken: false
  annotations: {}

# Secrets are NOT stored here. Use External Secrets Operator.
# See: externalSecrets section below
externalSecrets:
  enabled: true
  secretStoreName: "vault-backend"
  refreshInterval: "1h"
```

### Secret Injection with External Secrets Operator

Replace hardcoded secrets in values files with [External Secrets Operator](https://external-secrets.io) resources that pull secrets from Vault at runtime:

```yaml
# external-secret.yaml - Pull secrets from Vault, not values files
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: payments-api-secrets
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: payments-api-secrets
    creationPolicy: Owner
    deletionPolicy: Retain
    template:
      type: Opaque
      data:
        DATABASE_URL: "{{ .database_url }}"
        API_KEY: "{{ .api_key }}"
        TLS_CERT: "{{ .tls_cert }}"
        TLS_KEY: "{{ .tls_key }}"
  data:
    - secretKey: database_url
      remoteRef:
        key: secret/data/production/payments-api
        property: database_url
    - secretKey: api_key
      remoteRef:
        key: secret/data/production/payments-api
        property: api_key
    - secretKey: tls_cert
      remoteRef:
        key: secret/data/production/payments-api/tls
        property: cert
    - secretKey: tls_key
      remoteRef:
        key: secret/data/production/payments-api/tls
        property: key
---
# ClusterSecretStore - connects to Vault
apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.infrastructure.svc.cluster.local:8200"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "external-secrets"
          serviceAccountRef:
            name: "external-secrets"
            namespace: "external-secrets"
      caProvider:
        type: ConfigMap
        name: vault-ca
        namespace: external-secrets
        key: ca.crt
```

Reference the External Secret in the chart template instead of reading secrets from values:

```yaml
# templates/deployment.yaml - Reference ExternalSecret, not values
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}
spec:
  template:
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          envFrom:
            - secretRef:
                # This secret is created by ExternalSecret, not by Helm
                name: {{ .Release.Name }}-secrets
          securityContext:
            runAsNonRoot: {{ .Values.securityContext.runAsNonRoot }}
            runAsUser: {{ .Values.securityContext.runAsUser }}
            allowPrivilegeEscalation: {{ .Values.securityContext.allowPrivilegeEscalation }}
            readOnlyRootFilesystem: {{ .Values.securityContext.readOnlyRootFilesystem }}
            capabilities:
              drop:
                {{- toYaml .Values.securityContext.capabilities.drop | nindent 16 }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
```

### Pre-install and Pre-upgrade Validation Hooks

Use Helm hooks to run validation before the main deployment:

```yaml
# templates/pre-install-validate.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ .Release.Name }}-pre-validate
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: {{ .Release.Name }}-validator
      automountServiceAccountToken: true
      containers:
        - name: validate
          image: registry.internal.company.com/tools/helm-validator:1.2.0
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          command:
            - /bin/sh
            - -c
            - |
              set -e

              echo "Validating security requirements..."

              # Check that the image comes from the internal registry
              IMAGE="{{ .Values.image.repository }}:{{ .Values.image.tag }}"
              if ! echo "$IMAGE" | grep -q "^registry.internal.company.com/"; then
                echo "FAIL: Image must come from internal registry: $IMAGE"
                exit 1
              fi

              # Check that the image tag is not 'latest'
              if echo "$IMAGE" | grep -q ":latest$"; then
                echo "FAIL: 'latest' tag is not allowed"
                exit 1
              fi

              # Verify the image has a cosign signature
              cosign verify \
                --key /etc/cosign/image-signing-key.pub \
                "$IMAGE"
              if [ $? -ne 0 ]; then
                echo "FAIL: Image signature verification failed: $IMAGE"
                exit 1
              fi

              echo "All validation checks passed."
          volumeMounts:
            - name: cosign-key
              mountPath: /etc/cosign
              readOnly: true
          resources:
            limits:
              cpu: "100m"
              memory: "64Mi"
            requests:
              cpu: "50m"
              memory: "32Mi"
      volumes:
        - name: cosign-key
          configMap:
            name: image-signing-public-key
```

### CI Pipeline That Lints Values Against Schema

```yaml
# .github/workflows/helm-values-lint.yml
name: Helm Values Security Lint
on:
  pull_request:
    paths:
      - "charts/**"
      - "values/**"

jobs:
  lint-values:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Install Helm
        uses: azure/setup-helm@v4
        with:
          version: "v3.15.0"

      - name: Helm lint with strict mode
        run: |
          for chart_dir in charts/*/; do
            echo "Linting: $chart_dir"
            helm lint "$chart_dir" --strict
          done

      - name: Validate production values against schema
        run: |
          for values_file in values/production/*.yaml; do
            CHART_NAME=$(basename "$values_file" .yaml)
            CHART_DIR="charts/${CHART_NAME}"

            if [ ! -d "$CHART_DIR" ]; then
              echo "WARNING: No chart found for $values_file"
              continue
            fi

            echo "Validating $values_file against ${CHART_DIR}/values.schema.json"

            # helm template triggers schema validation
            helm template test "$CHART_DIR" \
              --values "$values_file" \
              > /dev/null

            echo "PASS: $values_file"
          done

      - name: Template and scan rendered manifests
        run: |
          for values_file in values/production/*.yaml; do
            CHART_NAME=$(basename "$values_file" .yaml)
            CHART_DIR="charts/${CHART_NAME}"

            if [ ! -d "$CHART_DIR" ]; then
              continue
            fi

            helm template "$CHART_NAME" "$CHART_DIR" \
              --values "$values_file" \
              > "/tmp/rendered-${CHART_NAME}.yaml"

            # Scan with kubesec for security scoring
            kubesec scan "/tmp/rendered-${CHART_NAME}.yaml" | \
              jq -e '.[].score >= 5' || {
                echo "FAIL: ${CHART_NAME} kubesec score below threshold"
                exit 1
              }

            # Scan with Trivy for misconfigurations
            trivy config "/tmp/rendered-${CHART_NAME}.yaml" \
              --severity HIGH,CRITICAL \
              --exit-code 1
          done

      - name: Check for hardcoded secrets
        run: |
          # Detect common secret patterns in values files
          PATTERNS=(
            "password:"
            "secret:"
            "api_key:"
            "apiKey:"
            "token:"
            "private_key:"
            "BEGIN RSA PRIVATE KEY"
            "BEGIN EC PRIVATE KEY"
          )

          FOUND=0
          for pattern in "${PATTERNS[@]}"; do
            if grep -rn "$pattern" values/ --include="*.yaml" | \
               grep -v "secretRef" | \
               grep -v "secretStoreName" | \
               grep -v "externalSecrets" | \
               grep -v "# reference only"; then
              echo "WARNING: Potential hardcoded secret matching pattern: $pattern"
              FOUND=1
            fi
          done

          if [ $FOUND -eq 1 ]; then
            echo "FAIL: Found potential hardcoded secrets in values files."
            echo "Use External Secrets Operator instead."
            exit 1
          fi
          echo "PASS: No hardcoded secrets detected."
```

## Expected Behaviour

After implementing values hardening:

```bash
# Verify schema rejects insecure values
helm template payments-api ./charts/payments-api \
  --set securityContext.runAsNonRoot=false
# Expected: Error: values don't meet the specifications of the schema:
# securityContext.runAsNonRoot: Must be true

# Verify 'latest' tag is rejected
helm template payments-api ./charts/payments-api \
  --set image.tag=latest
# Expected: Error: values don't meet the specifications of the schema:
# image.tag: Does not match pattern '^(v[0-9]+\.[0-9]+\.[0-9]+|sha256:[a-f0-9]{64})$'

# Verify missing resource limits are caught
helm template payments-api ./charts/payments-api \
  --set resources.limits=null
# Expected: Error: values don't meet the specifications of the schema:
# resources: limits is required

# Verify External Secrets creates the Kubernetes Secret
kubectl get externalsecret payments-api-secrets -n production
# Expected: STATUS=SecretSynced, indicates Vault secrets are synced

# Verify no secrets in Helm release data
helm get values payments-api -n production | grep -i password
# Expected: No output (secrets are in ExternalSecret, not values)

# Verify pre-install hook validates image signature
helm install payments-api ./charts/payments-api \
  --set image.tag=v1.5.0 \
  --namespace production
# Expected: Hook job runs cosign verify; if signature is missing, install fails
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| values.schema.json enforcement | Catches insecure values before deployment | Overly strict schemas block legitimate configurations and slow development | Maintain environment-specific schemas: strict for production, relaxed for development |
| Secure defaults in values.yaml | Developers get hardened config without effort | Defaults may not fit all workloads (some need writable filesystem, specific UIDs) | Document how to override defaults safely; schema allows specific overrides within bounds |
| External Secrets Operator | Secrets never stored in Git or Helm release data | Adds dependency on Vault and ESO controller; if either is down, secrets are not refreshed | ESO retains last synced secret; set `deletionPolicy: Retain` to keep secrets if ESO is removed |
| Pre-install validation hooks | Catches issues before any resources are created | Hook failures block deployment; hook job needs permissions to verify images | Keep hook logic minimal; use `hook-delete-policy: before-hook-creation` to clean up failed hooks |
| CI schema validation | Prevents insecure values from reaching the cluster | CI pipeline becomes a bottleneck for chart changes | Cache Helm and scanning tools; run validation only on changed charts |
| Hardcoded secret detection | Prevents accidental secret commits | Pattern matching produces false positives on field names like "secretRef" | Exclude known safe patterns; require manual review for flagged files |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Schema too restrictive | Legitimate `helm install` fails with schema validation error | Developer reports that valid configuration is rejected | Update schema to allow the valid pattern; add the case to schema tests |
| External Secrets Operator down | New secrets are not synced; existing secrets remain but become stale | ESO metrics show sync failures; ExternalSecret status shows error | ESO retains last synced secrets; fix ESO controller; secrets refresh on next sync interval |
| Vault unreachable | ESO cannot fetch secrets; new pods fail if secret does not exist yet | ExternalSecret status shows "SecretSyncedError"; Vault health check fails | Fix Vault connectivity; existing Kubernetes Secrets remain until ESO deletes them |
| Pre-install hook timeout | Deployment hangs waiting for validation job | Helm install shows "waiting for hook completion"; job stays in Pending state | Set `activeDeadlineSeconds` on the hook Job; investigate why validation is slow (registry access, network) |
| Schema not included in chart | `helm install` skips validation entirely; insecure values pass through | CI lint step passes but cluster receives insecure config | Add CI check that verifies `values.schema.json` exists in every chart directory |
| Secret pattern false positive | CI blocks PR due to a field named "password" in a comment or reference | CI output shows the flagged line; developer confirms it is not a real secret | Add the line to the exclusion list; improve pattern matching to reduce false positives |

## When to Consider a Managed Alternative

**Transition point:** When maintaining JSON schemas, External Secrets Operator, validation hooks, and CI scanning pipelines across more than 25 charts requires dedicated tooling beyond what a single platform team can sustain manually.

**What managed alternatives handle:**

- **Policy engines ([Kyverno](https://kyverno.io), [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)):** Enforce security constraints at the admission controller level, catching violations regardless of whether they came from Helm values, kubectl apply, or GitOps. Kyverno can mutate resources to inject security defaults that chart templates omit.

- **Secret management platforms ([HashiCorp Vault](https://www.vaultproject.io) with Agent Injector, [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) with CSI driver):** Vault Agent Injector provides an alternative to External Secrets Operator by injecting secrets as files into pods via init containers. AWS Secrets Manager CSI driver mounts secrets directly as volumes.

- **Chart scanning services ([Snyk](https://snyk.io) IaC, [Checkov](https://www.checkov.io)):** Automated scanning of Helm charts and rendered manifests integrated with pull request workflows. These tools maintain up-to-date security rule databases without manual schema maintenance.

**What you still control:** The specific security requirements for your organization (minimum UID, allowed capabilities, approved registries), the secret rotation policy, and the decision of which charts require strict validation versus relaxed development defaults.

## Related Articles

- [Securing Helm Charts: Chart Signing, Value Injection, and Template Security](/articles/cicd/helm-chart-security/)
- [Helm Supply Chain Security: OCI Registries, Provenance Verification, and Chart Mirroring](/articles/cicd/helm-supply-chain-security/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [GitOps Security Model: Separation of Duties, Drift Detection, and Rollback Controls](/articles/cicd/gitops-security/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Terraform Security: State Encryption, Provider Pinning, and Policy as Code](/articles/cicd/terraform-security/)
