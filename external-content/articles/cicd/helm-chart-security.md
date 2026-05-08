---
title: "Securing Helm Charts: Chart Signing, Value Injection, and Template Security"
description: "Helm is the dominant package manager for Kubernetes, but most teams install charts without verifying provenance, pass unvalidated values that end up..."
slug: "helm-chart-security"
date: 2026-03-01
lastmod: 2026-03-01
category: "cicd"
tags: ["helm", "kubernetes", "chart-signing", "cosign", "template-security"]
personas: ["devops-engineer", "platform-engineer"]
article_number: 59
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "hardened-helm-values"
published: true
layout: article.njk
permalink: "/articles/cicd/helm-chart-security/index.html"
---

# Securing [Helm](https://helm.sh) Charts: Chart Signing, Value Injection, and Template Security

## Problem

Helm is the dominant package manager for [Kubernetes](https://kubernetes.io), but most teams install charts without verifying provenance, pass unvalidated values that end up in security-sensitive fields, and use template functions that enable injection attacks. A Helm chart from a public repository runs with whatever permissions the templates request. If the chart includes a ClusterRoleBinding to cluster-admin, you have granted full cluster access to code you did not write.

The `tpl` function in Helm templates evaluates arbitrary Go template strings at render time. If user-supplied values are passed to `tpl`, an attacker who controls chart values can inject template directives that read secrets, environment variables, or other values from the release context. This is a server-side template injection equivalent for Kubernetes.

Chart repositories themselves are another attack surface. Public Helm repositories serve charts over HTTPS, but the integrity of individual chart packages is rarely verified. A compromised chart repository can serve a modified chart that passes basic validation but includes malicious containers or init containers.

## Threat Model

- **Adversary:** Compromised chart repository maintainer, attacker who modifies chart values in a pull request, or malicious chart in a public repository.
- **Objective:** Deploy privileged containers, exfiltrate cluster secrets through init containers, or escalate privileges via injected RBAC resources.
- **Blast radius:** A malicious chart can create any Kubernetes resource that the Helm release's service account or user can create, including ClusterRoles, Secrets, and DaemonSets.

## Configuration

### Chart Provenance Verification with Cosign

Sign OCI-based Helm charts with [cosign](https://docs.sigstore.dev/cosign/) after packaging:

```bash
#!/bin/bash
# sign-chart.sh - Package and sign a Helm chart

CHART_DIR="./charts/payments-api"
REGISTRY="registry.internal.company.com/charts"

# Package the chart
helm package "$CHART_DIR"
CHART_PACKAGE=$(ls payments-api-*.tgz)

# Push to OCI registry
helm push "$CHART_PACKAGE" "oci://$REGISTRY"

# Sign the chart artifact with cosign
CHART_VERSION=$(helm show chart "$CHART_DIR" | grep '^version:' | awk '{print $2}')
cosign sign --yes \
  --key env://COSIGN_PRIVATE_KEY \
  "$REGISTRY/payments-api:$CHART_VERSION"

echo "Chart signed: $REGISTRY/payments-api:$CHART_VERSION"
```

Verify chart signatures before installation:

```bash
#!/bin/bash
# verify-and-install.sh - Verify chart signature before installing

REGISTRY="registry.internal.company.com/charts"
CHART="payments-api"
VERSION="1.5.0"

# Verify signature
cosign verify \
  --key /etc/cosign/chart-signing-key.pub \
  "$REGISTRY/$CHART:$VERSION"

if [ $? -ne 0 ]; then
  echo "ERROR: Chart signature verification failed. Aborting installation."
  exit 1
fi

# Signature valid - proceed with installation
helm install payments-api "oci://$REGISTRY/$CHART" \
  --version "$VERSION" \
  --namespace payments \
  --values values-production.yaml
```

### Validating Chart Values

Create a JSON schema for your chart values to reject unexpected or dangerous inputs:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "replicaCount": {
      "type": "integer",
      "minimum": 1,
      "maximum": 20
    },
    "image": {
      "type": "object",
      "properties": {
        "repository": {
          "type": "string",
          "pattern": "^registry\\.internal\\.company\\.com/"
        },
        "tag": {
          "type": "string",
          "pattern": "^[a-f0-9]{40}$"
        }
      },
      "required": ["repository", "tag"]
    },
    "securityContext": {
      "type": "object",
      "properties": {
        "runAsNonRoot": {
          "type": "boolean",
          "const": true
        },
        "privileged": {
          "type": "boolean",
          "const": false
        }
      }
    }
  },
  "required": ["replicaCount", "image"]
}
```

Save this as `values.schema.json` in the chart root. Helm validates values against this schema during `helm install` and `helm upgrade`.

### Secure Template Patterns

Avoid `tpl` with user-supplied values. The `tpl` function evaluates Go templates, which means user input can execute template directives.

```yaml
# BAD: tpl with user-supplied value - template injection vulnerability
# If .Values.annotation contains {{ .Release.Namespace }}, it gets evaluated.
# Worse: {{ (lookup "v1" "Secret" "default" "my-secret").data }}
# could read cluster secrets.
annotations:
  custom: {{ tpl .Values.customAnnotation . }}

# GOOD: quote user-supplied values to prevent template evaluation
annotations:
  custom: {{ .Values.customAnnotation | quote }}
```

```yaml
# BAD: unquoted values in security-sensitive fields
spec:
  containers:
    - name: app
      image: {{ .Values.image.repository }}:{{ .Values.image.tag }}
      securityContext:
        runAsUser: {{ .Values.runAsUser }}

# GOOD: validate and quote properly
spec:
  containers:
    - name: app
      image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
      securityContext:
        runAsUser: {{ .Values.runAsUser | int }}
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
```

Enforce security context defaults in your chart templates regardless of values:

```yaml
# templates/deployment.yaml - hardcoded security baseline
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          {{- if .Values.resources }}
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          {{- else }}
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
            requests:
              cpu: "100m"
              memory: "128Mi"
          {{- end }}
```

### Scanning Charts for Misconfigurations

```yaml
# .github/workflows/chart-lint.yml
name: Chart Security Scan
on:
  pull_request:
    paths:
      - "charts/**"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Helm lint
        run: helm lint charts/payments-api --strict

      - name: Template and scan with Trivy
        run: |
          helm template payments-api charts/payments-api \
            --values charts/payments-api/values-production.yaml \
            > rendered.yaml
          trivy config rendered.yaml --severity HIGH,CRITICAL --exit-code 1

      - name: Scan with kubelinter
        run: |
          helm template payments-api charts/payments-api \
            --values charts/payments-api/values-production.yaml \
            | kube-linter lint --config .kube-linter.yaml -

      - name: Check for tpl with user values
        run: |
          # Detect potentially dangerous tpl usage
          if grep -rn 'tpl.*\.Values\.' charts/payments-api/templates/; then
            echo "WARNING: Found tpl usage with .Values input."
            echo "Review each occurrence for template injection risk."
            exit 1
          fi
```

```yaml
# .kube-linter.yaml
checks:
  addAllBuiltIn: true
  exclude:
    # Exclude checks that don't apply to your environment
    - "unset-cpu-requirements"  # We set defaults in templates
customChecks: []
```

### Chart Repository Security

For private chart repositories, enforce authentication and use OCI registries instead of legacy Helm repositories:

```bash
# Use OCI registry (preferred) instead of legacy chart museum
# OCI registries support authentication, signing, and access control natively

# Login to OCI registry
helm registry login registry.internal.company.com \
  --username "$HELM_USER" \
  --password "$HELM_TOKEN"

# Pull chart from OCI registry
helm pull oci://registry.internal.company.com/charts/payments-api \
  --version 1.5.0

# For third-party charts, mirror them into your internal registry
# so you control availability and can scan them
helm pull oci://public-chart-repo/nginx-ingress --version 4.10.0
helm push nginx-ingress-4.10.0.tgz oci://registry.internal.company.com/charts/vendor
```

## Expected Behaviour

- All charts deployed to production are signed with cosign and verified before installation
- Chart values are validated against a JSON schema that restricts image sources, security contexts, and resource limits
- No chart templates use `tpl` with user-supplied `.Values` input
- Security context defaults (non-root, read-only filesystem, dropped capabilities) are hardcoded in templates
- Every chart PR is scanned with Trivy and kube-linter before merge
- Third-party charts are mirrored to the internal registry and scanned before use

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Chart signing with cosign | Adds signing step to chart release pipeline | Signing key compromise allows signing malicious charts | Store keys in Vault or KMS. Rotate annually. Use keyless signing with Fulcio for CI. |
| Values schema validation | Restrictive schemas block legitimate customization | Overly strict schemas slow down development | Maintain separate schemas for dev/staging (relaxed) and production (strict). |
| Banning tpl with Values | Reduces chart flexibility for dynamic annotations and labels | Some legitimate use cases require template evaluation of values | Allow tpl only with hardcoded strings, not user-supplied values. Document approved patterns. |
| Mirroring third-party charts | Additional infrastructure; chart update lag | Stale charts miss upstream security fixes | Automate mirror sync daily. Alert when upstream charts have new versions. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Chart signature mismatch | Installation blocked by verification script | cosign verify returns non-zero exit code | Re-sign the chart with the correct key, or verify the public key is current. |
| Schema validation rejects valid values | `helm install` fails with schema validation error | Error message specifies which value fails validation | Update the schema to allow the valid value pattern. |
| tpl injection via chart values | Unexpected resources created or secrets exfiltrated | Audit log shows unexpected resource creation; [Kyverno](https://kyverno.io) blocks policy-violating resources | Remove tpl usage. Pin chart values in version control rather than passing dynamically. |
| Trivy scan blocks chart with false positive | Chart PR cannot merge due to scan failure | Trivy output shows the flagged issue with CVE details | Verify whether the finding is a true positive. If false positive, add to Trivy ignore file with documented justification. |

## When to Consider a Managed Alternative

Maintaining signed chart repositories, scanning infrastructure, and value validation schemas across dozens of charts requires dedicated platform engineering. [Snyk](https://snyk.io) IaC provides automated Helm chart scanning integrated with pull request workflows. For teams managing more than 20 charts, a managed OCI registry with built-in signing (JFrog #107, Cloudsmith #106) reduces the infrastructure burden. ArtifactHub provides discoverability for public charts but does not replace the need for internal verification.

**Premium content pack:** Hardened Helm value files for common charts (nginx-ingress, [cert-manager](https://cert-manager.io), prometheus-stack, external-dns). Includes values.schema.json templates, security context defaults, and kube-linter configuration.


## Related Articles

- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [GitOps Security Model: Separation of Duties, Drift Detection, and Rollback Controls](/articles/cicd/gitops-security/)
- [Artifact Integrity Verification: Checksums, Signatures, and Transparency Logs](/articles/cicd/artifact-integrity/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
