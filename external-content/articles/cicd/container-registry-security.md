---
title: "Container Registry Security: Access Control, Vulnerability Scanning, and Garbage Collection"
description: "Container registries store the most sensitive artifacts in your deployment pipeline."
slug: "container-registry-security"
date: 2026-03-29
lastmod: 2026-03-29
category: "cicd"
tags: ["container-registry", "harbor", "vulnerability-scanning", "trivy", "image-signing"]
personas: ["devops-engineer", "platform-engineer"]
article_number: 56
difficulty: "intermediate"
estimated_reading_time: 16
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "harbor-hardened-setup"
published: true
layout: article.njk
permalink: "/articles/cicd/container-registry-security/index.html"
---

# Container Registry Security: Access Control, Vulnerability Scanning, and Garbage Collection

## Problem

Container registries store the most sensitive artifacts in your deployment pipeline. Every image contains your application code, dependencies, and often embedded configuration. Default registry configurations allow any authenticated user to pull any image, retain every version indefinitely (consuming storage and expanding the attack surface), and accept unsigned images without verification.

A registry without access controls lets any developer pull production images containing proprietary code. Without vulnerability scanning, images with known critical CVEs persist in the registry and get deployed to production. Without retention policies, registries accumulate thousands of untagged images that contain old vulnerabilities but remain pullable by digest.

The solution combines repository-level access control (teams only access their own images), automated vulnerability scanning on every push, image signing to verify provenance, and garbage collection to remove stale and vulnerable images.

## Threat Model

- **Adversary:** Insider who pulls images they should not have access to, attacker who pushes a malicious image to a shared repository, or automated system that deploys an unscanned image.
- **Objective:** Exfiltrate proprietary code from production images, deploy images containing malware, or exploit known vulnerabilities in unpatched images.
- **Blast radius:** Without repository-level access control, every image in the registry is accessible to every authenticated user. A malicious image pushed to a shared namespace could be deployed by any team.

## Configuration

### Harbor Self-Managed Registry Setup

Harbor provides open-source registry with built-in access control, vulnerability scanning, and image signing.

```yaml
# harbor/values.yaml (Helm chart configuration)
expose:
  type: ingress
  tls:
    enabled: true
    certSource: secret
    secret:
      secretName: harbor-tls
  ingress:
    hosts:
      core: registry.internal.company.com
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "0"  # No upload size limit
      nginx.ingress.kubernetes.io/ssl-redirect: "true"

# Use external PostgreSQL and Redis for production
database:
  type: external
  external:
    host: harbor-db.internal.company.com
    port: 5432
    sslmode: require

# Trivy vulnerability scanner
trivy:
  enabled: true
  # Scan on push - every pushed image is scanned automatically
  autoScan: true

# Storage backend - S3 for durability
persistence:
  imageChartStorage:
    type: s3
    s3:
      region: eu-west-1
      bucket: harbor-registry-storage
      # Use IRSA (IAM Roles for Service Accounts) instead of static keys
      # accesskey and secretkey omitted - uses pod IAM role
```

### Repository-Level Access Control

Configure project-based isolation in Harbor so each team manages their own images:

```bash
#!/bin/bash
# harbor-setup.sh - Create projects with team-scoped access

HARBOR_URL="https://registry.internal.company.com"
ADMIN_CREDS="admin:$(vault kv get -field=password secret/harbor/admin)"

# Create project for the payments team
curl -s -u "$ADMIN_CREDS" -X POST "$HARBOR_URL/api/v2.0/projects" \
  -H "Content-Type: application/json" \
  -d '{
    "project_name": "payments",
    "metadata": {
      "public": "false",
      "auto_scan": "true",
      "prevent_vul": "true",
      "severity": "high"
    },
    "storage_limit": 53687091200
  }'

# Add the payments team as developers (push/pull)
curl -s -u "$ADMIN_CREDS" -X POST "$HARBOR_URL/api/v2.0/projects/payments/members" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": 2,
    "member_group": {
      "group_name": "payments-developers",
      "group_type": 1
    }
  }'

# Add the platform team as read-only (pull only) for deployment
curl -s -u "$ADMIN_CREDS" -X POST "$HARBOR_URL/api/v2.0/projects/payments/members" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": 3,
    "member_group": {
      "group_name": "platform-deployers",
      "group_type": 1
    }
  }'
```

### OIDC Authentication for Registry Access

Replace static credentials with OIDC-based authentication:

```yaml
# harbor/auth-config.yaml
auth_mode: oidc_auth
oidc_name: Okta
oidc_endpoint: https://company.okta.com/oauth2/default
oidc_client_id: harbor-registry
oidc_client_secret: "${OIDC_CLIENT_SECRET}"
oidc_groups_claim: groups
oidc_scope: "openid,profile,email,groups"
oidc_auto_onboard: true
oidc_admin_group: "registry-admins"
```

For CI/CD pipelines, use robot accounts with scoped permissions instead of user credentials:

```bash
# Create a robot account for CI - push only to the payments project
curl -s -u "$ADMIN_CREDS" -X POST "$HARBOR_URL/api/v2.0/robots" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-payments-push",
    "duration": -1,
    "description": "CI push access for payments project",
    "level": "project",
    "permissions": [
      {
        "kind": "project",
        "namespace": "payments",
        "access": [
          {"resource": "repository", "action": "push"},
          {"resource": "repository", "action": "pull"},
          {"resource": "tag", "action": "create"}
        ]
      }
    ]
  }'
```

### Vulnerability Scanning with Admission Control

Configure Harbor to block pulls of images that exceed a vulnerability threshold:

```bash
# Set project policy: prevent deployment of images with high/critical CVEs
curl -s -u "$ADMIN_CREDS" -X PUT "$HARBOR_URL/api/v2.0/projects/payments" \
  -H "Content-Type: application/json" \
  -d '{
    "metadata": {
      "prevent_vul": "true",
      "severity": "high",
      "auto_scan": "true"
    }
  }'
```

Add a [Kyverno](https://kyverno.io) policy to enforce that only scanned images from your registry are deployed:

```yaml
# kyverno/policies/verify-image-scanned.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-registry-and-scan
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-internal-registry
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Images must come from registry.internal.company.com"
        pattern:
          spec:
            containers:
              - image: "registry.internal.company.com/*"
    - name: verify-image-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "registry.internal.company.com/*"
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                      -----END PUBLIC KEY-----
```

### Image Signing with Cosign

Sign images after building and scanning:

```yaml
# .github/workflows/build-and-sign.yml
- name: Build and push image
  id: build
  run: |
    docker buildx build --push \
      --tag registry.internal.company.com/payments/api:${{ github.sha }} \
      .
    DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' \
      registry.internal.company.com/payments/api:${{ github.sha }})
    echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"

- name: Sign image with cosign
  run: |
    cosign sign --yes \
      --key env://COSIGN_PRIVATE_KEY \
      ${{ steps.build.outputs.digest }}

- name: Attach SBOM attestation
  run: |
    syft ${{ steps.build.outputs.digest }} -o spdx-json > sbom.spdx.json
    cosign attest --yes \
      --key env://COSIGN_PRIVATE_KEY \
      --predicate sbom.spdx.json \
      --type spdxjson \
      ${{ steps.build.outputs.digest }}
```

### Image Retention and Garbage Collection

Configure tag retention policies to automatically clean up old images:

```bash
# Create retention policy - keep last 10 tags per repository,
# plus anything pushed in the last 30 days
curl -s -u "$ADMIN_CREDS" -X POST "$HARBOR_URL/api/v2.0/retentions" \
  -H "Content-Type: application/json" \
  -d '{
    "algorithm": "or",
    "rules": [
      {
        "disabled": false,
        "action": "retain",
        "template": "latestPushedK",
        "params": {"latestPushedK": 10},
        "scope_selectors": {
          "repository": [{"kind": "doublestar", "decoration": "repoMatches", "pattern": "**"}]
        },
        "tag_selectors": [{"kind": "doublestar", "decoration": "matches", "pattern": "**"}]
      },
      {
        "disabled": false,
        "action": "retain",
        "template": "nDaysSinceLastPush",
        "params": {"nDaysSinceLastPush": 30},
        "scope_selectors": {
          "repository": [{"kind": "doublestar", "decoration": "repoMatches", "pattern": "**"}]
        },
        "tag_selectors": [{"kind": "doublestar", "decoration": "matches", "pattern": "**"}]
      }
    ],
    "trigger": {
      "kind": "Schedule",
      "settings": {"cron": "0 0 2 * * *"}
    },
    "scope": {
      "level": "project",
      "ref": 1
    }
  }'
```

Schedule garbage collection to reclaim storage from deleted images:

```bash
# Run garbage collection on a schedule (Harbor admin settings)
# Settings -> Garbage Collection -> Schedule: Daily at 03:00 UTC
# Enable "Delete untagged artifacts" to remove orphaned layers
```

## Expected Behaviour

- Each team can only push to and pull from their own projects
- CI pipelines use robot accounts with push-only scope to specific projects
- Every pushed image is automatically scanned for vulnerabilities
- Images with high or critical CVEs cannot be pulled (Harbor prevents deployment)
- All production images are signed with cosign and verified at admission time
- Images older than 30 days are automatically cleaned up (except the 10 most recent)
- Garbage collection runs daily to reclaim storage from deleted layers

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Vulnerability-based pull prevention | Blocks pulling images with high CVEs | Blocks legitimate deployments when a new CVE is published against an existing image | Set severity threshold to critical only for production; allow high in staging. Provide fast-track rebuild process. |
| Robot accounts per project | Many credentials to manage | Robot account credential leak exposes one project | Rotate robot account tokens quarterly. Use short-lived tokens where possible. |
| Aggressive retention policies | Reduces storage costs and attack surface | Cannot roll back to very old images | Keep last 10 tags, which covers typical rollback windows. Archive critical releases to a separate long-term repository. |
| Image signing requirement | Adds 5-10 seconds per build; key management overhead | Signing key compromise allows signing malicious images | Store signing keys in Vault or KMS. Rotate keys annually. Use keyless signing with Fulcio for CI builds. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Scanner database outdated | New CVEs not detected in scanned images | Trivy health check shows stale vulnerability database | Update Trivy database. Harbor admin can trigger manual database update. |
| Garbage collection deletes needed image | Rollback fails because target image was deleted | Deployment fails with image pull error; no matching tag/digest in registry | Rebuild from source at the target commit. Adjust retention policies to keep more tags. |
| Cosign verification failure | Pods fail to start; admission webhook rejects | Kyverno audit log shows signature verification failure | Verify the public key in the Kyverno policy matches the signing key. Re-sign the image if the key was rotated. |
| Harbor storage full | Image push fails with 507 | Harbor health check; S3 bucket metrics alert | Run garbage collection immediately. Increase S3 bucket quota. Review retention policies. |
| OIDC provider outage | Users cannot authenticate to registry | Login failures across all users; OIDC health check fails | Harbor supports fallback to local admin account for emergency access. |

## When to Consider a Managed Alternative

Self-managed Harbor requires PostgreSQL, Redis, S3 storage, TLS certificate management, and ongoing version upgrades. For teams that do not need fine-grained project isolation, [DigitalOcean](https://www.digitalocean.com) Container Registry integrates directly with managed [Kubernetes](https://kubernetes.io) and handles storage, scanning, and garbage collection. GHCR (GitHub Container Registry) provides free storage for public images and integrates with GitHub Actions. [Quay](https://quay.io) offers hosted registry with security scanning. For enterprise requirements with audit logging and geo-replication, [JFrog](https://jfrog.com) Artifactory and [Cloudsmith](https://cloudsmith.com) provide fully managed registries. [Snyk](https://snyk.io) Container adds vulnerability scanning and monitoring across any registry.

**Premium content pack:** Harbor hardened deployment kit. Includes Helm values for production Harbor, project setup scripts with team isolation, robot account provisioning, retention policies, Kyverno admission policies for image verification, and cosign integration for GitHub Actions and GitLab CI.


## Related Articles

- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [GitOps Security Model: Separation of Duties, Drift Detection, and Rollback Controls](/articles/cicd/gitops-security/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
