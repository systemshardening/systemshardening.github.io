---
title: "Harbor Container Registry Security Hardening"
description: "Harden Harbor container registry against CVE-2026-4404 hardcoded credential compromise, image tampering, and the silent-fix disclosure pattern in Harbor's rapidly evolving release cycle."
slug: harbor-registry-security
date: 2026-05-02
lastmod: 2026-05-02
category: cicd
tags: ["harbor", "container-registry", "cve-2026-4404", "hardcoded-credentials", "supply-chain", "image-security"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 370
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/cicd/harbor-registry-security/index.html"
---

# Harbor Container Registry Security Hardening

## Problem

Harbor is the CNCF-graduated open source container registry most commonly chosen when organizations need a self-hosted alternative to Docker Hub or ECR. Beyond basic image hosting, Harbor provides integrated vulnerability scanning via Trivy and Clair, content trust through Notary V2 and Cosign, configurable replication to remote registries, and role-based access control at the project level. This feature density makes Harbor attractive for enterprise and on-premises environments — and it makes a compromised Harbor instance extraordinarily damaging, because every artifact in your software supply chain flows through it.

CVE-2026-4404 (published March 23, 2026, CVSS 9.4, Critical) exposed a fundamental deployment-time failure in Harbor. Fresh Harbor deployments shipped with hardcoded default credentials — `admin` / `Harbor12345` — and there was no mechanism to force a password reset before the registry became operational. No first-login gate. No warning in the UI indicating the default credential was still active. No API-level check that blocked registry operations until the credential had been changed. An attacker who knew the default credential — which is documented in the public Harbor installation guide — could authenticate to any Harbor instance where the admin password had never been explicitly changed and gain full registry administrator access. Harbor v2.15.1 patched this by introducing a forced password reset flow on initial login and removing the hardcoded default entirely.

The CVSS score of 9.4 is appropriate because the attack path is trivial and the blast radius is severe. An authenticated registry admin can push to any repository, overwrite any tag, modify vulnerability scanner configuration, and manipulate replication rules. If an attacker pushes a backdoored version of `ubuntu:22.04` or `python:3.11-slim` to your Harbor registry and your CI/CD pipelines pull from that registry without signature verification, every downstream build after the push is potentially compromised. This is a software supply chain attack delivered through your own infrastructure.

The hardcoded credential problem is not unique to Harbor. Default passwords in infrastructure software — routers, databases, message brokers, registries — account for a disproportionate share of supply chain and infrastructure breaches. What distinguished CVE-2026-4404 was that Harbor had no compensating control. There was no deployment-time enforcement: no flag required on startup, no environment variable that must be set, no configuration validation that would fail a deployment where the default credential was still present. Deployments could run indefinitely with `Harbor12345` as the admin password, and nothing in the default Harbor deployment would surface this condition to operators.

The disclosure pattern for CVE-2026-4404 followed what is increasingly called the silent-fix pattern in open source security. The fix was included in Harbor v2.15.1, and the release notes described the change as "security improvements to initial authentication setup." The `CHANGELOG.md` entry for v2.15.1 did not reference CVE-2026-4404 by identifier. The CVE was published on March 23, 2026, but the Harbor project's formal security advisory was not available until after security researchers reviewed the authentication-related changes in the v2.15.1 release diff and cross-referenced them against newly published CVE database entries. For operators watching only the Harbor changelog, the severity of this change would not have been apparent.

This disclosure pattern has practical implications for Harbor operators. Waiting for a formal Harbor security advisory before patching is not a safe strategy — the advisory may lag the fix by days or weeks, and the patch-gap window is when opportunistic attackers scan for vulnerable instances. Effective monitoring requires watching multiple signals simultaneously: subscribe to `https://github.com/goharbor/harbor/security/advisories` for formal Harbor security advisories; watch `https://github.com/goharbor/harbor/releases` and filter for releases where the release body contains security-related terms; monitor changes to `src/common/utils/auth/` and `src/core/api/` in the Harbor source tree for authentication-related commits between releases; and query `https://osv.dev` for Harbor CVEs using the OSV API. Using `gh` CLI tooling to automate this monitoring is covered in the Configuration section.

Target systems: Harbor v2.15.0 and earlier (patched in Harbor v2.15.1+), all deployment methods — Helm chart, Docker Compose, and the Harbor operator.

## Threat Model

The following adversaries are ordered from most opportunistic to most sophisticated.

1. **CVE-2026-4404 credential spray** — An external attacker with knowledge of Harbor's default `admin/Harbor12345` credential (documented publicly in Harbor's installation guide) scans Shodan or Censys for hosts responding on port 443 with Harbor's characteristic UI or API response headers. Against any Harbor instance running v2.15.0 or earlier where the admin password was never changed, the attacker authenticates successfully and gains registry admin access. From that position, the attacker overwrites a commonly-used base image tag — `ubuntu:22.04`, `python:3.11-slim`, `alpine:3.19` — with a backdoored variant. All downstream CI/CD builds that pull this image and do not verify image signatures are now building on attacker-controlled code.

2. **Vulnerability scan redirection** — An authenticated attacker with legitimate membership in a Harbor project exploits Harbor's configurable vulnerability scanner endpoint. By submitting an API request to update the scanner configuration to point to an attacker-controlled Trivy-compatible server, the attacker receives full vulnerability scan reports for all images scanned subsequently. These reports enumerate CVEs present in production images, identifying high-value targets for exploitation that are known to be unpatched in the target environment.

3. **Patch-gap credential scan** — An attacker monitors the Harbor v2.15.1 release diff, identifies the forced password reset flow as the remediation for a credential hardening issue, and immediately begins scanning publicly accessible Harbor instances. The window between the fix being identifiable in the release diff and Harbor operators completing their upgrade cycle is measured in days to weeks. Shodan indexes Harbor API endpoints by their response characteristics; a targeted scan for Harbor instances on port 443 responding with API version information consistent with v2.15.0 or earlier is technically straightforward.

4. **Replication rule exfiltration** — A compromised Harbor instance can be configured to replicate all repositories to an external attacker-controlled registry using Harbor's built-in replication functionality. Replication rules run as a background job and do not require interactive admin presence after configuration. This allows an attacker who gains brief admin access to establish persistent image exfiltration that continues after the initial access event. Conversely, an attacker can configure Harbor to pull images from a malicious external registry and make them available internally, introducing supply chain risk without the visibility of a direct push operation.

The blast radius of a Harbor compromise extends to every system that trusts images from the registry. If Harbor is the authoritative source for base images used in CI/CD, a compromise poisons all builds until the registry is cleaned and image provenance is re-established. Recovery requires identifying which images were modified and when, invalidating any builds that used a compromised image, re-establishing the integrity baseline for all tags in the registry, and notifying consumers of affected images. This recovery process can take days in a large organization.

## Configuration / Implementation

### Upgrading Harbor to v2.15.1

Upgrade Harbor via the official Helm chart. Harbor Helm chart version 1.16.1 corresponds to Harbor v2.15.1.

```bash
# Update the Harbor Helm repo
helm repo update harbor

# Upgrade Harbor, reusing existing values
helm upgrade harbor harbor/harbor \
  --version 1.16.1 \
  --namespace harbor \
  --reuse-values \
  --wait \
  --timeout 10m
```

Verify the deployed Harbor version via the system info API:

```bash
curl -s https://harbor.company.com/api/v2.0/systeminfo | jq .harbor_version
```

Expected output: `"v2.15.1"`. If this returns an earlier version, the upgrade did not complete successfully — check the pod rollout status with `kubectl rollout status deployment/harbor-core -n harbor`.

Immediately after upgrading, rotate the admin password. On first login to a patched Harbor v2.15.1 instance where the default credential was still active, Harbor forces a password reset interactively. For automated remediation, use the Harbor API:

```bash
# Verify the default credential is still active (returns 200 if vulnerable)
curl -s -o /dev/null -w "%{http_code}" \
  -u admin:Harbor12345 \
  https://harbor.company.com/api/v2.0/users

# If the above returns 200, rotate the password immediately
curl -X PUT \
  -H "Content-Type: application/json" \
  -u admin:Harbor12345 \
  https://harbor.company.com/api/v2.0/users/1/password \
  -d '{"old_password":"Harbor12345","new_password":"<strong-random-password>"}'
```

Generate a strong replacement password before running this command:

```bash
openssl rand -base64 32
```

After rotating the admin password, store it in your secrets manager (Vault, AWS Secrets Manager, or Kubernetes external secrets) rather than in plaintext in any configuration file.

### Credential Audit and Password Policy Enforcement

Run the credential audit against all Harbor instances in your environment as part of your CVE-2026-4404 response:

```bash
#!/usr/bin/env bash
# harbor-audit.sh — check for default credential across all Harbor instances
HARBOR_HOSTS=(
  "harbor.company.com"
  "harbor-staging.company.com"
  "harbor-dev.company.com"
)

for host in "${HARBOR_HOSTS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    --connect-timeout 5 \
    -u admin:Harbor12345 \
    "https://${host}/api/v2.0/users")
  if [ "$status" = "200" ]; then
    echo "VULNERABLE: ${host} accepts default credential"
  else
    echo "OK: ${host} returned ${status}"
  fi
done
```

After rotating credentials, enforce Harbor's password complexity policy. In the Harbor admin UI: `Administration > Configuration > System Settings > Password Complexity`. Set minimum length to 12, require mixed case, numbers, and special characters. This policy applies to all local user accounts, including robot accounts with password-based credentials.

### RBAC and Project-Scoped Robot Accounts

The admin credential must never be used in CI/CD pipelines. Create project-scoped robot accounts with the minimum permissions required for each pipeline operation.

```yaml
# harbor-robot-account.yaml — applies via Harbor API
# POST https://harbor.company.com/api/v2.0/robots
{
  "name": "ci-push",
  "description": "CI/CD push access for project myapp",
  "duration": 90,
  "level": "project",
  "permissions": [
    {
      "kind": "project",
      "namespace": "myapp",
      "access": [
        {"resource": "repository", "action": "push"},
        {"resource": "repository", "action": "pull"},
        {"resource": "artifact", "action": "delete"},
        {"resource": "tag", "action": "create"},
        {"resource": "tag", "action": "delete"}
      ]
    }
  ]
}
```

Create the robot account via the API and capture the generated token:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -u admin:<admin-password> \
  https://harbor.company.com/api/v2.0/robots \
  -d @harbor-robot-account.json | jq '{name: .name, secret: .secret}'
```

Store the robot account secret as a Kubernetes secret for use by CI/CD:

```bash
kubectl create secret docker-registry harbor-robot-ci-push \
  --docker-server=harbor.company.com \
  --docker-username="robot\$ci-push" \
  --docker-password=<robot-account-secret> \
  --namespace=cicd-system
```

For vulnerability scanner integration, create a separate robot account with only the `scanner` role — not admin access:

```bash
# Scanner robot account — read-only access for scanning
curl -X POST \
  -H "Content-Type: application/json" \
  -u admin:<admin-password> \
  https://harbor.company.com/api/v2.0/robots \
  -d '{
    "name": "trivy-scanner",
    "description": "Vulnerability scanner access",
    "duration": 365,
    "level": "system",
    "permissions": [
      {
        "kind": "project",
        "namespace": "*",
        "access": [
          {"resource": "repository", "action": "pull"},
          {"resource": "artifact", "action": "read"},
          {"resource": "scan", "action": "create"},
          {"resource": "scan", "action": "read"}
        ]
      }
    ]
  }'
```

Restrict replication rule creation to admin accounts only, and audit existing replication rules to identify any rules targeting external registries that were not explicitly authorized:

```bash
curl -s -u admin:<admin-password> \
  https://harbor.company.com/api/v2.0/replication/policies | \
  jq '.[] | {id: .id, name: .name, dest_registry: .dest_registry.url, enabled: .enabled}'
```

### Network Isolation

Harbor should not be directly internet-accessible. If internet access is required (for example, to support distributed development teams), place Harbor behind an authentication proxy and restrict direct access to the Harbor API port.

In your Helm values, force HTTPS-only and disable HTTP:

```yaml
# harbor-values.yaml
expose:
  type: ingress
  tls:
    enabled: true
    certSource: secret
    secret:
      secretName: harbor-tls
  ingress:
    hosts:
      core: harbor.company.com
    annotations:
      nginx.ingress.kubernetes.io/ssl-redirect: "true"
      nginx.ingress.kubernetes.io/proxy-body-size: "0"

externalURL: https://harbor.company.com

# Disable HTTP listener — HTTPS only
internalTLS:
  enabled: true

# Network policy to restrict Harbor access to CI/CD namespaces
networkPolicy:
  enabled: true
```

Apply a Kubernetes NetworkPolicy to restrict which pods can reach the Harbor service:

```yaml
# harbor-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: harbor-ingress-restrict
  namespace: harbor
spec:
  podSelector:
    matchLabels:
      app: harbor
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              harbor-access: "true"
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 80
```

Label the namespaces that require Harbor access:

```bash
kubectl label namespace cicd-system harbor-access=true
kubectl label namespace production harbor-access=true
```

### Image Signing and Content Trust

Configure Cosign signing in your CI/CD pipeline before pushing images to Harbor:

```bash
# Generate a Cosign keypair (store private key in Vault or KMS)
cosign generate-key-pair --kms gcpkms://projects/myproject/locations/global/keyRings/cicd/cryptoKeys/cosign

# Sign an image after push
cosign sign --key gcpkms://projects/myproject/locations/global/keyRings/cicd/cryptoKeys/cosign \
  harbor.company.com/myapp/api:v1.2.3

# Verify signature on pull
cosign verify --key gcpkms://projects/myproject/locations/global/keyRings/cicd/cryptoKeys/cosign \
  harbor.company.com/myapp/api:v1.2.3
```

In Harbor, enable content trust enforcement at the project level. Navigate to `Project > myapp > Configuration` and enable `Enable content trust`. With this setting active, Harbor rejects image pulls for images without a valid signature. This prevents unsigned images — including any backdoored images pushed by an attacker who somehow bypassed signing — from being pulled by consumers.

For Notation-based signing (CNCF Notary V2, supported natively in Harbor v2.11+):

```bash
# Sign with Notation
notation sign harbor.company.com/myapp/api:v1.2.3 \
  --key myapp-signing-key

# Verify
notation verify harbor.company.com/myapp/api:v1.2.3 \
  --policy ./trust-policy.json
```

### Monitoring Harbor for Security Fixes

Automate detection of Harbor releases that contain security-relevant changes using the GitHub API:

```bash
# Check the five most recent Harbor releases for security-related release notes
gh api repos/goharbor/harbor/releases \
  --jq '.[0:5] | .[] | select(.body | test("security|CVE|vuln|auth|credential|hardcode"; "i")) | {tag: .tag_name, body: .body[:300]}'
```

Watch the Harbor authentication source for changes between releases:

```bash
# Compare auth-related files between two Harbor releases
git diff v2.15.0..v2.15.1 -- src/common/utils/auth/ src/core/api/
```

For automated monitoring, set up a Renovate configuration to track the Harbor Helm chart version:

```json
{
  "helmValues": [
    {
      "fileMatch": ["harbor-values\\.yaml$"],
      "datasource": "helm",
      "registryUrls": ["https://helm.goharbor.io"]
    }
  ],
  "packageRules": [
    {
      "matchPackageNames": ["harbor"],
      "matchDatasources": ["helm"],
      "automerge": false,
      "reviewers": ["security-team"]
    }
  ]
}
```

Query the OSV database for Harbor CVEs programmatically:

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "harbor", "ecosystem": "Go"}}' | \
  jq '.vulns[] | {id: .id, summary: .summary, severity: .severity}'
```

Subscribe to `https://github.com/goharbor/harbor/security/advisories` via GitHub's watch/subscribe mechanism to receive notifications for formal Harbor security advisories as they are published.

## Expected Behaviour

| Signal | Default Harbor (unpatched v2.15.0) | Patched + hardened (v2.15.1+) |
|--------|-------------------------------------|-------------------------------|
| Default credential login (`admin/Harbor12345`) | Returns HTTP 200, full admin session granted | Returns HTTP 401; first-login forced reset flow if password unchanged, else hard rejection |
| Admin credential used in CI/CD pipeline | Succeeds; grants global admin access across all projects | Robot account with project-scoped push permission only; admin credential not present in CI/CD context |
| Image push without signature | Succeeds; image available for pull immediately | Push succeeds but pull rejected by Harbor content trust enforcement for unsigned images |
| Replication rule to external registry | Can be created by any admin-level user; runs silently in background | Restricted to admin accounts; all replication rules audited and require approval via change management |
| Patch-gap credential scan on port 443 | Attacker authenticates with `Harbor12345`, gains admin | Authentication fails; no default credential active; rate limiting and audit logging capture the attempt |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Project-scoped robot accounts | Limits blast radius of a compromised CI/CD credential to a single project | Multiplicative account management overhead as the number of projects grows; robot account tokens expire and must be rotated | Automate robot account creation and rotation via Harbor API in your infrastructure-as-code; set calendar alerts for token expiry |
| Mandatory content trust (Cosign/Notation) | Prevents unsigned or tampered images from being pulled; attestation chain from build to deployment | Breaks builds that pull unsigned base images from upstream (e.g., before `ubuntu:22.04` is re-signed in your registry) | Maintain a signing pipeline that re-signs upstream base images after verification; use a staging project for unverified images |
| Internet restriction (no direct external Harbor access) | Eliminates the patch-gap credential scan attack path for remote attackers; reduces exposure to unauthenticated API abuse | Developers working outside the corporate network need VPN or jump host to access Harbor; adds friction to developer workflows | Deploy a split-DNS setup so Harbor is resolvable internally; use VPN with split tunneling to minimize friction |
| Helm chart version lock (pinning to 1.16.1) | Ensures a known-good, security-reviewed configuration; prevents unintended upgrades during dependency updates | Delays adoption of upstream features and non-security fixes; Renovate PRs for minor Harbor updates require manual review | Pin in Helm values but configure Renovate to open PRs for patch-level Harbor Helm chart updates; review and merge promptly |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Robot account token expires | CI/CD pipeline fails at registry push step with `401 Unauthorized` or `authentication required` error | Monitor pipeline failure alerts; set token expiry reminder 7 days before configured `duration` elapses | Regenerate robot account secret via Harbor API; update the corresponding Kubernetes secret; re-trigger failed pipeline |
| Content trust rejects unsigned base image | Build fails at image pull step with `no trust data for tag` or cosign verification error; blocks all builds using that base image | Build failure alert; check Harbor project settings for content trust enforcement; verify cosign signatures present on pulled image | Pull the base image from upstream, sign it with your CI signing key, push the signed version to Harbor; update image reference in build spec |
| Harbor upgrade breaks database schema | Harbor core pod fails to start after upgrade; logs show database migration error; API returns 503 | Check pod logs: `kubectl logs deployment/harbor-core -n harbor`; Harbor upgrade logs show migration step failure | Roll back the Helm release: `helm rollback harbor -n harbor`; review Harbor upgrade notes for required manual migration steps; re-run upgrade with `--set database.internal.migrationAlways=true` |
| Replication rule targets deprecated registry API | Replication job shows `Success` in Harbor UI but images do not appear in the destination registry; or replication jobs fail silently with non-descriptive error | Check Harbor replication execution logs: `Administration > Replications > Execution History`; verify destination registry API compatibility; check Harbor core logs for replication errors | Update the replication policy with the correct destination registry URL and API version; trigger a manual replication execution to confirm; alert on replication job failures via Harbor webhook to your alerting system |

## Related Articles

- [Container Registry Security](/articles/cicd/container-registry-security/)
- [Artifact Integrity](/articles/cicd/artifact-integrity/)
- [Sigstore Keyless Signing](/articles/cicd/sigstore-keyless-signing/)
- [Container Build Hardening](/articles/cicd/container-build-hardening/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
