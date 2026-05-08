---
title: "Crossplane Provider and Credential Security"
description: "Harden Crossplane provider credentials against over-scoped cloud access, composite resource privilege escalation, and the silent-fix pattern in Crossplane's distributed provider release ecosystem."
slug: crossplane-provider-security
date: 2026-05-03
lastmod: 2026-05-03
category: cicd
tags: ["crossplane", "provider", "credentials", "cloud-credentials", "rbac", "composite-resource", "supply-chain"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 378
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/cicd/crossplane-provider-security/index.html"
---

# Crossplane Provider and Credential Security

## Problem

Crossplane is a CNCF graduated open source project that extends Kubernetes with the ability to provision and manage cloud infrastructure using Kubernetes-native APIs. Instead of running Terraform pipelines or cloud CLI scripts, platform teams install Crossplane on a Kubernetes cluster and declare infrastructure as Kubernetes resources. `Provider` packages extend Crossplane with support for specific cloud services — `upbound/provider-aws` handles AWS resources, `upbound/provider-azure` handles Azure, `upbound/provider-gcp` handles GCP. `CompositeResourceDefinitions` (XRDs) and `Compositions` allow platform teams to build self-service infrastructure APIs for developers: a developer creates a `Claim` (the tenant-facing object) and Crossplane's reconciliation loop creates the actual cloud resources defined in the underlying `Composition`. The result is a GitOps-friendly, Kubernetes-native infrastructure control plane that many organizations have adopted for internal developer platforms.

The credential over-scoping problem is severe. Crossplane providers authenticate to cloud APIs using credentials stored in Kubernetes Secrets, referenced through `ProviderConfig` objects. In most default deployments, a single credential secret covers the entire provider: one AWS IAM user with `PowerUserAccess` for the entire AWS provider, or one Azure service principal with `Contributor` on the subscription. The provider pod runs continuously in the cluster, reconciling the desired state of all managed resources. If an attacker compromises that provider pod — through a container escape, a vulnerability in the provider binary, or a supply chain compromise — they inherit full cloud infrastructure access. The credential secret is mounted into the provider pod or read via the Kubernetes API; either way it is accessible from within the pod's execution context.

Composite Resource privilege escalation is a less obvious but equally serious threat. `CompositeResourceDefinitions` and `Compositions` create an abstraction layer between what a developer requests and what Crossplane actually provisions. A developer with `Claim` creation rights in a namespace may believe they are limited to creating a "small database" — the XRD schema constrains the fields they can supply. But if the `Composition` backing that claim is misconfigured, a developer could request a claim with a legitimate field value that the Composition transforms into a cloud resource configuration far exceeding their intended privilege level. A Composition that creates an EC2 instance based on a developer-supplied `instanceType` field, and also unconditionally attaches an IAM instance profile with broad permissions, allows any developer with Claim access to spawn an instance capable of assuming that IAM role. The developer did not need to know the IAM role ARN, did not need `iam:PassRole` in their Kubernetes RBAC — the Composition did it for them.

The open source provider ecosystem compounds these risks through a pattern that can be called the silent fix. Crossplane's provider ecosystem spans `upbound/provider-aws`, `upbound/provider-azure`, `upbound/provider-gcp`, and dozens of community providers maintained by teams with varying security maturity. The `crossplane/crossplane` core repository has a formal security advisory process at `https://github.com/crossplane/crossplane/security/advisories`, but provider repositories have inconsistent disclosure practices. Many provider repositories have no `SECURITY.md` file and have never filed a CVE. Security-relevant fixes land in provider releases with changelog entries like "Improve secret handling", "Fix credential rotation edge case", or "Update credential file permissions" — no CVE number, no GitHub Security Advisory, no separate notification. A common fix pattern: a provider writes cloud credentials to a temporary file before passing them to the cloud SDK. An older version writes this file with permissions `0644`, readable by any user in the pod. A patched version writes with `0600`. This is a meaningful security improvement, but clusters running the old provider version remain vulnerable to credential exfiltration by any process that achieves code execution in the provider container, and most operators never learn the fix was shipped.

Monitoring for these silent fixes requires active watching rather than waiting for CVE feeds. The GitHub API can surface security-adjacent changelog content across provider repositories: `gh api repos/upbound/provider-aws/releases --jq '.[0:5] | .[] | {tag: .tag_name, body: .body[:300]}'`. Watching `internal/controller/` directories in provider repositories for changes to credential handling files catches fixes before they appear in any advisory database. Renovate can automate provider package version bumps in Crossplane `Provider` resources, ensuring patches reach production without a manual update workflow.

Target systems: Crossplane 1.x, upbound/provider-aws 1.x, upbound/provider-azure 1.x, upbound/provider-gcp 1.x, Kubernetes 1.28+.

## Threat Model

1. **Compromised provider pod — cloud credential access.** An attacker who achieves code execution inside a Crossplane provider pod (via container escape, supply chain compromise, or RCE in the provider binary) gains access to the cloud credential secret mounted in that pod. With a broad IAM policy or a subscription-level service principal, this translates to unrestricted access to the entire cloud account — the ability to create, read, modify, and delete any resource the provider manages, including exfiltrating data from storage, launching compute for cryptomining, or pivoting to other services.

2. **Developer Claim as privilege escalation vector.** A developer with `Claim` creation rights in a namespace crafts a Claim that triggers a misconfigured Composition. The Composition creates an EC2 instance, attaches an IAM instance profile with `AdministratorAccess`, and tags the instance with the developer's user ID. The developer did not need IAM permissions in their Kubernetes RBAC to achieve IAM privilege escalation — the `Composition` intermediary performed the `iam:PassRole` action on their behalf using the provider's broad credentials. This is analogous to a confused deputy attack mediated by the infrastructure control plane.

3. **Silent-fix exploitation.** The provider `upbound/provider-aws` ships `v1.x.y` with a fix to credential file permissions — credentials are now written to tmpfs with mode `0600` instead of `0644`. The fix appears in `CHANGELOG.md` as "Fix credential file permissions" with no associated CVE. Clusters running the previous version write credentials readable by any UID in the provider pod. An attacker with the ability to inject a sidecar or exploit a secondary vulnerability to execute code in the provider pod can read the credential file at a predictable path and exfiltrate long-lived AWS access keys or Azure client secrets without touching the Kubernetes API.

4. **Provider package supply chain.** Crossplane providers are distributed as OCI-formatted packages (`xpkg`) from `xpkg.upbound.io` or user-configured registries. A compromised provider package — through a compromised build pipeline, a dependency confusion attack on the provider's Go modules, or a registry hijack — could ship a malicious provider binary that installs legitimate-looking controllers while also running a goroutine that periodically exfiltrates cloud credentials from the pod's environment or mounted secrets to an external endpoint. Because the provider pod runs with the same service account regardless of package content, a supply chain compromise delivers immediate cloud account access.

The blast radius in the default single-credential configuration is the entire cloud account. A single provider compromise exposes every resource provisioned by that provider. Separating credentials by environment and by provider capability limits the blast radius: a compromised dev-environment provider credential cannot touch production infrastructure; a provider scoped to S3 and RDS cannot create IAM roles or VPC peering connections.

## Configuration / Implementation

### Least-Privilege Provider Credentials with IRSA (AWS)

Replace long-lived IAM access keys with IAM Roles for Service Accounts (IRSA). IRSA eliminates the credential secret entirely for the provider pod — the pod's service account token is exchanged for short-lived STS credentials scoped to a specific IAM role.

First, create the IAM OIDC provider for your EKS cluster and create the IAM role:

```bash
# Retrieve your EKS OIDC issuer URL
OIDC_ISSUER=$(aws eks describe-cluster \
  --name my-cluster \
  --query "cluster.identity.oidc.issuer" \
  --output text | sed 's|https://||')

# Create the IAM role trust policy
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_ISSUER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_ISSUER}:sub": "system:serviceaccount:crossplane-system:provider-aws",
          "${OIDC_ISSUER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF

aws iam create-role \
  --role-name crossplane-provider-aws-s3-rds \
  --assume-role-policy-document file://trust-policy.json
```

Define a minimal IAM policy that covers only the resources the provider provisions. A provider managing S3 buckets and RDS instances needs nothing beyond those service actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3BucketManagement",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketVersioning",
        "s3:PutBucketAcl",
        "s3:PutBucketPolicy",
        "s3:PutBucketVersioning",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging",
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "RDSInstanceManagement",
      "Effect": "Allow",
      "Action": [
        "rds:CreateDBInstance",
        "rds:DeleteDBInstance",
        "rds:DescribeDBInstances",
        "rds:ModifyDBInstance",
        "rds:AddTagsToResource",
        "rds:ListTagsForResource",
        "rds:CreateDBSubnetGroup",
        "rds:DeleteDBSubnetGroup",
        "rds:DescribeDBSubnetGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

Verify the policy grants only the required actions before attaching it:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn "arn:aws:iam::${AWS_ACCOUNT_ID}:role/crossplane-provider-aws-s3-rds" \
  --action-names "ec2:RunInstances" "iam:CreateRole" "s3:CreateBucket" \
  --query 'EvaluationResults[].{Action:EvalActionName,Decision:EvalDecision}'
```

Configure the Crossplane provider to use IRSA:

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-aws
spec:
  package: xpkg.upbound.io/upbound/provider-aws@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
  packagePullPolicy: IfNotPresent
  controllerConfigRef:
    name: provider-aws-irsa
---
apiVersion: pkg.crossplane.io/v1alpha1
kind: ControllerConfig
metadata:
  name: provider-aws-irsa
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::${AWS_ACCOUNT_ID}:role/crossplane-provider-aws-s3-rds"
spec:
  podSecurityContext:
    fsGroup: 2000
```

The `ProviderConfig` then references the IRSA source instead of a Secret:

```yaml
apiVersion: aws.upbound.io/v1beta1
kind: ProviderConfig
metadata:
  name: aws-prod
spec:
  credentials:
    source: IRSA
```

### Secret Scoping with Per-Environment ProviderConfig

Use separate `ProviderConfig` objects per environment, each backed by a distinct credential with permissions scoped to that environment's resources. Developers must not be able to substitute a production `ProviderConfig` in a dev-tier Claim:

```yaml
apiVersion: aws.upbound.io/v1beta1
kind: ProviderConfig
metadata:
  name: aws-dev
spec:
  credentials:
    source: Secret
    secretRef:
      namespace: crossplane-system
      name: aws-dev-credentials
      key: credentials
---
apiVersion: aws.upbound.io/v1beta1
kind: ProviderConfig
metadata:
  name: aws-prod
spec:
  credentials:
    source: IRSA
```

Lock down which Compositions can reference each ProviderConfig by specifying the `providerConfigRef` in the Composition rather than allowing it as a developer-supplied field. If the Composition hard-codes `providerConfigRef.name: aws-prod`, a developer Claim cannot override it.

Audit all ProviderConfig objects across namespaces to understand your current credential surface:

```bash
kubectl get providerconfig -A -o json | \
  jq '.items[] | {
    name: .metadata.name,
    namespace: .metadata.namespace,
    source: .spec.credentials.source,
    secretRef: .spec.credentials.secretRef
  }'
```

### Composition Input Validation

Every field in an XRD schema that a developer can supply is a potential escalation vector if the Composition maps it to a sensitive cloud resource property. Use `x-kubernetes-validations` (CEL expressions) in the XRD schema to enforce an allowlist of acceptable values.

```yaml
apiVersion: apiextensions.crossplane.io/v1
kind: CompositeResourceDefinition
metadata:
  name: xdatabases.platform.example.com
spec:
  group: platform.example.com
  names:
    kind: XDatabase
    plural: xdatabases
  claimNames:
    kind: Database
    plural: databases
  versions:
    - name: v1alpha1
      served: true
      referenceable: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                parameters:
                  type: object
                  properties:
                    size:
                      type: string
                      enum: ["small", "medium", "large"]
                      description: "Database size tier"
                    region:
                      type: string
                      enum: ["us-east-1", "eu-west-1"]
                      description: "Allowed deployment regions"
                    engine:
                      type: string
                      enum: ["postgres", "mysql"]
                  required: ["size", "region", "engine"]
                  x-kubernetes-validations:
                    - rule: "self.size in ['small', 'medium', 'large']"
                      message: "size must be one of: small, medium, large"
                    - rule: "self.region in ['us-east-1', 'eu-west-1']"
                      message: "region must be a pre-approved deployment region"
```

In the corresponding `Composition`, map developer inputs only to pre-validated fields. Never pass a developer-supplied string directly to a field that controls IAM role ARNs, security group IDs, subnet IDs, or instance profiles:

```yaml
apiVersion: apiextensions.crossplane.io/v1
kind: Composition
metadata:
  name: database-aws
spec:
  compositeTypeRef:
    apiVersion: platform.example.com/v1alpha1
    kind: XDatabase
  resources:
    - name: rds-instance
      base:
        apiVersion: rds.aws.upbound.io/v1beta1
        kind: DBInstance
        spec:
          forProvider:
            # Region is validated by CEL in the XRD — safe to pass through
            region: us-east-1
            # instance class is resolved from the size tier here, not passed directly
            dbInstanceClass: db.t3.medium
            engine: postgres
            engineVersion: "15.4"
            skipFinalSnapshot: true
          providerConfigRef:
            # Hard-coded to prod config — not a developer-supplied field
            name: aws-prod
      patches:
        - type: FromCompositeFieldPath
          fromFieldPath: spec.parameters.region
          toFieldPath: spec.forProvider.region
        - type: FromCompositeFieldPath
          fromFieldPath: spec.parameters.size
          toFieldPath: spec.forProvider.dbInstanceClass
          transforms:
            - type: map
              map:
                small: db.t3.micro
                medium: db.t3.medium
                large: db.r6g.large
```

The `transforms.map` approach is critical: the developer supplies `"small"` and Crossplane resolves it to `db.t3.micro`. The developer never touches an instance class string directly, and the map only contains pre-approved values.

### RBAC for Crossplane CRDs

Platform engineers own `Composition` and `CompositeResource` write access at the cluster level. Developers get `Claim` create/read/delete only within their team namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: crossplane-developer
rules:
  - apiGroups: ["platform.example.com"]
    resources: ["databases"]
    verbs: ["get", "list", "watch", "create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: crossplane-developer-team-a
  namespace: team-a
subjects:
  - kind: Group
    name: team-a-developers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: crossplane-developer
  apiGroup: rbac.authorization.k8s.io
```

Developers must not have `create` or `update` on `Composition`, `CompositeResourceDefinition`, or `ProviderConfig` at the cluster level. Audit for misconfigurations:

```bash
kubectl get clusterrolebinding -o json | \
  jq '.items[] | select(
    .roleRef.name | test("crossplane|xrd|composition|provider"; "i")
  ) | {
    binding: .metadata.name,
    role: .roleRef.name,
    subjects: [.subjects[]? | {kind: .kind, name: .name, namespace: .namespace}]
  }'
```

### Provider Package Verification and Digest Pinning

Pin provider packages by digest in the `Provider` resource to prevent automatic upgrades that could introduce regressions or, in a supply chain attack scenario, a backdoored image:

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-aws
spec:
  # Use digest, not a mutable tag
  package: xpkg.upbound.io/upbound/provider-aws@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
  packagePullPolicy: IfNotPresent
  revisionActivationPolicy: Manual
```

`revisionActivationPolicy: Manual` means a new package version requires explicit activation — a new revision is downloaded and verified but not activated until the operator sets the active revision. This gives a review window before new provider code runs in the cluster.

Verify the provider package signature before pinning the digest:

```bash
# Retrieve the digest for the current release tag
DIGEST=$(crane digest xpkg.upbound.io/upbound/provider-aws:v1.14.0)

# Verify cosign signature
cosign verify \
  --certificate-identity-regexp "https://github.com/upbound/provider-aws" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "xpkg.upbound.io/upbound/provider-aws@${DIGEST}"

echo "Verified digest: ${DIGEST}"
```

### Monitoring Provider Releases for Silent Security Fixes

Watch provider release notes for security-adjacent changes that ship without CVE assignment. The GitHub API makes it possible to filter release bodies for keywords:

```bash
# Scan recent provider-aws releases for security-relevant changelog entries
gh api repos/upbound/provider-aws/releases \
  --jq '.[0:10] | .[] | select(
    .body | test("secret|credential|permission|auth|fix.*perm|CVE|security|token"; "i")
  ) | {tag: .tag_name, published: .published_at, excerpt: .body[:400]}'
```

Watch for changes in the credential handling paths within provider repositories. The most security-sensitive code in any provider lives in the controller setup and credential management files:

```bash
# Check what changed in credential-related files between two provider versions
gh api repos/upbound/provider-aws/compare/v1.13.0...v1.14.0 \
  --jq '.files[] | select(.filename | test("credential|secret|auth|config"; "i")) | {
    file: .filename,
    additions: .additions,
    deletions: .deletions,
    patch: .patch[:500]
  }'
```

Check the official Crossplane security advisories and cross-reference with provider release timing:

```bash
# List published Crossplane core security advisories
gh api repos/crossplane/crossplane/security/advisories \
  --jq '.[] | {summary: .summary, severity: .severity, published: .published_at}'
```

Configure Renovate to automate provider version tracking in your Crossplane `Provider` resources. Add a `customManagers` entry in `renovate.json` to match the `spec.package` field in Provider manifests, enabling automated PRs when new provider digests are available for review.

## Expected Behaviour

| Signal | Default Crossplane (broad credentials) | IRSA + Scoped ProviderConfig + Composition Validation |
|---|---|---|
| Provider pod credential access | Pod has a long-lived IAM access key with PowerUserAccess mounted as a Secret | Pod uses IRSA short-lived STS tokens scoped to S3 and RDS actions only; no credential Secret exists to steal |
| Developer Claim triggers overprivileged Composition | Composition unconditionally attaches IAM instance profile; any Claim creator inherits IAM role | `providerConfigRef` is hard-coded in Composition; IAM-sensitive fields are not developer-exposed; CEL validation blocks off-allowlist inputs |
| Provider package digest mismatch | `packagePullPolicy: Always` pulls latest tag; no digest verification; malicious update activates automatically | Digest-pinned package; `revisionActivationPolicy: Manual` blocks automatic activation; cosign verification required before digest is pinned |
| Silent credential fix ships in provider release | No monitoring; cluster runs vulnerable provider version indefinitely | Renovate opens PR within 24h of new release; `gh api` release scan flags security-adjacent changelog entries for human review |
| RBAC Composition write restriction | Default RBAC may grant developer service accounts cluster-wide write on Crossplane CRDs | ClusterRole audit shows only platform-engineer group can write Compositions; developers limited to Claim verbs in their namespace |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| IRSA vs long-lived access keys | No static credentials to steal or rotate; tokens are short-lived and scoped | Requires EKS with OIDC provider configured; not portable to non-AWS or non-EKS clusters | For non-EKS deployments, use IAM roles with EC2 instance metadata; for Azure/GCP, use Workload Identity equivalents |
| Per-environment ProviderConfig | Blast radius limited to a single environment; dev compromise cannot touch prod | More ProviderConfig objects and IAM roles to manage; onboarding new environments requires new credential setup | Automate ProviderConfig and IAM role creation with Terraform or the Crossplane provider itself bootstrapping its own credentials |
| Composition input validation with CEL | Prevents Composition-mediated privilege escalation; forces allowlist-based input control | Reduces developer flexibility; valid inputs outside the allowlist require platform team intervention to add | Treat the XRD schema as an API contract; version it; communicate allowlist changes through the internal developer platform changelog |
| Provider digest pinning | Prevents silent supply chain upgrades; enables pre-activation review | Manual update workflow; security patches require a deliberate pin update cycle | Automate digest pinning with Renovate; require PR review for digest updates with a fast-track path for CVE-level patches |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| IRSA role trust policy misconfigured (wrong namespace or service account name in condition) | Provider pod cannot provision resources; all managed resources enter a `False` Synced condition with an `AccessDenied` error | `kubectl describe managed <resource>` shows STS `AssumeRoleWithWebIdentity` failure; CloudTrail logs show denied STS calls | Correct the trust policy condition to match the actual service account name and namespace; no credential rotation required |
| Composition CEL validation rejects valid developer input (allowlist too restrictive) | Claims fail to create or update with a validation error; developers receive 422 responses from the Kubernetes API | Developers report failed Claims; `kubectl describe claim <name>` shows validation rejection message | Add the valid value to the XRD allowlist via a new XRD version; use conversion webhooks to maintain backward compatibility |
| Provider digest outdated — security patch not applied | Cluster runs a provider version with a known credential handling vulnerability; no user-visible symptom | Renovate PR open for an extended period; release scan script flags security-adjacent changelog entries with no action taken | Apply the Renovate PR after review; activate the new revision; verify provider health after activation |
| ProviderConfig scoping blocks legitimate cross-environment resource access (e.g., shared DNS zone) | Cross-environment resource creation fails with ProviderConfig not found or credential not authorized | `kubectl get managed -A` shows resources in error state referencing an unavailable ProviderConfig | Create a dedicated ProviderConfig and IAM role for shared resources with a narrowly scoped cross-account policy; avoid sharing dev/prod credentials |

## Related Articles

- [Terraform Security](/articles/cicd/terraform-security/)
- [OpenTofu Provider Supply Chain](/articles/cicd/opentofu-provider-supply-chain/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [OIDC Federation Hardening](/articles/cicd/oidc-federation-hardening/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
