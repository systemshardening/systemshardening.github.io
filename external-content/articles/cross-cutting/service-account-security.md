---
title: "Service Account Security: Hardening Non-Human Identities Across Cloud and Kubernetes"
description: "Service accounts are the most common vector for credential theft and privilege escalation — long-lived, over-privileged, and rarely reviewed. This guide covers least-privilege service account design, OIDC workload identity replacing static credentials, detecting unused accounts, and audit strategies for non-human identity hygiene."
slug: service-account-security
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - service-accounts
  - workload-identity
  - oidc
  - least-privilege
  - non-human-identity
personas:
  - security-engineer
  - platform-engineer
article_number: 599
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/service-account-security/
---

# Service Account Security: Hardening Non-Human Identities Across Cloud and Kubernetes

## Why Service Accounts Are the Attacker's First Choice

Service accounts — IAM users, GCP service accounts, Kubernetes service accounts, and their equivalents — represent the densest concentration of unmanaged privilege in most organisations. They share three properties that make them attractive targets:

**Long lifetime.** Human accounts get deprovisioned when people leave. Service accounts created for a project that shipped in 2021 often still exist in 2026, carrying the same permissions, with the same keys.

**Broad permissions.** When a developer doesn't know exactly what a service needs, they grant it broad access. `roles/editor` is a common default on GCP. `arn:aws:iam::*:policy/AdministratorAccess` appears in environments that should know better. The accounts are never narrowed down because the service "just works."

**Minimal monitoring.** SIEM rules focus on human authentication anomalies: impossible travel, off-hours logins, MFA failures. Service account activity generates less scrutiny, so an attacker using a stolen SA key can operate quietly for weeks.

The 2024 Mandiant M-Trends report found that compromised service account credentials were the initial access vector in 35% of cloud intrusions. Once inside, attackers use SA permissions to pivot laterally, enumerate other credentials, and establish persistence — often through creating new service accounts or access keys that survive the incident response cleanup.

This article covers how to structure service accounts correctly, replace static credentials with OIDC workload identity, detect unused and over-privileged accounts, and establish the monitoring that catches abuse early.

## Threat Model

- **Adversary 1 — Credential theft from code or config:** a service account key committed to a repo, embedded in a container image, or left in an unencrypted config file. Attacker finds it via GitHub search or by reading a compromised artifact registry.
- **Adversary 2 — Compromise of a workload:** attacker gains code execution inside a pod, EC2 instance, or GCP VM and reads credentials from the environment or the metadata service.
- **Adversary 3 — Insider / supply chain:** a dependency or internal tool that uses a broadly-scoped SA to perform a targeted action.
- **Adversary 4 — Stale account exploitation:** SA created for a decommissioned service still has working credentials; attacker finds them in an old secrets manager version, backup, or archived CI pipeline.
- **Objective:** use SA credentials to access data stores, cloud APIs, or other services; pivot to escalate privileges; persist by creating new credentials.
- **Blast radius with poor hygiene:** full environment access, often cross-account or cross-project. Blast radius with correct hygiene: single service, scoped permissions, short-lived credentials that expire before the attacker can use them.

## AWS: IAM Roles for Service Workloads

AWS offers three patterns for giving workloads an identity without static credentials.

### EC2 Instance Profiles

An instance profile is an IAM role attached to an EC2 instance. The AWS SDK retrieves short-lived credentials from the EC2 Instance Metadata Service (IMDS) automatically. The credentials rotate every hour with no application involvement.

The critical hardening requirement is IMDSv2. IMDSv1 is vulnerable to SSRF — a request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` from any HTTP client inside the instance retrieves the SA credentials. IMDSv2 requires a session-oriented token obtained via PUT request with a TTL, which server-side request forgery cannot easily obtain because the attacker cannot control the PUT.

```bash
# Enforce IMDSv2 on an existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-endpoint enabled

# Enforce IMDSv2 for all new instances via SCP / launch template default
aws ec2 create-launch-template-version \
  --launch-template-id lt-0123456789abcdef0 \
  --source-version 1 \
  --launch-template-data '{"MetadataOptions":{"HttpTokens":"required","HttpEndpoint":"enabled"}}'
```

For new accounts, enforce IMDSv2 as a Service Control Policy requirement. Never allow `ec2:RunInstances` with `HttpTokens: optional` from a production OU.

### ECS Task Roles

ECS injects task-specific IAM credentials via a local HTTP endpoint. Each task definition should have its own IAM role scoped to the exact APIs that container calls. The common failure is attaching a broad role at the cluster or service level and reusing it across tasks with different permission requirements.

```json
{
  "taskRoleArn": "arn:aws:iam::123456789012:role/payments-processor-task",
  "executionRoleArn": "arn:aws:iam::123456789012:role/ecs-execution-role"
}
```

Note the distinction: `taskRoleArn` is for the application; `executionRoleArn` is for ECS itself to pull the container image and write logs. They must not be the same role.

### Lambda Execution Roles

Lambda execution roles follow the same principle: one role per function, scoped to only what that function reads or writes. Lambda's short lifecycle (milliseconds to minutes) means static credentials are particularly wasteful — workload identity is fully available and requires no extra infrastructure.

The failure pattern is a single Lambda execution role shared across dozens of functions because "it's easier to manage one role." An attacker who compromises any one of those functions inherits the union of all permissions.

## GCP: Workload Identity Federation Over Key Files

GCP service accounts have a structural risk: their key files. A GCP SA key is a long-lived JSON file containing an RSA private key that grants full access to everything the SA can do. Keys do not expire. Keys are easy to exfiltrate. Revocation requires knowing you were compromised.

**The correct posture is to never create SA key files for workloads running on GCP infrastructure.**

### On GKE: Workload Identity

Workload Identity binds a Kubernetes service account to a GCP service account. Pods running under the KSA receive short-lived GCP credentials from the metadata server without any key files.

```bash
# Enable Workload Identity on a GKE cluster
gcloud container clusters update my-cluster \
  --workload-pool=my-project.svc.id.goog

# Bind KSA to GSA
gcloud iam service-accounts add-iam-policy-binding \
  payments-processor@my-project.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:my-project.svc.id.goog[payments/processor]"
```

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: processor
  namespace: payments
  annotations:
    iam.gke.io/gcp-service-account: payments-processor@my-project.iam.gserviceaccount.com
```

### Off-GCP Workloads: Workload Identity Federation

For workloads running outside GCP (on-premise, another cloud, GitHub Actions), Workload Identity Federation allows them to exchange an OIDC token from their own issuer for short-lived GCP credentials. No key files cross the boundary.

```bash
gcloud iam workload-identity-pools create github-pool \
  --location=global \
  --display-name="GitHub Actions Pool"

gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location=global \
  --workload-identity-pool=github-pool \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='myorg/myrepo'"
```

### SA Impersonation Instead of Key Files

When one GCP service needs to act as another GCP service account — for example, a deployment pipeline granting narrower access to an SA before handing it to a workload — use SA impersonation (`roles/iam.serviceAccountTokenCreator`) rather than generating a key file. The impersonating SA generates a short-lived token (maximum 1 hour) without persisting any long-term credential.

If static key files are truly unavoidable (legacy systems with no OIDC support), GCP Policy Intelligence will flag which keys have not been used in 90 days — rotate and delete those. Treat an active SA key file as a compliance finding, not a configuration choice.

## Kubernetes: Service Account Hygiene

Every Kubernetes pod receives an automatically-mounted service account token by default. This is a broad attack surface: the default service account in most namespaces has a token, and that token can be used to call the Kubernetes API.

### Disable Auto-Mounting by Default

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
  namespace: production
automountServiceAccountToken: false
```

Set this on the default service account in every namespace. Pods that genuinely need API access get their own named SA with specific RBAC, and opt in explicitly:

```yaml
spec:
  serviceAccountName: metrics-collector
  automountServiceAccountToken: true
```

### Least-Privilege RBAC for Service Accounts

The most common Kubernetes SA misconfiguration is binding a service account to `cluster-admin` or to a ClusterRole with `*` verbs. Audit all ClusterRoleBindings:

```bash
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]?.kind == "ServiceAccount") | 
      {name: .metadata.name, subjects: .subjects, role: .roleRef.name}'
```

Create narrow roles. A pod that only reads ConfigMaps in its own namespace needs:

```yaml
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["get", "list", "watch"]
```

Not `get,list,watch,create,update,patch,delete` on `*`. Not a ClusterRole when a Role suffices.

### Projected Service Account Tokens

Kubernetes 1.20+ supports projected service account tokens — short-lived, audience-scoped tokens that expire. These are the correct token type for modern workloads.

```yaml
volumes:
- name: token
  projected:
    sources:
    - serviceAccountToken:
        audience: https://api.internal
        expirationSeconds: 3600
        path: token
```

Projected tokens can be refreshed by the kubelet automatically. They bind to a specific audience, so a token obtained for your internal API cannot be replayed against the Kubernetes API server or another cluster.

## OIDC Workload Identity: The Gold Standard

The pattern that eliminates static service account credentials entirely is OIDC workload identity. Each workload receives a short-lived OIDC token from its runtime — Kubernetes, GitHub Actions, GitLab CI, CircleCI, or a SPIFFE issuer. The target system (AWS, GCP, Azure, Vault) validates that token against the issuer's public JWKS endpoint and exchanges it for short-lived credentials.

The trust is cryptographic, not secret-based. The attacker who steals an OIDC token has a credential that expires in minutes or hours, not years. There is no long-lived key to exfiltrate.

### GitHub Actions to AWS

```yaml
jobs:
  deploy:
    permissions:
      id-token: write
      contents: read
    steps:
    - uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: arn:aws:iam::123456789012:role/github-actions-deploy
        aws-region: us-east-1
        role-session-name: github-${{ github.run_id }}
```

The IAM role trust policy restricts which GitHub repo and branch can assume it:

```json
{
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"
    }
  }
}
```

No AWS access keys in CI secrets. No rotation. The token expires with the job.

### Kubernetes to AWS via IRSA

IAM Roles for Service Accounts (IRSA) is the EKS implementation of the same pattern. Pods annotated with a role ARN receive OIDC tokens that AWS STS validates directly. The role trust policy restricts which Kubernetes service account can assume the role.

## Detecting Unused Service Accounts

Unused service accounts are dead weight that carries live risk. An adversary with access to a backup, an old CI pipeline, or a forgotten secrets manager entry can activate credentials nobody knew were still valid.

### AWS: IAM Access Advisor

The IAM console and CLI report the last time each service (S3, EC2, etc.) was accessed by an IAM entity. Any SA that has not accessed any service in 90 days is a candidate for disabling; in 180 days, for deletion.

```bash
# Get last-used date for all IAM users with service account naming pattern
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | \
  base64 -d | grep svc- | \
  awk -F, '{print $1, $5, $11}' | \
  # columns: username, password_last_used, access_key_1_last_used_date
  sort -k3
```

For IAM roles, use `get-role-last-used`:

```bash
aws iam get-role-last-used --role-name payments-processor-task \
  --query 'RoleLastUsed'
```

### GCP: Policy Intelligence and Recommender

GCP's IAM Recommender surfaces roles that have not been used in the past 90 days and proposes narrower replacements. The Inactive Identity Recommender flags service accounts with no activity.

```bash
gcloud recommender recommendations list \
  --project=my-project \
  --location=global \
  --recommender=google.iam.policy.Recommender \
  --format="table(name,description,stateInfo.state)"
```

Policy Insights separately flags service accounts with no activity in 90 days. Integrate this into a weekly review: apply recommendations to staging first, validate no breakage, then promote to production.

### Kubernetes: Unused SA Detection

Kubernetes does not have a built-in "last used" timestamp for service accounts. Detection requires correlating audit log entries with SA names.

```bash
# Find service accounts with no pods currently referencing them
kubectl get serviceaccounts --all-namespaces -o json | \
  jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"' > /tmp/all-sas.txt

kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | "\(.metadata.namespace)/\(.spec.serviceAccountName)"' | \
  sort -u > /tmp/used-sas.txt

comm -23 <(sort /tmp/all-sas.txt) /tmp/used-sas.txt
```

This identifies SAs not referenced by any running pod. Cross-reference with audit logs to confirm they have not been used recently before deletion.

## Service Account Naming Conventions

A service account named `sa-1` or `app-service` tells you nothing about who owns it, what it does, or whether it should still exist. A naming convention that encodes ownership makes auditing possible.

Recommended pattern: `{service}-{component}-{environment}`

Examples:
- `payments-api-prod`
- `inventory-worker-staging`
- `infra-cert-rotation-prod`

For cloud providers, add a prefix to distinguish SA types from human accounts:
- AWS IAM users: `svc-payments-api` (prefix `svc-` marks service account)
- GCP: `payments-api-prod@project.iam.gserviceaccount.com`
- Kubernetes: namespace provides environment scope, name provides service

Enforce naming via:
- AWS: SCP or IAM policy denying `iam:CreateUser` if the username does not match the `svc-*` pattern
- GCP: Organisation Policy with custom constraint
- Kubernetes: OPA/Gatekeeper or Kyverno policy rejecting ServiceAccount resources without a required `owner` label

## Service Account Inventory and Ownership

Every service account must have a declared owner — a team or individual responsible for its permissions and lifecycle. Without ownership, accounts accumulate and nobody reviews them.

Minimum metadata per SA:

| Field | Purpose |
|-------|---------|
| `owner` | Team or individual (use group email, not personal) |
| `service` | Application or system this SA is for |
| `created_date` | When it was created |
| `review_date` | Next scheduled review (no more than 12 months out) |
| `purpose` | One-sentence description of what this SA does |
| `oidc_preferred` | Whether static credentials have been replaced |

Implement as tags in AWS, labels in GCP/Kubernetes. Deny creation of SAs without required tags via policy. Generate a quarterly report of SAs missing tags or past their review date.

## Key Rotation When Static Credentials Are Unavoidable

Some legacy systems cannot use OIDC. Rotation is a compensating control, not a substitute for eliminating static credentials.

**Maximum key age: 90 days.** Any key older than 90 days should be treated as a finding. Enforce this with:
- AWS: Config rule `iam-user-unused-credentials-check` with max age 90 days
- GCP: Security Command Center finding for SA keys older than 90 days
- A custom scanner that queries key metadata and opens tickets automatically

**Zero-downtime rotation pattern:**
1. Create a new key.
2. Update the secret in the secrets manager.
3. Deploy the updated configuration to the workload (rolling restart).
4. Verify the workload is using the new key (check logs or metrics).
5. Delete the old key.

Steps 1 and 5 must not happen simultaneously. An old key that a workload still uses must not be deleted before the workload has been confirmed to use the new one.

## Monitoring Service Account Credential Usage for Anomalies

Correct provisioning reduces the attack surface; monitoring detects when it is breached.

**Detect credential use from unexpected sources.** A service account for a Lambda function should never produce calls from an EC2 instance or an external IP. A Kubernetes pod's SA should never issue API calls from outside the cluster.

AWS CloudTrail provides `sourceIPAddress` on every API call. Alert when a service account (identified by `userIdentity.arn`) makes calls from a source not matching its expected pattern — Lambda ARN, ECS task ARN, or a known IP range.

**Detect calls to unexpected services.** An SA scoped to S3 read access should never produce IAM or STS API calls. Alert on any service access that was not included in the SA's policy.

**Detect high call volumes at unusual times.** Automated workloads follow predictable call patterns. A spike in S3 ListBucket or GetObject calls at 3 AM from a service account that normally runs during business hours is worth investigating.

**Kubernetes audit policy.** Enable audit logging for all API calls made by service accounts:

```yaml
- level: Request
  users: ["system:serviceaccount:*"]
  verbs: ["create", "update", "patch", "delete"]
  resources:
  - group: ""
    resources: ["secrets", "configmaps", "serviceaccounts"]
```

Alert on any SA modifying secrets or creating new service accounts — those are lateral movement or persistence signals.

## Operational Checklist

Use this as a starting point for a quarterly service account review:

- [ ] All workloads on AWS EC2/ECS/Lambda use instance profiles, task roles, or execution roles — no IAM user keys in environment variables or secrets manager for workloads on AWS infrastructure
- [ ] IMDSv2 enforced on all EC2 instances
- [ ] All GCP workloads on GKE use Workload Identity — no SA key files attached to GKE workloads
- [ ] No GCP SA key files older than 90 days
- [ ] `automountServiceAccountToken: false` on the default service account in every Kubernetes namespace
- [ ] No Kubernetes SA bound to `cluster-admin` without documented justification reviewed in the past 90 days
- [ ] All CI/CD pipelines using OIDC workload identity rather than long-lived cloud provider credentials
- [ ] IAM Access Advisor / GCP Recommender reviewed; recommendations applied or documented as exceptions
- [ ] All service accounts have owner tags/labels
- [ ] Unused service accounts (no activity in 90 days) flagged for deletion
- [ ] CloudTrail / GCP audit logs / Kubernetes audit logs generating alerts on anomalous SA usage patterns
- [ ] SAs for decommissioned services deleted (not just disabled)

## Summary

Service accounts fail quietly. A key committed to a repo three years ago, an SA created for a prototype that never got deleted, a Kubernetes service account with cluster-admin "until we had time to scope it properly" — these are the starting points for most cloud intrusions.

The path forward is architectural, not just operational: replace static credentials with OIDC workload identity wherever possible, scope remaining SAs tightly, enforce naming and ownership conventions that make audits possible, and build monitoring that surfaces anomalies before they become incidents. Each of these steps is independently valuable; together they reduce service account risk from "common initial access vector" to "hardened, auditable, and monitored."
