---
title: "Kubernetes Service Account Token Security: Bound Tokens, Projected Volumes, and OIDC"
description: "Every pod in Kubernetes receives a service account token by default. In clusters running older configurations or without explicit hardening, these..."
slug: "service-account-tokens"
date: 2026-01-01
lastmod: 2026-01-01
category: "kubernetes"
tags: ["kubernetes", "service-accounts", "tokens", "oidc", "workload-identity"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 25
difficulty: "intermediate"
estimated_reading_time: 19
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
published: true
layout: article.njk
permalink: "/articles/kubernetes/service-account-tokens/index.html"
---

# [Kubernetes](https://kubernetes.io) Service Account Token Security: Bound Tokens, Projected Volumes, and OIDC

## Problem

Every pod in Kubernetes receives a service account token by default. In clusters running older configurations or without explicit hardening, these tokens are long-lived, non-expiring JWTs stored at `/var/run/secrets/kubernetes.io/serviceaccount/token`. A compromised pod can use this token to authenticate to the API server and perform any action the service account is permitted to do.

The specific problems with legacy token behaviour:

- **Tokens never expire.** Legacy service account tokens (created via Secret objects) have no expiration. A token extracted from a compromised pod remains valid until the service account is deleted or the token secret is manually removed. Attackers can exfiltrate the token and use it from outside the cluster indefinitely.
- **Tokens are auto-mounted into every pod.** By default, Kubernetes mounts a service account token into every pod, even when the workload never communicates with the API server. A web server, a batch job, and a database all receive tokens they do not need.
- **The default service account has implicit permissions.** The `default` service account in each namespace accumulates RBAC bindings over time. When teams bind roles to `default` instead of creating per-workload service accounts, every pod in the namespace inherits those permissions.
- **Tokens are not audience-bound.** Legacy tokens can be used against any service that trusts the cluster's signing key, not just the API server. This broadens the blast radius of token theft.

Kubernetes 1.22+ introduced bound service account tokens that are time-limited, audience-bound, and object-bound. Kubernetes 1.24+ stopped auto-generating long-lived Secret-based tokens. This article covers configuring projected token volumes, disabling auto-mounting, using the TokenRequest API, and integrating with OIDC for cloud workload identity.

**Target systems:** Kubernetes 1.29+ with default service account token projection enabled (default since 1.21).

## Threat Model

- **Adversary:** Attacker with code execution inside a pod (via application vulnerability, dependency compromise, or SSRF that allows file reads), or an attacker with access to etcd backups or node filesystem snapshots.
- **Access level:** Read access to `/var/run/secrets/kubernetes.io/serviceaccount/token` inside a pod, or access to Secret objects stored in etcd.
- **Objective:** Use the stolen token to query the API server for secrets, create privileged pods, modify deployments, or escalate privileges. With OIDC-federated tokens, pivot to cloud provider APIs (AWS, GCP, Azure) using the Kubernetes identity.
- **Blast radius:** With a legacy non-expiring token bound to a service account with broad permissions, the attacker has persistent API server access until manually revoked. With bound tokens, access expires within the token lifetime (typically 1 hour) and is limited to the specified audience.

## Configuration

### Step 1: Disable Auto-Mounting on Service Accounts and Pods

For workloads that never need API server access (most web applications, batch jobs, databases), disable token auto-mounting at both the service account and pod levels:

```yaml
# no-token-service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: web-app
  namespace: production
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      serviceAccountName: web-app
      automountServiceAccountToken: false
      containers:
        - name: web
          image: registry.example.com/web-app:2.1.0
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
```

The pod-level setting overrides the service account setting. Set both for defense in depth: if someone changes the service account setting, the pod-level setting still blocks mounting.

Verify no token is mounted:

```bash
kubectl exec -n production deploy/web-app -- ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1
# Expected: ls: /var/run/secrets/kubernetes.io/serviceaccount/: No such file or directory
```

### Step 2: Use Projected Volumes for Workloads That Need API Access

For workloads that legitimately need to communicate with the API server (operators, controllers, CI/CD agents), use projected service account token volumes with explicit expiration and audience:

```yaml
# controller-with-bound-token.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: deployment-controller
  namespace: platform
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deployment-controller
  namespace: platform
spec:
  replicas: 1
  selector:
    matchLabels:
      app: deployment-controller
  template:
    metadata:
      labels:
        app: deployment-controller
    spec:
      serviceAccountName: deployment-controller
      automountServiceAccountToken: false
      containers:
        - name: controller
          image: registry.example.com/deploy-controller:1.8.0
          volumeMounts:
            - name: token
              mountPath: /var/run/secrets/tokens
              readOnly: true
            - name: ca-cert
              mountPath: /var/run/secrets/kubernetes.io/ca
              readOnly: true
          env:
            - name: KUBERNETES_SERVICE_HOST
              value: "kubernetes.default.svc"
            - name: KUBERNETES_SERVICE_PORT
              value: "443"
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
      volumes:
        - name: token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 3600
                  audience: "https://kubernetes.default.svc"
        - name: ca-cert
          projected:
            sources:
              - configMap:
                  name: kube-root-ca.crt
                  items:
                    - key: ca.crt
                      path: ca.crt
```

Key parameters for the projected token:

- **`expirationSeconds`**: Token lifetime. Minimum is 600 seconds (10 minutes). The kubelet automatically rotates the token when 80% of the lifetime has elapsed. Set to 3600 (1 hour) for most workloads.
- **`audience`**: The intended recipient of the token. The API server only accepts tokens with its own audience. Tokens with a different audience are rejected.

### Step 3: Use the TokenRequest API for Short-Lived Tokens

For scripts, jobs, or one-time operations that need a token with a specific lifetime, use the TokenRequest API directly:

```bash
# Request a token valid for 10 minutes
kubectl create token deployment-controller \
  --namespace platform \
  --duration 600s \
  --audience "https://kubernetes.default.svc"

# Use the token for a specific operation
TOKEN=$(kubectl create token deployment-controller -n platform --duration 600s)
kubectl --token="$TOKEN" get deployments -n production
```

For programmatic use inside a pod, call the TokenRequest API:

```yaml
# token-request-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: rotate-secrets
  namespace: platform
spec:
  template:
    spec:
      serviceAccountName: secret-rotator
      automountServiceAccountToken: false
      containers:
        - name: rotator
          image: registry.example.com/secret-rotator:1.2.0
          command:
            - /bin/sh
            - -c
            - |
              # Request a short-lived token via the API
              TOKEN=$(cat /var/run/secrets/tokens/token)
              curl -s -H "Authorization: Bearer $TOKEN" \
                --cacert /var/run/secrets/kubernetes.io/ca/ca.crt \
                https://kubernetes.default.svc/api/v1/namespaces/production/secrets
          volumeMounts:
            - name: token
              mountPath: /var/run/secrets/tokens
              readOnly: true
            - name: ca-cert
              mountPath: /var/run/secrets/kubernetes.io/ca
              readOnly: true
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
      volumes:
        - name: token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 600
                  audience: "https://kubernetes.default.svc"
        - name: ca-cert
          projected:
            sources:
              - configMap:
                  name: kube-root-ca.crt
                  items:
                    - key: ca.crt
                      path: ca.crt
      restartPolicy: Never
```

### Step 4: Clean Up Legacy Long-Lived Tokens

Identify and remove Secret-based service account tokens that were created by older Kubernetes versions:

```bash
# Find all legacy service account token secrets
kubectl get secrets --all-namespaces -o json | \
  jq -r '.items[] | select(.type=="kubernetes.io/service-account-token") |
  "\(.metadata.namespace)/\(.metadata.name) -> SA: \(.metadata.annotations["kubernetes.io/service-account.name"])"'

# Check if any workloads reference these secrets directly
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[] | select(.spec.volumes[]?.secret.secretName |
  test("token")) | "\(.metadata.namespace)/\(.metadata.name)"'

# Delete legacy token secrets (after verifying no workloads depend on them)
kubectl delete secret <legacy-token-secret> -n <namespace>
```

### Step 5: Configure OIDC Federation for Cloud Workload Identity

For workloads that need to access cloud provider APIs (S3, GCS, Azure Blob), federate Kubernetes service account tokens with cloud IAM instead of storing cloud credentials as Kubernetes secrets.

**AWS EKS IRSA (IAM Roles for Service Accounts):**

```yaml
# aws-workload-identity.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: s3-reader
  namespace: production
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/s3-reader-role"
automountServiceAccountToken: false
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: data-processor
  namespace: production
spec:
  replicas: 2
  selector:
    matchLabels:
      app: data-processor
  template:
    metadata:
      labels:
        app: data-processor
    spec:
      serviceAccountName: s3-reader
      containers:
        - name: processor
          image: registry.example.com/data-processor:3.0.1
          # EKS automatically injects the projected token and
          # AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE env vars
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
```

**GKE Workload Identity:**

```yaml
# gke-workload-identity.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gcs-writer
  namespace: production
  annotations:
    iam.gke.io/gcp-service-account: "gcs-writer@my-project.iam.gserviceaccount.com"
automountServiceAccountToken: false
```

```bash
# Bind the Kubernetes SA to the GCP SA
gcloud iam service-accounts add-iam-policy-binding \
  gcs-writer@my-project.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-project.svc.id.goog[production/gcs-writer]"
```

**Self-managed clusters with OIDC discovery:**

For non-cloud clusters, configure the API server to serve OIDC discovery documents so external systems can validate Kubernetes-issued tokens:

```bash
# API server flags for OIDC discovery
--service-account-issuer=https://oidc.example.com
--service-account-jwks-uri=https://oidc.example.com/openid/v1/jwks
--service-account-signing-key-file=/etc/kubernetes/pki/sa.key
```

External services can then validate projected tokens by fetching the JWKS from your issuer URL and verifying the JWT signature, audience, and expiration.

## Expected Behaviour

After configuring service account token security:

- Pods without `automountServiceAccountToken` overrides have no token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`
- Projected tokens rotate automatically; the kubelet refreshes them at 80% of the expiration time
- Expired tokens are rejected by the API server with `401 Unauthorized`
- Tokens with the wrong audience are rejected even if the signature is valid
- Legacy Secret-based tokens no longer exist in the cluster
- Cloud workloads authenticate to provider APIs using federated identity instead of stored credentials
- `kubectl auth can-i` correctly reports permissions for each service account

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Disable auto-mounting globally | Pods cannot reach the API server unless explicitly configured | Workloads that silently depended on the auto-mounted token break (health checks that query the API, sidecar containers) | Audit all workloads for API server usage before disabling. Roll out namespace by namespace |
| Short token expiration (600-3600s) | Stolen tokens expire quickly, limiting attacker window | Applications that cache tokens and do not handle refresh fail after token expiry | Use client libraries that support automatic token refresh (client-go, all official SDKs). Test with short expirations in staging |
| Audience-bound tokens | Tokens only work against the intended service | Applications that use the same token for multiple services fail | Issue separate tokens for each audience using multiple projected volume sources |
| Remove legacy token secrets | Eliminates long-lived credential exposure | Breaks any external system that was using a legacy token to access the cluster | Identify all consumers of legacy tokens before deletion. Issue short-lived tokens via TokenRequest API as replacements |
| OIDC federation | No cloud credentials stored as Kubernetes secrets | Adds dependency on OIDC discovery endpoint availability | Monitor the OIDC issuer endpoint. For self-managed clusters, ensure the issuer URL is highly available |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Auto-mounting disabled on a workload that needs API access | Application logs show "connection refused" or "unauthorized" when contacting the API server | Application error logs; pod events showing readiness probe failures | Add a projected volume with appropriate audience and expiration to the pod spec |
| Token expiration too short | Frequent 401 errors in application logs during token rotation windows | Spike in API server 401 responses; application log monitoring | Increase `expirationSeconds` to 3600. Ensure the application re-reads the token file on each request rather than caching it at startup |
| OIDC issuer unreachable | Cloud workloads cannot exchange tokens for cloud credentials; API calls to AWS/GCP/Azure fail | Cloud SDK errors in application logs; IAM authentication failures in cloud provider logs | Check OIDC discovery endpoint availability. For self-managed issuers, verify the endpoint is accessible from the cloud provider's token exchange service |
| Legacy token deletion breaks external integration | CI/CD pipelines, monitoring tools, or external services lose cluster access | Authentication failures in external tool logs; pipeline failures | Create a new short-lived token using `kubectl create token` and update the external system. Migrate to OIDC-based authentication for external access |
| Projected volume misconfiguration | Pod fails to start with "projected volume source not found" or token file is empty | `kubectl describe pod` shows volume mount errors; application cannot read token file | Verify the service account exists, the projected volume spec is valid, and the audience string matches the target service |

## When to Consider a Managed Alternative

**Transition point:** Managing service account tokens is straightforward for small clusters with a handful of workloads. When your cluster runs 50+ workloads across multiple namespaces, auditing token usage, cleaning up legacy tokens, and maintaining OIDC federation becomes a recurring time investment. If your team spends more than 4 hours per month on service account token management and auditing, automation tools provide significant value.

**Recommended providers:**

- **Managed Kubernetes (EKS, GKE, AKS):** Workload identity federation is built in. EKS IRSA and GKE Workload Identity eliminate the need for stored cloud credentials entirely. Token projection and rotation are configured by default.
- **[Sysdig](https://sysdig.com):** Detects pods with auto-mounted tokens that never use API server access, identifies legacy long-lived tokens, and alerts on service accounts with excessive permissions. Provides continuous compliance monitoring for token security.

**What you still control:** The decision of which workloads need API server access, the RBAC permissions bound to each service account, token expiration policies, and the OIDC audience configuration for each external service integration.


## Related Articles

- [Kubernetes API Server Hardening: Flags, Authentication, and Audit Logging](/articles/kubernetes/api-server-hardening/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
- [Kubelet Security Configuration: Authentication, Authorization, and Read-Only Port](/articles/kubernetes/kubelet-security/)
