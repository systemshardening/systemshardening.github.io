---
title: "Kubernetes OIDC Authentication and kubectl Access Control"
description: "Static kubeconfigs with long-lived certificates are the norm but not the standard. OIDC authentication gives kubectl short-lived tokens, group-based RBAC, and a full audit trail tied to real identities."
slug: "kubernetes-oidc-authentication"
date: 2026-04-30
lastmod: 2026-04-30
category: "kubernetes"
tags: ["oidc", "kubectl", "authentication", "rbac", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 248
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/kubernetes/kubernetes-oidc-authentication/index.html"
---

# Kubernetes OIDC Authentication and kubectl Access Control

## Problem

Most Kubernetes clusters authenticate human users via static kubeconfig files containing long-lived client certificates. These certificates share several structural problems:

- **No identity binding.** A certificate CN might say `alice`, but there is no link to the identity provider. When Alice leaves the organisation, her certificate remains valid until expiry (often 1 year).
- **No revocation.** Kubernetes has no native CRL or OCSP for client certificates. Revoking access requires rotating the CA (affecting all users) or waiting for expiry.
- **Shared certificates.** Teams share admin kubeconfigs stored in wikis, password managers, or Slack. The certificate holder is "admin", not a real person.
- **No MFA.** Client certificates cannot enforce MFA; possession of the certificate file is sufficient.
- **Audit trail by cert CN, not identity.** Kubernetes audit logs show `user: alice` but this is the certificate CN, not verified to be the real Alice.

OIDC authentication replaces this with tokens issued by an external identity provider (IdP) — Okta, Azure Entra, Google, Keycloak, Dex. Users authenticate to the IdP (with MFA), receive a short-lived JWT, and present it to the Kubernetes API server. The API server verifies the JWT signature against the IdP's public keys. Token lifetime is typically 1 hour. When a user leaves, disabling their IdP account immediately blocks kubectl access — no certificate rotation required.

The specific gaps this article addresses: API server OIDC configuration, mapping IdP groups to Kubernetes RBAC roles, `kubelogin` credential plugin for transparent token refresh, and distributing kubeconfigs without embedding credentials.

**Target systems:** Kubernetes 1.28+ (OIDC authenticator stable); any OIDC-compliant IdP (Okta, Azure Entra ID, Google Workspace, Keycloak 22+, Dex 2.37+); `kubelogin` v0.1.4+ (kubectl credential plugin).

## Threat Model

- **Adversary 1 — Exfiltrated static kubeconfig:** A developer's laptop is compromised. Their kubeconfig contains a long-lived certificate granting cluster-admin. The attacker has permanent cluster access until the certificate expires or the CA is rotated.
- **Adversary 2 — Departed employee retains access:** An employee leaves but their client certificate remains valid. They continue to access the cluster for months.
- **Adversary 3 — Shared admin kubeconfig:** The cluster admin kubeconfig is stored in a shared wiki. An attacker with wiki access has cluster-admin. No audit trail identifies which human performed which action.
- **Adversary 4 — Token theft after OIDC:** An attacker steals a valid OIDC JWT from the user's local token cache. The token is valid for its remaining lifetime (typically < 1 hour), then expires without refresh (refresh requires IdP re-authentication, which requires MFA).
- **Adversary 5 — Group membership manipulation:** An attacker compromises the IdP and adds themselves to a Kubernetes-mapped group (e.g., `kubernetes-admins`). They gain RBAC permissions tied to that group.
- **Access level:** Adversaries 1–3 have the credential file. Adversary 4 has filesystem access on the user's machine. Adversary 5 has IdP admin access.
- **Objective:** Execute arbitrary Kubernetes API operations, exfiltrate secrets, modify workloads, escalate privileges.
- **Blast radius:** Static kubeconfig theft = persistent cluster access. OIDC token theft = access limited to token lifetime (≤1h). OIDC with MFA enforcement = token theft requires MFA bypass to refresh.

## Configuration

### Step 1: Configure the API Server for OIDC

Add OIDC flags to the kube-apiserver configuration:

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml (kubeadm-managed cluster)
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        # Existing flags ...

        # OIDC configuration.
        - --oidc-issuer-url=https://accounts.google.com
        - --oidc-client-id=kubernetes-cluster-prod
        - --oidc-username-claim=email
        - --oidc-username-prefix=oidc:
        - --oidc-groups-claim=groups
        - --oidc-groups-prefix=oidc:
        - --oidc-required-claim=hd=example.com   # Restrict to your org's domain (Google).
```

For managed clusters (EKS, GKE, AKS), configure via the cluster API:

```bash
# EKS: configure OIDC provider.
eksctl utils associate-iam-oidc-provider \
  --cluster prod-cluster \
  --approve

# For kubectl OIDC (not IAM): use the API server OIDC flags via a custom config.
# EKS supports this via --oidc-issuer-url etc. in the cluster config.
eksctl create cluster \
  --name prod-cluster \
  --kubernetes-network-config apiServerConfig.oidc.issuerURL=https://your-idp.internal \
  --kubernetes-network-config apiServerConfig.oidc.clientID=kubernetes
```

For Keycloak as the IdP:

```bash
# Create a Keycloak client for Kubernetes.
kcadm.sh create clients -r master \
  -s clientId=kubernetes \
  -s 'redirectUris=["http://localhost:8000"]' \
  -s publicClient=false \
  -s standardFlowEnabled=true \
  -s directAccessGrantsEnabled=false

# Configure groups claim in the client mapper.
kcadm.sh create clients/{client-id}/protocol-mappers/models -r master \
  -s name=groups \
  -s protocol=openid-connect \
  -s protocolMapper=oidc-group-membership-mapper \
  -s 'config."claim.name"=groups' \
  -s 'config."full.path"=false' \
  -s 'config."access.token.claim"=true'
```

API server flags for Keycloak:

```yaml
- --oidc-issuer-url=https://keycloak.internal/realms/master
- --oidc-client-id=kubernetes
- --oidc-username-claim=preferred_username
- --oidc-username-prefix=oidc:
- --oidc-groups-claim=groups
- --oidc-groups-prefix=oidc:
```

### Step 2: Map IdP Groups to Kubernetes RBAC

With `--oidc-groups-prefix=oidc:`, group names from the JWT appear in Kubernetes as `oidc:group-name`. Bind them to roles:

```yaml
# clusterrolebinding-devs.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-developers
subjects:
  - kind: Group
    name: "oidc:kubernetes-developers"   # Maps to IdP group "kubernetes-developers".
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
---
# Namespace-scoped: developers can deploy in their team namespace.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: oidc-team-a-deploy
  namespace: team-a
subjects:
  - kind: Group
    name: "oidc:team-a"
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
---
# SRE team: read-only cluster-wide + exec into pods in production.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-sre-readonly
subjects:
  - kind: Group
    name: "oidc:sre-team"
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

Custom ClusterRole for the SRE exec capability:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-exec
rules:
  - apiGroups: [""]
    resources: ["pods/exec", "pods/portforward"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-sre-exec
subjects:
  - kind: Group
    name: "oidc:sre-team"
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: pod-exec
  apiGroup: rbac.authorization.k8s.io
```

### Step 3: Install and Configure kubelogin

`kubelogin` (also called `kubectl-oidc_login`) is a kubectl credential plugin that handles the OIDC browser-based authentication flow and token caching transparently:

```bash
# Install kubelogin.
# Linux.
curl -LO https://github.com/int128/kubelogin/releases/latest/download/kubelogin_linux_amd64.zip
unzip kubelogin_linux_amd64.zip && mv kubelogin /usr/local/bin/kubectl-oidc_login

# macOS via Homebrew.
brew install int128/kubelogin/kubelogin

# Verify.
kubectl oidc-login --help
```

### Step 4: Distribute kubeconfig Without Embedded Credentials

Generate a kubeconfig that uses the credential plugin instead of embedding a certificate or token:

```yaml
# kubeconfig-prod.yaml
apiVersion: v1
kind: Config
clusters:
  - name: prod
    cluster:
      server: https://api.prod.k8s.example.com
      certificate-authority-data: <base64-encoded-CA>
contexts:
  - name: prod
    context:
      cluster: prod
      user: oidc-user
current-context: prod
users:
  - name: oidc-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: kubectl
        args:
          - oidc-login
          - get-token
          - --oidc-issuer-url=https://accounts.google.com
          - --oidc-client-id=kubernetes-cluster-prod
          - --oidc-extra-scope=email
          - --oidc-extra-scope=groups
          - --grant-type=auto       # Browser flow for interactive; device flow for CI.
        env: null
        interactiveMode: IfAvailable
```

This kubeconfig contains no credentials. When a user runs `kubectl get pods`, kubelogin opens a browser, the user authenticates to the IdP (with MFA), and the resulting JWT is cached locally with a 1-hour TTL. Subsequent kubectl commands within that hour use the cached token silently.

Distribute this kubeconfig via an internal portal, not as a personal certificate:

```bash
# Users download the kubeconfig from an internal portal.
# No per-user customisation needed — OIDC maps identity at the IdP level.
curl -s https://cluster-portal.internal/kubeconfig/prod > ~/.kube/config
chmod 600 ~/.kube/config
```

### Step 5: Device Flow for CI/CD Pipelines

CI pipelines cannot perform interactive browser login. For automated contexts, use a service account token (separate from human OIDC) or the OIDC device flow with a dedicated CI client:

```yaml
# For CI pipelines: use a dedicated Kubernetes service account with narrow RBAC.
# Do NOT use OIDC device flow with human credentials in CI.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ci-deployer
  namespace: team-a
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ci-deployer-edit
  namespace: team-a
subjects:
  - kind: ServiceAccount
    name: ci-deployer
    namespace: team-a
roleRef:
  kind: ClusterRole
  name: edit
  apiGroup: rbac.authorization.k8s.io
```

Generate a short-lived token for CI:

```bash
# Generate a token with 1-hour expiry for the CI service account.
kubectl create token ci-deployer --namespace team-a --duration=3600s
```

This token is scoped to the `team-a` namespace and expires after 1 hour.

### Step 6: Structured Audit Logging with OIDC Identities

With OIDC, audit log entries contain the real user identity from the IdP:

```json
{
  "apiVersion": "audit.k8s.io/v1",
  "kind": "Event",
  "user": {
    "username": "oidc:alice@example.com",
    "groups": ["oidc:kubernetes-developers", "oidc:team-a", "system:authenticated"]
  },
  "verb": "get",
  "objectRef": {"resource": "secrets", "namespace": "production", "name": "db-password"},
  "responseStatus": {"code": 200}
}
```

This is the key audit improvement: `alice@example.com` is a verified IdP identity, not just a certificate CN.

```yaml
# kube-apiserver audit policy.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all secret access at RequestResponse level.
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]

  # Log all write operations on RBAC resources.
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterrolebindings", "rolebindings"]

  # Log all pod exec operations.
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods/exec", "pods/portforward"]

  # Minimal logging for read-only operations on non-sensitive resources.
  - level: Metadata
    verbs: ["get", "list", "watch"]

  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
      - group: ""
        resources: ["endpoints", "services"]
```

### Step 7: Token Rotation and Session Management

```bash
# Clear cached tokens (force re-authentication at next kubectl command).
kubelogin clean

# List cached tokens.
ls ~/.kube/cache/oidc-login/

# Configure shorter token lifetime in the IdP.
# Keycloak: access token lifespan = 1 hour (default is 5 minutes in some configs).
kcadm.sh update realms/master -s accessTokenLifespan=3600

# Revoke a user's access: disable their IdP account.
# The current token remains valid for its remaining lifetime (<= 1h).
# Immediate revocation: add the token to a denylist via the API server's
# TokenReview webhook (advanced; requires a custom webhook).
```

For immediate revocation without a TokenReview webhook: reduce token lifetime to 5 minutes in the IdP. The cost is more frequent browser re-authentication for users.

### Step 8: Telemetry

```
apiserver_authentication_attempts_total{result, authenticator}       counter
apiserver_audit_event_total                                          counter
oidc_token_cache_hit_total{user}                                     counter
oidc_token_refresh_total{user, result}                               counter
kubectl_oidc_login_duration_seconds{user}                            histogram
```

Alert on:

- `apiserver_authentication_attempts_total{result="error", authenticator="oidc"}` spike — OIDC auth failures; possible misconfiguration or token tampering attempt.
- Static certificate CN appearing in audit logs — someone using an old kubeconfig with a cert instead of OIDC; track down and rotate.
- Unexpected group in RBAC binding — a new `oidc:group-name` subject appearing in a RoleBinding; review whether the group was intentionally created.

## Expected Behaviour

| Signal | Static kubeconfig | OIDC authentication |
|--------|------------------|---------------------|
| Employee leaves | Certificate valid until expiry (up to 1 year) | Disable IdP account; next token refresh fails within 1 hour |
| Audit log identity | Certificate CN (unverified string) | Verified IdP email + group memberships |
| Stolen credential validity | Until certificate expiry | Token TTL remaining (≤ 1 hour) |
| MFA enforcement | Not possible with certificates | Enforced by IdP at every re-authentication |
| Credential rotation | Distribute new cert to each user | IdP handles; kubeconfig unchanged |
| First kubectl of the day | Instant (cert always present) | Browser opens; user authenticates; cached for 1 hour |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| OIDC browser flow | MFA; real identity in audit logs | Browser required for first daily auth | Acceptable for interactive use; use service accounts for CI. |
| 1-hour token lifetime | Short window of exposure if stolen | Re-authentication required each hour | kubelogin handles refresh silently if the IdP issues refresh tokens; only re-prompts when refresh expires. |
| IdP as dependency | Centralised access control | kubectl fails if IdP is unreachable | Maintain a break-glass static kubeconfig in a secure location for emergencies; never use day-to-day. |
| Group-based RBAC | Easy access control via IdP group management | IdP group changes propagate only on next token issue | Acceptable; token TTL bounds the lag. |
| kubelogin credential plugin | Transparent to kubectl usage | Requires installation on every developer workstation | Distribute via internal tooling or Homebrew tap. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| IdP unreachable | `kubectl` fails with OIDC token fetch error | User reports; monitoring on IdP availability | Use break-glass static kubeconfig; restore IdP; token cache may carry users for remaining TTL. |
| Clock skew between API server and IdP | JWT validation fails (`iat` or `exp` claim mismatch) | `apiserver_authentication_attempts_total{result="error"}` spike | Sync NTP on API server; typical leeway in `kubelogin` is 10s. |
| Group claim missing from JWT | User authenticates but has no RBAC permissions | 403 on all kubectl operations; missing group in `kubectl auth whoami` | Add the groups mapper to the IdP client; re-authenticate to get a token with groups. |
| kubelogin not installed | `kubectl: exec: "kubectl-oidc_login": executable file not found` | User reports; check `which kubectl-oidc_login` | Distribute kubelogin as part of the developer onboarding tooling installation. |
| Token cache corrupted | Repeated browser prompts; or stale token used | kubelogin errors; `kubelogin clean` resolves | `kubelogin clean` clears cache; user re-authenticates. |
| OIDC issuer URL changed | All OIDC auth fails; API server rejects tokens | Mass auth failure across all users | Update `--oidc-issuer-url` on API server; restart API server; users re-authenticate. |

## Related Articles

- [RBAC Design Patterns in Kubernetes](/articles/kubernetes/rbac-design-patterns/)
- [Kubernetes API Server Hardening](/articles/kubernetes/api-server-hardening/)
- [Service Account Token Security](/articles/kubernetes/service-account-tokens/)
- [OIDC Federation Hardening for CI-to-Cloud](/articles/cicd/oidc-federation-hardening/)
- [OAuth 2.0 and OIDC Implementation Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
