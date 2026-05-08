---
title: "Kubernetes API Server Hardening: Flags, Authentication, and Audit Logging"
description: "The API server is the front door to the Kubernetes cluster. Every kubectl command, every controller reconciliation, every pod scheduling decision,..."
slug: "api-server-hardening"
date: 2026-02-15
lastmod: 2026-02-15
category: "kubernetes"
tags: ["kubernetes", "api-server", "authentication", "audit-logging", "oidc"]
personas: ["platform-engineer", "security-engineer"]
article_number: 23
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
published: true
layout: article.njk
permalink: "/articles/kubernetes/api-server-hardening/index.html"
---

# [Kubernetes](https://kubernetes.io) API Server Hardening: Flags, Authentication, and Audit Logging

## Problem

The API server is the front door to the Kubernetes cluster. Every kubectl command, every controller reconciliation, every pod scheduling decision, and every secret read passes through it. On self-managed clusters, the API server exposes 20+ configurable flags that directly affect security posture. A single misconfiguration can undermine every other security control you have in place.

The most common misconfigurations:

- **Anonymous authentication enabled.** By default, `--anonymous-auth=true` allows unauthenticated requests to reach the API server. While RBAC typically blocks them from doing anything useful, anonymous auth has been the entry point for multiple CVEs where unauthenticated users could access kubelet APIs or retrieve cluster information.
- **No audit logging.** Without audit logs, you have no record of who accessed what, when secrets were read, or what changes were made. After a breach, you have no forensic data.
- **Client certificate authentication for human users.** Client certificates cannot be revoked without rotating the entire CA. When an employee leaves, their certificate remains valid until it expires. OIDC authentication with your identity provider solves this.
- **Missing admission plugins.** Plugins like `NodeRestriction` (prevents nodes from modifying other nodes' objects) and `PodSecurity` (enforces Pod Security Standards) are not always enabled in self-managed clusters.
- **No rate limiting.** Without `--max-requests-inflight` and `--max-mutating-requests-inflight`, a single misbehaving controller or script can overwhelm the API server and cause a cluster-wide outage.

**Target systems:** Self-managed Kubernetes 1.29+ (kubeadm, k3s, RKE2). Managed Kubernetes providers (EKS, GKE, AKS) handle most API server flags for you; this article explicitly highlights what managed providers handle versus what remains your responsibility.

## Threat Model

- **Adversary:** External attacker scanning for exposed API servers, malicious insider with valid credentials, or compromised application making unauthorized API calls via a stolen service account token.
- **Access level:** Ranges from unauthenticated (if anonymous auth is enabled and the API server is exposed) to fully authenticated user with excessive RBAC permissions.
- **Objective:** Cluster enumeration (discover namespaces, services, and secrets), credential theft (read secrets via the API), privilege escalation (create privileged pods, modify RBAC), and persistent access (create new service accounts or certificates).
- **Blast radius:** The API server is the single point of control for the entire cluster. Compromise of the API server is equivalent to compromise of every workload, secret, and configuration in the cluster.

## Configuration

### Step 1: Disable Anonymous Authentication

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml (kubeadm)
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --anonymous-auth=false
        # ... other flags ...
```

```bash
# Verify anonymous auth is disabled:
curl -k https://<api-server-ip>:6443/api/v1/namespaces
# Expected: 401 Unauthorized
# If you get a 403 Forbidden, anonymous auth is enabled but RBAC is blocking.
# If you get a 200 with data, the cluster is critically misconfigured.
```

**Note:** Some health check endpoints (`/healthz`, `/livez`, `/readyz`) need to remain accessible without authentication for load balancer health checks. Kubernetes handles this by allowing these specific endpoints even with `--anonymous-auth=false`.

### Step 2: Configure OIDC Authentication

Replace client certificate authentication for human users with OIDC from your identity provider (Keycloak, Okta, Azure AD, Google Workspace).

```yaml
# API server OIDC flags
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --oidc-issuer-url=https://keycloak.example.com/realms/kubernetes
        - --oidc-client-id=kubernetes
        - --oidc-username-claim=email
        - --oidc-username-prefix="oidc:"
        - --oidc-groups-claim=groups
        - --oidc-groups-prefix="oidc:"
        - --oidc-ca-file=/etc/kubernetes/pki/oidc-ca.crt
```

**kubeconfig for OIDC users:**

```yaml
# ~/.kube/config
apiVersion: v1
kind: Config
clusters:
  - name: production
    cluster:
      server: https://api.k8s.example.com:6443
      certificate-authority-data: <base64-ca-cert>
contexts:
  - name: production
    context:
      cluster: production
      user: oidc-user
users:
  - name: oidc-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1beta1
        command: kubectl
        args:
          - oidc-login
          - get-token
          - --oidc-issuer-url=https://keycloak.example.com/realms/kubernetes
          - --oidc-client-id=kubernetes
          - --oidc-client-secret=<client-secret>
```

Install the `kubectl oidc-login` plugin:

```bash
# Install kubelogin (OIDC helper)
kubectl krew install oidc-login

# Test authentication:
kubectl get nodes
# Browser opens for OIDC login. After authentication,
# kubectl receives a token and the command completes.
```

**RBAC binding for OIDC groups:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-cluster-viewer
subjects:
  - kind: Group
    name: "oidc:platform-engineers"
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
```

### Step 3: Enable Audit Logging

Audit logging records every API request with configurable detail levels.

```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Do not log requests to health endpoints
  - level: None
    nonResourceURLs:
      - /healthz*
      - /livez*
      - /readyz*
      - /metrics

  # Do not log watch requests (very noisy)
  - level: None
    verbs: ["watch"]

  # Log secret access at RequestResponse level (full request and response bodies)
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]

  # Log RBAC changes at RequestResponse level
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

  # Log authentication-related resources
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["serviceaccounts", "serviceaccounts/token"]

  # Log pod creation and deletion at Request level
  - level: Request
    resources:
      - group: ""
        resources: ["pods"]
    verbs: ["create", "delete"]

  # Log everything else at Metadata level
  - level: Metadata
    resources:
      - group: ""
      - group: "apps"
      - group: "batch"
```

**API server flags for audit logging:**

```yaml
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
        - --audit-log-path=/var/log/kubernetes/audit.log
        - --audit-log-maxage=30
        - --audit-log-maxbackup=10
        - --audit-log-maxsize=100
        # ... other flags ...
      volumeMounts:
        - name: audit-policy
          mountPath: /etc/kubernetes/audit-policy.yaml
          readOnly: true
        - name: audit-log
          mountPath: /var/log/kubernetes
  volumes:
    - name: audit-policy
      hostPath:
        path: /etc/kubernetes/audit-policy.yaml
        type: File
    - name: audit-log
      hostPath:
        path: /var/log/kubernetes
        type: DirectoryOrCreate
```

**Query audit logs for suspicious activity:**

```bash
# Find all secret reads in the last hour:
cat /var/log/kubernetes/audit.log | \
  jq -r 'select(.verb == "get" and .objectRef.resource == "secrets") |
    "\(.requestReceivedTimestamp) \(.user.username) read secret \(.objectRef.namespace)/\(.objectRef.name)"'

# Find all RBAC changes:
cat /var/log/kubernetes/audit.log | \
  jq -r 'select(.objectRef.apiGroup == "rbac.authorization.k8s.io" and
    (.verb == "create" or .verb == "update" or .verb == "delete")) |
    "\(.requestReceivedTimestamp) \(.user.username) \(.verb) \(.objectRef.resource) \(.objectRef.name)"'

# Find failed authentication attempts:
cat /var/log/kubernetes/audit.log | \
  jq -r 'select(.responseStatus.code >= 401 and .responseStatus.code <= 403) |
    "\(.requestReceivedTimestamp) \(.sourceIPs[0]) \(.responseStatus.code) \(.requestURI)"'
```

### Step 4: Enable Required Admission Plugins

```yaml
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --enable-admission-plugins=NodeRestriction,PodSecurity,ServiceAccount,ResourceQuota,LimitRanger
```

| Plugin | Purpose | Risk if disabled |
|--------|---------|-----------------|
| `NodeRestriction` | Prevents nodes from modifying pods/nodes that are not assigned to them | A compromised node can modify any pod or node in the cluster |
| `PodSecurity` | Enforces Pod Security Standards | Privileged containers can be deployed in any namespace |
| `ServiceAccount` | Automates service account token injection | Pods get no service account token (breaks most controllers) |
| `ResourceQuota` | Enforces resource quotas per namespace | A single namespace can consume all cluster resources |
| `LimitRanger` | Sets default resource limits | Pods without resource limits can starve other pods |

### Step 5: Configure Rate Limiting

```yaml
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --max-requests-inflight=400
        - --max-mutating-requests-inflight=200
        # Priority and Fairness (replaces simple rate limiting in 1.29+)
        - --enable-priority-and-fairness=true
```

Priority and Fairness provides more granular control than simple request limits:

```yaml
# flow-schema-limit-ci.yaml
# Limit CI/CD service accounts to prevent them from overwhelming the API server
apiVersion: flowcontrol.apiserver.k8s.io/v1
kind: FlowSchema
metadata:
  name: ci-cd-limited
spec:
  priorityLevelConfiguration:
    name: ci-cd
  matchingPrecedence: 1000
  rules:
    - subjects:
        - kind: ServiceAccount
          serviceAccount:
            name: ci-deployer
            namespace: "*"
      resourceRules:
        - apiGroups: ["*"]
          resources: ["*"]
          verbs: ["*"]
          namespaces: ["*"]
---
apiVersion: flowcontrol.apiserver.k8s.io/v1
kind: PriorityLevelConfiguration
metadata:
  name: ci-cd
spec:
  type: Limited
  limited:
    nominalConcurrencyShares: 10
    limitResponse:
      type: Queue
      queuing:
        queues: 16
        handSize: 4
        queueLengthLimit: 50
```

### Step 6: Restrict API Server Network Access

```bash
# The API server should only be accessible from:
# 1. Nodes in the cluster (kubelet, kube-proxy)
# 2. Developer/admin workstations (via VPN or bastion)
# 3. CI/CD systems

# If using iptables on the control plane node:
iptables -A INPUT -p tcp --dport 6443 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 6443 -s 192.168.1.0/24 -j ACCEPT  # VPN range
iptables -A INPUT -p tcp --dport 6443 -j DROP
```

## Expected Behaviour

After hardening the API server:

- Unauthenticated requests to the API server return 401 Unauthorized
- Human users authenticate via OIDC (browser-based login flow)
- All API requests are logged in the audit log with timestamps, user identity, and resource details
- Secret access is logged at RequestResponse level (full content recorded for forensics)
- RBAC changes are logged at RequestResponse level
- NodeRestriction prevents nodes from modifying objects outside their scope
- Rate limiting prevents any single client from overwhelming the API server
- Failed authentication attempts are visible in audit logs for monitoring

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Disable anonymous auth | Health check endpoints still work; unauthenticated clients get 401 | Load balancers or monitoring tools that rely on anonymous access to `/api` break | Update health checks to use `/healthz` (works without auth) or configure a service account token for the monitoring tool |
| OIDC authentication | Users must authenticate via browser; no more static kubeconfig with embedded certificate | OIDC provider downtime prevents human access to the cluster | Maintain one emergency client certificate for break-glass access. Store it offline, not in any kubeconfig. Document the break-glass procedure |
| Audit logging at RequestResponse level for secrets | Full secret content is recorded in audit logs | Audit logs themselves become a sensitive data store; compromise of audit logs exposes all secrets that were accessed | Encrypt audit log storage. Restrict access to audit logs to security team only. Consider logging only Metadata level for secrets if full content is not needed |
| Rate limiting | Protects API server from overload | Legitimate high-throughput controllers may be throttled | Tune Priority and Fairness settings. Assign higher priority to system-critical controllers. Monitor 429 responses |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| OIDC provider unreachable | Human users cannot authenticate; kubectl commands fail with token errors | kubectl shows "unable to connect to OIDC provider"; monitoring alerts on OIDC endpoint health | Use the break-glass client certificate. Restore OIDC provider access. Service account tokens and node authentication are not affected by OIDC outage |
| Audit log volume fills disk | API server stops writing audit logs or crashes if the log volume is full | Disk usage alerts on `/var/log/kubernetes`; API server process exits | Increase disk size. Reduce audit log retention (`--audit-log-maxage`). Ship logs to external storage ([Elasticsearch](https://www.elastic.co/elasticsearch), S3) and reduce local retention |
| Rate limiting too aggressive | Legitimate controllers are throttled; pods take longer to schedule; deployments are slow | 429 (Too Many Requests) responses in controller logs; API server metrics show queued requests | Increase `nominalConcurrencyShares` for affected priority levels. Monitor `apiserver_flowcontrol_rejected_requests_total` metric |
| Admission plugin ordering wrong | API server fails to start | API server pod in CrashLoopBackOff; kubelet logs show admission plugin error | Fix the `--enable-admission-plugins` flag. Remove any plugins that conflict or are not available |
| Audit policy too broad | Audit logs are massive (gigabytes per day); disk fills quickly | Rapid disk consumption; high I/O on control plane node | Add `level: None` rules for high-volume, low-value requests (list/watch on configmaps, events). Keep RequestResponse only for secrets and RBAC |

## When to Consider a Managed Alternative

**Transition point:** API server hardening on self-managed clusters requires configuring 10+ flags correctly, maintaining audit policies, managing OIDC integration, and monitoring rate limits. Every Kubernetes upgrade requires reviewing these settings. Managed providers handle all API server flags, provide built-in audit logging (often with integrated SIEM), and manage OIDC integration through their IAM systems.

**Recommended providers:**

- **[Sysdig](https://sysdig.com):** Provides API server audit log analysis, detects anomalous API access patterns (unusual secret reads, RBAC modifications outside change windows), and alerts on suspicious activity. Useful for both managed and self-managed clusters.

**What you still control on managed providers:** RBAC configuration, audit log retention and analysis, and network access restrictions (who can reach the API server endpoint). The provider handles the API server flags, TLS configuration, admission plugin management, and high availability.

**What this article shows about the self-managed burden:** Every section above is work that managed providers do for you. If your team spends more than 4 hours per month on API server configuration, upgrades, and audit log management, the operational cost exceeds what most teams budget for infrastructure security.


## Related Articles

- [Kubelet Security Configuration: Authentication, Authorization, and Read-Only Port](/articles/kubernetes/kubelet-security/)
- [Kubernetes Service Account Token Security: Bound Tokens, Projected Volumes, and OIDC](/articles/kubernetes/service-account-tokens/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
- [Kubernetes RBAC Design Patterns: Least Privilege Without Paralysing Developers](/articles/kubernetes/rbac-design-patterns/)
