---
title: "Cluster API Security for Kubernetes Fleet Management"
description: "Secure Cluster API (CAPI) deployments by hardening controller RBAC, provider credentials, bootstrap token lifecycle, and Machine provisioning pipelines."
slug: cluster-api-security
date: 2026-05-02
lastmod: 2026-05-02
category: kubernetes
tags: ["cluster-api", "capi", "fleet-management", "bootstrap", "iam", "multi-cluster"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 328
difficulty: advanced
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/kubernetes/cluster-api-security/index.html"
---

# Cluster API Security for Kubernetes Fleet Management

## Problem

Cluster API (CAPI) is a Kubernetes project that brings declarative, Kubernetes-style APIs to cluster lifecycle management. Instead of running shell scripts, Terraform modules, or cloud-vendor wizards to create workload clusters, platform teams create `Cluster`, `Machine`, `MachineDeployment`, and `KubeadmControlPlane` custom resources inside a dedicated management cluster. CAPI controllers reconcile those resources against cloud provider APIs to provision, upgrade, scale, and delete entire Kubernetes clusters on demand. The appeal is enormous: cluster creation becomes a `kubectl apply`, upgrades become a field update, and fleet consistency becomes policy-as-code. The security implications are equally large, and they are underappreciated in most CAPI adoption stories.

The management cluster is the single most sensitive system in a CAPI fleet. It holds cloud provider credentials — service account keys, IAM role bindings, or federated identity tokens — for every workload cluster it manages. Those credentials are scoped to provision compute, networking, storage, and identity resources across an entire cloud account or subscription. An attacker who gains `cluster-admin` on the management cluster, or who can exec into a CAPI controller pod, effectively holds credentials to provision or destroy compute across the entire fleet. The blast radius is not limited to Kubernetes: IAM roles with broad EC2 permissions can be used to exfiltrate data from S3, modify VPC routes, or pivot to other AWS services entirely. This is a qualitatively different threat profile from compromising a single workload cluster.

Bootstrap tokens are short-lived Kubernetes secrets used during the `kubeadm` node join process. A new node presents the token to the API server to retrieve its TLS bootstrap credentials. CAPI creates these tokens automatically during `Machine` provisioning and embeds them in node cloud-init UserData. The CAPI specification defaults allow TTLs of one hour or more. If a node takes longer than expected to boot — due to AMI pull time, cloud capacity constraints, or network issues — operators sometimes respond by increasing the TTL rather than investigating the underlying cause. A bootstrap token with a long TTL sitting in `kube-system` is a standing invitation: any actor who can read that secret, or who intercepts the UserData through the cloud metadata service, can join an unauthorized node to the cluster until the token expires.

CAPI providers — CAPA for AWS, CAPZ for Azure, CAPG for GCP, and others — require IAM permissions that are difficult to scope minimally. Provisioning a cluster requires creating EC2 instances, load balancers, security groups, subnets, IAM instance profiles, EBS volumes, and Route 53 records. Most teams start with the example IAM policies from provider documentation and never revisit them. Those example policies are intentionally broad to minimize setup friction. In production, a single shared IAM role used by the CAPA controller for all managed clusters means that credential compromise affects every cluster in the fleet regardless of workload criticality, environment, or business unit.

ClusterClass, introduced in CAPI v1.2 as part of the topology feature, centralizes cluster template definitions. A ClusterClass defines a reusable skeleton for control plane and worker configuration, and individual `Cluster` resources reference it via `spec.topology.class`. This reduces configuration duplication and enables fleet-wide upgrades by updating a single ClusterClass. The security implication is that ClusterClass becomes a high-value target: a mutation to the template propagates to every cluster referencing it. An attacker or misconfigured automation pipeline with write access to a ClusterClass can change machine types, inject UserData, alter network configuration, or disable security controls fleet-wide without touching individual cluster objects.

Most CAPI fleets are managed via GitOps — Flux or Argo CD applies cluster manifests from a Git repository to the management cluster. This is the correct operational pattern, but it shifts the security boundary to the Git repository and the GitOps tooling. Branch protection rules, required reviewers for the `clusters/` directory, and the RBAC constraints on the GitOps service account all become part of the cluster security posture. A developer who can push directly to the main branch, or who can approve their own pull requests, effectively has the ability to create, modify, or delete clusters without human review.

**Target systems:** Cluster API v1.7+, CAPA v2.x (AWS), CAPZ v1.x (Azure), clusterctl v1.7+.

## Threat Model

1. **Management cluster compromise for fleet-wide credential access.** An attacker gains code execution inside the management cluster — through a vulnerable workload, a misconfigured admission policy, or a stolen kubeconfig. They locate the `AWSClusterControllerIdentity` or provider secret, extract cloud credentials, and use them to provision unauthorized EC2 instances, read S3 buckets, or pivot to other services. All workload clusters managed by the compromised controller are affected.

2. **Developer with Machine write access provisioning unauthorized compute.** A developer granted write access to `Machine` or `MachineDeployment` objects — for troubleshooting or scaling purposes — creates additional machines in a production cluster outside of the normal change process. Without cost controls or MachineDeployment quotas, they can provision GPU instances, overprovision capacity, or cause cloud account spending spikes. With a custom `AWSMachineTemplate` referencing a backdoored AMI, the unauthorized node joins the cluster and runs attacker-controlled workloads.

3. **Bootstrap token reuse by rogue node.** A bootstrap token with a TTL of one hour is embedded in a Machine's cloud-init UserData. The intended node never boots — cloud capacity is unavailable, or the machine is deleted after a failed join attempt. The token remains valid in `kube-system`. Thirty minutes later, an attacker who has read the token from the cloud metadata service, from a leaked UserData log, or from a compromised secrets store uses it to join an unauthorized node to the cluster. The node receives a valid client certificate and appears as a legitimate cluster member.

4. **ClusterClass mutation escaping template constraints.** An attacker or misconfigured CI pipeline with write access to a ClusterClass modifies the worker `MachineTemplate` reference to one with `hostNetwork: true` or a privileged container in the JoinConfiguration. Because ClusterClass changes propagate during the next reconciliation cycle to all referencing clusters, every managed cluster that reconciles the topology upgrade deploys the modified — and now privileged — node configuration.

The blast radius across all four scenarios extends beyond Kubernetes. Cloud credential compromise enables actions against the cloud control plane: creating new IAM users, modifying S3 bucket policies, altering VPC firewall rules. Bootstrap token abuse produces nodes that are trusted members of the workload cluster's control plane trust domain. ClusterClass mutations affect every cluster in the fleet simultaneously rather than a single workload cluster. CAPI fleet management concentrates risk in a way that individual cluster management does not, and defenses must be proportionally stronger.

## Configuration / Implementation

### Management Cluster Isolation

The management cluster must not run production workloads. Mixing workload deployments with CAPI controllers means that a compromised workload application can access controller service account tokens through the shared API server. Dedicate a small, hardened cluster exclusively to fleet management. For cost-sensitive environments, a single-node or three-node management cluster running on minimal instance types is acceptable; the criticality of the cluster does not correlate with its size.

Apply `PodSecurityStandard` `restricted` to all CAPI namespaces to prevent controllers themselves from running as root or with elevated capabilities:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: capi-system
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
---
apiVersion: v1
kind: Namespace
metadata:
  name: capa-system
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

Restrict CAPI controller egress to only cloud API endpoints using NetworkPolicy. CAPI controllers have no legitimate reason to initiate connections to workload cluster pod CIDRs or internal RFC 1918 ranges other than the cloud API:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: capa-controller-egress
  namespace: capa-system
spec:
  podSelector:
    matchLabels:
      control-plane: capa-controller-manager
  policyTypes:
    - Egress
  egress:
    # Allow DNS resolution
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    # Allow AWS API endpoints (resolve via DNS, so allow 443 broadly)
    - ports:
        - port: 443
          protocol: TCP
    # Allow management cluster API server
    - ports:
        - port: 6443
          protocol: TCP
```

### Provider Credential Scoping (CAPA / AWS)

Replace static credentials with IRSA (IAM Roles for Service Accounts). The CAPA controller service account in `capa-system` should assume a role whose trust policy requires the EKS OIDC condition matching that specific service account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLEOIDCID"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLEOIDCID:sub": "system:serviceaccount:capa-system:capa-controller-manager",
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLEOIDCID:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

Use per-workload-cluster IAM roles by creating a dedicated `AWSClusterRoleIdentity` for each workload cluster rather than relying on the default `AWSClusterControllerIdentity`. This limits the credential blast radius to one cluster:

```yaml
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: AWSClusterRoleIdentity
metadata:
  name: production-us-east-1-identity
  namespace: clusters
spec:
  allowedNamespaces:
    list:
      - clusters
  roleARN: arn:aws:iam::111122223333:role/capa-production-us-east-1
  sessionName: capa-production-us-east-1
  durationSeconds: 3600
---
apiVersion: cluster.x-k8s.io/v1beta1
kind: Cluster
metadata:
  name: production-us-east-1
  namespace: clusters
spec:
  infrastructureRef:
    apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
    kind: AWSCluster
    name: production-us-east-1
  # ... other fields
---
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: AWSCluster
metadata:
  name: production-us-east-1
  namespace: clusters
spec:
  region: us-east-1
  identityRef:
    kind: AWSClusterRoleIdentity
    name: production-us-east-1-identity
```

Apply an SCP deny-override on the management account to prevent the CAPA role from performing actions outside its intended scope, such as creating IAM users or modifying billing settings:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCAPAEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:AttachUserPolicy",
        "organizations:*",
        "account:*"
      ],
      "Resource": "*",
      "Condition": {
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::111122223333:role/capa-*"
        }
      }
    }
  ]
}
```

### Bootstrap Token Hardening

Set `bootstrapTokenTTL` to fifteen minutes or less in both `KubeadmControlPlane` and `KubeadmConfigTemplate`. This window must be long enough for the cloud instance to boot, pull the container runtime, and reach the API server, but short enough that a token from a failed provisioning attempt cannot be reused:

```yaml
apiVersion: controlplane.cluster.x-k8s.io/v1beta1
kind: KubeadmControlPlane
metadata:
  name: production-control-plane
  namespace: clusters
spec:
  kubeadmConfigSpec:
    clusterConfiguration: {}
    initConfiguration:
      bootstrapTokens:
        - ttl: 15m0s
          usages:
            - signing
            - authentication
          groups:
            - system:bootstrappers:kubeadm:default-node-token
    joinConfiguration:
      nodeRegistration:
        kubeletExtraArgs:
          cloud-provider: external
---
apiVersion: bootstrap.cluster.x-k8s.io/v1beta1
kind: KubeadmConfigTemplate
metadata:
  name: production-workers
  namespace: clusters
spec:
  template:
    spec:
      joinConfiguration:
        nodeRegistration:
          kubeletExtraArgs:
            cloud-provider: external
      # CAPI generates bootstrap tokens; enforce TTL via MachineDeployment rollout strategy
```

Audit expired and orphaned bootstrap tokens regularly. CAPI does not always clean up tokens from machines that failed to join:

```bash
# List all bootstrap tokens with their expiration times
kubectl get secrets -n kube-system \
  --field-selector type=bootstrap.kubernetes.io/token \
  -o custom-columns='NAME:.metadata.name,EXPIRATION:.data.expiration' | \
  while read name exp; do
    echo "$name expires $(echo $exp | base64 -d)"
  done

# Delete expired bootstrap tokens older than 1 hour
kubectl get secrets -n kube-system \
  --field-selector type=bootstrap.kubernetes.io/token \
  -o json | \
  jq -r '.items[] | select(.data.expiration != null) | .metadata.name' | \
  xargs -r kubectl delete secret -n kube-system
```

### RBAC for CAPI CRDs

Platform teams who create and manage clusters need write access to core CAPI CRDs. Developers who request clusters through a self-service interface should have read-only access at most, with actual cluster creation mediated by a GitOps workflow and human review:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: capi-platform-admin
rules:
  - apiGroups: ["cluster.x-k8s.io"]
    resources:
      - clusters
      - machines
      - machinedeployments
      - machinesets
      - machinehealthchecks
      - clusterclasses
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["infrastructure.cluster.x-k8s.io"]
    resources: ["*"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["controlplane.cluster.x-k8s.io"]
    resources: ["*"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["bootstrap.cluster.x-k8s.io"]
    resources: ["*"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: capi-developer-readonly
rules:
  - apiGroups: ["cluster.x-k8s.io"]
    resources:
      - clusters
      - machines
      - machinedeployments
      - machinesets
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: capi-platform-admin-binding
subjects:
  - kind: Group
    name: platform-team
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: capi-platform-admin
  apiGroup: rbac.authorization.k8s.io
```

Use `ClusterClass` with `allowedTopologies` in the workers topology to constrain what instance types developers can request through a self-service `Cluster` object:

```yaml
apiVersion: cluster.x-k8s.io/v1beta1
kind: ClusterClass
metadata:
  name: standard-production
  namespace: clusters
spec:
  workers:
    machineDeployments:
      - class: default-worker
        template:
          bootstrap:
            ref:
              apiVersion: bootstrap.cluster.x-k8s.io/v1beta1
              kind: KubeadmConfigTemplate
              name: standard-production-worker-bootstrap
          infrastructure:
            ref:
              apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
              kind: AWSMachineTemplate
              name: standard-production-worker
        machineHealthCheck:
          maxUnhealthy: 33%
          nodeStartupTimeout: 10m
          unhealthyConditions:
            - type: Ready
              status: Unknown
              timeout: 300s
            - type: Ready
              status: "False"
              timeout: 300s
  variables:
    - name: workerInstanceType
      required: true
      schema:
        openAPIV3Schema:
          type: string
          enum:
            - m6i.large
            - m6i.xlarge
            - m6i.2xlarge
          description: "Allowed worker instance types"
```

### Machine Image Pinning

Pin AMI references in `AWSMachineTemplate` to specific AMI IDs validated by your image pipeline. Avoid `filters` selectors that resolve at provision time and can be influenced by AMI tag manipulation:

```yaml
apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
kind: AWSMachineTemplate
metadata:
  name: production-worker-v1-29-4
  namespace: clusters
spec:
  template:
    spec:
      instanceType: m6i.xlarge
      ami:
        id: ami-0a1b2c3d4e5f67890   # Pinned; validated by AMI pipeline on 2026-04-28
      iamInstanceProfile: production-nodes-instance-profile
      sshKeyName: ""   # Disable SSH key injection; use SSM Session Manager
      additionalSecurityGroups:
        - id: sg-0abc123def456789a
      rootVolume:
        size: 50
        type: gp3
        encrypted: true
      nonRootVolumes: []
      imdsOptions:
        httpPutResponseHopLimit: 1
        httpTokens: required   # IMDSv2 required
```

Deploy a `MachineHealthCheck` per `MachineDeployment` to enable automatic remediation of unhealthy nodes without requiring manual intervention that might involve elevated privileges:

```yaml
apiVersion: cluster.x-k8s.io/v1beta1
kind: MachineHealthCheck
metadata:
  name: production-worker-health
  namespace: clusters
spec:
  clusterName: production-us-east-1
  selector:
    matchLabels:
      cluster.x-k8s.io/deployment-name: production-workers
  maxUnhealthy: 33%
  nodeStartupTimeout: 10m
  unhealthyConditions:
    - type: Ready
      status: Unknown
      timeout: 300s
    - type: Ready
      status: "False"
      timeout: 300s
  remediationTemplate:
    apiVersion: infrastructure.cluster.x-k8s.io/v1beta2
    kind: AWSRemediationTemplate
    name: production-worker-remediation
    namespace: clusters
```

### GitOps Integration

Scope the Flux or Argo CD service account used to apply CAPI objects to only the `clusters` namespace, not cluster-admin across the management cluster:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: capi-gitops-applier
  namespace: clusters
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: capi-gitops-role
  namespace: clusters
rules:
  - apiGroups: ["cluster.x-k8s.io", "infrastructure.cluster.x-k8s.io",
                "controlplane.cluster.x-k8s.io", "bootstrap.cluster.x-k8s.io"]
    resources: ["*"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  # Explicitly deny delete — cluster deletion requires manual approval
  # (omitting delete from verbs achieves this)
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: capi-gitops-binding
  namespace: clusters
subjects:
  - kind: ServiceAccount
    name: capi-gitops-applier
    namespace: clusters
roleRef:
  kind: Role
  name: capi-gitops-role
  apiGroup: rbac.authorization.k8s.io
```

Reference that service account from the Flux `Kustomization`:

```yaml
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: capi-clusters
  namespace: flux-system
spec:
  interval: 5m
  path: ./clusters
  prune: false   # Disable prune — accidental cluster deletion is catastrophic
  sourceRef:
    kind: GitRepository
    name: fleet-config
  serviceAccountName: capi-gitops-applier
  targetNamespace: clusters
  healthChecks:
    - apiVersion: cluster.x-k8s.io/v1beta1
      kind: Cluster
      name: "*"
      namespace: clusters
```

Enforce branch protection in GitHub or GitLab for the `clusters/` directory path. A `CODEOWNERS` file requiring approval from the platform-team group before any merge achieves this without custom tooling:

```
# .github/CODEOWNERS
/clusters/    @org/platform-team
/clusters/production/    @org/platform-team @org/security-team
```

### Audit Logging on the Management Cluster

Configure the API server audit policy to capture all write and delete operations on CAPI resources at the `RequestResponse` level. Read operations on `Cluster` and `Machine` objects should be captured at `Metadata` level to track who is querying the fleet state:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Capture all writes to CAPI resources at full request/response
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: "cluster.x-k8s.io"
        resources: ["clusters", "machines", "machinedeployments", "clusterclasses"]
      - group: "infrastructure.cluster.x-k8s.io"
        resources: ["awsclusters", "awsmachines", "awsmachinetemplates",
                    "awsclusterroleidentities"]
      - group: "controlplane.cluster.x-k8s.io"
        resources: ["kubeadmcontrolplanes"]
      - group: "bootstrap.cluster.x-k8s.io"
        resources: ["kubeadmconfigs", "kubeadmconfigtemplates"]

  # Capture reads at metadata level
  - level: Metadata
    verbs: ["get", "list", "watch"]
    resources:
      - group: "cluster.x-k8s.io"
        resources: ["clusters", "machines", "machinedeployments"]

  # Capture bootstrap token access
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]
    namespaces: ["kube-system"]

  - level: None
    users: ["system:kube-controller-manager"]
    verbs: ["get", "list", "watch"]

  - level: Metadata
    omitStages:
      - RequestReceived
```

Ship these audit logs to your SIEM. Alert on: `Machine` creates outside of business hours, `AWSClusterRoleIdentity` modifications, any `ClusterClass` updates, and bootstrap secret reads by non-controller principals.

## Expected Behaviour

| Signal | Without Hardening | With Hardening |
|---|---|---|
| Provider credential blast radius | Single `AWSClusterControllerIdentity` with broad permissions covers all clusters; one compromise exposes entire fleet | Per-cluster `AWSClusterRoleIdentity` with minimal permissions; compromise of one role affects one cluster |
| Bootstrap token reuse | Token TTL 1 hour; failed Machine leaves valid token; rogue node can join up to 60 minutes after failure | Token TTL 15 minutes; CAPI audit alert fires on bootstrap secret reads by non-controller principals; expired tokens cleaned up automatically |
| Unauthorized Machine provisioning | Developer with `Machine` write access creates GPU instances with custom AMI; joins cluster as trusted node | RBAC restricts `Machine` write to platform-team group; `ClusterClass` variable schema enforces allowed instance types; GitOps service account cannot delete clusters |
| ClusterClass constraint bypass | Attacker with `ClusterClass` write modifies worker template fleet-wide; propagates to all clusters on next reconcile | `ClusterClass` write restricted to platform-team; CODEOWNERS requires security-team review; audit alert fires on any `ClusterClass` update |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Per-cluster IAM roles | Blast radius limited to one workload cluster per credential compromise | N IAM roles to create and manage; role rotation complexity scales with fleet size | Automate role creation as part of cluster bootstrap pipeline; use AWS Organizations SCPs as a backstop |
| Short bootstrap TTL (≤ 15 minutes) | Stale tokens from failed provisioning cannot be reused | On slow cloud regions or large AMIs, node may not reach API server within window, causing join failure and requiring Machine reprovisioning | Profile actual node boot time per region; set TTL to measured p99 boot time plus two minutes; use MachineHealthCheck to auto-remediate join failures |
| Dedicated management cluster | No shared blast radius with workload applications; PodSecurityStandard can be enforced aggressively | Additional cluster cost and operational overhead; one more cluster to patch and upgrade | Use minimal instance types (three m6i.large nodes is sufficient for most CAPI controllers); treat management cluster upgrades as highest-priority maintenance |
| ClusterClass variable schema constraints | Prevents developers from requesting oversized or disallowed instance types; enforces fleet consistency | Reduces developer self-service flexibility; new instance types require schema update before adoption | Maintain a documented process for schema additions with a SLA (for example, 48-hour turnaround for approved instance type additions) |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| IRSA role assumption denied | CAPA controller logs `AccessDenied: sts:AssumeRoleWithWebIdentity`; `AWSCluster` object stuck in `Provisioning` with event `failed to get AWS session` | CloudTrail AssumeRoleWithWebIdentity failures from the controller pod IP; CAPA controller error metric spike | Verify OIDC thumbprint in IAM identity provider matches cluster; confirm service account annotation `eks.amazonaws.com/role-arn` is set; check trust policy `StringEquals` condition matches exact service account name and namespace |
| Bootstrap token expires before node joins | Machine object shows `BootstrapReady: false`; node never appears in `kubectl get nodes`; cloud instance is running but repeatedly failing `/v1beta1/token` requests against API server | CloudWatch/cloud logs showing HTTP 401 from node bootstrap requests; CAPI Machine event `bootstrap token expired` | Delete the failed Machine object; CAPI will create a new one with a fresh bootstrap token; investigate underlying slow boot cause (AMI pull time, cloud init scripts) |
| MachineHealthCheck remediation loop | Nodes repeatedly deleted and recreated; MachineDeployment replica count oscillates; cluster unavailable as remediation consumes node quota | CAPI MachineHealthCheck metric `unhealthy_machines` above 0 for more than two reconciliation periods; cloud cost spike from instance churn | Check `maxUnhealthy` threshold — if set too low, transient failures trigger remediation; pause remediation with `cluster.x-k8s.io/paused` annotation while investigating root cause (node condition misconfiguration, cloud instance quota, kernel crash) |
| ClusterClass schema validation rejects valid topology | `Cluster` object with a legitimate topology update fails admission with `spec.topology.workers.machineDeployments[0].variables: Invalid value`; platform team cannot apply cluster change | Kubernetes admission webhook rejection events in API server audit log; Flux/Argo CD sync failure notification | Add the required instance type or variable value to the `ClusterClass` schema enum; re-apply the `Cluster` object; review `ClusterClass` variable schema as part of the change approval process to prevent recurrence |

## Related Articles

- [Node Hardening](/articles/kubernetes/node-hardening/)
- [RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Karpenter Node Provisioning Security](/articles/kubernetes/karpenter-node-security/)
- [GitOps Security](/articles/cicd/gitops-security/)
- [SPIFFE/SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
