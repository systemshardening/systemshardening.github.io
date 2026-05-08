---
title: "Karpenter Node Provisioning Security"
description: "Harden Karpenter-managed node provisioning by securing NodePools, EC2NodeClass IAM roles, node registration, and instance metadata access."
slug: karpenter-node-security
date: 2026-05-01
lastmod: 2026-05-01
category: kubernetes
tags: ["karpenter", "node-security", "iam", "ec2", "nodepool", "kubernetes", "eks"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 320
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/kubernetes/karpenter-node-security/index.html"
---

# Karpenter Node Provisioning Security

## Problem

Karpenter fundamentally changes how Kubernetes nodes join a cluster. Where the Cluster Autoscaler operates against Auto Scaling Groups that a human pre-configured, Karpenter holds IAM credentials that let it call the EC2 API directly: it evaluates pending pod scheduling constraints, selects an instance type, launches an EC2 instance, and registers it to the cluster — all within seconds. That speed is the product's value proposition, and it is also its security surface. The IAM permissions granted to the Karpenter controller must be broad enough to accomplish this, and the nodes it launches must be trusted by the control plane. Both facts create attack paths that did not exist with earlier autoscalers.

Karpenter reached general availability as v1.0 in late 2024 and adoption accelerated quickly across EKS fleets. Many organisations carried forward their Cluster Autoscaler security posture without accounting for the architectural differences. The Cluster Autoscaler reads EC2, it does not write EC2 at scale. Karpenter needs `ec2:RunInstances`, `ec2:CreateFleet`, `ec2:CreateLaunchTemplate`, and a family of related actions. If the controller's IAM role is over-permissioned, compromising that role — through a workload running in the `karpenter` namespace, through SSRF against the controller pod, or through any misconfiguration that leaks IRSA tokens — hands an attacker the ability to launch arbitrary compute in your AWS account.

The NodePool and EC2NodeClass custom resources define what Karpenter is allowed to provision. A NodePool with no `requirements` field restrictions is willing to request any instance family, including `p4d` GPU instances with per-hour costs measured in tens of dollars and compute-to-network ratios useful for data exfiltration. An EC2NodeClass governs the AMI, subnet, security group, and IAM instance profile attached to launched nodes. A developer with write access to EC2NodeClass can swap the AMI selector for a community image containing a cryptominer, or widen the security groups to open SSH to the internet. The blast radius of a single misconfigured CRD is the entire node fleet served by that class.

Instance Metadata Service version 1 (IMDSv1) remains the default on some older Amazon Linux AMIs and in some community Bottlerocket configurations. IMDSv1 accepts unauthenticated HTTP GET requests to `169.254.169.254`. Any container that breaks out of its namespace — or any pod running in host network mode — can retrieve the node's IAM role credentials directly from IMDS. On a Karpenter-managed node the instance profile is the node IAM role, which if broadly scoped can allow S3 reads, SSM parameter access, or ECR authentication that the workload should never possess. A single container escape on an unhardened node becomes lateral movement across AWS services.

Node bootstrap in EKS relies on a mechanism where the new instance authenticates using its instance identity document and the cluster's `aws-auth` ConfigMap (or EKS access entries in newer configurations). If the node IAM role is shared across NodePools or is the same role used by the Karpenter controller, an attacker who compromises one node role can influence the provisioning plane. UserData in the EC2NodeClass is executed as root during first boot. There is no built-in signature verification on that content: an attacker with EC2NodeClass write permission can inject arbitrary shell commands that run before any Kubernetes agent starts, before any runtime policy applies, before any audit log is written.

Target systems: Karpenter v1.x on EKS 1.28+, AWS provider. The IAM-specific controls are AWS-specific, but the NodePool admission controls, RBAC hardening, and node expiry concepts apply to the Azure (`karpenter-provider-azure`) and GCP (`karpenter-provider-gcp`) providers with provider-equivalent substitutions.

## Threat Model

1. **Container-escape attacker accessing IMDSv1.** A workload with a kernel vulnerability or container runtime CVE escapes to the host network namespace. On a node where IMDSv1 is accessible, one HTTP request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` yields a valid AWS session. The attacker now holds node credentials with whatever permissions the instance profile grants. If the node role has `s3:GetObject *`, `ssm:GetParameter *`, or any cross-account trust, the blast radius extends beyond the cluster.

2. **Developer with NodePool write access launching oversized instances.** A developer with RBAC permission to create or edit `NodePool` objects removes the `requirements` constraints that restrict instance families. They submit a pod with a large `resources.requests` that Karpenter satisfies by launching a `p4d.24xlarge` or `trn1.32xlarge`. The cost impact is immediate; the GPU capacity could be repurposed for coin mining. Without `expireAfter` set, the node persists indefinitely regardless of whether the requesting pod is deleted.

3. **Supply-chain attacker injecting malicious UserData in EC2NodeClass.** An attacker with write access to an EC2NodeClass — through a compromised CI pipeline credential, a stolen kubeconfig, or a misconfigured RBAC binding — modifies the `userData` field. The next node Karpenter launches executes that content as root at boot. Because this runs before kubelet starts, no Falco rule, no OPA policy, and no audit log captures the execution. The attacker can install a persistent backdoor, exfiltrate bootstrap credentials, or disable security tooling before the node ever registers.

4. **Network-adjacent attacker exploiting node bootstrap.** During the window between instance launch and kubelet registration, the node makes outbound calls: it fetches the EKS cluster endpoint, retrieves bootstrap configuration, and writes to the node's kubeconfig. On a VPC without strict egress controls, a network-adjacent attacker on the same subnet can attempt to intercept these calls or inject responses. In environments using `aws-auth` ConfigMap mode rather than EKS access entries, the node's IAM role must appear in the ConfigMap before the node can join; the brief period before that entry is added is a window for a race condition that produces confusing RBAC states.

The blast radius comparison is significant. A misconfiguration in Cluster Autoscaler typically causes scaling failures — a safety problem. The same class of misconfiguration in Karpenter can cause EC2 spending spikes, node credential theft, persistent host-level compromise, and supply chain injection — a combined financial, operational, and security problem. Karpenter's power multiplies the consequences of every permission that is too broad.

## Configuration / Implementation

### Least-Privilege IAM for the Karpenter Controller

The Karpenter controller requires EC2 and IAM permissions to provision nodes. The official installation documentation provides a starting policy that is reasonable but should be further constrained using IAM condition keys. The most important conditions are `aws:RequestedRegion`, `ec2:Region`, and resource-level ARN restrictions where EC2 supports them.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KarpenterEC2Fleet",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateFleet",
        "ec2:RunInstances",
        "ec2:CreateLaunchTemplate",
        "ec2:DeleteLaunchTemplate",
        "ec2:DescribeLaunchTemplates"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        },
        "StringLike": {
          "aws:ResourceTag/karpenter.sh/nodepool": "*"
        }
      }
    },
    {
      "Sid": "KarpenterEC2Describe",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeImages",
        "ec2:DescribeSpotPriceHistory",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": "*"
    },
    {
      "Sid": "KarpenterEC2TerminateTagged",
      "Effect": "Allow",
      "Action": "ec2:TerminateInstances",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/karpenter.sh/managed-by": "karpenter"
        }
      }
    },
    {
      "Sid": "KarpenterIAMPassRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/KarpenterNodeRole-*"
    },
    {
      "Sid": "DenyBroadIAM",
      "Effect": "Deny",
      "Action": [
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach this policy to the Karpenter controller's IRSA role (or EKS Pod Identity association in EKS 1.29+). The trust policy should restrict the `sub` claim to the Karpenter service account in its specific namespace:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub": "system:serviceaccount:kube-system:karpenter",
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

### EC2NodeClass Hardening

The `EC2NodeClass` resource is where instance-level security controls live. The two highest-priority settings are IMDSv2 enforcement and EBS encryption. Set `httpTokens: required` and `httpPutResponseHopLimit: 1`. The hop limit of 1 ensures that containers cannot reach IMDS even in host-network mode without additional network manipulation — each NAT hop decrements the TTL, and a containerised process cannot reach the metadata endpoint in one hop from inside a network namespace.

```yaml
apiVersion: karpenter.k8s.aws/v1
kind: EC2NodeClass
metadata:
  name: default
  namespace: kube-system
spec:
  amiFamily: Bottlerocket
  # Pin to specific AMI IDs rather than relying on tags alone.
  # Tags can be modified by anyone with ec2:CreateTags permission.
  amiSelectorTerms:
    - id: ami-0abcdef1234567890
    - id: ami-0fedcba0987654321
  subnetSelectorTerms:
    - tags:
        karpenter.sh/discovery: "my-cluster"
  securityGroupSelectorTerms:
    - tags:
        karpenter.sh/discovery: "my-cluster"
  # Separate node IAM role from controller role
  role: "KarpenterNodeRole-my-cluster"
  metadataOptions:
    httpEndpoint: enabled
    httpProtocolIPv6: disabled
    # Enforce IMDSv2 — reject unauthenticated token requests
    httpTokens: required
    # Hop limit of 1 prevents container access to IMDS
    httpPutResponseHopLimit: 1
  blockDeviceMappings:
    - deviceName: /dev/xvda
      ebs:
        volumeSize: 50Gi
        volumeType: gp3
        # Encrypt root volume with a customer-managed KMS key
        encrypted: true
        kmsKeyID: "arn:aws:kms:us-east-1:123456789012:key/mrk-example1234"
        deleteOnTermination: true
  # Validate and minimise UserData; avoid embedding secrets
  userData: |
    [settings.kubernetes]
    cluster-name = "my-cluster"
    api-server = "https://EXAMPLED539D4633E53DE1B71EXAMPLE.gr7.us-east-1.eks.amazonaws.com"
    cluster-certificate = "LS0t..."
    cluster-dns-ip = "172.20.0.10"
    max-pods = 110
```

AMI selection by tag alone (`amiSelectorTerms[].tags`) is a weak control because any principal with `ec2:CreateTags` can tag a malicious AMI to match your selector and have Karpenter launch it. Prefer `id`-based selection for production, with a separate automated process that updates the IDs when new hardened AMIs are published. If you must use tag-based selection for operational convenience, add an `owners` constraint to restrict to AMIs owned by your account or a trusted AMI pipeline account:

```yaml
  amiSelectorTerms:
    - tags:
        karpenter.sh/ami-type: "bottlerocket-hardened"
      owners:
        - "123456789012"
```

### NodePool Security Constraints

`NodePool` resources control which instances Karpenter may request. Without explicit `requirements`, Karpenter will select whatever instance type satisfies the pending pod's resource request most efficiently — which may include bare-metal instances, GPU instances, or instances with local NVMe storage that bypasses EBS encryption controls.

```yaml
apiVersion: karpenter.sh/v1
kind: NodePool
metadata:
  name: general-purpose
  namespace: kube-system
spec:
  template:
    metadata:
      labels:
        node-role: general-purpose
      annotations:
        # Document intent for auditors
        security.company.com/approved-by: "platform-team"
    spec:
      nodeClassRef:
        group: karpenter.k8s.aws
        kind: EC2NodeClass
        name: default
      requirements:
        # Restrict to known-safe instance families
        - key: karpenter.k8s.aws/instance-family
          operator: In
          values: ["m6i", "m6a", "m7i", "c6i", "c6a", "r6i"]
        # Explicitly exclude bare metal
        - key: karpenter.k8s.aws/instance-size
          operator: NotIn
          values: ["metal"]
        # Exclude GPU instances from general-purpose pool
        - key: karpenter.k8s.aws/instance-gpu-count
          operator: DoesNotExist
        - key: kubernetes.io/arch
          operator: In
          values: ["amd64"]
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["on-demand", "spot"]
      # Rotate nodes after 72 hours to cycle credentials and apply AMI updates
      expireAfter: 72h
  disruption:
    consolidationPolicy: WhenEmptyOrUnderutilized
    consolidateAfter: 30m
    # Budget: limit disruption to 20% of nodes at once
    budgets:
      - nodes: "20%"
  # Cap spending by limiting total CPU across this NodePool
  limits:
    cpu: "500"
    memory: "2000Gi"
```

The `expireAfter` field is a security control as well as an operational one. Rotating nodes every 72 hours ensures that any credential fetched from IMDS has a maximum lifetime of 72 hours in the hands of an attacker, and that AMI security patches are applied on a bounded schedule without requiring manual drains.

### Node IAM Role Scoping

The instance profile attached to Karpenter-launched nodes should be the minimum required for the node to operate. Nodes need to pull images from ECR, write logs, and optionally connect via SSM for breakglass access. They do not need S3 access, RDS access, or permission to call IAM APIs.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ECRPull",
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SSMCoreNode",
      "Effect": "Allow",
      "Action": [
        "ssm:UpdateInstanceInformation",
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EKSNodeDescribe",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeVolumesModifications",
        "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyBroadS3",
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}
```

If different workload tiers require different AWS permissions, create separate EC2NodeClass resources with separate node IAM roles, and separate NodePools that reference each class. Do not solve per-workload AWS access by broadening the node IAM role — solve it with IRSA or EKS Pod Identity on the workload's service account.

### Admission Control for EC2NodeClass

Enforce IMDSv2 and EBS encryption requirements at admission time so that a misconfigured EC2NodeClass is rejected before Karpenter can act on it. The following Kyverno `ClusterPolicy` validates both requirements:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-ec2nodeclass-hardening
  annotations:
    policies.kyverno.io/title: "Require EC2NodeClass Hardening"
    policies.kyverno.io/description: >
      Enforces IMDSv2-only and EBS encryption on all EC2NodeClass resources.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-imdsv2
      match:
        any:
          - resources:
              kinds:
                - EC2NodeClass
      validate:
        message: "EC2NodeClass must set metadataOptions.httpTokens=required"
        pattern:
          spec:
            metadataOptions:
              httpTokens: "required"
    - name: require-imds-hop-limit
      match:
        any:
          - resources:
              kinds:
                - EC2NodeClass
      validate:
        message: "EC2NodeClass must set httpPutResponseHopLimit=1 to block container IMDS access"
        pattern:
          spec:
            metadataOptions:
              httpPutResponseHopLimit: 1
    - name: require-ebs-encryption
      match:
        any:
          - resources:
              kinds:
                - EC2NodeClass
      validate:
        message: "All EBS block device mappings must have encrypted=true"
        foreach:
          - list: "request.object.spec.blockDeviceMappings"
            pattern:
              ebs:
                encrypted: true
```

If your cluster runs Kubernetes 1.30+ and you prefer not to add Kyverno, the same rules can be expressed as a `ValidatingAdmissionPolicy` using CEL:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: ec2nodeclass-imdsv2
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["karpenter.k8s.aws"]
        apiVersions: ["v1"]
        resources: ["ec2nodeclasses"]
        operations: ["CREATE", "UPDATE"]
  validations:
    - expression: >
        object.spec.metadataOptions.httpTokens == "required" &&
        object.spec.metadataOptions.httpPutResponseHopLimit == 1
      message: "EC2NodeClass must enforce IMDSv2 with hop limit 1"
```

### RBAC for Karpenter CRDs

`NodePool` and `EC2NodeClass` resources should be writable only by the platform team and the Karpenter controller itself. Grant application teams read-only access at most.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: karpenter-crd-viewer
rules:
  - apiGroups: ["karpenter.sh", "karpenter.k8s.aws"]
    resources: ["nodepools", "ec2nodeclasses", "nodeclaims"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: karpenter-crd-viewer-developers
subjects:
  - kind: Group
    name: "developers"
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: karpenter-crd-viewer
  apiGroup: rbac.authorization.k8s.io
```

The Karpenter controller service account should have write access via a dedicated role scoped to what the controller actually needs. Application teams and CI pipelines must never hold `create`, `update`, `patch`, or `delete` on `ec2nodeclasses` or `nodepools`.

Additionally, protect the `karpenter` namespace itself:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: karpenter-namespace-admin
  namespace: kube-system
rules:
  - apiGroups: [""]
    resources: ["pods", "configmaps", "secrets"]
    verbs: ["get", "list", "watch"]
---
# Ensure no general ClusterRoleBinding grants write to kube-system
# Audit with: kubectl get rolebindings,clusterrolebindings -A -o json |
#   jq '.items[] | select(.subjects[]?.name == "developers")'
```

## Expected Behaviour

| Signal | Without Hardening | With Hardening |
|---|---|---|
| Pod calls `curl http://169.254.169.254/latest/meta-data/iam/` | Returns node IAM credentials after one unauthenticated GET | HTTP 401 — IMDSv1 not available; IMDSv2 requires a PUT token the container cannot obtain through the hop-limit restriction |
| Developer submits NodePool with no instance-family requirement | Karpenter schedules GPU instances costing $30/hr to satisfy a 96-CPU request | Kyverno or VAP rejects the NodePool; admission webhook returns validation error |
| Node runs for 10 days without rotation | Node carries an 10-day-old credential exposure window; unpatched AMI vulnerabilities accumulate | `expireAfter: 72h` triggers graceful drain and replacement; IAM credential maximum age is 72 hours |
| EC2NodeClass modified with malicious AMI tag | Karpenter picks up the new AMI on the next launch; nodes boot with backdoored OS | AMI selectors pin to explicit IDs; tag-only selectors are blocked at admission; ID change requires platform team write access |
| Node IAM role used to list S3 buckets from inside a pod | `aws s3 ls` returns bucket listing via instance profile credentials | `s3:*` Deny in node IAM policy; operation returns AccessDenied |
| Developer deletes running NodePool | Karpenter immediately begins draining nodes in that pool, disrupting workloads | `disruption.budgets` limits concurrent disruptions; PodDisruptionBudgets on workloads gate the drain |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| AMI ID pinning | Eliminates risk of attacker-tagged AMIs being launched; deterministic OS baseline | Requires automated AMI pipeline to publish new IDs on patch release; misses automatic security updates | Build an AMI factory with CIS-hardened images; use EventBridge rule to update IDs when new AMI passes CIS scan |
| Strict instance-family requirements | Prevents GPU/bare-metal abuse; makes spend auditable by family | Reduces Karpenter's ability to find cheap spot capacity; may increase cost 5–15% in constrained regions | Maintain a small approved list of alternative families; review quarterly against Spot availability |
| `expireAfter: 72h` node rotation | Bounds credential exposure window; enforces AMI patching cadence | Increases node churn and workload disruptions, especially for stateful apps | Tune PodDisruptionBudgets; use `disruption.budgets` nodes percentage; set `expireAfter` per NodePool by workload sensitivity |
| Separate node IAM roles per EC2NodeClass | Allows per-pool AWS permission scoping; blast radius isolated to pool | More IAM roles to manage; more `iam:PassRole` grants to track | Manage via Terraform module that creates role per NodePool; tag roles with `karpenter.sh/nodepool` for audit |
| RBAC restricting NodePool writes | Prevents developer abuse of provisioning plane | Slows legitimate platform changes that go through a review gate | Use GitOps (Flux/Argo CD) so changes are PR-reviewed and CI-validated before apply; platform team reviews in <1 business day |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| EC2NodeClass AMI ID selector matches nothing | Pods remain Pending indefinitely; Karpenter logs `no AMIs found` for NodeClaim; no new nodes launch | `kubectl get nodeclaim -A`; Karpenter controller logs: `level=error msg="failed to resolve AMIs"`; CloudWatch metric `karpenter_nodeclaims_disrupted` | Update `amiSelectorTerms` with a valid AMI ID; if using an AMI pipeline, check whether the pipeline published to the correct region and account |
| IAM permission denied on node registration | Node launches (visible in EC2 console) but never appears in `kubectl get nodes`; instance terminates after bootstrap timeout | CloudWatch Logs for bootstrap: `AccessDenied calling eks:DescribeCluster`; EKS access entry / `aws-auth` ConfigMap missing node role ARN | Verify node IAM role ARN appears in EKS access entries or `aws-auth`; check that `iam:PassRole` covers the node role ARN pattern |
| NodePool disruption budget exhausted during maintenance | Rolling update stalls; drains blocked; `kubectl drain` returns `cannot evict pod` | `kubectl get nodeclaim -A`; Karpenter logs show `blocked by disruption budget`; `kubectl describe pdb` shows `DisruptionsAllowed: 0` | Temporarily widen `disruption.budgets.nodes` percentage; identify which PDB is blocking; coordinate with application team to accept disruption window |
| Karpenter controller leader election failure | All Karpenter controller replicas log `failed to acquire leader election lock`; no new nodes launch and no nodes drain | `kubectl get lease -n kube-system karpenter`; `kubectl describe pod -n kube-system -l app.kubernetes.io/name=karpenter`; controller pod restarts | Check RBAC — controller service account needs `leases` write in `kube-system`; check for stale lease with very long duration; delete lease object to force re-election |
| Kyverno admission webhook unavailable | EC2NodeClass and NodePool creates/updates fail with timeout or connection refused | `kubectl get validatingwebhookconfigurations`; Kyverno pod logs; API server logs show webhook call failures | Check Kyverno pod health; if Kyverno is in a crash loop, temporarily set `failurePolicy: Ignore` on non-blocking webhooks; restore `Enforce` once Kyverno recovers |

## Related Articles

- [Node Hardening](/articles/kubernetes/node-hardening/) — OS-level and kubelet configuration hardening that complements Karpenter's provisioning controls
- [RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/) — Structuring ClusterRole and RoleBinding hierarchies to protect privileged CRDs
- [Pod Security Context](/articles/kubernetes/pod-security-context/) — Workload-level controls that reduce the value of node credential access
- [OIDC Federation Hardening](/articles/cicd/oidc-federation-hardening/) — Securing the IRSA trust relationships that grant Karpenter its IAM permissions
- [SPIFFE/SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/) — Replacing node-identity-based AWS access with per-workload cryptographic identity
