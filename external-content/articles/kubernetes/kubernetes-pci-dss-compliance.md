---
title: "Kubernetes PCI DSS Compliance: Scope Reduction, Network Isolation, and Audit Trails"
description: "Running card-processing workloads in Kubernetes requires explicit PCI DSS scope reduction, strict NetworkPolicy isolation, pod-level security controls, and per-node audit logging that satisfies Requirements 1, 2, 7, and 10. This guide maps Kubernetes controls to PCI DSS v4.0 and provides assessor-ready evidence commands."
slug: kubernetes-pci-dss-compliance
date: 2026-05-07
lastmod: 2026-05-07
category: kubernetes
tags:
  - pci-dss
  - kubernetes
  - compliance
  - network-policy
  - cde
personas:
  - security-engineer
  - compliance-engineer
article_number: 626
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-pci-dss-compliance/
---

# Kubernetes PCI DSS Compliance: Scope Reduction, Network Isolation, and Audit Trails

## Problem

Kubernetes was not designed with PCI DSS in mind. It was designed to run workloads at scale with sensible defaults for developers. Those defaults are a compliance problem in a cardholder data environment (CDE):

- **Flat pod networking by default.** Without NetworkPolicy, every pod can reach every other pod in every namespace across the cluster. A payment microservice, a logging sidecar, and a developer debug pod all share the same flat network. PCI DSS Requirement 1 demands network controls between CDE components and everything else. Default Kubernetes networking has none.
- **Shared node OS.** Unless you dedicate node pools to CDE workloads, a shopping cart service and a card processor run on the same kernel. Privilege escalation in any co-located container can affect CDE nodes. Requirement 2 says system components must be configured securely; shared node pools make that very hard to scope and evidence.
- **Secrets stored in etcd as base64.** The default Kubernetes Secrets store writes values as base64-encoded plaintext to etcd. Any process that can read etcd data — including etcd backups stored in S3 — can extract every database credential and API key in the cluster. Requirement 6.3 requires cryptographic protection of stored cardholder data; base64 is not encryption.
- **Complex scope determination.** In a traditional PCI environment, scope is drawn around servers in a PCI network segment. In Kubernetes, a single cluster can run in-scope and out-of-scope workloads simultaneously. Without explicit namespace labelling, admission controls, and NetworkPolicy enforcement, the scope creeps to cover the entire cluster — dramatically increasing audit burden and cost.
- **No audit logging by default.** The Kubernetes API server does not enable audit logging without explicit configuration. Requirement 10 requires a detailed audit trail of all access to system components and cardholder data. A cluster without an audit policy has no record of who ran `kubectl exec` into a payment pod or who read a Secret containing a database password.

**Applicable PCI DSS v4.0 requirements:**

| Requirement | Description | Kubernetes relevance |
|---|---|---|
| Req 1 | Network security controls | NetworkPolicy, namespace isolation, ingress/egress rules |
| Req 2 | Secure configurations | Pod Security Standards, no privileged containers, immutable filesystems |
| Req 6 | Secure systems and software | Image signing, admission control, no known-vulnerable base images |
| Req 7 | Restrict access to system components | RBAC, ServiceAccount least privilege |
| Req 8 | Identify users and authenticate access | kubectl MFA, OIDC integration, no shared credentials |
| Req 10 | Log and monitor all access | Kubernetes audit policy, immutable log shipping |

**Common PCI failures in Kubernetes:**

- Default allow-all (no NetworkPolicy) in CDE namespaces passes traffic between card-processing pods and every other tenant in the cluster.
- Privileged containers (`securityContext.privileged: true`) running in CDE namespaces can escape container boundaries and access node-level resources, putting the entire node in scope.
- Kubernetes Secrets storing PAN-adjacent credentials (database passwords, encryption keys) written to etcd without `EncryptionConfiguration` — plaintext in backups.
- No `kube-apiserver` audit policy means `kubectl exec` into payment pods, secret reads, and RBAC changes have no audit record. QSAs ask for 12 months of access logs; there are none.

**Target systems:** Kubernetes 1.29+, self-managed (kubeadm) or managed (EKS, GKE, AKS) clusters running PCI-scoped workloads. Kyverno 1.12+ for policy enforcement. Calico or Cilium CNI for NetworkPolicy support.

## Threat Model

Three adversaries map directly to PCI DSS concerns:

**Adversary 1 — RCE on a payment microservice.** An attacker exploits a vulnerability (Log4Shell-style RCE, deserialization bug, or SSRF) in a payment API pod running in the CDE namespace. Without NetworkPolicy, they can scan adjacent pods and directly reach PAN data stored in a CDE database pod on the same cluster network. With default-deny NetworkPolicy and explicit allow rules, the compromised pod can only reach its declared dependencies — the payment pod cannot connect to the database pod unless a NetworkPolicy explicitly permits that flow.

**Adversary 2 — Compromised CI/CD pipeline.** An attacker compromises a GitHub Actions runner or Tekton pipeline and gains the ability to push images to the container registry and deploy to the cluster. Without admission control that verifies image signatures and enforces Pod Security Standards, the attacker deploys a backdoored image to `cde-processing` with a reverse shell. With Kyverno policies enforcing signed images, readOnlyRootFilesystem, and runAsNonRoot, the malicious deployment is rejected before it schedules.

**Adversary 3 — Insider with kubectl access.** A platform engineer with legitimate cluster access uses `kubectl get secret -n cde-processing` to read database credentials. Without RBAC scoping secrets access to specific ServiceAccounts (not human users), and without audit logging that records secret reads at `RequestResponse` level, there is no evidence the access occurred. With a correct audit policy, every secret read generates an audit event with the user's identity, timestamp, secret name, and the full response body.

## Configuration

### Namespace-per-CDE-tier Architecture (Req 1)

Divide the CDE into three namespaces that map to PCI DSS network segments. This is the foundation of scope reduction — each tier is isolated, labelled, and has its own NetworkPolicy enforced by admission control.

```bash
# Create CDE namespaces with PCI scope label.
kubectl create namespace cde-frontend
kubectl create namespace cde-processing
kubectl create namespace cde-storage

# Label all CDE namespaces for scope identification and PSS enforcement.
kubectl label namespace cde-frontend \
  pci-scope=in-scope \
  environment=production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

kubectl label namespace cde-processing \
  pci-scope=in-scope \
  environment=production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

kubectl label namespace cde-storage \
  pci-scope=in-scope \
  environment=production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
```

The `pod-security.kubernetes.io/enforce=restricted` label activates Kubernetes Pod Security Standards at the Restricted profile, which blocks privileged containers, hostPath volumes, and containers running as root — all in the namespace admission webhook without any additional tooling.

### Default-Deny NetworkPolicy for CDE Namespaces (Req 1)

Apply default-deny ingress and egress to all CDE namespaces as the first NetworkPolicy. Every subsequent policy is an explicit allow. This satisfies PCI DSS Requirement 1.3 ("prohibit all traffic from untrusted networks except that required for the cardholder data environment").

```yaml
# cde-default-deny.yaml
# Apply to each CDE namespace separately.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: cde-frontend       # Repeat for cde-processing and cde-storage.
  labels:
    pci-control: "req-1"
spec:
  podSelector: {}               # Matches all pods in the namespace.
  policyTypes:
    - Ingress
    - Egress
  # No ingress or egress rules means everything is denied.
```

Apply to all three namespaces:

```bash
for ns in cde-frontend cde-processing cde-storage; do
  kubectl apply -f cde-default-deny.yaml \
    --namespace "$ns" \
    --dry-run=server && \
  kubectl -n "$ns" apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: $ns
  labels:
    pci-control: req-1
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
EOF
done
```

**Allow only required flows.** After default-deny, define explicit allow rules for each required traffic path:

```yaml
# cde-frontend-ingress-from-loadbalancer.yaml
# Allow ingress from the ingress controller namespace only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-controller
  namespace: cde-frontend
  labels:
    pci-control: "req-1"
spec:
  podSelector:
    matchLabels:
      app: payment-api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
          podSelector:
            matchLabels:
              app.kubernetes.io/name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8443
---
# Allow cde-frontend to call cde-processing only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-processing
  namespace: cde-frontend
  labels:
    pci-control: "req-1"
spec:
  podSelector:
    matchLabels:
      app: payment-api
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: cde-processing
          podSelector:
            matchLabels:
              tier: card-processor
      ports:
        - protocol: TCP
          port: 9443
    # Allow DNS resolution.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

```yaml
# cde-processing-to-storage.yaml
# Allow card processor pods to reach the storage namespace only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-storage
  namespace: cde-processing
  labels:
    pci-control: "req-1"
spec:
  podSelector:
    matchLabels:
      tier: card-processor
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: cde-storage
          podSelector:
            matchLabels:
              tier: encrypted-datastore
      ports:
        - protocol: TCP
          port: 5432    # PostgreSQL. Adjust for your datastore.
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Kyverno Policy: Enforce CDE Controls on Labelled Namespaces (Req 2)

OPA Gatekeeper and Kyverno both work here. Kyverno is used below because its policies are expressed as Kubernetes resources with a lower operational barrier. This ClusterPolicy fires on any Pod admission request in a namespace labelled `pci-scope: in-scope` and rejects non-compliant workloads before they schedule.

```yaml
# kyverno-cde-pod-security.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: cde-pod-security-requirements
  annotations:
    policies.kyverno.io/title: CDE Pod Security Requirements
    policies.kyverno.io/description: >
      Enforces PCI DSS Req 2 controls on pods in pci-scope=in-scope namespaces.
      Blocks privileged containers, hostPath, containers running as root, and
      writable root filesystems.
    pci-control: "req-2"
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: no-privileged-containers
      match:
        any:
          - resources:
              kinds: ["Pod"]
              namespaceSelector:
                matchLabels:
                  pci-scope: "in-scope"
      validate:
        message: "PCI DSS Req 2: Privileged containers are not permitted in CDE namespaces."
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): "false"
            =(initContainers):
              - =(securityContext):
                  =(privileged): "false"

    - name: no-hostpath-volumes
      match:
        any:
          - resources:
              kinds: ["Pod"]
              namespaceSelector:
                matchLabels:
                  pci-scope: "in-scope"
      validate:
        message: "PCI DSS Req 2: hostPath volumes are not permitted in CDE namespaces."
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.volumes[].hostPath | length(@) }}"
                operator: GreaterThan
                value: "0"

    - name: require-readonly-root-filesystem
      match:
        any:
          - resources:
              kinds: ["Pod"]
              namespaceSelector:
                matchLabels:
                  pci-scope: "in-scope"
      validate:
        message: "PCI DSS Req 2: readOnlyRootFilesystem must be true in CDE namespaces."
        pattern:
          spec:
            containers:
              - securityContext:
                  readOnlyRootFilesystem: true

    - name: require-run-as-non-root
      match:
        any:
          - resources:
              kinds: ["Pod"]
              namespaceSelector:
                matchLabels:
                  pci-scope: "in-scope"
      validate:
        message: "PCI DSS Req 2: Containers must run as non-root in CDE namespaces."
        pattern:
          spec:
            =(securityContext):
              runAsNonRoot: true
            containers:
              - securityContext:
                  runAsNonRoot: true

    - name: require-networkpolicy-exists
      match:
        any:
          - resources:
              kinds: ["Namespace"]
              selector:
                matchLabels:
                  pci-scope: "in-scope"
      preconditions:
        all:
          - key: "{{ request.operation }}"
            operator: AnyIn
            value: ["CREATE", "UPDATE"]
      validate:
        message: "PCI DSS Req 1: Namespaces labelled pci-scope=in-scope must have a default-deny-all NetworkPolicy."
        deny:
          conditions:
            all:
              - key: "{{ networkpolicies(request.object.metadata.name).items[?metadata.name == 'default-deny-all'] | length(@) }}"
                operator: Equals
                value: "0"
```

Apply the policy and verify it loads without errors:

```bash
kubectl apply -f kyverno-cde-pod-security.yaml
kubectl get clusterpolicy cde-pod-security-requirements -o jsonpath='{.status.conditions}'
# Expect: Ready=True
```

### etcd Encryption at Rest for Secrets (Req 2 / Req 6)

```yaml
# /etc/kubernetes/encryption-config.yaml
# On every control plane node. Restart kube-apiserver after applying.
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      # aesgcm preferred: authenticated encryption, detects tampering.
      - aesgcm:
          keys:
            - name: key-20260507
              secret: <base64-encoded-32-byte-key>   # openssl rand -base64 32
      # identity fallback allows reading pre-existing unencrypted secrets
      # during migration. Remove after re-encrypting all existing secrets.
      - identity: {}
```

Enable it in the API server manifest:

```bash
# /etc/kubernetes/manifests/kube-apiserver.yaml — add to command args:
# --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

# After restarting the API server, re-encrypt all existing secrets:
kubectl get secrets --all-namespaces -o json | \
  kubectl replace -f -

# Verify a CDE secret is stored as encrypted ciphertext in etcd:
ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/cde-processing/db-credentials | hexdump -C | head -5
# Output should begin with k8s:enc:aesgcm:v1: — not plaintext.
```

### Dedicated CDE Node Pool (Req 2)

Co-locating CDE workloads with non-scoped workloads extends scope to the entire cluster. Dedicated nodes allow separate hardening baselines, separate OS audit logging, and clear scope boundaries for the QSA.

```bash
# Taint CDE nodes so only CDE workloads schedule there.
kubectl taint nodes cde-node-1 cde-node-2 cde-node-3 \
  pci-scope=in-scope:NoSchedule

# Label CDE nodes for nodeSelector matching.
kubectl label nodes cde-node-1 cde-node-2 cde-node-3 \
  pci-scope=in-scope

# Add to all CDE Deployment specs:
# spec:
#   template:
#     spec:
#       tolerations:
#         - key: pci-scope
#           operator: Equal
#           value: in-scope
#           effect: NoSchedule
#       nodeSelector:
#         pci-scope: in-scope
```

### RBAC for CDE Namespaces (Req 7 / Req 8)

Each CDE microservice gets its own ServiceAccount with the minimum permissions required. No ServiceAccount has wildcard verbs on secrets. Human access to CDE namespaces is audited via the audit policy.

```yaml
# cde-payment-api-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-api
  namespace: cde-frontend
automountServiceAccountToken: false   # Opt in explicitly; do not auto-mount.
---
# The payment-api ServiceAccount needs only to read its own config.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: payment-api-role
  namespace: cde-frontend
  labels:
    pci-control: "req-7"
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["payment-api-config"]   # Named resource only.
    verbs: ["get"]
  # No access to secrets via the API — credentials injected via
  # external-secrets-operator from Vault, not K8s Secrets.
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payment-api-rolebinding
  namespace: cde-frontend
  labels:
    pci-control: "req-7"
subjects:
  - kind: ServiceAccount
    name: payment-api
    namespace: cde-frontend
roleRef:
  kind: Role
  name: payment-api-role
  apiGroup: rbac.authorization.k8s.io
```

Audit existing CDE RBAC for wildcard permissions:

```bash
# Find any Role or ClusterRole with wildcard verbs on secrets in CDE namespaces.
kubectl get roles -n cde-processing -o json | \
  jq '.items[] | select(.rules[] | (.resources[] | contains("secrets")) and
    (.verbs[] | contains("*"))) | .metadata.name'

# Find ClusterRoleBindings that grant cluster-admin to CDE service accounts.
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.roleRef.name == "cluster-admin") |
    .subjects[] | select(.namespace | startswith("cde-")) | .name'
```

### Kubernetes Audit Policy for PCI DSS (Req 10)

PCI DSS Requirement 10.2 specifies which events must be logged: access to cardholder data, all actions taken by individuals with root or admin privileges, access to all audit trails, invalid logical access attempts, use of identification and authentication mechanisms. The following audit policy captures these at the correct verbosity levels.

```yaml
# /etc/kubernetes/audit-policy-pci.yaml
# Configure kube-apiserver with:
#   --audit-policy-file=/etc/kubernetes/audit-policy-pci.yaml
#   --audit-log-path=/var/log/kubernetes/audit.log
#   --audit-log-maxage=365          # PCI Req 10.5: retain 12 months.
#   --audit-log-maxbackup=10
#   --audit-log-maxsize=100
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived    # Reduce noise; log only completed requests.

rules:
  # PCI Req 10.2.1: Log all access to secrets in CDE namespaces at
  # RequestResponse level so the full secret name and requester identity
  # are captured. Do NOT log secret values (responses are metadata only).
  - level: RequestResponse
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources: ["secrets"]
    namespaces: ["cde-frontend", "cde-processing", "cde-storage"]

  # PCI Req 10.2.2: Log all pod exec and port-forward in CDE namespaces.
  # These are high-value events: interactive access to card-processing pods.
  - level: Request
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["pods/exec", "pods/portforward", "pods/attach"]
    namespaces: ["cde-frontend", "cde-processing", "cde-storage"]

  # PCI Req 10.2.5: Log all RBAC changes cluster-wide.
  # Tracks privilege escalation attempts.
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete", "bind", "escalate"]
    resources:
      - group: "rbac.authorization.k8s.io"
        resources:
          - clusterroles
          - clusterrolebindings
          - roles
          - rolebindings

  # PCI Req 10.2.3: Log all authentication failures.
  - level: Request
    omitStages: []
    verbs: ["*"]
    resources: []
    namespaces: []
    users: ["system:anonymous"]

  # PCI Req 10.2.7: Log all pod lifecycle events in CDE namespaces.
  # Captures workload changes — new deployments, deleted pods.
  - level: Request
    verbs: ["create", "delete", "deletecollection"]
    resources:
      - group: ""
        resources: ["pods"]
    namespaces: ["cde-frontend", "cde-processing", "cde-storage"]

  # PCI Req 10.2.6: Log all audit log configuration changes.
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: ""
        resources: ["configmaps"]
    namespaces: ["kube-system"]
    resourceNames: ["kube-apiserver-audit-policy"]

  # Log all control plane configuration changes at Request level.
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: "apps"
        resources: ["deployments", "daemonsets", "statefulsets"]
    namespaces: ["cde-frontend", "cde-processing", "cde-storage"]

  # Log kube-system events that affect cluster security posture.
  - level: Metadata
    verbs: ["create", "update", "patch", "delete"]
    namespaces: ["kube-system"]

  # Default: log metadata for everything else.
  - level: Metadata
```

**Ship audit logs to an immutable SIEM.** PCI DSS Requirement 10.5.1 states that audit log files must be protected from modification and deletion. Kubernetes audit logs written to a local file on the control plane node are not sufficient — they must be shipped to a separate system that the Kubernetes control plane cannot write to.

```yaml
# fluentd-pci-audit.yaml — DaemonSet running on control plane nodes.
# Tails /var/log/kubernetes/audit.log and ships to Elasticsearch
# with an index lifecycle policy that sets Object Lock on rollover.
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd-audit-shipper
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: fluentd-audit-shipper
  template:
    metadata:
      labels:
        app: fluentd-audit-shipper
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
        - key: node-role.kubernetes.io/control-plane
          effect: NoSchedule
      containers:
        - name: fluentd
          image: fluent/fluentd-kubernetes-daemonset:v1.17-debian-elasticsearch8-1
          env:
            - name: FLUENT_ELASTICSEARCH_HOST
              value: "siem.internal.example.com"
            - name: FLUENT_ELASTICSEARCH_PORT
              value: "9200"
            - name: FLUENT_ELASTICSEARCH_INDEX_NAME
              value: "k8s-pci-audit"
          volumeMounts:
            - name: audit-log
              mountPath: /var/log/kubernetes/audit.log
              readOnly: true
      volumes:
        - name: audit-log
          hostPath:
            path: /var/log/kubernetes/audit.log
            type: File
```

Configure Elasticsearch with an ILM policy that moves rolled indices to a frozen tier with Object Lock enabled on the backing S3 bucket. PCI DSS requires audit logs to be available for at least 12 months, with the most recent 3 months readily accessible.

## Expected Behaviour

The following table maps each PCI DSS v4.0 requirement to the Kubernetes control that satisfies it, and the command a QSA can run to generate evidence on the day of assessment.

| PCI DSS Req | Control | Assessor verification command |
|---|---|---|
| **1.3** — Restrict inbound/outbound traffic to only what is necessary | Default-deny NetworkPolicy on all CDE namespaces | `kubectl get networkpolicy -n cde-processing` — should include `default-deny-all` with no ingress/egress rules |
| **1.3.2** — Prohibit all traffic not explicitly required | Allowlist NetworkPolicy per flow | `kubectl describe networkpolicy -n cde-frontend allow-egress-to-processing` — verify only port 9443 to cde-processing is allowed |
| **2.2.1** — All system components configured to prevent known vulnerabilities | Pod Security Standards Restricted profile | `kubectl get namespace cde-processing -o jsonpath='{.metadata.labels}'` — verify `pod-security.kubernetes.io/enforce=restricted` |
| **2.2.6** — System security parameters configured to prevent misuse | Kyverno ClusterPolicy blocking privileged/root containers | `kubectl get clusterpolicy cde-pod-security-requirements -o jsonpath='{.status.conditions}'` — verify Ready=True |
| **2.2.7** — Sensitive data encrypted during transmission | TLS on all inter-pod communication | `kubectl exec -n cde-processing <pod> -- openssl s_client -connect cde-storage-svc:5432` |
| **3.5.1** — PAN stored using strong cryptography | etcd EncryptionConfiguration with aesgcm | `etcdctl get /registry/secrets/cde-processing/db-credentials \| hexdump -C \| head -3` — verify `k8s:enc:aesgcm:v1:` prefix |
| **7.2.1** — Access to system components limited to least privilege | Namespace-scoped Roles per ServiceAccount | `kubectl get rolebindings -n cde-processing -o wide` — verify no ClusterRole references |
| **7.2.2** — Access rights granted based on job function | No wildcard verbs on secrets | `kubectl auth can-i list secrets --as=system:serviceaccount:cde-processing:card-processor -n cde-processing` — should return `no` |
| **8.6.1** — All user IDs and authentication factors managed | OIDC integration for kubectl; no shared service accounts | `kubectl config view --raw` — verify OIDC provider configured; `kubectl get sa -n cde-processing` — verify unique SA per workload |
| **10.2.1** — Audit logs capture all access to CDE components | Kubernetes audit policy at RequestResponse level for secrets | `grep '"resource":"secrets"' /var/log/kubernetes/audit.log \| jq .` — verify secret access events with user identity |
| **10.2.2** — Audit logs capture all individual user access | Audit policy captures pod exec at Request level | `grep '"subresource":"exec"' /var/log/kubernetes/audit.log \| jq '{user:.user.username,pod:.objectRef.name,time:.requestReceivedTimestamp}'` |
| **10.3.2** — Audit logs protected from modification | Logs shipped to immutable SIEM | `kubectl get daemonset fluentd-audit-shipper -n monitoring` — verify running on control plane nodes |
| **10.5.1** — Retain audit logs for at least 12 months | Elasticsearch ILM policy with 365-day retention | `curl -s siem.internal.example.com:9200/_ilm/policy/k8s-pci-audit \| jq .` |

## Trade-offs

**NetworkPolicy performance overhead.** Default-deny with explicit allow rules adds iptables or eBPF rule evaluation to every packet. On high-throughput payment processing paths, this can add 0.5–2ms of latency per request depending on CNI and rule complexity. Cilium's eBPF dataplane is significantly faster than iptables-based CNIs (Calico in iptables mode) for large rule sets. For CDE workloads processing thousands of transactions per second, benchmark with realistic traffic before enabling default-deny. Cilium's Hubble observability layer also lets you visualise dropped flows before policies go live, reducing the risk of blocking required traffic.

**Operational complexity of namespace isolation.** Three CDE namespaces instead of one means three sets of NetworkPolicy, three ResourceQuotas, three sets of RBAC, and three sets of Kyverno policy exceptions. Every new service dependency requires a NetworkPolicy update in both the originating and destination namespace. Teams accustomed to deploying freely will encounter more friction. Mitigate this with a Helm chart or Kustomize overlay that generates the standard CDE namespace configuration, so spinning up a new CDE namespace is a single command rather than eight YAML files.

**Audit log volume.** A `RequestResponse` level audit policy on Secrets in busy namespaces generates substantial log volume. A cluster with 50 microservices in CDE namespaces doing periodic secret reads can generate 5–20GB of audit logs per day. Size your log shipper, Elasticsearch storage, and SIEM ingest pipeline accordingly before enabling the PCI audit policy in production. Use the `omitManagedFields: true` option (available in Kubernetes 1.28+) to reduce individual event size without losing compliance-relevant fields.

**Shared control plane risk.** In EKS, GKE, and AKS, the control plane is managed by the cloud provider and is shared infrastructure. The QSA must be satisfied that the cloud provider's SOC 2 Type II and PCI DSS Attestation of Compliance (AoC) cover the shared components. Request the cloud provider's AoC before the assessment. For GKE, this is available via the Google Cloud Compliance page. For EKS and AKS, the respective compliance portals provide equivalent documentation.

## Failure Modes

The following failures are the most common reasons a PCI assessment of a Kubernetes CDE fails. Run these pre-QSA checks before scheduling your Qualified Security Assessor visit.

**Failure 1 — NetworkPolicy gap: non-CDE namespace can reach CDE pods.**

```bash
# Run a network connectivity test from a non-scoped namespace.
kubectl run nettest --image=nicolaka/netshoot --rm -it \
  --namespace=default -- \
  curl -m 5 http://payment-api.cde-frontend.svc.cluster.local:8443/health
# Expected: connection timeout or connection refused.
# Failure: HTTP 200 from a non-CDE namespace means NetworkPolicy is missing
# or the podSelector is too broad.

# List all NetworkPolicies in CDE namespaces to spot gaps.
for ns in cde-frontend cde-processing cde-storage; do
  echo "=== $ns ===";
  kubectl get networkpolicy -n "$ns" -o wide;
done
```

**Failure 2 — Kyverno policy not enforcing: non-compliant pods scheduled in CDE namespace.**

```bash
# Attempt to deploy a privileged container in a CDE namespace.
# This should be REJECTED by Kyverno.
kubectl run priv-test --image=alpine --privileged \
  --namespace=cde-processing -- sleep 3600
# Expected: Error from server: admission webhook denied the request.
# Failure: Pod schedules — Kyverno policy is in Audit mode, not Enforce,
# or the policy selector does not match the namespace label.

# Check Kyverno policy mode:
kubectl get clusterpolicy cde-pod-security-requirements \
  -o jsonpath='{.spec.validationFailureAction}'
# Must return: Enforce  (not Audit)
```

**Failure 3 — etcd not encrypted: secrets stored as base64 plaintext.**

```bash
# Read a CDE secret directly from etcd and check for encryption prefix.
SECRET_PATH="/registry/secrets/cde-processing/db-credentials"
ETCDCTL_API=3 etcdctl \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get "$SECRET_PATH" | strings | head -5
# Expected: first bytes are k8s:enc:aesgcm:v1:
# Failure: plaintext JSON with "data" key visible — EncryptionConfiguration
# is missing, the API server was not restarted, or existing secrets were
# not re-encrypted after enabling encryption.
```

**Failure 4 — Audit log missing secret access events.**

```bash
# Perform a test secret read and verify the audit log captures it.
kubectl get secret db-credentials -n cde-processing > /dev/null

# Check the audit log for the event with the correct level.
grep '"resource":"secrets"' /var/log/kubernetes/audit.log | \
  jq 'select(.objectRef.namespace == "cde-processing") |
    {level: .level, user: .user.username, secret: .objectRef.name,
     verb: .verb, time: .requestReceivedTimestamp}' | tail -5
# Expected: level=RequestResponse events with user identity, timestamp,
# and secret name.
# Failure: no matching events — audit policy file path is wrong, API server
# was not restarted, or the policy rule for secrets omits the CDE namespaces.
```

**Failure 5 — Wildcard RBAC on CDE secrets.**

```bash
# Enumerate all RoleBindings in CDE namespaces that grant secrets access.
for ns in cde-frontend cde-processing cde-storage; do
  kubectl get rolebindings,clusterrolebindings -n "$ns" -o json | \
    jq --arg ns "$ns" '
      .items[] |
      . as $rb |
      .roleRef.name as $role |
      select(
        ($rb | .rules // empty | .[] |
          (.resources[] | contains("secrets")) and
          (.verbs[] | (. == "*" or . == "get" or . == "list"))
        ) // false
      ) |
      {namespace: $ns, binding: .metadata.name, role: $role}
    ' 2>/dev/null
done
# Any result here is a finding. CDE workload service accounts should not
# have secrets access via the Kubernetes API — use an external secrets
# operator (Vault, AWS Secrets Manager) instead.
```

**Failure 6 — Audit log not shipping to external SIEM.**

```bash
# Verify the Fluentd DaemonSet is running on all control plane nodes.
kubectl get pods -n monitoring -l app=fluentd-audit-shipper \
  -o wide | grep control-plane
# All control plane nodes should have a Running pod.

# Verify recent events are appearing in Elasticsearch.
curl -s "siem.internal.example.com:9200/k8s-pci-audit-*/_count" | jq .
# Count should be increasing. If 0, check Fluentd pod logs:
kubectl logs -n monitoring -l app=fluentd-audit-shipper --tail=50
```

Running all six checks before the QSA visit converts assessment day from an anxious discovery exercise into a documentation review. The commands above can be wrapped into a shell script that generates a pre-assessment evidence package — a timestamped HTML report showing pass/fail for each control — which QSAs find useful as a starting point for their own testing.
