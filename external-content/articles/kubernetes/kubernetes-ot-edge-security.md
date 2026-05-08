---
title: "Kubernetes at the IT/OT Boundary: Zero Trust for Industrial Edge"
description: "CISA's OT Zero Trust guidance places IT-side infrastructure in a DMZ zone. Learn how to use Kubernetes network policy as ISA/IEC 62443 conduit enforcement, isolate OT-adjacent workloads, and prevent K8s from bridging into OT networks."
slug: kubernetes-ot-edge-security
date: 2026-05-03
lastmod: 2026-05-03
category: kubernetes
tags:
  - ot-security
  - industrial-edge
  - network-policy
  - ics
  - zero-trust
personas:
  - platform-engineer
  - security-engineer
article_number: 400
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-ot-edge-security/
---

# Kubernetes at the IT/OT Boundary: Zero Trust for Industrial Edge

## The Problem

Kubernetes clusters deployed near OT networks routinely violate the core principle that CISA articulated in its April 2026 guidance "Adapting Zero Trust Principles to Operational Technology": there must be no implicit trust between IT and OT zones. Default Kubernetes does the opposite. All pod-to-pod traffic within a cluster is permitted unless a `NetworkPolicy` exists. All egress to external IPs is permitted unless explicitly denied. Service accounts accumulate permissions because RBAC is under-specified. The result is a platform that is, by default, a lateral movement surface rather than a security boundary.

The ISA/IEC 62443 zones-and-conduits model divides an industrial environment into security zones with distinct trust levels, connected only through explicitly defined and monitored conduits. CISA's guidance maps IT-side infrastructure — including container platforms — into Zone 3, the IT/OT DMZ. The OT network proper occupies Zone 2 (control system) and Zone 1 (field devices). Communication from Zone 3 into Zone 2 is a conduit: it must be defined, protocol-specific, minimised, and monitored.

Kubernetes is increasingly deployed in Zone 3 in three roles. First, as the hosting platform for OT-adjacent applications: historian web interfaces, SCADA dashboards, MES connectors, and PI Web API relays that need to reach both the IT enterprise network and the OT historian on separate subnets. Second, as an edge orchestration layer using K3s or MicroK8s on industrial edge hardware, running OT protocol gateway containers that translate Modbus or DNP3 to MQTT for upstream processing. Third, as the platform for OT security tools: CISA's Malcolm network analysis framework, Zeek sensors, and asset inventory services that passively observe OT traffic.

In all three roles, the K8s API server becomes a high-value lateral movement target. An attacker who can create a privileged pod with `hostNetwork: true` on a node that has a NIC on both the DMZ and the OT LAN has effectively bypassed the entire zone boundary. The firewall protecting Zone 2 becomes irrelevant when the attacker's code runs on a machine that is physically inside both zones. This is not a theoretical risk: OT nodes are frequently dual-homed because the initial deployment connected them to both networks for convenience during commissioning, and that configuration was never cleaned up.

The K8s CNI matters enormously in this environment. Flannel and Weave do not enforce `NetworkPolicy` in a meaningful way — Flannel in particular has no enforcement mechanism; NetworkPolicy objects are accepted by the API server but ignored at the data plane. In an OT-adjacent cluster, using a CNI that does not enforce NetworkPolicy is equivalent to having no network policy at all. Cilium and Calico both enforce NetworkPolicy at the kernel level via eBPF and iptables respectively, and both support egress policies to external CIDRs, which is the specific capability needed to block pod egress into OT subnets.

## Threat Model

**Compromised pod with OT subnet egress.** A containerised Modbus-to-MQTT bridge or PI connector is compromised via a supply chain attack on the container image or a dependency. The attacker's process has outbound network connectivity. With default-allow egress, the process can reach the OT historian on port 102 (ISO-TSAP), engineering workstations on port 445 (SMB), or PLC subnets on Modbus TCP port 502. The OT network has no way to distinguish this from legitimate connector traffic because the source IP is the same node.

**K8s API server compromise leading to OT network bridging.** An attacker gains access to a service account token with `pods/create` or `*` permissions. They create a pod with `spec.hostNetwork: true` and `spec.nodeName` targeting an OT-adjacent node. The pod inherits the node's network stack, including any NIC that is connected to the OT LAN segment. The attacker now has a shell inside Zone 2 via the Kubernetes API server.

**Supply chain attack on a containerised OT connector.** A Modbus-to-MQTT bridge image is pulled from a public registry. The image contains a backdoored library that phones home on startup. Because the connector legitimately needs Modbus port 502 egress to reach PLCs, and that egress is allowed, the attacker has a persistent outbound channel from inside the OT-adjacent pod. The backdoor can also probe other OT devices on the same subnet because the pod's egress to the OT CIDR is not further restricted by device or port.

**Shared node pool causing historian downtime.** A general-purpose workload (a CI build job, a batch analytics task) is scheduled onto an OT-adjacent node because no taint prevents it. The workload consumes all available CPU or memory. The OT historian connector on the same node is starved of resources and stops polling. The historian loses data for the duration. In process industries, historian gaps can trigger compliance findings and make post-incident root cause analysis impossible.

## Hardening Configuration

### 1. Dedicated Node Pools for OT-Adjacent Workloads

Label OT-adjacent nodes and apply a taint that prevents general workloads from being scheduled there:

```bash
kubectl label node ot-edge-node-01 ot-adjacent=true zone=dmz-ot
kubectl taint node ot-edge-node-01 ot-adjacent=true:NoSchedule
```

OT-adjacent pods must carry the matching toleration and `nodeSelector`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: modbus-mqtt-bridge
  namespace: ot-connectors
spec:
  template:
    spec:
      nodeSelector:
        ot-adjacent: "true"
      tolerations:
        - key: ot-adjacent
          operator: Equal
          value: "true"
          effect: NoSchedule
      containers:
        - name: bridge
          image: internal-registry.example.com/modbus-mqtt-bridge:1.4.2
```

General workloads carry no toleration and cannot be scheduled on OT nodes. The taint acts as a hard boundary enforced by the Kubernetes scheduler itself, before any network policy is consulted.

### 2. NetworkPolicy as ISA/IEC 62443 Conduit Enforcement

Apply a default-deny baseline to the OT connectors namespace first. This is the equivalent of a closed conduit: no traffic flows unless explicitly defined.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ot-connectors
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

Then define the conduit: the specific pod, the specific OT subnet, and the specific protocol port. This policy models the ISA/IEC 62443 conduit from Zone 3 (the K8s pod) to Zone 2 (the OT historian) on exactly the protocol required:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: modbus-bridge-conduit
  namespace: ot-connectors
spec:
  podSelector:
    matchLabels:
      app: modbus-mqtt-bridge
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 10.20.30.0/24
      ports:
        - protocol: TCP
          port: 502
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: mqtt-broker
          podSelector:
            matchLabels:
              app: mosquitto
      ports:
        - protocol: TCP
          port: 1883
```

The first egress rule is the conduit to the OT subnet on Modbus TCP port 502 only. The second allows the bridge to publish to the MQTT broker inside the cluster. Every other egress destination — including other OT subnets, the engineering workstation subnet, and the internet — is denied by the default-deny policy established above.

Block all pod egress to OT CIDRs from general namespaces to prevent any non-OT workload from accidentally or intentionally reaching OT networks. Apply this cluster-wide using Cilium's `CiliumClusterwideNetworkPolicy`:

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: block-ot-egress-default
spec:
  endpointSelector:
    matchExpressions:
      - key: ot-adjacent
        operator: NotIn
        values:
          - "true"
  egress:
    - toEntities:
        - world
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
            - port: "80"
              protocol: TCP
    - toCIDRSet:
        - cidr: 10.20.0.0/16
          except:
            - 10.20.30.0/24
```

This policy allows general pods internet egress on standard ports but blocks all egress to the OT CIDR (`10.20.0.0/16`). Only pods labelled `ot-adjacent=true` are excluded from this policy, and their egress is controlled by the namespace-scoped policies above.

### 3. API Server Access Restriction

The API server's `--authorization-mode` must include both `RBAC` and `Node`. The `Node` authorizer prevents a compromised kubelet from reading secrets or configmaps that belong to pods on other nodes — an important boundary even within the cluster.

```yaml
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --authorization-mode=Node,RBAC
        - --anonymous-auth=false
        - --audit-log-path=/var/log/kubernetes/audit.log
        - --audit-log-maxage=30
        - --audit-log-maxbackup=10
        - --audit-log-maxsize=100
        - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
```

The audit policy must capture `exec` and `portforward` verb usage explicitly. Both verbs can give an attacker an interactive shell inside an OT-adjacent pod:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    verbs:
      - create
    resources:
      - group: ""
        resources:
          - pods/exec
          - pods/portforward
          - pods/attach
  - level: Metadata
    resources:
      - group: ""
        resources:
          - secrets
  - level: None
    users:
      - system:kube-proxy
    verbs:
      - watch
    resources:
      - group: ""
        resources:
          - endpoints
          - services
  - level: Metadata
    omitStages:
      - RequestReceived
```

The `system:masters` group bypasses RBAC entirely. No human user or service account should be bound to `system:masters` in an OT-adjacent cluster. Audit all existing bindings:

```bash
kubectl get clusterrolebindings -o json | \
  jq '.items[] | select(.subjects[]?.name == "system:masters") | .metadata.name'
```

Remove any binding that references `system:masters` for non-bootstrap purposes. Cluster administrators should use a `cluster-admin` ClusterRoleBinding to a specific group from your IdP, which can be audited and revoked.

### 4. Service Account RBAC Minimisation

OT-adjacent pods must not use the `default` service account and must not carry any cluster-wide permissions. Create a dedicated service account with the minimum required permissions:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: modbus-bridge-sa
  namespace: ot-connectors
automountServiceAccountToken: false
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: modbus-bridge-role
  namespace: ot-connectors
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["modbus-bridge-config"]
    verbs: ["get", "watch"]
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: modbus-bridge-rolebinding
  namespace: ot-connectors
subjects:
  - kind: ServiceAccount
    name: modbus-bridge-sa
    namespace: ot-connectors
roleRef:
  kind: Role
  name: modbus-bridge-role
  apiGroup: rbac.authorization.k8s.io
```

Setting `automountServiceAccountToken: false` at the ServiceAccount level prevents the API token from being injected as a volume unless explicitly overridden in the pod spec. This means a compromised OT connector pod cannot use its service account token to make API calls.

### 5. Kyverno Policy to Enforce Host Isolation

Enforce at admission that no pod in the `ot-connectors` namespace can request host-level access. A pod with `hostNetwork: true` on an OT-adjacent node is the direct path to Zone 2 bypass:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-ot-host-access
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: deny-host-network
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - ot-connectors
                - ot-security-tools
      validate:
        message: "OT-adjacent pods must not use hostNetwork, hostPID, or hostIPC."
        pattern:
          spec:
            hostNetwork: "false | ~X"
            hostPID: "false | ~X"
            hostIPC: "false | ~X"
    - name: deny-privileged-containers
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - ot-connectors
                - ot-security-tools
      validate:
        message: "OT-adjacent containers must not run as privileged."
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): "false"
```

The `~X` operator in Kyverno means "not present or false" — it catches both explicit `false` and the absence of the field, which is the same as false in Kubernetes semantics. Without this, a pod spec that simply omits `hostNetwork` would not match a pattern checking for `false` and would pass the policy incorrectly.

### 6. Node Network Interface Isolation

OT-adjacent nodes must have exactly one NIC connected to the DMZ network. Dual-homing — where the node has an interface connected to both the DMZ and the OT LAN — makes NetworkPolicy irrelevant for host-level processes and creates a physical path from the cluster node into Zone 2 that bypasses all Kubernetes controls.

Verify each OT-adjacent node's network interfaces:

```bash
kubectl debug node/ot-edge-node-01 -it --image=busybox -- ip link show
```

Expected output for a correctly isolated node:

```bash
1: lo: <LOOPBACK,UP,LOWER_UP>
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
```

`eth0` should be the DMZ interface only. If you see a second physical interface (`eth1`, `ens4`, `bond1`) that is connected to the OT subnet, the node is dual-homed and must be reconfigured before any hardening at the Kubernetes layer is meaningful. Document this in the cluster run book: no OT-adjacent node may have an interface with an IP in the OT CIDR range.

Verify IP addresses on each interface to confirm no OT subnet addressing:

```bash
kubectl debug node/ot-edge-node-01 -it --image=busybox -- ip addr show
```

Any interface with an address in the OT CIDR (e.g. `10.20.30.0/24`) indicates dual-homing. Remove or disable that interface at the OS level and update the physical or virtual switch configuration to ensure the port is not trunked to both VLANs.

## Expected Behaviour After Hardening

With `NetworkPolicy` enforced by Cilium or Calico, a test pod in the `default` namespace cannot reach the OT subnet:

```bash
kubectl run test-egress --image=busybox --restart=Never -- \
  sh -c "nc -zv 10.20.30.100 502; echo exit=$?"
```

Expected: the connection times out and exits non-zero. The Cilium flow log shows a `DROPPED` verdict with reason `policy-verdict`. If the connection succeeds, the CNI is not enforcing NetworkPolicy.

A pod spec requesting `hostNetwork: true` in the `ot-connectors` namespace is rejected at admission by Kyverno before it reaches the scheduler:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: ot-connectors
spec:
  hostNetwork: true
  containers:
    - name: test
      image: busybox
EOF
```

Expected: `Error from server: admission webhook "validate.kyverno.svc" denied the request: OT-adjacent pods must not use hostNetwork, hostPID, or hostIPC.`

The audit log captures every `exec` attempt against OT-adjacent pods:

```bash
grep '"resource":"pods"' /var/log/kubernetes/audit.log | \
  jq 'select(.objectRef.subresource == "exec") | {user: .user.username, pod: .objectRef.name, ns: .objectRef.namespace, time: .requestReceivedTimestamp}'
```

Any entry in this output should trigger a review. Routine operations on OT connector pods should not require exec access. If a human operator needs to inspect the connector state, a read-only logging sidecar or structured application metrics should be the mechanism, not `kubectl exec`.

## Trade-offs and Operational Considerations

Dedicated OT-adjacent node pools increase cluster infrastructure cost. In a small edge deployment running K3s on three nodes, creating a dedicated pool might mean doubling hardware. The trade-off is accepted because the alternative — co-scheduling OT connectors with general workloads — violates the ISA/IEC 62443 zone model at the compute layer. Document this cost as a zone-separation control in your security architecture review, not as an optional optimisation.

NetworkPolicy rules that reference OT subnet CIDRs require accurate subnet information from the OT network team. In practice, OT networks are often under-documented: subnets were assigned during plant commissioning a decade ago, are not in any CMDB, and are known only to the automation engineers. Getting accurate CIDR ranges is a prerequisite for writing correct egress policies. If the ranges are wrong or incomplete, the policy either blocks legitimate traffic (connector fails to reach the PLC) or leaves gaps that allow lateral movement. Schedule a working session with the OT network team before writing any CIDR-based policy and validate the ranges against actual traffic captures from the historian or a passive sensor.

Some OT connectors use dynamic or application-defined ports. OSIsoft PI Web API defaults to port 443 but can be configured otherwise. Ignition gateways use port 8088 for the web interface and 4840 for OPC-UA. Enumerate ports in use before writing the NetworkPolicy conduit rules:

```bash
ss -tnp | grep <connector-process-name>
```

Or, if you have a passive network sensor (Zeek, Malcolm) on the OT segment, query it for all connections originating from the node's DMZ IP to the OT CIDR over the previous 30 days. This gives you a complete port inventory from observed behaviour rather than documentation.

When OT connectors use UDP (DNP3 can run over UDP), note that Kubernetes `NetworkPolicy` egress rules require explicit protocol specification. A rule specifying `protocol: TCP` does not cover UDP. Write separate rules for each protocol if the connector uses both.

## Failure Modes

**CNI does not enforce NetworkPolicy.** The most dangerous failure mode. Flannel does not enforce NetworkPolicy. Weave's enforcement has known gaps with egress `ipBlock` rules. If you deploy a `NetworkPolicy` with an OT CIDR block using Flannel, the policy is accepted by the API server, `kubectl get networkpolicy` shows it as applied, and pods can still reach the OT subnet. Always verify enforcement with an active test after deployment. If your CNI does not pass the test above, migrate to Cilium or Calico before relying on any NetworkPolicy-based isolation.

**DaemonSet scheduled on OT-adjacent node opens unexpected egress.** Cluster-wide DaemonSets — log forwarders (Fluent Bit, Filebeat), monitoring agents (Datadog agent, Prometheus node exporter), or vulnerability scanners — are scheduled on every node by default, including OT-adjacent nodes. These agents often have egress to external telemetry endpoints: cloud-based log aggregators, SaaS monitoring platforms, or external APM services. This egress bypasses the intent of the conduit model: the OT-adjacent node now has an outbound path to the internet that was not explicitly defined. Audit all DaemonSets in the cluster and apply `nodeAffinity` or `nodeSelector` rules to exclude OT-adjacent nodes from any DaemonSet that does not have an approved network conduit for its external egress.

**Cluster upgrade invalidates NetworkPolicy behaviour.** Kubernetes 1.32 introduced changes to how `NetworkPolicy` interacts with the new `AdminNetworkPolicy` API. A cluster upgraded from 1.30 to 1.32 without reviewing NetworkPolicy semantics may find that existing policies interact with new default admission policies in unexpected ways. After every cluster upgrade in an OT-adjacent environment, re-run the egress test above to confirm that OT CIDR blocks are still enforced. Treat this as a required post-upgrade validation step in your runbook alongside health checks and application smoke tests.

**OT connector image pulled from public registry at runtime.** If the pod spec references `image: somevendor/modbus-bridge:latest` without a digest pin, a node restart or pod reschedule triggers a fresh pull from the public registry. A compromised or hijacked image on the registry is pulled without any alert. Pin all OT-adjacent container images to a digest and pull from an internal registry that has been scanned. Use Kyverno to enforce this:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-ot-image-digest
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-image-digest
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaces:
                - ot-connectors
      validate:
        message: "OT-adjacent container images must reference a digest and use the internal registry."
        pattern:
          spec:
            containers:
              - image: "internal-registry.example.com/*@sha256:*"
```

## Related Articles

- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [Cilium Network Policy](/articles/kubernetes/cilium-network-policy/)
- [Kyverno Policy Development](/articles/kubernetes/kyverno-policy-development/)
- [Node Hardening](/articles/kubernetes/node-hardening/)
- [OT Network Segmentation Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)
