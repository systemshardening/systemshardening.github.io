---
title: "Kubernetes for OT Security Tooling: Deploying Malcolm and Zeek in the SOC"
description: "CISA recommends Malcolm for OT network traffic analysis. Deploy it on Kubernetes for reproducible SOC infrastructure — DaemonSet packet capture, persistent storage for 90-day retention, and RBAC-controlled analyst access."
slug: kubernetes-ot-security-tooling
date: 2026-05-03
lastmod: 2026-05-03
category: kubernetes
tags:
  - ot-security
  - malcolm
  - zeek
  - soc
  - daemonset
personas:
  - platform-engineer
  - security-engineer
article_number: 408
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-ot-security-tooling/
---

# Kubernetes for OT Security Tooling: Deploying Malcolm and Zeek in the SOC

## The Problem

OT SOC tooling is typically deployed as ad-hoc virtual machines or bare-metal servers, making it difficult to reproduce, audit, or scale. CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" recommends Malcolm as the primary open-source platform for OT network traffic analysis. Malcolm is not a single container: it bundles five tightly coupled components — Zeek (protocol parsing), Arkime (full-packet capture and search), OpenSearch (index and query backend), OpenSearch Dashboards (analyst UI), and NetBox (asset inventory). Each component has distinct memory and CPU profiles. On a standalone VM, nothing prevents Arkime from consuming all available memory during a high-traffic event, evicting Zeek's log writers or causing OpenSearch JVM to OOM and restart.

Running Malcolm on Kubernetes solves these problems through declarative, version-controlled manifests. Resource limits per component prevent noisy-neighbour exhaustion. `PersistentVolumeClaims` with defined `StorageClass` policies replace ad-hoc disk management. RBAC separates SOC analyst access from platform administrator access. And the full deployment — capture node configuration, PVC definitions, network policies, ingress rules — lives in a git repository that can be reviewed, diffed, and redeployed after a node failure.

The core challenge is packet capture. Zeek requires access to a raw network interface on the physical node connected to the OT SPAN port. A standard Kubernetes pod with a CNI-assigned IP address cannot do this: the pod sees only the virtual network interface. Capturing at the SPAN port requires the Zeek pod to use the node's actual network stack via `hostNetwork: true`. This is a significant security exception. Without careful scoping, a `hostNetwork: true` pod can bind to any interface on the node, including the management NIC and any internal cluster network. The mitigations are a dedicated capture node, a taint that prevents other workloads from landing there, and a `nodeSelector` that ensures only the Zeek DaemonSet is scheduled on that node.

The second operational constraint is storage. OT security investigations frequently require packet-level evidence going back 60 to 90 days. Engineering credentials pass in plaintext over Modbus, DNP3, and older OPC-DA protocols — a full-packet capture is often the only way to prove what credentials were in transit during an incident. A 4 TB PVC is the minimum practical allocation for 90-day full-packet retention at typical OT network volumes (50–200 Mbps sustained traffic on a busy manufacturing segment). Zeek log data is far smaller — 500 GB covers 90 days of compressed conn, dns, http, and protocol-specific logs at the same traffic volumes.

## Threat Model

**SOC tooling compromise via OpenSearch backend access.** An attacker who reaches Malcolm's OpenSearch API on port 9200 can query and exfiltrate full OT packet captures including engineering workstation credentials, PLC configuration downloads, and historian authentication tokens transmitted in plaintext over legacy OT protocols. Port 9200 must never be reachable from analyst workstations or from cluster-internal pods outside the `ot-soc` namespace. NetworkPolicy must enforce this separation even if the analyst can reach the Dashboards frontend on port 443.

**Noisy-neighbour resource exhaustion.** Arkime ingests a burst of OT traffic — common after a firmware update event where dozens of PLCs simultaneously transfer large configuration files over Ethernet/IP or PROFINET. Without a memory limit, Arkime's packet writer threads consume all available node memory. OpenSearch's JVM heap is evicted, the Dashboards service becomes unavailable, and Zeek's log writers drop packets. Resource limits with correctly sized requests prevent this: Arkime gets a hard ceiling, OpenSearch gets a guaranteed reservation, and the scheduler will OOM-kill Arkime rather than cascading into the entire Malcolm stack.

**Unauthorised dashboard access.** Malcolm's OpenSearch Dashboards interface exposes saved searches, network graphs, and protocol analysis derived from OT traffic. If exposed without TLS termination and authentication, any host on the management network — including workstations that are only supposed to reach the corporate intranet — can read OT network behaviour. This is a high-value reconnaissance resource for an attacker preparing a process disruption. The mitigation is TLS termination at an Nginx ingress with a certificate from an internal CA, and a NetworkPolicy that whitelists only analyst workstation subnets.

**Capture node privilege escalation.** The Zeek DaemonSet pod runs with `CAP_NET_RAW` and `CAP_NET_ADMIN`, and uses `hostNetwork: true` to access the SPAN interface. A compromised Zeek container — via a malicious Zeek script package, a vulnerability in the Zeek binary, or a supply chain attack on the container image — has the ability to send and receive arbitrary frames on the node's network stack. This is effectively a full network pivot from inside the K8s cluster onto the OT SPAN port's upstream switch. The mitigations are: image pinning to a verified digest, a `seccompProfile` that blocks unexpected syscalls, and no other workloads scheduled on the capture node via taint.

## Hardening Configuration

### 1. Dedicated Capture Node

Label one node `role=ot-capture` and apply a taint. The capture node needs two physical NICs: a management NIC for K8s pod network traffic, and a capture NIC connected to the OT SPAN port with no IP address assigned. Without an IP on the capture NIC, the interface cannot initiate connections — it can only receive traffic from the SPAN.

```bash
kubectl label node ot-capture-node-01 role=ot-capture zone=ot-soc
kubectl taint node ot-capture-node-01 role=ot-capture:NoSchedule
```

On the node itself, verify the capture interface has no IP address before proceeding:

```bash
ip link show ens4
ip addr show ens4
```

The interface should show state `UP` with no `inet` or `inet6` address entries. If it has an IP, remove it — an IP-addressed SPAN interface can participate in ARP and respond to probes, which is not appropriate for a passive capture port.

Set the interface into promiscuous mode so Zeek can receive all frames:

```bash
ip link set ens4 promisc on
```

Persist this across reboots via a systemd unit or a `NetworkManager` dispatcher script. Kubernetes does not manage host-level interface configuration, so this step must be documented and applied as part of node provisioning.

### 2. Zeek Capture DaemonSet

The DaemonSet uses `hostNetwork: true` scoped strictly to the capture node via `nodeSelector` and `tolerations`. Capabilities are restricted to `CAP_NET_RAW` (required for raw socket capture) and `CAP_NET_ADMIN` (required to set the interface into promiscuous mode programmatically). All other capabilities are dropped. The pod does not run as root beyond what the capability set requires.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: zeek-capture
  namespace: ot-soc
spec:
  selector:
    matchLabels:
      app: zeek-capture
  template:
    metadata:
      labels:
        app: zeek-capture
    spec:
      hostNetwork: true
      nodeSelector:
        role: ot-capture
      tolerations:
        - key: role
          operator: Equal
          value: ot-capture
          effect: NoSchedule
      serviceAccountName: zeek-capture-sa
      automountServiceAccountToken: false
      containers:
        - name: zeek
          image: internal-registry.example.com/zeek:6.0.4@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
          args:
            - -i
            - ens4
            - /etc/zeek/local.zeek
          securityContext:
            capabilities:
              add:
                - NET_RAW
                - NET_ADMIN
              drop:
                - ALL
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: false
            runAsUser: 0
          seccompProfile:
            type: RuntimeDefault
          resources:
            requests:
              memory: 2Gi
              cpu: 1000m
            limits:
              memory: 4Gi
              cpu: 2000m
          volumeMounts:
            - name: zeek-logs
              mountPath: /zeek/logs
            - name: zeek-config
              mountPath: /etc/zeek
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: zeek-logs
          persistentVolumeClaim:
            claimName: zeek-logs-pvc
        - name: zeek-config
          configMap:
            name: zeek-config
        - name: tmp
          emptyDir: {}
```

`runAsUser: 0` is required because libpcap needs root for raw socket access even with the capability flags set. This is a known limitation of libpcap on Linux; document it as an exception in the security architecture review and note that the capability drop (`drop: ALL` with only `NET_RAW` and `NET_ADMIN` added back) constrains the blast radius compared to a fully privileged container.

### 3. PersistentVolumeClaims for Packet Retention

Two PVCs are required: one for Arkime's PCAP files (4 TB) and one for Zeek's log output (500 GB). Both use a `StorageClass` with `reclaimPolicy: Retain` to prevent accidental deletion when the PVC is released. In an incident investigation, losing 90 days of packet data because a pod restart triggered PVC reclamation is a compliance failure and potentially an evidence destruction event.

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ot-soc-retain
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Retain
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: arkime-pcap-pvc
  namespace: ot-soc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ot-soc-retain
  resources:
    requests:
      storage: 4Ti
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: zeek-logs-pvc
  namespace: ot-soc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ot-soc-retain
  resources:
    requests:
      storage: 500Gi
```

`WaitForFirstConsumer` binding mode defers PV provisioning until a pod is actually scheduled, which ensures the volume is provisioned on the same node as the capture pod when using local storage. If you use a network-attached storage backend (NFS, iSCSI, Ceph), change `volumeBindingMode` to `Immediate`.

Local-path storage is adequate and cost-effective for a dedicated capture node, but there is no redundancy: if the node's storage disk fails, all packet data is lost. The mitigation is a documented backup strategy — incremental PCAP exports to object storage (S3-compatible) triggered nightly, with a 90-day retention policy on the object store. Arkime supports this via its S3 export plugin.

### 4. Resource Limits Per Component

Apply a `ResourceQuota` to the `ot-soc` namespace that defines aggregate limits, and set per-container `requests` and `limits` in each component's deployment manifest. The quota catches drift — if someone adds an unplanned component or raises a container's limit without updating the quota, the namespace admission controller rejects the change.

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: ot-soc-quota
  namespace: ot-soc
spec:
  hard:
    requests.memory: 32Gi
    limits.memory: 36Gi
    requests.cpu: "8"
    limits.cpu: "12"
```

Per-component limits to specify in each deployment's container spec:

```yaml
resources:
  requests:
    memory: 12Gi
    cpu: 2000m
  limits:
    memory: 16Gi
    cpu: 4000m
```

That block applies to the OpenSearch container. Set OpenSearch's `OPENSEARCH_JAVA_OPTS` environment variable to `-Xms12g -Xmx12g` so the JVM heap is set to match the container memory request. If the JVM heap exceeds the container memory limit, the Linux OOM killer terminates the container before the JVM can handle the condition gracefully, causing a hard restart and potential index corruption. Aligning heap size with memory limits prevents this.

For Arkime: 8 GB limit, 6 GB request. For Zeek: 4 GB limit, 2 GB request. For OpenSearch Dashboards: 2 GB limit, 1 GB request. For NetBox: 2 GB limit, 512 MB request.

### 5. RBAC for SOC Access

Create a dedicated `ot-soc-analyst` Role in the `ot-soc` namespace. SOC analysts need read access to pod logs (to review Zeek and Arkime status) and access to the Dashboards service endpoint. They do not need any write access to resources, and they must not be able to exec into pods, create or delete resources, or access Secrets (which contain OpenSearch credentials).

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ot-soc-analyst
  namespace: ot-soc
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["services", "endpoints"]
    verbs: ["get", "list", "watch"]
```

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ot-soc-analyst-binding
  namespace: ot-soc
subjects:
  - kind: Group
    name: ot-soc-analysts
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: ot-soc-analyst
  apiGroup: rbac.authorization.k8s.io
```

Enforce network-layer access control with a `NetworkPolicy` that allows analyst workstations to reach the Dashboards ingress on port 443 but explicitly blocks direct access to the OpenSearch API port 9200. The policy must use an `ipBlock` selector targeting the analyst workstation subnet rather than a broad namespace selector.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: soc-analyst-ingress
  namespace: ot-soc
spec:
  podSelector:
    matchLabels:
      app: opensearch-dashboards
  policyTypes:
    - Ingress
  ingress:
    - from:
        - ipBlock:
            cidr: 192.168.10.0/24
      ports:
        - protocol: TCP
          port: 5601
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-opensearch-external
  namespace: ot-soc
spec:
  podSelector:
    matchLabels:
      app: opensearch
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: opensearch-dashboards
        - podSelector:
            matchLabels:
              app: arkime
        - podSelector:
            matchLabels:
              app: zeek-capture
      ports:
        - protocol: TCP
          port: 9200
        - protocol: TCP
          port: 9300
```

Port 9200 is reachable only from other Malcolm components inside the `ot-soc` namespace. No analyst workstation IP, no ingress controller pod, and no other namespace can reach it directly.

### 6. TLS for All Malcolm Interfaces

Terminate TLS at an Nginx ingress controller in front of the OpenSearch Dashboards service. Use cert-manager with an internal CA ClusterIssuer so the certificate is renewed automatically and is signed by your organisation's private PKI rather than a self-signed cert that analysts must individually trust.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: malcolm-dashboards
  namespace: ot-soc
  annotations:
    cert-manager.io/cluster-issuer: internal-ca-issuer
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - malcolm.soc.internal
      secretName: malcolm-dashboards-tls
  rules:
    - host: malcolm.soc.internal
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: opensearch-dashboards
                port:
                  number: 5601
```

The `proxy-body-size: "0"` annotation removes Nginx's default 1 MB request body limit, which would otherwise truncate large Arkime search queries that include extended time ranges or packet filter expressions. The read and send timeouts accommodate slow OpenSearch queries on large PCAP indexes — without these, Nginx terminates the connection before a 90-day retrospective search completes.

Set `ssl-redirect: "true"` to ensure that any analyst who navigates to `http://malcolm.soc.internal` is redirected to HTTPS. HTTP traffic to the Dashboards interface carries session cookies that include OpenSearch query context; transmitting these over plaintext on the SOC management VLAN is unnecessary risk.

## Expected Behaviour After Hardening

Verify the capture DaemonSet is running and bound to the correct interface:

```bash
kubectl logs -n ot-soc -l app=zeek-capture --tail=30
```

The logs should show Zeek startup messages including `listening on ens4` and the loaded protocol parsers (ENIP, DNP3, Modbus, BACnet depending on your `local.zeek` configuration). If you see `permission denied opening socket` or `interface not found`, the node label or taint selector is incorrect and the pod has scheduled on a node without the SPAN NIC.

Verify PVC binding:

```bash
kubectl get pvc -n ot-soc
```

Both `arkime-pcap-pvc` and `zeek-logs-pvc` should show `STATUS: Bound`. A `Pending` status indicates the PV has not been provisioned — check that the `StorageClass` and PV exist and that `volumeBindingMode: WaitForFirstConsumer` has resolved after a pod was scheduled.

Verify RBAC enforcement. The SOC analyst account should reach Dashboards and be blocked from the OpenSearch API:

```bash
curl -k -u analyst:password https://malcolm.soc.internal
```

Expected: HTTP 200 with the Dashboards HTML response.

```bash
curl -k -u analyst:password https://malcolm.soc.internal:9200/_cluster/health
```

Expected: connection refused or a 403 response. If this returns a 200 with cluster health data, the NetworkPolicy blocking port 9200 is either not applied or the CNI is not enforcing it. Run `kubectl describe networkpolicy block-opensearch-external -n ot-soc` to confirm the policy exists, then verify the CNI (Cilium or Calico) is running and enforcing policies with an active test.

## Trade-offs and Operational Considerations

Kubernetes adds significant operational complexity compared to a standalone Malcolm VM or a docker-compose deployment. Malcolm's official deployment mechanism is docker-compose. Running Malcolm on Kubernetes requires translating the compose file into K8s manifests — Deployments, Services, ConfigMaps, PVCs, and Ingress resources — and maintaining that translation through every Malcolm upstream release. When Malcolm 24.x introduces a new component or changes a service port, the K8s manifests must be updated manually; there is no automatic translation. This maintenance burden is only justified if your organisation already runs Kubernetes for other SOC or OT tooling and can amortise the platform overhead. If Malcolm is the only containerised workload in the SOC, a well-configured VM with docker-compose and a configuration backup strategy is operationally simpler and lower risk.

The `hostNetwork: true` exception on the Zeek DaemonSet is a material deviation from Kubernetes security baselines including the Pod Security Standards `restricted` profile. It must be documented as an accepted exception in every security audit, with a clear justification (passive SPAN capture requires raw socket access), a description of the compensating controls (dedicated node with taint, capability drop, seccomp profile, image digest pin), and a named owner who reviews the exception annually. If your organisation uses a Pod Security Admission controller enforcing the `restricted` standard cluster-wide, the `ot-soc` namespace must be explicitly exempted at the `baseline` or `privileged` level, and that exemption must be tracked in the same change management process as the exception documentation.

The 4 TB PVC requires storage infrastructure that supports large volumes. The `kubernetes.io/no-provisioner` local-path approach is adequate and avoids network storage latency for high-throughput PCAP writes, but offers no redundancy. A disk failure on the capture node destroys all retained packet data. The nightly PCAP export to object storage described above is mandatory in this configuration, not optional. If your organisation cannot tolerate any packet data loss, use a storage backend with RAID or erasure coding — Ceph with a `RWX` PVC shared between a primary and a standby capture pod, or an NFS appliance with mirrored volumes — at the cost of higher write latency and more complex infrastructure.

## Failure Modes

**Capture DaemonSet scheduled on the wrong node.** If the `nodeSelector` label is applied too broadly — `zone=ot-soc` matches three nodes instead of one — Zeek pods will be scheduled on nodes that have no SPAN NIC. Those pods will start, bind to a non-existent or wrong interface, and produce no logs. The capture appears healthy from the Kubernetes perspective (pods are `Running`) but no OT traffic is being parsed. Validate by checking `kubectl logs` for the interface binding message immediately after deployment and again after any node pool change.

**OpenSearch JVM heap exceeds container memory limit.** If `OPENSEARCH_JAVA_OPTS=-Xmx14g` is set but the container memory limit is `16Gi`, a JVM heap allocation plus native memory overhead can exceed 16 GB, triggering the Linux OOM killer. OpenSearch is terminated mid-write. On restart, it performs a recovery scan of its data directory, which can take 10–20 minutes on a large index. During that time, Zeek logs are not indexed and Arkime PCAP references are not queryable. Set `Xms` and `Xmx` to no more than 60% of the container memory limit to leave headroom for the JVM's native memory allocations, OS page cache, and the OpenSearch off-heap data structures.

**NetworkPolicy allows analyst access to OpenSearch port 9200.** If the NetworkPolicy for OpenSearch ingress includes an `ipBlock` that covers the analyst workstation subnet, analysts can query the OpenSearch REST API directly — bypassing Dashboards access controls, index-level permissions, and audit logging. This gives any analyst the ability to delete indices, modify mappings, run expensive aggregation queries that saturate the node, or exfiltrate raw log data to an external host. Audit the NetworkPolicy after every change: port 9200 and 9300 must only be reachable from within the `ot-soc` namespace's own pods.

**Malcolm updated via docker-compose on the capture node, bypassing K8s manifests.** If someone SSHes to the capture node and runs `docker compose pull && docker compose up -d` in the Malcolm directory, the containers running outside Kubernetes will conflict with the K8s-managed pods or silently replace them with newer versions. The K8s control plane has no visibility into containers started directly by Docker. The resource limits, NetworkPolicies, RBAC, and PVC bindings defined in the K8s manifests do not apply to the docker-compose containers. The SOC then operates Malcolm at a version and configuration that is not tracked in the git repository. Prevent this by removing Docker from the capture node's container runtime and relying solely on the containerd runtime used by kubelet. If Docker is required for maintenance tasks, document a change management gate that requires updating the K8s manifests before any Malcolm version change is applied.

## Related Articles

- [OT Network Monitoring Malcolm](/articles/observability/ot-network-monitoring-malcolm/)
- [Kubernetes OT Edge Security](/articles/kubernetes/kubernetes-ot-edge-security/)
- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [OTel Collector Hardening](/articles/observability/otel-collector-hardening/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
