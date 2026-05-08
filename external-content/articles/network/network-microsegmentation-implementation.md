---
title: "Network Microsegmentation Implementation: eBPF, SPIFFE, and Per-Workload Isolation"
description: "VLANs and coarse security zones leave east-west traffic within a segment unrestricted. Microsegmentation enforces per-workload firewall policy based on workload identity, not IP address — using eBPF with Cilium, systemd network namespaces, SPIFFE/SPIRE SVIDs, and service mesh mTLS."
slug: network-microsegmentation-implementation
date: 2026-05-07
lastmod: 2026-05-07
category: network
tags:
  - microsegmentation
  - zero-trust
  - ebpf
  - cilium
  - network-policy
personas:
  - security-engineer
  - platform-engineer
article_number: 515
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/network/network-microsegmentation-implementation/
---

# Network Microsegmentation Implementation: eBPF, SPIFFE, and Per-Workload Isolation

## The Problem

VLANs were designed to segment broadcast domains. They are a Layer 2 construct: they tell a switch which ports belong to the same network segment. They say nothing about which hosts within that segment may communicate with each other. A web application server and a database server in the same VLAN can reach each other on any port without restriction, because the VLAN policy only governs traffic crossing a segment boundary — not traffic flowing within one.

This boundary is where modern attacks live. In a flat network where east-west traffic is unrestricted within a segment, an attacker who compromises one workload has full network access to every other workload in the same VLAN:

- A container running a compromised application image connects directly to the adjacent PostgreSQL container on port 5432 — the database accepts all connections from the pod subnet.
- Malware on a node scans the pod CIDR range and finds Redis instances listening without authentication.
- A containerised batch job with a compromised dependency exfiltrates data to a neighbouring service — no traffic leaves the host, so perimeter firewalls never see it.

The deeper problem is that IP addresses are a terrible identity primitive for fine-grained policy. In a Kubernetes cluster, pod IPs are ephemeral and frequently reassigned. A firewall rule permitting `10.0.0.15` to reach `10.0.0.22` becomes meaningless minutes after either pod is rescheduled. You cannot write stable, auditable policy using coordinates that change.

Microsegmentation reframes the problem: instead of asking "which IP can reach which other IP," ask "which workload identity can reach which other workload identity, on which protocol and port." The policy is declared in terms of Kubernetes labels, SPIFFE IDs, or service account names — stable identifiers tied to what the workload is, not where it happens to be running at this moment.

## Microsegmentation Defined

Microsegmentation means per-workload or per-process firewall policy enforced at the host or hypervisor level, based on workload identity rather than IP address. Three properties distinguish microsegmentation from coarser segmentation models:

1. **Granularity.** Policy is applied per workload — per pod, per VM, per container, per process — not per subnet or VLAN.
2. **Enforcement point.** Policy is enforced in the kernel (eBPF, iptables/nftables), at the hypervisor vNIC, or in the sidecar proxy — not at a central firewall appliance that never sees intra-VLAN traffic.
3. **Identity binding.** Policy references workload identity — Kubernetes labels, SPIFFE SVIDs, service account names — not IP addresses.

The result is a default-deny posture at the workload level: no two workloads communicate unless a policy explicitly permits it, and that policy is expressed in terms that remain valid across pod restarts, scaling events, and node migrations.

## eBPF-Based Microsegmentation with Cilium

Cilium implements microsegmentation using eBPF programs loaded into the kernel to intercept and evaluate every packet before it is forwarded. This happens without iptables, without a sidecar proxy, and with near-zero overhead because the filtering is done in the kernel data path before the packet reaches userspace.

### Identity-Based L4 Policy

Cilium assigns each pod an internal numeric identity derived from its Kubernetes labels. Network policy decisions are made against this identity, not the pod IP. When a pod is rescheduled with a new IP, its identity is unchanged and the policy continues to apply correctly.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: payments-isolation
  namespace: payments
spec:
  endpointSelector:
    matchLabels:
      app: payments-api
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: api-gateway
            io.kubernetes.pod.namespace: frontend
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
  egress:
    - toEndpoints:
        - matchLabels:
            app: payments-db
            io.kubernetes.pod.namespace: payments
      toPorts:
        - ports:
            - port: "5432"
              protocol: TCP
    - toFQDNs:
        - matchName: "stripe.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
```

This policy selects the `payments-api` pods and applies a default-deny stance: only ingress from `api-gateway` in the `frontend` namespace on port 8080 is permitted, and only egress to the `payments-db` pods on port 5432 and to `stripe.com:443` via DNS-based FQDN matching. Everything else — including traffic to other pods in the same namespace — is dropped.

### L7 Policy for HTTP and gRPC

For HTTP and gRPC, Cilium proxies matching traffic through an embedded Envoy instance on the node (no sidecar) and evaluates L7 rules before allowing the connection:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: payments-l7
  namespace: payments
spec:
  endpointSelector:
    matchLabels:
      app: payments-api
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: api-gateway
            io.kubernetes.pod.namespace: frontend
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: "POST"
                path: "^/v1/charge$"
              - method: "GET"
                path: "^/v1/status/[0-9]+$"
```

Only two URL patterns are permitted. An attacker who compromises the `api-gateway` pod cannot enumerate other endpoints, trigger admin operations, or reach internal debug routes — even though the network-layer connection is permitted.

For gRPC, the same structure applies using the `grpc` rules key:

```yaml
          rules:
            grpc:
              - serviceName: "payments.PaymentsService"
                methodName: "Charge"
```

### Hubble for Policy Visibility

Hubble is Cilium's observability layer. It captures flow metadata — source identity, destination identity, L4 port, L7 path, and policy verdict — without capturing payload. Use it to audit what your existing policies are actually permitting and to generate allow-list policies from observed traffic:

```bash
# Install Hubble CLI
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
curl -L --fail --remote-name-all \
  "https://github.com/cilium/hubble/releases/download/${HUBBLE_VERSION}/hubble-linux-amd64.tar.gz"
tar xzvf hubble-linux-amd64.tar.gz
sudo mv hubble /usr/local/bin/

# Enable port-forward to Hubble relay
cilium hubble port-forward &

# Watch live flows for the payments namespace
hubble observe \
  --namespace payments \
  --verdict DROPPED \
  --follow

# Generate policy from observed allow traffic (useful for initial policy bootstrap)
hubble observe \
  --namespace payments \
  --verdict FORWARDED \
  --output json \
  | cilium policy generate
```

### Policy Audit Mode

Before enforcing a new policy in production, validate it with Cilium's audit mode. Packets that would be dropped are instead allowed and logged:

```bash
kubectl -n payments annotate pod -l app=payments-api \
  policy.cilium.io/proxy-visibility="+ingress/8080/TCP/HTTP"

# Enable audit mode per-namespace
kubectl annotate namespace payments \
  "policy.cilium.io/proxy-visibility=Audit"
```

Audit mode lets you observe what would have been denied without causing service disruption, then tighten to enforce once you are confident the policy is correct.

## Linux iptables/nftables Per-Service Microsegmentation

For non-Kubernetes workloads running directly on Linux hosts, per-service network namespaces combined with nftables rules provide equivalent isolation.

### systemd Network Namespace Isolation

```ini
# /etc/systemd/system/payments-api.service
[Unit]
Description=Payments API
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/payments-api
NetworkNamespacePath=/var/run/netns/payments-api
User=payments
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
PrivateNetwork=false
```

Create the namespace and configure its nftables policy before starting the service:

```bash
# Create named network namespace
ip netns add payments-api

# Create veth pair to connect namespace to host
ip link add veth-pay0 type veth peer name veth-pay1
ip link set veth-pay1 netns payments-api

# Configure addresses
ip addr add 192.168.100.1/30 dev veth-pay0
ip netns exec payments-api ip addr add 192.168.100.2/30 dev veth-pay1
ip netns exec payments-api ip link set lo up
ip netns exec payments-api ip link set veth-pay1 up
ip link set veth-pay0 up

# Apply nftables policy inside the namespace — default deny
ip netns exec payments-api nft -f - <<'EOF'
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 8080 ip saddr 192.168.100.1 accept
    # explicit drop with logging
    log prefix "payments-api-dropped: " drop
  }
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    tcp dport 5432 ip daddr 10.0.1.10 accept  # payments-db
    tcp dport 443  ip daddr 3.18.0.0/16 accept # Stripe CIDR
    log prefix "payments-api-egress-dropped: " drop
  }
}
EOF
```

The service runs in its own network namespace with a tight nftables policy. Traffic from the service to the host network or to other services on the same host is denied unless explicitly permitted.

## VMware NSX-T and Antrea for VM Workloads

For VM-based workloads, microsegmentation is enforced at the vNIC level by the hypervisor. NSX-T's distributed firewall (DFW) attaches a stateful firewall policy to each VM's virtual NIC. Policy is defined in terms of NSX-T Security Groups with membership criteria based on VM tags, OS type, or AD group — not IP addresses.

Antrea provides the same model for Kubernetes clusters running on VMware infrastructure, integrating with NSX-T for policy inheritance. The `AntreaNetworkPolicy` resource extends standard Kubernetes NetworkPolicy with priorities, logging, and applied-to selectors that mirror NSX-T DFW semantics:

```yaml
apiVersion: crd.antrea.io/v1beta1
kind: AntreaNetworkPolicy
metadata:
  name: payments-isolation
  namespace: payments
spec:
  priority: 10
  appliedTo:
    - podSelector:
        matchLabels:
          app: payments-api
  ingress:
    - action: Allow
      from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: frontend
          podSelector:
            matchLabels:
              app: api-gateway
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - action: Allow
      to:
        - podSelector:
            matchLabels:
              app: payments-db
      ports:
        - protocol: TCP
          port: 5432
```

For VMs that are not containerised, Antrea's VM agent can enforce the same policy at the vNIC level, providing a unified policy model across containers and VMs in a hybrid environment.

## Process-Level Microsegmentation

Falco, combined with its network rules engine, can enforce or alert on process-level network behaviour that violates expected policy. While Falco's primary model is detection rather than enforcement, pairing it with a kernel module or eBPF-based network drop mechanism provides process-aware blocking:

```yaml
# falco rule: detect unexpected outbound connections from payments-api
- rule: Unexpected Egress from Payments Process
  desc: payments-api connects to an unexpected destination
  condition: >
    evt.type = connect
    and container.image.repository contains "payments-api"
    and not fd.sip in (allowed_payments_egress)
    and fd.typechar = 4  # IPv4
  output: >
    Unexpected egress from payments process
    (pid=%proc.pid cmd=%proc.cmdline sip=%fd.sip sport=%fd.sport
     dip=%fd.dip dport=%fd.dport container=%container.name)
  priority: WARNING
  tags: [network, microsegmentation]
```

For stronger isolation, gVisor (runsc) intercepts all syscalls from containerised processes through a user-space kernel. Its network stack is separate from the host kernel network stack. A container running under gVisor cannot reach the host network stack directly — it must communicate through gVisor's virtual network device, which can be filtered independently.

```bash
# Configure containerd to use gVisor for high-value workloads
cat >> /etc/containerd/config.toml <<'EOF'
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
EOF

# Use the gVisor runtime class in the pod spec
kubectl apply -f - <<'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF
```

Add `runtimeClassName: gvisor` to pod specs for workloads handling sensitive data. gVisor's network isolation means that even a kernel exploit within the container cannot directly access host network interfaces.

## Identity-Based Segmentation with SPIFFE/SPIRE

IP-based firewall rules cannot scale to thousands of ephemeral workloads with dynamic addressing. SPIFFE (Secure Production Identity Framework For Everyone) solves this by issuing cryptographic identities — SVIDs (SPIFFE Verifiable Identity Documents) — to each workload. The SVID is an X.509 certificate with the workload's SPIFFE ID embedded in the Subject Alternative Name field:

```
spiffe://example.org/ns/payments/sa/payments-api
```

SPIRE (the SPIFFE Runtime Environment) is the reference implementation. Each node runs a SPIRE agent that attests the workload identity by inspecting its Unix UID, Kubernetes service account, and process namespace, then issues the SVID from the SPIRE server.

### Configuring SPIRE for Kubernetes

```bash
# Deploy SPIRE server and agent
kubectl apply -f https://spiffe.io/downloads/spire-1.9.0-k8s-quickstart.yaml

# Register workload entries — bind SPIFFE ID to k8s service account
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://example.org/ns/payments/sa/payments-api \
    -parentID spiffe://example.org/spire/agent/k8s_psat/default/$(kubectl get node -o jsonpath='{.items[0].metadata.name}') \
    -selector k8s:ns:payments \
    -selector k8s:sa:payments-api
```

### Using SVIDs in Firewall and mTLS Policy

Cilium can use SPIFFE SVIDs for policy matching when integrated with SPIRE via the SPIFFE Workload API. The SVID presented during TLS handshake is extracted from the `X-Forwarded-Client-Cert` header by Envoy and used to make L7 policy decisions:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: spiffe-based-ingress
  namespace: payments
spec:
  endpointSelector:
    matchLabels:
      app: payments-api
  ingress:
    - fromEndpoints:
        - matchLabels:
            spiffe.io/spiffe-id: "spiffe://example.org/ns/frontend/sa/api-gateway"
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
```

This binds firewall policy to cryptographic workload identity rather than network coordinates. A pod cannot spoof its SPIFFE ID without compromising the SPIRE server.

## East-West Encryption: mTLS as a Complement

Network microsegmentation controls which workloads may communicate. It does not protect the content of that communication if a host is compromised and traffic can be intercepted on the wire. mTLS completes the picture: even if a host-level packet capture or kernel exploit grants an attacker access to network traffic, the content remains encrypted.

Cilium Transparent Encryption uses WireGuard between all nodes, encrypting all pod-to-pod traffic in transit without requiring any application changes:

```bash
# Enable WireGuard transparent encryption
helm upgrade cilium cilium/cilium \
  --namespace kube-system \
  --reuse-values \
  --set encryption.enabled=true \
  --set encryption.type=wireguard

# Verify encryption is active
cilium encrypt status
# Output: Encryption: Wireguard
#         Node encryption: Disabled (default)
#         Cluster-wide keys: ...
```

For service-to-service mTLS with identity verification (not just encryption), use Cilium's Mutual Authentication mode, which wires SPIFFE identity into the mTLS handshake for each pair of communicating endpoints:

```bash
helm upgrade cilium cilium/cilium \
  --namespace kube-system \
  --reuse-values \
  --set authentication.mutual.spire.enabled=true \
  --set authentication.mutual.spire.install.enabled=true
```

With mutual authentication enabled, two pods cannot establish a connection unless both have valid SVIDs from the same SPIRE trust domain and the connection is explicitly permitted by `CiliumNetworkPolicy`. Network-layer firewall, identity verification, and encryption are enforced together.

## Implementing Microsegmentation in Stages

Rolling out microsegmentation in a running system without causing service disruptions requires an incremental approach. The following four-stage model works for Kubernetes environments but the principle applies to any platform.

**Stage 1: Namespace isolation.** Apply default-deny at the namespace level. All intra-namespace traffic is permitted; cross-namespace traffic is denied by default and must be explicitly allowed.

```bash
# Apply default-deny to a namespace
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
EOF
```

After applying, explicitly permit necessary cross-namespace paths (ingress from `frontend`, egress to `monitoring`). This alone eliminates most lateral movement across namespace boundaries.

**Stage 2: L4 per-workload policies.** Replace the namespace-level default-deny with per-workload `CiliumNetworkPolicy` resources that specify exact ports and peer identities. Use Hubble's flow data to discover all current communication paths before writing policy:

```bash
# Observe all flows in the payments namespace for 10 minutes
hubble observe --namespace payments --follow --output json \
  | tee /tmp/payments-flows.json

# Summarise communication patterns
jq -r '[.source.labels, .destination.labels, .destination_port] | @tsv' \
  /tmp/payments-flows.json | sort -u
```

**Stage 3: L7 policies.** Narrow HTTP and gRPC policies to specific methods and paths. Use audit mode first (see the Cilium section above) to validate the policy before enforcing it.

**Stage 4: mTLS with SPIFFE identity.** Enable Cilium mutual authentication and SPIRE. All permitted connections now require cryptographic identity verification. Update firewall policies to reference SPIFFE IDs rather than label selectors where workload identity is the critical invariant.

## Auditing Microsegmentation Policy

Microsegmentation policy is only as good as your ability to verify that it is being enforced correctly. Three audit techniques:

**Cilium policy audit mode.** As described above, switches from drop to allow-with-log for a transition period. Review the audit log for unexpected flows before tightening to enforce.

**Active probing.** Deploy a test pod that attempts connections it should not be allowed to make. If the connection succeeds, the policy has a gap:

```bash
kubectl run probe --image=nicolaka/netshoot --rm -it \
  --namespace=monitoring \
  -- nc -zv payments-api.payments.svc.cluster.local 8080
# Should time out or be refused if microsegmentation is correct
```

**Hubble policy-aware flow analysis.** Filter for `FORWARDED` flows from unexpected source identities to confirm that no communication path has been missed in the policy model:

```bash
hubble observe \
  --namespace payments \
  --from-label "app!=api-gateway" \
  --to-label "app=payments-api" \
  --verdict FORWARDED
# Zero results means the policy is working
```

Run active probing as a scheduled job in CI/CD. A policy regression — caused by a label change, a new deployment, or a Cilium upgrade — will be caught before it reaches production.

## Summary

VLANs segment broadcast domains; microsegmentation segments workload communication. The implementation stack for modern environments combines:

- eBPF-based identity-aware enforcement (Cilium) for per-pod L4 and L7 policy with near-zero overhead
- Namespace network isolation as the first barrier, followed by per-workload `CiliumNetworkPolicy` and L7 rules
- SPIFFE/SPIRE for cryptographic workload identity that replaces IP-based policy matching
- WireGuard transparent encryption or service-mesh mTLS to protect the content of permitted connections
- Continuous audit with Hubble flow analysis and active probing to verify policy remains correct as the environment changes

The default-deny posture enforced at the workload level means a compromised container or VM cannot reach adjacent workloads, cannot enumerate the internal network, and cannot exfiltrate data to unexpected destinations — regardless of what subnet or VLAN the workload happens to be in.
