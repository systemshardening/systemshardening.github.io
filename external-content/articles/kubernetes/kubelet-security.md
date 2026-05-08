---
title: "Kubelet Security Configuration: Authentication, Authorization, and Read-Only Port"
description: "The kubelet runs on every node in the cluster with root-level access to the container runtime, all pod specifications, mounted secrets, and the host.."
slug: "kubelet-security"
date: 2026-03-26
lastmod: 2026-03-26
category: "kubernetes"
tags: ["kubernetes", "kubelet", "node-security", "authentication", "tls"]
personas: ["platform-engineer", "security-engineer"]
article_number: 24
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
published: true
layout: article.njk
permalink: "/articles/kubernetes/kubelet-security/index.html"
---

# Kubelet Security Configuration: Authentication, Authorization, and Read-Only Port

## Problem

The kubelet runs on every node in the cluster with root-level access to the container runtime, all pod specifications, mounted secrets, and the host filesystem. Its API (port 10250) can list running pods, exec into containers, retrieve logs, and access environment variables containing credentials. On many self-managed clusters, the kubelet is configured with defaults that allow anonymous access or expose a read-only port (10255) that leaks pod metadata to anyone who can reach the node network.

The specific risks:

- **Anonymous authentication is enabled by default in some distributions.** When `--anonymous-auth=true` (the default), any HTTP request to the kubelet API on port 10250 is accepted without credentials. An attacker with network access to a node can list all pods, exec into any container, and read all pod logs.
- **The read-only port exposes metadata without authentication.** Port 10255 serves a subset of the kubelet API (pod lists, node stats, spec data) over plain HTTP with no authentication at all. This includes pod names, namespaces, container images, resource limits, and environment variable names.
- **Pod-to-node kubelet access is unrestricted by default.** A compromised pod can reach the kubelet API on its own node via the node's internal IP. Without network policies blocking this traffic, any pod with code execution can query the kubelet directly.
- **TLS configuration is often incomplete.** Self-managed clusters may use self-signed certificates for kubelet serving, skip certificate rotation, or disable certificate verification between the API server and kubelet.

This article covers locking down kubelet authentication and authorization, disabling the read-only port, configuring TLS properly, and preventing pod-level access to the kubelet API.

**Target systems:** [Kubernetes](https://kubernetes.io) 1.29+ on self-managed clusters (kubeadm, k3s, Rancher RKE2, bare-metal). Managed providers (EKS, GKE, AKS) handle most kubelet configuration automatically.

## Threat Model

- **Adversary:** Attacker with code execution inside a pod (via application vulnerability or supply chain compromise), or an attacker with network access to the node subnet (via compromised adjacent workload, VPN misconfiguration, or cloud VPC misrouting).
- **Access level:** Network connectivity to kubelet ports 10250 or 10255 on any cluster node.
- **Objective:** Enumerate running pods and their metadata (reconnaissance), exec into other containers on the same node (lateral movement), read secrets mounted as environment variables or volumes (credential theft), or access container logs containing sensitive data.
- **Blast radius:** With anonymous kubelet access, a single compromised pod can reach every container on its node. If node-to-node traffic is unfiltered, the attacker can pivot to kubelets on other nodes, gaining access to every pod in the cluster.

## Configuration

### Step 1: Disable Anonymous Authentication and Enable Webhook Authorization

Configure the kubelet to require authentication for all API requests and delegate authorization decisions to the API server.

Create or update the kubelet configuration file:

```yaml
# /var/lib/kubelet/config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
    cacheTTL: "2m0s"
  x509:
    clientCAFile: "/etc/kubernetes/pki/ca.crt"
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: "5m0s"
    cacheUnauthorizedTTL: "30s"
```

If your distribution uses command-line flags instead of a config file, set these flags in the kubelet service unit:

```ini
# /etc/systemd/system/kubelet.service.d/10-hardening.conf
[Service]
Environment="KUBELET_EXTRA_ARGS=--anonymous-auth=false --authorization-mode=Webhook --authentication-token-webhook=true --client-ca-file=/etc/kubernetes/pki/ca.crt"
```

Restart the kubelet after changes:

```bash
sudo systemctl daemon-reload
sudo systemctl restart kubelet

# Verify the kubelet is running with the new config
sudo systemctl status kubelet
```

### Step 2: Disable the Read-Only Port

The read-only port (10255) serves pod metadata over unencrypted HTTP with no authentication. Disable it entirely:

```yaml
# /var/lib/kubelet/config.yaml (add to the existing config)
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
readOnlyPort: 0
```

Or via command-line flag:

```ini
Environment="KUBELET_EXTRA_ARGS=--read-only-port=0"
```

Verify the port is closed after restart:

```bash
# Should return "connection refused" or no output
curl -s http://localhost:10255/pods
# Expected: curl: (7) Failed to connect to localhost port 10255

# Verify with ss
sudo ss -tlnp | grep 10255
# Expected: no output (port not listening)
```

**Note:** Some monitoring tools (older versions of [Prometheus](https://prometheus.io) node-exporter, cAdvisor scrapers) rely on port 10255 for metrics. Before disabling it, verify your monitoring stack uses the authenticated metrics endpoint on port 10250 instead. Kubernetes 1.29+ exposes `/metrics/resource` on the secure port.

### Step 3: Configure TLS for the Kubelet Serving Certificate

Enable TLS with automatic certificate rotation so that the kubelet serves its API over HTTPS with valid, regularly rotated certificates:

```yaml
# /var/lib/kubelet/config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
serverTLSBootstrap: true
rotateCertificates: true
tlsCipherSuites:
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
tlsMinVersion: "VersionTLS12"
```

When `serverTLSBootstrap` is enabled, the kubelet creates a CertificateSigningRequest (CSR) for its serving certificate. You must approve these CSRs:

```bash
# List pending CSRs
kubectl get csr | grep Pending

# Approve a kubelet serving certificate CSR
kubectl certificate approve csr-<id>

# For automated approval, deploy a CSR approver controller
# or use kubeadm's built-in approval for node certificates
```

Verify TLS is working:

```bash
# Connect to the kubelet with certificate verification
curl -k --cacert /etc/kubernetes/pki/ca.crt \
  --cert /etc/kubernetes/pki/apiserver-kubelet-client.crt \
  --key /etc/kubernetes/pki/apiserver-kubelet-client.key \
  https://localhost:10250/healthz

# Expected output: ok
```

### Step 4: Protect the Kubelet API from Pod-Level Access

Even with authentication enabled, a compromised pod can attempt to reach the kubelet on its node. Use a NetworkPolicy to block pod-to-kubelet traffic:

```yaml
# block-kubelet-access.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-kubelet-access
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    # Allow DNS
    - to: []
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # Allow traffic to the API server (typical ClusterIP range)
    - to:
        - ipBlock:
            cidr: 10.96.0.0/12
      ports:
        - protocol: TCP
          port: 443
    # Allow traffic to pod network (adjust CIDR to your cluster)
    - to:
        - ipBlock:
            cidr: 10.244.0.0/16
    # Block node IPs (including kubelet ports) by omitting them
    # All egress not explicitly allowed is denied
```

**Important:** This policy uses a "default deny with explicit allow" pattern. Adjust the CIDRs to match your cluster's pod network and service network. The key is that node IPs (where kubelet listens) are not included in any allow rule.

For clusters using [Cilium](https://cilium.io), you can use a more targeted CiliumNetworkPolicy:

```yaml
# cilium-block-kubelet.yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: deny-kubelet-access
  namespace: production
spec:
  endpointSelector: {}
  egressDeny:
    - toEntities:
        - host
      toPorts:
        - ports:
            - port: "10250"
              protocol: TCP
```

### Step 5: Verify All Settings

Run these verification commands on each node to confirm the hardening is in place:

```bash
# 1. Verify anonymous auth is disabled
curl -sk https://localhost:10250/pods
# Expected: 401 Unauthorized

# 2. Verify read-only port is closed
curl -s http://localhost:10255/pods
# Expected: connection refused

# 3. Verify TLS is active
openssl s_client -connect localhost:10250 -showcerts </dev/null 2>/dev/null | head -5
# Expected: shows certificate chain

# 4. Verify authorization mode
ps aux | grep kubelet | grep -o 'authorization-mode=[^ ]*'
# Expected: authorization-mode=Webhook

# 5. Check kubelet config via the API server (requires admin access)
kubectl get --raw "/api/v1/nodes/<node-name>/proxy/configz" | jq .
```

For automated compliance checking across all nodes, use this script:

```bash
#!/bin/bash
for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== Checking $node ==="
  kubectl debug node/$node -it --image=busybox -- sh -c \
    'wget -qO- --timeout=2 http://localhost:10255/pods 2>&1 || echo "PASS: read-only port closed"'
done
```

## Expected Behaviour

After applying the kubelet hardening configuration:

- Unauthenticated requests to port 10250 return `401 Unauthorized`
- Port 10255 is not listening; connection attempts are refused
- The kubelet serves its API over TLS with a valid, auto-rotated certificate
- Pods cannot reach the kubelet API on their host node due to network policies
- The API server communicates with the kubelet over mutual TLS
- Monitoring tools that use the authenticated `/metrics` endpoint on port 10250 continue to function normally
- `kubectl logs`, `kubectl exec`, and `kubectl port-forward` continue to work because they proxy through the API server, which authenticates to the kubelet with its client certificate

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Disable anonymous auth | All kubelet API access requires valid credentials | Tools or scripts that relied on unauthenticated kubelet access break | Audit all monitoring and tooling for kubelet API usage before applying. Update tools to use the authenticated endpoint |
| Disable read-only port | No unauthenticated metadata exposure | Monitoring tools using port 10255 for metrics stop working | Migrate to the authenticated metrics endpoint on port 10250. Update Prometheus scrape configs |
| Webhook authorization | The API server decides what each caller can do on the kubelet | Adds latency to kubelet API calls (mitigated by authorization cache) | Configure appropriate cache TTLs. Monitor API server availability, as kubelet authorization depends on it |
| Network policies blocking kubelet | Pods cannot directly access the kubelet API | Legitimate workloads that need node metrics or kubelet health data are blocked | Create targeted exceptions for monitoring agents. Deploy node-level monitoring as DaemonSets with hostNetwork access |
| TLS certificate rotation | Certificates rotate automatically before expiry | CSR approval is required; missed approvals cause certificate expiry | Automate CSR approval for kubelet serving certificates. Monitor for pending CSRs |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Kubelet fails to start after config change | Node shows NotReady; pods are not scheduled | `kubectl get nodes` shows NotReady; `journalctl -u kubelet` shows config errors | Check kubelet logs for the specific error. Common issue: wrong path to CA file or malformed YAML in config.yaml. Fix the config and restart |
| CSR not approved after enabling serverTLSBootstrap | Kubelet serves with a self-signed certificate; API server logs TLS warnings | `kubectl get csr` shows pending CSRs; kubelet logs show "certificate not yet available" | Approve pending CSRs manually or deploy an auto-approver. The kubelet continues to function but with a self-signed cert |
| Network policy blocks legitimate traffic | Monitoring agents, log collectors, or service mesh sidecars cannot reach required endpoints | Gaps in metrics collection; alerts for missing data points | Add targeted egress exceptions for monitoring namespaces. Test network policies in audit mode before enforcing |
| Authorization webhook unavailable | API server is down or unreachable; kubelet cannot authorize requests | Kubelet API calls fail; `kubectl exec` and `kubectl logs` stop working | The authorization cache serves recent decisions during brief outages. For extended API server downtime, the kubelet continues running pods but cannot process new API requests |
| Monitoring breakage after disabling port 10255 | Prometheus scrape targets return errors; node metrics dashboards go blank | Prometheus target status shows "connection refused" for port 10255 targets | Update scrape configs to use port 10250 with bearer token authentication. Use the ServiceMonitor CRD if running Prometheus Operator |

## When to Consider a Managed Alternative

**Transition point:** Kubelet hardening on self-managed clusters requires configuration across every node, ongoing verification after node additions or upgrades, and CSR management for certificate rotation. When your cluster exceeds 20 nodes or your team spends more than 4 hours per month on kubelet configuration management, managed solutions reduce the operational burden significantly.

**Recommended providers:**

- **Managed Kubernetes (EKS, GKE, AKS):** The cloud provider manages kubelet configuration, including authentication, TLS, and port settings. The read-only port is disabled by default, anonymous auth is off, and certificate rotation is automatic. This eliminates the entire category of kubelet hardening work.
- **[Sysdig](https://sysdig.com):** Verifies kubelet compliance across all nodes continuously. Detects configuration drift when nodes are added or upgraded with insecure defaults. Provides alerts for kubelet misconfigurations without requiring manual verification scripts.

**What you still control:** Even on managed providers, you control network policies that restrict pod-to-node traffic, RBAC rules that limit which users and service accounts can access kubelet subresources (exec, logs, port-forward), and monitoring configuration for kubelet metrics endpoints.


## Related Articles

- [Kubernetes Node Hardening: From OS Configuration to kubelet Lockdown](/articles/kubernetes/node-hardening/)
- [Kubernetes API Server Hardening: Flags, Authentication, and Audit Logging](/articles/kubernetes/api-server-hardening/)
- [Hardening Kubernetes Ingress Controllers: NGINX, Traefik, and Envoy Compared](/articles/kubernetes/ingress-controller-comparison/)
- [Kubernetes Network Policies That Actually Work: From Default Deny to Microsegmentation](/articles/kubernetes/kubernetes-network-policies/)
- [Seccomp Profiles for Production Workloads: Writing, Testing, and Deploying Custom Profiles](/articles/kubernetes/seccomp-profiles/)
