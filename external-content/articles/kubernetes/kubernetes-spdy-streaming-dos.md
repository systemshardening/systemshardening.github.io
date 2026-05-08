---
title: "Kubernetes SPDY Streaming DoS: Hardening Against CVE-2026-35469"
description: "CVE-2026-35469 lets an attacker crash kubelet and kube-apiserver via malformed SPDY frames. Learn how the silent-branch pattern works and how to close the window with version pinning, RBAC restrictions, and streaming endpoint controls."
slug: kubernetes-spdy-streaming-dos
date: 2026-05-03
lastmod: 2026-05-03
category: kubernetes
tags:
  - kubelet
  - kube-apiserver
  - spdy
  - denial-of-service
  - cve
personas:
  - platform-engineer
  - security-engineer
article_number: 392
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/kubernetes/kubernetes-spdy-streaming-dos/
---

# Kubernetes SPDY Streaming DoS: Hardening Against CVE-2026-35469

## The Problem

SPDY is a Google-era multiplexing protocol from 2012, deprecated by HTTP/2 in 2015, yet still alive inside Kubernetes for `exec`, `attach`, `logs`, and `port-forward` streaming. CVE-2026-35469 exploits a frame-handling loop in the Go SPDY implementation — specifically in `golang.org/x/net/http2/h2c` and the upstream `k8s.io/apiserver/pkg/util/proxy` — that never bounds memory allocation when it receives pathologically large or repeated HEADER frames. The receiving goroutine allocates without limit until the process runs out of heap and is killed by the OOM killer or panics.

The vulnerability is straightforward in practice: send a stream of malformed SPDY HEADER frames over an authenticated streaming connection, hold the connection open, and the target process exhausts memory. No further exploitation is required. The denial-of-service is reliable and repeatable.

What makes this CVE particularly noteworthy is the disclosure timeline. The fix was merged into the `release-1.32` branch of `kubernetes/kubernetes` as a routine pull request before the formal CVE advisory was published. GitHub branch history is public. Anyone watching the release branches — a technique routinely used by vulnerability researchers, exploit brokers, and sophisticated attackers — could observe the patch, understand the bug class from the diff, and begin developing a reproducer days before operators received an advisory. This is the silent-branch pattern, and it is a standard part of the Kubernetes release process. Fixes go into release branches under embargo, but the code is public from the moment the PR merges. The window between branch merge and public advisory may be anywhere from hours to several days.

The practical implication is that patch timing matters more than many operators assume. Once a fix appears in a release branch, the clock starts. Clusters still running unpatched versions after advisory publication are not racing against an unknown threat — they are racing against a known, public patch that any competent attacker can reverse-engineer.

The bug has been silently present in the SPDY implementation since 2015. It was not introduced by a recent change; the missing bounds check was part of the original Go SPDY library code that Kubernetes imported and has carried forward across releases without meaningful security review of that specific code path. Years of CVE scanning, CIS benchmarks, and penetration tests all missed it because the vulnerable surface — the streaming endpoint handshake — is not covered by most standard tooling.

## Threat Model

The attack surface covers two distinct attacker positions.

**Attacker with RBAC access to streaming verbs:** A pod (or the human operator of a pod) with `pods/exec`, `pods/log`, or `pods/portforward` RBAC permissions can open a streaming connection to the kubelet's port 10250 on its own node. By sending crafted SPDY frames over that connection, the attacker crashes the kubelet process. A kubelet crash on a node causes all pods on that node to lose their health management process. Kubernetes marks the node `NotReady` after the node lease expires (default: 40 seconds), which triggers pod eviction to other nodes. Depending on cluster capacity and the number of affected nodes, this can cascade into a cluster-wide resource exhaustion event. A single malicious pod scheduled across multiple nodes can crash multiple kubelets simultaneously.

**Network-adjacent attacker reaching the API server streaming port:** The kube-apiserver proxies streaming connections on port 6443. An attacker who can reach that port and authenticate — via a stolen token, a compromised CI/CD credential, or a misconfigured OIDC provider — can send crafted SPDY frames directly to the apiserver's streaming handler. An apiserver crash causes a full control-plane outage: no new deployments, no pod rescheduling, no secret reads, no admission webhook calls. Existing workloads continue running, but the cluster becomes unmanageable until the apiserver restarts.

**Affected versions:**

- Kubernetes: all versions before 1.30.12, 1.31.8, and 1.32.4
- CRI-O: versions before 1.32.2
- containerd: versions before 2.2.3

**Not affected:** Managed Kubernetes offerings that run patched control plane versions automatically (GKE Autopilot, EKS Fargate) may be patched on the control-plane side but still expose kubelet-level risk if node images are not updated.

## Hardening Configuration

Apply these controls in order. Version upgrade is the only complete fix; the remaining controls reduce the attack surface while the upgrade is staged.

### 1. Verify your current versions

Check what is running before making any changes.

```bash
kubectl version --output=json | jq '{client: .clientVersion.gitVersion, server: .serverVersion.gitVersion}'

kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.containerRuntimeVersion}{"\n"}{end}'

kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\n"}{end}'
```

Patched versions are Kubernetes 1.30.12+, 1.31.8+, and 1.32.4+. For the container runtime, containerd 2.2.3+ and CRI-O 1.32.2+ contain the fix.

### 2. Restrict RBAC access to streaming verbs

The most effective mitigation short of patching is ensuring that only explicitly trusted service accounts and human users hold `pods/exec`, `pods/log`, and `pods/portforward` permissions. Audit existing bindings first.

```bash
kubectl get clusterrolebindings,rolebindings -A -o json \
  | jq -r '
    .items[] |
    select(.roleRef.name != "system:node" and .roleRef.name != "system:kubelet-api-admin") |
    .metadata.namespace as $ns |
    .subjects[]? |
    "\($ns // "cluster")\t\(.kind)\t\(.name)"
  ' | sort -u
```

Then create a tightly scoped role for services that legitimately need streaming access, and remove broader grants.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: streaming-access-restricted
rules:
  - apiGroups: [""]
    resources: ["pods/exec", "pods/log", "pods/portforward"]
    verbs: ["create", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: streaming-access-restricted
  namespace: debug-tools
subjects:
  - kind: ServiceAccount
    name: debug-runner
    namespace: debug-tools
roleRef:
  kind: ClusterRole
  name: streaming-access-restricted
  apiGroup: rbac.authorization.k8s.io
```

Do not grant these verbs cluster-wide to developer groups or CI/CD service accounts unless absolutely necessary. A `ClusterRoleBinding` for streaming verbs means any pod in the cluster can potentially be used as a pivot point.

### 3. Force HTTP/2 on the API server with `--goaway-chance`

Kubernetes 1.29 introduced the `--goaway-chance` flag on kube-apiserver. Setting it to `1.0` causes the apiserver to send HTTP/2 GOAWAY frames aggressively, which forces clients to reconnect using HTTP/2 rather than falling back to SPDY. This does not eliminate SPDY entirely, but it significantly reduces the surface area for streaming connections that land in the SPDY handler.

For kubeadm-managed clusters, edit the apiserver static pod manifest:

```yaml
spec:
  containers:
    - name: kube-apiserver
      command:
        - kube-apiserver
        - --goaway-chance=1.0
```

For clusters managed via configuration files:

```bash
grep -r "goaway-chance" /etc/kubernetes/manifests/kube-apiserver.yaml
```

After adding the flag, the kubelet will restart the apiserver static pod automatically. Verify the flag is active:

```bash
kubectl -n kube-system get pod -l component=kube-apiserver -o jsonpath='{.items[0].spec.containers[0].command}' \
  | tr ',' '\n' | grep goaway
```

Note: this flag is only available in Kubernetes 1.29 and later. On older versions, skip this step and prioritise the version upgrade.

### 4. Disable anonymous authentication on the kubelet

Unauthenticated requests to the kubelet cannot trigger the SPDY vulnerability, but only if authentication is required in the first place. Verify and enforce `--anonymous-auth=false` on every node.

On kubeadm clusters, edit `/var/lib/kubelet/config.yaml` on each node:

```yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
    cacheTTL: 2m0s
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
```

Apply the change and restart the kubelet:

```bash
systemctl daemon-reload && systemctl restart kubelet
```

Verify the kubelet is no longer accepting anonymous requests:

```bash
NODE_IP=$(kubectl get node <node-name> -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
curl -sk https://${NODE_IP}:10250/pods | head -5
```

An anonymous request should return a 401 response with `Unauthorized`, not pod JSON.

### 5. Block pod-to-kubelet traffic with NetworkPolicy

Even with authentication enforced, restricting which pods can initiate connections to the kubelet reduces the blast radius of a compromised workload. Apply a default-deny egress policy to application namespaces and explicitly block port 10250.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-kubelet-egress
  namespace: default
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 80
        - protocol: TCP
          port: 53
      to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.0.0/16
```

This approach requires care: some CNI health check mechanisms and node-local DNS configurations use port 10250 or node-local IP ranges. Review your CNI documentation before applying broad egress restrictions. Test in a non-production namespace first.

### 6. Verify container runtime versions

The vulnerability affects CRI-O and containerd as well as the Kubernetes components. Check and upgrade the runtime on each node.

```bash
containerd --version

crio --version
```

For containerd upgrades on systemd-managed nodes:

```bash
apt-get install --only-upgrade containerd.io

systemctl restart containerd
```

For CRI-O:

```bash
dnf upgrade cri-o

systemctl restart crio
```

Node upgrades require draining the node to safely evict pods before restarting system services:

```bash
kubectl drain <node-name> --ignore-daemonsets --delete-emptydir-data

apt-get install --only-upgrade containerd.io && systemctl restart containerd

kubectl uncordon <node-name>
```

## Expected Behaviour After Hardening

After applying all controls, verify the cluster behaves correctly.

Check versions to confirm the upgrade landed:

```bash
kubectl version --output=json | jq '.serverVersion.gitVersion'
kubectl get nodes -o custom-columns='NAME:.metadata.name,RUNTIME:.status.nodeInfo.containerRuntimeVersion,KUBELET:.status.nodeInfo.kubeletVersion'
```

Confirm the `--goaway-chance` flag is active on the apiserver:

```bash
kubectl -n kube-system describe pod -l component=kube-apiserver | grep goaway
```

Verify that streaming still works — disabling SPDY does not break `exec` or `logs`, it forces a protocol upgrade to HTTP/2:

```bash
kubectl run test-exec --image=alpine --restart=Never --command -- sleep 3600
kubectl exec -it test-exec -- sh -c "echo streaming works"
kubectl logs test-exec
kubectl delete pod test-exec
```

If streaming fails after the `--goaway-chance` change, the most likely cause is an old `kubectl` client binary that does not support HTTP/2 streaming. Update the client binary to match or be within one minor version of the server.

Check that anonymous kubelet requests are rejected on a representative node:

```bash
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
curl -sk https://${NODE_IP}:10250/pods | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message','no message'))"
```

The response should contain `Unauthorized`, not pod data.

## Trade-offs and Operational Considerations

**RBAC restrictions break ad hoc debugging workflows.** Many engineering teams rely on `kubectl exec` as a first-line debugging tool — getting a shell into a running pod to inspect environment variables, check file contents, or run diagnostic commands. Removing `pods/exec` from developer roles will generate support requests. Plan for this by establishing an alternative debugging workflow before removing permissions: ephemeral debug containers (`kubectl debug`), centralized log aggregation, and structured application metrics reduce the dependency on direct exec access.

**`--goaway-chance=1.0` is aggressive.** The flag was designed to be used at fractional values (e.g., `0.001`) to gradually drain connections during rolling restarts, not at `1.0` for security purposes. At `1.0`, every connection that could be served over SPDY receives a GOAWAY frame immediately. Old `kubectl` binaries (pre-1.26) that do not handle GOAWAY correctly will experience connection drops and may not retry over HTTP/2 automatically. Audit your `kubectl` client versions across the organisation before enabling this at `1.0`. A value of `0.1` provides a partial mitigation with lower operational risk while the client upgrade rolls out.

**Runtime upgrades require node drains.** Upgrading containerd or CRI-O in place while pods are running is possible but introduces risk — a failed runtime restart can strand running containers in an unmanageable state. The drain-upgrade-uncordon cycle is slower but safe. For large clusters, automate this with a rolling update across nodes using a node pool upgrade mechanism or a tool like Ansible. Budget time: a 100-node cluster draining one node at a time with a 5-minute pod eviction grace period takes over 8 hours end to end.

**The silent-branch pattern has no clean solution.** Watching Kubernetes release branches for security-relevant commits is a legitimate practice, but acting on unannounced fixes before the advisory is published carries its own risk — you may misinterpret the fix, cause unintended downtime, or upgrade to a release-candidate build that has other regressions. The pragmatic answer is to subscribe to the official `kubernetes-security-announce` mailing list and have a documented upgrade runbook that can be executed within 24 hours of advisory publication for critical severity findings.

## Failure Modes

**Patching Kubernetes but not the runtime.** The most common partial fix. Operators upgrade kube-apiserver and kubelet to the patched version but leave containerd or CRI-O at the old version on worker nodes. Both the apiserver streaming handler and the runtime streaming handler are vulnerable independently. Check both sides.

**NetworkPolicy that permits pod-to-kubelet traffic.** Some CNI implementations use port 10250 for health probes, and some Prometheus node exporters scrape the kubelet's metrics endpoint directly from within the cluster. A NetworkPolicy that blocks port 10250 egress broadly can break these integrations silently — the metrics stop arriving, but no alert fires because the alerting rule itself depends on those metrics. Audit NetworkPolicy changes against existing monitoring and CNI health-check configurations before deploying cluster-wide. Apply to a single non-production namespace first and watch for 48 hours.

**Kubelet crash monitoring with insufficient sensitivity.** A kubelet memory-exhaustion attack takes on the order of seconds to minutes to crash the process. If the monitoring system polls kubelet health every 60 seconds and requires two consecutive failures before alerting, the node can be `NotReady` for over two minutes before any human is paged. By that time, pod eviction is already in progress. Lower the kubelet health check interval in your monitoring stack to 15 seconds and set the failure threshold to one consecutive failure, not two. The increased alert noise from transient kubelet restarts during upgrades is an acceptable trade-off.

**RBAC audit that misses RoleBindings in system namespaces.** The `kube-system` namespace frequently contains service accounts with broad permissions granted during cluster bootstrap or by third-party operators. A targeted audit of application namespaces that misses `kube-system` may leave monitoring agents, log collectors, or CNI components with `pods/exec` permissions that could be abused. Run the RBAC audit query across all namespaces, including `kube-system`, `kube-public`, and `default`.

## Related Articles
- [Kubelet Security](/articles/kubernetes/kubelet-security/)
- [Kubernetes API Server Hardening](/articles/kubernetes/api-server-hardening/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [Kubernetes Audit Log Design](/articles/observability/k8s-audit-log-design/)
