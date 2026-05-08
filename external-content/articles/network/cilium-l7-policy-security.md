---
title: "Cilium L7 Network Policy Security"
description: "Harden Cilium L7 HTTP, gRPC, and DNS network policies against CVE-2026-33726-class bypasses, per-endpoint routing pitfalls, and silent policy enforcement gaps in fast-moving Cilium releases."
slug: cilium-l7-policy-security
date: 2026-05-02
lastmod: 2026-05-02
category: network
tags: ["cilium", "l7-policy", "cve-2026-33726", "network-policy", "envoy", "per-endpoint-routing"]
personas: ["platform-engineer", "sre", "security-engineer"]
article_number: 353
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/network/cilium-l7-policy-security/index.html"
---

# Cilium L7 Network Policy Security

## Problem

Cilium extends Kubernetes `NetworkPolicy` with application-layer (L7) awareness through its custom `CiliumNetworkPolicy` resource. Where standard Kubernetes network policy can only match on IP addresses, ports, and namespace/pod selectors, Cilium lets you match on HTTP methods and path regexes, gRPC service and method names, DNS FQDNs and glob patterns, and Kafka topics. This layer-7 enforcement is implemented via Cilium's embedded Envoy proxy — one sidecar-less proxy per node — which intercepts and inspects traffic in-kernel via BPF before handing off to Envoy for L7 decision-making, then allowing or denying based on the `CiliumNetworkPolicy` rules.

The trust assumption most operators make is straightforward: if a `CiliumNetworkPolicy` is deployed with `toEndpoints` selectors combined with `toPorts.rules.http` or `toPorts.rules.grpc` blocks, all matching traffic will be inspected at L7 before it is forwarded. This assumption is reasonable and correct in many configurations. It breaks down in ways that are neither obvious nor immediately visible in logs when certain datapath modes are combined. The enforcement path through Envoy depends on per-endpoint routing configuration, whether BPF host routing is active, and the tunnel mode in use — none of which are surfaced prominently in standard Cilium dashboards.

**CVE-2026-33726** (disclosed March 26, 2026) is the clearest documented instance of this class of failure. Cilium's L7 ingress network policy enforcement could be bypassed for traffic from pods to L7-enabled Services — including services fronted by Cilium's Envoy proxy and GAMMA-mode services — when **per-endpoint routing is enabled** and **BPF host routing is disabled**. This combination is common in Amazon EKS clusters running in ENI mode, where the default Cilium Helm values produce exactly the affected configuration. In this configuration, traffic from a pod to a backend on the same node bypasses the Envoy L7 inspection path entirely. The packet is delivered directly to the backend without being evaluated against `http` or `grpc` policy rules, and no error is surfaced — neither in the Cilium agent logs nor in Envoy access logs — because Envoy is never consulted. From the operator's perspective, policy appears to be applied; from the attacker's perspective, it is not.

The CVE is tracked under GHSA-hxv8-4j4r-cqgv. The fix landed in PR #44693 in the Cilium GitHub repository and is included in patched releases 1.17.14, 1.18.8, and 1.19.2. Clusters running Cilium versions between 1.14 and 1.19.1 with the affected configuration remain vulnerable until upgraded.

The open-source development model of Cilium creates an additional operational challenge: the fix PR (#44693) was merged to the main Cilium repository and publicly visible on GitHub before the patched releases were available and before the security advisory was published via `cilium-security-announce`. Operators watching `https://github.com/cilium/cilium/pulls` for changes to `pkg/proxy/` and `pkg/envoy/` could identify the bypass and its root cause before the advisory was formally published — but only if they were actively monitoring the repository at that granularity. Cilium releases very frequently, often with weekly minor point releases, which makes it difficult to distinguish security-relevant fixes from routine feature work without reading every commit. The changelog at `https://github.com/cilium/cilium/releases` does not consistently flag security fixes with a standardised marker. The recommended monitoring approach is to watch GitHub security advisories directly at `https://github.com/cilium/cilium/security/advisories`, subscribe to the Cilium Slack `#cilium-security` channel, and use a dependency automation tool such as Renovate to auto-raise pull requests when new Cilium Helm chart versions are published.

CVE-2026-33726 is not an isolated occurrence. Cilium's datapath complexity — spanning native routing, tunnel mode, ENI mode, BPF host routing, per-endpoint routing, and GAMMA service mesh integration — creates a large matrix of configurations that must each be tested for L7 policy enforcement correctness. Operators who deploy Cilium and rely on L7 policy for security boundaries should treat that enforcement as unverified until they have confirmed it with active probing in their specific cluster configuration.

**Target systems:** Cilium 1.14–1.19.1 (vulnerable configurations), Kubernetes 1.28+, EKS ENI mode deployments with `enable-endpoint-routes: "true"` and `tunnel: disabled`.

## Threat Model

1. **Same-node L7 bypass via CVE-2026-33726.** A pod co-located on the same node as a target service sends HTTP requests that a `CiliumNetworkPolicy` with `toPorts.rules.http` should deny. In the affected configuration the packet bypasses Envoy entirely and is delivered to the backend. The target service receives and processes the request, the Cilium policy shows no violation, and the operator has no visibility that the policy was silently skipped. This enables unauthorized API access that appears compliant from a policy audit perspective.

2. **Patch-gap attacker.** An adversary monitoring Cilium's public GitHub repository observes the merge of PR #44693 on March 26, 2026. The PR title and diff make clear that the fix addresses an L7 policy bypass affecting pods communicating to local-node backends. The adversary identifies that EKS ENI-mode clusters with Cilium are the primary affected population — ENI mode is a well-documented default for Cilium on EKS — and scans for such clusters via Shodan and AWS cloud metadata APIs. They exploit the L7 bypass during the window between public fix availability and operator patching, which for a weekly-release project can extend from days to weeks for teams without automated upgrade pipelines.

3. **gRPC method-level policy bypass.** A gRPC service has a `CiliumNetworkPolicy` that permits only `/api.UserService/GetProfile`. A client pod on the same node calls `/api.UserService/DeleteUser`. In the affected configuration the gRPC traffic is never evaluated by Envoy's L7 filter, the `DeleteUser` method executes successfully, and the Cilium policy appears fully applied. This is particularly dangerous because gRPC method-level access control is often the sole authorization boundary for internal microservices that do not implement application-layer authN/authZ.

4. **DNS FQDN policy bypass.** A `toFQDNs` policy is intended to block DNS resolution of a category of domains (for example, exfiltration endpoints or external package registries in a build cluster). When per-endpoint routing is active in certain configurations, the FQDN policy is silently not applied and the pod resolves and connects to blocked domains without any alert or dropped packet logged.

The blast radius of a successful L7 bypass depends on what the bypassed policy is protecting. In microservice architectures where Cilium L7 policy is the primary access control mechanism between services — common in environments that have not deployed a separate service mesh with mTLS — a single bypassed rule can grant a compromised pod unrestricted access to internal APIs that were believed to be segmented. The same-node constraint of CVE-2026-33726 limits the initial blast radius to backends co-located with the attacker pod, but Kubernetes does not guarantee pod placement, and an attacker with the ability to influence scheduling (for example via a compromised deployment controller) can eliminate that constraint.

## Configuration / Implementation

### Checking if your cluster is affected by CVE-2026-33726

First confirm your Cilium version:

```bash
cilium version
```

Check the three configuration values that determine whether the vulnerable combination is active:

```bash
kubectl get configmap -n kube-system cilium-config -o yaml \
  | grep -E "enable-endpoint-routes|bpf-masquerade|tunnel"
```

Your cluster is in the affected configuration if all of the following are true:

- `enable-endpoint-routes: "true"` is present
- `tunnel: disabled` (ENI mode or native routing without a tunnel)
- Cilium version is earlier than 1.17.14, 1.18.8, or 1.19.2 on the respective minor branch

A one-liner that checks all three conditions:

```bash
CILIUM_VER=$(kubectl exec -n kube-system \
  "$(kubectl get pod -n kube-system -l k8s-app=cilium -o name | head -1)" \
  -- cilium version --client 2>/dev/null | awk '/Client:/{print $2}')
EP_ROUTES=$(kubectl get configmap -n kube-system cilium-config \
  -o jsonpath='{.data.enable-endpoint-routes}')
TUNNEL=$(kubectl get configmap -n kube-system cilium-config \
  -o jsonpath='{.data.tunnel}')
echo "Cilium: ${CILIUM_VER}  ep-routes: ${EP_ROUTES}  tunnel: ${TUNNEL}"
```

If `ep-routes: true` and `tunnel: disabled`, apply the upgrade immediately.

### Upgrading Cilium

Rolling upgrade to the patched release using Helm:

```bash
helm repo update cilium
helm upgrade cilium cilium/cilium \
  --version 1.19.2 \
  --namespace kube-system \
  --reuse-values \
  --wait \
  --timeout 10m
```

The `--reuse-values` flag preserves your existing configuration. Cilium performs a rolling restart of the DaemonSet, but there is a brief window during upgrade where individual nodes are running different Cilium versions. During this window, avoid relying on L7 policy enforcement on nodes that have not yet been upgraded.

Verify all agents are Running on the new version:

```bash
kubectl get pods -n kube-system -l k8s-app=cilium -o wide
kubectl rollout status daemonset/cilium -n kube-system
```

Confirm the L7 proxy is active on upgraded nodes:

```bash
cilium status --verbose | grep -i "l7 proxy"
# Expected output includes:
# L7 Proxy:        OK
```

### Verifying L7 policy is actually enforced

Deploying a version of Cilium does not itself confirm that L7 enforcement is working for your specific configuration. Perform active probing after every Cilium upgrade:

```bash
# Deploy a test namespace and pods
kubectl create namespace cilium-l7-test

kubectl run protected-service \
  --image=nginx:1.27-alpine \
  --namespace cilium-l7-test \
  --labels="app=protected"

kubectl run test-client \
  --image=curlimages/curl:8.7.1 \
  --namespace cilium-l7-test \
  --labels="app=test-client" \
  --command -- sleep 3600
```

Apply an L7 policy that only allows GET /api/public:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: http-l7-test
  namespace: cilium-l7-test
spec:
  endpointSelector:
    matchLabels:
      app: protected
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: test-client
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "^/api/public/.*$"
```

Test that the allowed path works and the denied path is rejected:

```bash
# Should succeed (HTTP 200)
kubectl exec -n cilium-l7-test test-client -- \
  curl -sv http://protected-service/api/public/health

# Should be rejected (HTTP 403 from Envoy, NOT connection refused)
kubectl exec -n cilium-l7-test test-client -- \
  curl -sv http://protected-service/admin
```

The critical verification: when L7 policy is correctly enforced, denied requests receive an HTTP 403 response from the Cilium Envoy proxy — not a TCP connection reset or timeout. If the `/admin` request returns a 200 from nginx, L7 enforcement is bypassed.

Confirm Envoy is processing the traffic:

```bash
# Watch L7 traffic events in real time
kubectl exec -n kube-system daemonset/cilium -- \
  cilium monitor --type l7 --json 2>/dev/null | head -20

# Verify the policy is loaded in the Cilium agent
kubectl exec -n kube-system daemonset/cilium -- \
  cilium policy get | grep -A5 "http-l7-test"
```

### L7 HTTP policy authoring best practices

A complete `CiliumNetworkPolicy` combining L3 endpoint selection with L7 HTTP rules:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-server-l7-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: api-server
      tier: backend
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: frontend
            tier: web
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: "GET"
                path: "^/api/v1/users/[0-9]+$"
              - method: "POST"
                path: "^/api/v1/users$"
              - method: "GET"
                path: "^/api/v1/health$"
    - fromEndpoints:
        - matchLabels:
            app: metrics-collector
      toPorts:
        - ports:
            - port: "9090"
              protocol: TCP
```

Key authoring principles:

- Use anchored regexes (`^` and `$`) in `path` fields. An unanchored pattern like `/api/` matches `/evil/api/inject` as well as `/api/users`.
- Combine L3 `fromEndpoints` with L7 `http` rules in a single ingress rule. Splitting them across two separate ingress entries creates an implicit OR — traffic matching either selector is allowed, bypassing the L7 check.
- Cilium's default-deny behaviour for L7 applies only to the ports listed in `toPorts`. Ports not listed in any `toPorts` rule are governed by L3/L4 policy only. Ensure you do not have a separate L4 `allow all` rule on the same port.

### gRPC L7 policy

gRPC uses HTTP/2 with `POST` as the only method and a path format of `/package.ServiceName/MethodName`. Match gRPC traffic using:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: grpc-user-service-policy
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: user-service
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: api-gateway
      toPorts:
        - ports:
            - port: "50051"
              protocol: TCP
          rules:
            http:
              - method: "POST"
                path: "^/api\\.UserService/GetProfile$"
                headers:
                  - "content-type: application/grpc"
              - method: "POST"
                path: "^/api\\.UserService/ListProfiles$"
                headers:
                  - "content-type: application/grpc"
```

Note that the dot separator in the protobuf package name must be escaped (`api\.UserService`) because the `path` field is a regex. The `headers` match on `content-type: application/grpc` provides defence in depth against non-gRPC HTTP/2 traffic attempting to match the path pattern.

### DNS policy

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: egress-dns-restricted
  namespace: production
spec:
  endpointSelector:
    matchLabels:
      app: build-agent
  egress:
    - toEndpoints:
        - matchLabels:
            "k8s:io.kubernetes.pod.namespace": kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
          rules:
            dns:
              - matchPattern: "*.internal.example.com"
              - matchName: "registry.npmjs.org"
    - toFQDNs:
        - matchPattern: "*.internal.example.com"
        - matchName: "registry.npmjs.org"
```

Verify DNS policy is active and the FQDN cache is populated:

```bash
kubectl exec -n kube-system daemonset/cilium -- \
  cilium fqdn cache list

# Confirm a blocked domain is not resolving from the build-agent pod
kubectl exec -n production build-agent-pod -- \
  nslookup pypi.org
# Expected: SERVFAIL or NXDOMAIN if DNS policy is enforced
```

### Monitoring Cilium for silent policy fixes

Subscribe to GitHub security advisories via the API to detect new advisories before they are broadcast:

```bash
gh api repos/cilium/cilium/security/advisories \
  --jq '.[].summary' 2>/dev/null | head -10
```

Watch for changes to the files most commonly involved in L7 policy enforcement:

```bash
# Check recent commits touching proxy or envoy packages
gh api repos/cilium/cilium/commits \
  --field path=pkg/proxy/ \
  --jq '.[].commit.message' | head -5

gh api repos/cilium/cilium/commits \
  --field path=pkg/envoy/ \
  --jq '.[].commit.message' | head -5
```

Renovate configuration for automated Cilium Helm chart upgrades:

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["cilium"],
      "matchDatasources": ["helm"],
      "automerge": false,
      "prPriority": 10,
      "labels": ["security", "cilium", "infrastructure"],
      "schedule": ["at any time"],
      "commitMessageExtra": "- review GHSA advisories before merging"
    }
  ]
}
```

Setting `automerge: false` and `prPriority: 10` ensures Cilium upgrades are raised immediately and reviewed by a human before merging — appropriate for a component that controls cluster-wide network policy.

## Expected Behaviour

| Signal | CVE-2026-33726 affected config | Patched + verified |
|--------|-------------------------------|-------------------|
| HTTP request to denied path on same-node pod | Returns HTTP 200 from backend — policy bypassed silently | Returns HTTP 403 from Cilium Envoy proxy |
| gRPC call to unauthorized method (`DeleteUser`) on same-node pod | Method executes successfully, no policy violation logged | Envoy returns gRPC status `PERMISSION_DENIED` (HTTP 403) |
| DNS resolution of FQDN blocked by `toFQDNs` | Resolves successfully, connection established | DNS response is `SERVFAIL`; `cilium fqdn cache list` shows domain absent |
| `cilium monitor --type l7` output during HTTP request | No L7 events emitted — Envoy not consulted | L7 flow events emitted with policy verdict `allow` or `deny` |
| Patch-gap detection: CVE published | Manual monitoring required; no automated signal | Renovate PR raised within hours; `gh api` advisory query returns new entry |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| L7 inspection via embedded Envoy | Fine-grained HTTP/gRPC/DNS access control without a separate service mesh | Envoy intercept adds approximately 1 ms of latency per request on a lightly loaded node; higher under CPU contention | Profile latency-sensitive paths; consider L4-only policy for non-HTTP internal traffic where L7 control is not required |
| Per-endpoint routing enabled | Reduces packet copies on ENI-mode nodes; improves throughput for east-west traffic | Was the precondition for CVE-2026-33726 L7 bypass in combination with disabled tunnel mode | Upgrade to patched Cilium; keep per-endpoint routing enabled post-patch for performance — the fix removes the bypass, not the feature |
| Strict HTTP path regex matching | Prevents unintended path access; forces explicit allowlisting | Path regex maintenance overhead; regex errors silently deny legitimate traffic or permit unexpected paths | Use anchored regexes; maintain a regression test suite of allowed and denied example paths; review policies in staging before production rollout |
| Cilium upgrade frequency (weekly minor releases) | Security fixes reach users quickly; feature velocity is high | Difficult to distinguish security-critical upgrades from feature releases without dedicated monitoring | Subscribe to `cilium-security-announce`; configure Renovate to raise PRs for every release; keep a change log review step in your upgrade runbook |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| L7 policy silently not enforced (CVE-2026-33726 or misconfiguration) | Denied HTTP paths return 200; gRPC forbidden methods succeed; no errors in Cilium or application logs | Active probing: send a request to a path that should be denied and verify you receive HTTP 403, not 200; `cilium monitor --type l7` emits no events during the request | Upgrade Cilium to patched version; re-verify enforcement with active probe after upgrade |
| Envoy proxy crash drops L7 enforcement (fail-open behaviour) | All L7 policy rules on the affected node stop being enforced; traffic passes L3/L4 policy only | `kubectl logs -n kube-system` on the Cilium DaemonSet pod shows Envoy restart; `cilium status` reports `L7 Proxy: Error`; L7 monitor events cease | Cilium automatically restarts the embedded Envoy process; monitor restart frequency; if frequent, check Envoy resource limits and OOM events; consider adding L4 policy as a backstop |
| Cilium upgrade breaks existing L3 policy semantics | Pods that were communicating begin receiving connection resets; or pods that should be blocked continue to communicate after a policy-visible upgrade | Alerts on connection error rates in service monitoring; Cilium `policy-verdict` metric shows unexpected changes | Roll back Cilium version using Helm; examine the upstream changelog for breaking changes in the CiliumNetworkPolicy schema; test policy upgrades in a non-production cluster first |
| `cilium monitor` overwhelmed on busy node | `cilium monitor --type l7` drops events under high traffic load, producing an incomplete picture of policy enforcement | The monitor CLI warns about dropped events; event counts in Prometheus metric `cilium_drop_count_total` spike | Use Hubble instead of the low-level monitor CLI for production observability; Hubble's ring buffer is larger and survives bursts; `hubble observe --type l7` with appropriate label filters |

## Related Articles

- [Cilium Network Policy](/articles/kubernetes/cilium-network-policy/)
- [mTLS and Service Mesh Security](/articles/network/mtls-service-mesh/)
- [Envoy Security Hardening](/articles/network/envoy-security-hardening/)
- [gRPC Security](/articles/network/grpc-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
