---
title: "CI/CD Pipeline Egress Control: Runner Network Isolation, Allowlists, and Supply-Chain Exfiltration Defense"
description: "Most build pipelines run with unrestricted outbound internet. A single compromised dependency exfiltrates secrets, tokens, and source code in seconds."
slug: "pipeline-egress-control"
date: 2026-04-24
lastmod: 2026-04-24
category: "cicd"
tags: ["cicd", "github-actions", "egress", "network-policy", "supply-chain"]
personas: ["platform-engineer", "security-engineer", "devops"]
article_number: 166
difficulty: "intermediate"
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/cicd/pipeline-egress-control/index.html"
---

# CI/CD Pipeline Egress Control: Runner Network Isolation, Allowlists, and Supply-Chain Exfiltration Defense

## Problem

A typical CI/CD runner has:

- The repository's full source, including any embedded secrets the pipeline needs.
- Short-lived cloud credentials minted by OIDC federation (AWS, GCP, Azure) with permission to deploy.
- Registry push credentials, signing keys, cache keys.
- Environment secrets injected by the platform (`GITHUB_TOKEN`, `VAULT_ADDR`, `DOCKERHUB_PASSWORD`).
- Full outbound internet access. Nothing stops it.

A compromised dependency executes during `npm install`, `pip install`, `go mod download`, `bundle install`, or any post-install hook, with the same privileges as the pipeline. It has seconds to:

1. Read the credentials from environment variables or the runner filesystem.
2. `curl` them to an attacker-controlled endpoint.
3. Optionally modify the build output before any signing step.

This has shipped in public incidents: the 2022 `ctx` / `phppass` PyPI packages, the 2023 `3CX` desktop app supply-chain compromise, the 2024 series of typosquatted npm packages targeting wallet developers, and the ongoing trickle of malicious GitHub Actions published in the Marketplace. In each case the payload relied on outbound HTTPS to a freshly-registered domain or a hardcoded cloud endpoint. Egress control breaks the exfiltration step regardless of what dependency compromise comes next.

The gaps in a default runner configuration:

- Runners can resolve and connect to any DNS name and any IP address on ports 443, 80, 22, and arbitrary high ports.
- Package manager installs execute post-install scripts with pipeline-level privileges.
- No audit trail of which hostnames a build actually contacted — so anomalies cannot be detected after the fact.
- Ephemeral runners are discarded after each run, erasing local evidence of compromise.

This article covers four layers: DNS-level allowlisting, outbound firewall rules, container-level network isolation for contained steps, and audit logging of every network call a build makes.

**Target systems:** self-hosted GitHub Actions runners on Kubernetes (Actions Runner Controller), GitLab Runner on Kubernetes, Jenkins build agents in containers, and Buildkite agents. Adaptations noted for GitHub-hosted runners via the `step-security/harden-runner` action.

## Threat Model

- **Adversary:** Maintainer of a compromised package (npm, PyPI, Go module, Maven Central, RubyGems, [crates.io](https://crates.io)) or a crafted GitHub Action. Also: the attacker who has taken over a legitimate maintainer's account via credential stuffing or social engineering.
- **Access level:** Arbitrary code execution during dependency resolution or build. No prior access to the build environment, no credentials, no persistent foothold.
- **Objective:** Exfiltrate secrets reachable from the build environment (cloud credentials, signing keys, source code of proprietary repos), or use the build credentials to publish malicious artifacts downstream.
- **Blast radius:** With no egress control, anything the runner can reach on the network is reachable by the attacker. OIDC-federated cloud credentials allow pivoting to cloud resources. Push tokens allow publishing malicious artifacts back to a registry the organization trusts. Cache keys allow poisoning subsequent builds.

## Configuration

### Layer 1: DNS Allowlisting

Require builds to resolve only known hostnames. Block everything else at the resolver.

Deploy CoreDNS on the runner's network with an allowlist:

```yaml
# coredns-runner-allowlist.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-runner
  namespace: ci-runners
data:
  Corefile: |
    . {
        # Allowlist zone — only these domains resolve to real IPs.
        template IN A {
            match "^(github\.com|api\.github\.com|objects\.githubusercontent\.com|codeload\.github\.com|pkg-containers\.githubusercontent\.com|.*\.actions\.githubusercontent\.com)\.$"
            answer "{{ .Name }} 60 IN A 140.82.121.3"
            fallthrough
        }
        # Package registries.
        forward registry.npmjs.org pypi.org files.pythonhosted.org index.docker.io production.cloudflare.docker.com proxy.golang.org sum.golang.org . /etc/resolv.conf
        # Everything else: return NXDOMAIN.
        template ANY ANY {
            rcode NXDOMAIN
        }
        log
        errors
    }
```

Point the runner pod's DNS at this resolver:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gha-runner
  namespace: ci-runners
spec:
  dnsPolicy: None
  dnsConfig:
    nameservers:
      - 10.96.0.53   # ClusterIP of the restricted CoreDNS Service.
    options:
      - name: ndots
        value: "2"
  containers:
    - name: runner
      image: summerwind/actions-runner:latest
```

A compromised dependency that tries to resolve `attacker.example.com` receives NXDOMAIN before any packet leaves the pod.

### Layer 2: Outbound Firewall Allowlist

DNS alone is insufficient — malware can hardcode IPs or use DNS-over-HTTPS to bypass your resolver. Enforce at Layer 3/4 with a NetworkPolicy (for Kubernetes) or security group (for VM runners):

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: runner-egress-allowlist
  namespace: ci-runners
spec:
  podSelector:
    matchLabels:
      role: ci-runner
  policyTypes:
    - Egress
  egress:
    # DNS to our restricted resolver only.
    - to:
        - namespaceSelector:
            matchLabels:
              name: ci-runners
          podSelector:
            matchLabels:
              app: coredns-restricted
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    # HTTPS egress to known CIDR ranges only.
    - to:
        # GitHub service IPs (published at api.github.com/meta; pin a snapshot).
        - ipBlock:
            cidr: 140.82.112.0/20
        - ipBlock:
            cidr: 143.55.64.0/20
        # npm registry behind Cloudflare.
        - ipBlock:
            cidr: 104.16.0.0/12
      ports:
        - protocol: TCP
          port: 443
```

Cilium NetworkPolicy supports FQDN-based egress, which removes the IP-pinning problem:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: runner-fqdn-egress
spec:
  endpointSelector:
    matchLabels:
      role: ci-runner
  egress:
    - toFQDNs:
        - matchName: github.com
        - matchName: api.github.com
        - matchName: registry.npmjs.org
        - matchName: pypi.org
        - matchName: files.pythonhosted.org
        - matchPattern: "*.actions.githubusercontent.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    # Kubernetes DNS always allowed.
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s:k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
```

Cilium tracks DNS responses for the allowed FQDNs and opens egress for the resolved IPs for the TTL of the response, closing the "DNS resolves, traffic blocked" gap.

### Layer 3: Per-Step Network Isolation

Not every step in a pipeline needs network access. The test step after dependencies are installed rarely does. Restrict per-step using a container sidecar pattern or by running untrusted steps under a second, more restrictive NetworkPolicy.

For GitHub-hosted runners (where you cannot control the kernel), use the [`step-security/harden-runner`](https://github.com/step-security/harden-runner) action:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: block
          allowed-endpoints: >
            api.github.com:443
            github.com:443
            codeload.github.com:443
            objects.githubusercontent.com:443
            registry.npmjs.org:443
          disable-sudo: true
          disable-file-monitoring: false

      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
```

`harden-runner` installs a local eBPF-based firewall on the GitHub-hosted VM and blocks egress to any endpoint not in the allowlist. It generates a per-run audit of every DNS lookup and outbound connection, published as a run artifact.

### Layer 4: HTTPS Egress Through an Auditing Proxy

For the highest assurance, route all HTTPS through a TLS-inspecting proxy that logs every request. Deploy `mitmproxy` or `squid` in the runner namespace and configure package managers to use it:

```yaml
env:
  - name: HTTPS_PROXY
    value: "http://egress-proxy.ci-runners.svc.cluster.local:3128"
  - name: NO_PROXY
    value: "localhost,.svc,.cluster.local,169.254.169.254"
```

With `mitmproxy`, you get a full log of method + host + path for every request, including DNS-over-HTTPS attempts (which show up as `dns.google:443` or similar). Alert on any request to a host not in your allowlist.

```python
# mitmproxy addon: block requests to non-allowlisted hosts and log all traffic.
# Save as block_and_audit.py, load with `mitmproxy -s block_and_audit.py`.
import json
from mitmproxy import http

ALLOWED = {
    "github.com", "api.github.com", "objects.githubusercontent.com",
    "codeload.github.com", "registry.npmjs.org", "pypi.org",
    "files.pythonhosted.org", "proxy.golang.org", "sum.golang.org",
}

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    allowed = host in ALLOWED or any(host.endswith("." + d) for d in ALLOWED)
    event = {
        "host": host, "method": flow.request.method,
        "path": flow.request.path, "allowed": allowed,
    }
    print(json.dumps(event))
    if not allowed:
        flow.response = http.Response.make(403, b"blocked by egress proxy",
                                           {"Content-Type": "text/plain"})
```

## Expected Behaviour

| Signal | Before | After |
|--------|--------|-------|
| `curl attacker.com` from inside runner | Succeeds, exfiltration works | DNS NXDOMAIN; if IP hardcoded, NetworkPolicy drops the packet |
| `npm install` with malicious post-install script | Runs with full outbound access | Post-install `fetch` calls to unknown hosts fail; legitimate fetches to registry.npmjs.org succeed |
| Audit trail of build's network activity | None | mitmproxy log + CoreDNS log + NetworkPolicy drop counters |
| Pipeline runtime | Baseline | +2-5s per build for DNS allowlist cache misses; negligible for warm runners |
| Compromised OIDC token exfiltration | Transparent (HTTPS to attacker) | Blocked before reaching the attacker; alert fires |

Baseline verification:

```bash
# In a test pipeline, confirm blocked egress.
- run: |
    set +e
    curl --max-time 5 -s -o /dev/null -w '%{http_code}\n' https://attacker.example.com
    # Expected: 000 (connection failure) or 403 (blocked by proxy).

    curl --max-time 5 -s -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org
    # Expected: 200.
```

## Trade-offs

| Control | Security Benefit | Cost | Mitigation |
|---------|------------------|------|------------|
| DNS allowlist | First-line defense; catches dumb malware | Legitimate new dependencies may resolve to unknown CDNs and fail | Allowlist upstream CDNs (Cloudflare, Fastly, CloudFront public IPs) for known registries only. |
| NetworkPolicy IP allowlist | Works even if DNS is bypassed | IP ranges change; pinned CIDRs go stale | Refresh from `https://api.github.com/meta` and similar endpoints weekly via a cron. Use Cilium FQDN policy if available. |
| FQDN-based Cilium policy | Eliminates IP-pinning maintenance | Requires Cilium as the CNI; not available on GKE/EKS unless you install it | For non-Cilium clusters, combine IP NetworkPolicy with DNS allowlist for a functional equivalent. |
| `harden-runner` on GitHub-hosted | Works without self-hosted infra | Only supports eBPF on `ubuntu-*` runners, not `windows-*` or `macos-*` | Run sensitive steps on `ubuntu-latest`; run other platforms in separate jobs with fewer secrets. |
| Auditing HTTPS proxy | Full visibility into every request | Extra hop adds latency; TLS inspection needs a trusted root on all runners | Deploy as a sidecar, not a separate service, to avoid per-request latency. Distribute the root cert via the runner base image. |
| Per-step network isolation | Limits blast radius of any single dependency | Additional configuration per pipeline | Enforce via a reusable workflow / shared template that every team inherits. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Legitimate dependency moves to new CDN | Install step fails with DNS resolution error | Pipeline logs show NXDOMAIN for a host never seen before | Extend allowlist after verifying the new host belongs to the expected upstream. Do not blindly allow. |
| Malicious post-install bypasses proxy via hardcoded IP | Proxy logs show no unusual hosts, but exfiltration still works | NetworkPolicy drop counter increases for the runner pod | NetworkPolicy must enforce at L3/L4, not just at the proxy. Verify `iptables -L` on the node. |
| GitHub IP ranges outdated | Pipeline fails to reach github.com or api.github.com | Intermittent connection failures after months of working | Automate IP range refresh from `api.github.com/meta` via a daily cron that updates the NetworkPolicy ConfigMap. |
| DNS-over-HTTPS bypass | Malware resolves via `https://dns.google/dns-query` and connects to arbitrary IPs | Proxy logs show `dns.google` as a destination | Add `dns.google`, `1.1.1.1`, `cloudflare-dns.com` to an explicit deny list. Block port 443 to any IP not in allowlist, not just any hostname. |
| OIDC token exfiltrated before egress controls applied | Build completed; cloud audit log shows API calls from an unexpected IP shortly after | Cloud CloudTrail/AuditLog discrepancy; unexpected IAM role usage | Rotate the role's trust policy, scope the role's permissions smaller, audit for resources created during the window. The egress control would have blocked the exfiltration had it been in place. |
| harden-runner removed by PR author | Formerly-protected job no longer has allowlist | Code review catches the removal; branch protection rules block merge | Require `step-security/harden-runner` as a status check; forbid pipeline changes to workflows without CODEOWNERS approval. |

## When to Consider a Managed Alternative

Running self-hosted runners with egress control at scale requires CoreDNS configuration, NetworkPolicy maintenance, proxy deployment, audit log pipeline, and IP-range automation (6-12 hours/month for a 100-pipeline organization).

- **[StepSecurity Managed Runners](https://stepsecurity.io):** Self-hosted GitHub Actions runners with egress filtering preconfigured per-repo. Policy lives in a central config, audit logs integrated with SIEM.
- **[GitHub Actions Larger Runners with private network](https://docs.github.com/en/actions/using-github-hosted-runners/about-larger-runners):** Runners inside your VPC, so standard VPC egress controls apply. Requires Organization Enterprise.
- **[GitLab SaaS Runners with private fleet](https://docs.gitlab.com/ee/ci/runners/):** Similar to GitHub's private runners, routed through your VPC egress.

## Related Articles

- [Securing GitHub Actions Workflows](/articles/cicd/securing-github-actions/)
- [Securing Self-Hosted CI/CD Runners](/articles/cicd/securing-cicd-runners/)
- [SLSA Build Provenance](/articles/cicd/slsa-provenance/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [Container Registry Security](/articles/cicd/container-registry-security/)
