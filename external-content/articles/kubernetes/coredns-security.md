---
title: "CoreDNS Security Hardening: Rebinding Protection, Plugin Configuration, and DNSSEC Forwarding"
description: "CoreDNS is the authoritative DNS server for Kubernetes service discovery. Misconfigured plugins, missing rebinding protection, and unauthenticated health endpoints expose the cluster to DNS-based attacks. Locking down CoreDNS limits lateral movement and prevents DNS-based data exfiltration."
slug: "coredns-security"
date: 2026-05-01
lastmod: 2026-05-01
category: "kubernetes"
tags: ["coredns", "dns", "kubernetes", "rebinding", "plugin-security"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 296
difficulty: "intermediate"
estimated_reading_time: 12
published: true
layout: article.njk
permalink: "/articles/kubernetes/coredns-security/index.html"
---

# CoreDNS Security Hardening: Rebinding Protection, Plugin Configuration, and DNSSEC Forwarding

## Problem

CoreDNS is the default DNS server in Kubernetes clusters, handling service discovery, pod name resolution, and external DNS forwarding. Every pod in the cluster sends DNS queries to CoreDNS. A misconfigured or compromised CoreDNS can redirect all cluster DNS traffic, enabling man-in-the-middle attacks on service-to-service communication.

Common security weaknesses:

- **DNS rebinding via wildcard responses.** CoreDNS's default configuration forwards unknown queries to the host resolver. An attacker who controls an external domain can configure it to return internal cluster IP addresses in DNS responses, enabling a browser-based DNS rebinding attack that bypasses same-origin policy.
- **No DNSSEC validation on forwarded queries.** CoreDNS forwards external queries to upstream resolvers (typically `8.8.8.8` or the node's `/etc/resolv.conf`). Without DNSSEC validation, a forged DNS response from an on-path attacker can redirect cluster traffic to attacker-controlled endpoints.
- **Overpermissive Corefile plugins.** The CoreDNS Corefile configures plugins. Plugins like `file` (serve arbitrary zone files), `auto` (auto-load zone files from a directory), and `transfer` (allow zone transfers) can be misconfigured to expose cluster DNS data to external parties.
- **Health and metrics endpoints exposed to pods.** CoreDNS exposes `/health` and `/ready` HTTP endpoints plus Prometheus metrics on port 9153. Without network policy restrictions, any pod can query CoreDNS metrics, which reveal cluster service topology.
- **Excessive privileges for CoreDNS pods.** CoreDNS pods in many clusters run with `NET_BIND_SERVICE` capability and no other restrictions — acceptable. But some distributions grant broader capabilities or disable seccomp, creating unnecessary attack surface.
- **No query logging or anomaly detection.** Malware commonly uses DNS for command-and-control and data exfiltration (DNS tunnelling). Without query logging, exfiltration via CoreDNS is undetected.

**Target systems:** CoreDNS 1.11+ (Kubernetes 1.28+); Corefile plugin configuration; NodeLocal DNSCache for performance and isolation; NetworkPolicy for CoreDNS access control.

## Threat Model

- **Adversary 1 — DNS rebinding attack:** A malicious pod resolves an attacker-controlled domain that returns a private IP address (e.g., `10.96.0.1` — the Kubernetes API server). The browser (or application) then sends HTTP requests to the Kubernetes API, bypassing same-origin policy. Without rebinding protection, CoreDNS returns private IPs for external domains.
- **Adversary 2 — DNS response poisoning:** An on-path attacker between CoreDNS and the upstream resolver forges a DNS response, redirecting `api.external-service.com` to an attacker IP. Without DNSSEC validation, CoreDNS caches and serves the poisoned response to all pods.
- **Adversary 3 — DNS tunnelling for data exfiltration:** Malware on a compromised pod encodes exfiltrated data in DNS query subdomains (`exfildata.c2.attacker.com`). CoreDNS forwards the query to the attacker's authoritative DNS server, delivering the data. Without query monitoring, this is invisible.
- **Adversary 4 — CoreDNS zone transfer.** The `transfer` plugin is misconfigured to allow transfers from any IP. An attacker performs a zone transfer and receives a complete map of all internal DNS names, revealing service topology.
- **Adversary 5 — Metric endpoint reconnaissance.** Any pod queries CoreDNS metrics on port 9153 and receives a complete list of recently queried DNS names — revealing which external services the cluster depends on.
- **Access level:** Adversaries 1, 3, and 5 only need to run a pod in the cluster. Adversary 2 is on-path between CoreDNS and the upstream resolver. Adversary 4 needs network access to CoreDNS.
- **Objective:** Redirect service traffic, exfiltrate data, enumerate service topology, bypass network controls.
- **Blast radius:** Successful DNS poisoning for a high-value internal service affects every pod that queries that name — potentially all inter-service communication.

## Configuration

### Step 1: Corefile Hardening

```
# /etc/coredns/Corefile — hardened configuration.

# Cluster-internal DNS zone.
cluster.local:53 {
    errors
    health {
        lameduck 5s
    }
    ready
    kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure          # insecure: trust pod IP for PTR; use verified for stricter mode.
        fallthrough in-addr.arpa ip6.arpa
        ttl 30
    }
    prometheus :9153           # Metrics — restrict access via NetworkPolicy.
    forward . /etc/resolv.conf {
        max_concurrent 1000
    }
    cache 30 {
        # Prevent negative caching poisoning.
        denial 9984 30         # Cache NXDOMAIN for 30s max.
        success 9984 30        # Cache successful responses for 30s max.
    }
    loop
    reload
    loadbalance
}

# External DNS forwarding with rebinding protection.
.:53 {
    errors
    # Rebinding protection: deny responses that return private IPs for external domains.
    # The acl plugin blocks queries that would resolve to private ranges.
    acl {
        answer name .* ip 10.0.0.0/8 deny     # Block private RFC1918 responses.
        answer name .* ip 172.16.0.0/12 deny
        answer name .* ip 192.168.0.0/16 deny
        answer name .* ip 100.64.0.0/10 deny   # CGNAT range.
        allow
    }
    
    # Forward external queries to trusted resolvers with DNSSEC validation.
    forward . tls://1.1.1.1 tls://1.0.0.1 {
        tls_servername cloudflare-dns.com     # Verify TLS certificate.
        max_concurrent 1000
        health_check 5s
        expire 10s
    }
    
    cache 300 {
        denial 9984 30
        success 9984 300
    }
    
    # Log queries for DNS tunnelling detection.
    log . {
        class denial error
    }
    
    loop
    loadbalance
}
```

### Step 2: DNS-over-TLS for Upstream Forwarding

Plain UDP forwarding to upstream resolvers is unencrypted and susceptible to response forgery. Use DNS-over-TLS:

```
# CoreDNS forward with TLS to Cloudflare (1.1.1.1) and Google (8.8.8.8).
forward . tls://1.1.1.1 tls://8.8.8.8 {
    tls_servername cloudflare-dns.com  # Verify server certificate.
    # This prevents on-path DNS response poisoning between CoreDNS and the resolver.
    max_concurrent 1000
    expire 30s
    health_check 10s
}
```

```yaml
# Apply via Kubernetes ConfigMap.
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
      forward . tls://1.1.1.1 tls://1.0.0.1 {
        tls_servername cloudflare-dns.com
        max_concurrent 1000
      }
      cache 300
      errors
      log
    }
    cluster.local:53 {
      kubernetes cluster.local in-addr.arpa ip6.arpa {
        pods insecure
        fallthrough in-addr.arpa ip6.arpa
      }
      cache 30
      errors
    }
```

### Step 3: NetworkPolicy for CoreDNS

Restrict which pods can query CoreDNS and who can reach its metrics:

```yaml
# Allow all pods to query CoreDNS on UDP/TCP 53.
# Restrict metrics (9153) to monitoring namespace only.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: coredns-access
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      k8s-app: kube-dns
  policyTypes:
    - Ingress
  ingress:
    # DNS queries from all pods (required for cluster function).
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP

    # Metrics: only from monitoring namespace.
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - port: 9153
          protocol: TCP

    # Health/ready probes: only from kube-system (kubelet).
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 8080
          protocol: TCP
```

### Step 4: CoreDNS Pod Security

```yaml
# Harden the CoreDNS Deployment (patch via strategic merge).
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: coredns
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop: ["ALL"]
              add: ["NET_BIND_SERVICE"]   # Required to bind port 53.
          resources:
            limits:
              cpu: "200m"
              memory: "170Mi"
            requests:
              cpu: "100m"
              memory: "70Mi"
          # Liveness probe using health endpoint.
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
              scheme: HTTP
            initialDelaySeconds: 60
            timeoutSeconds: 5
            successThreshold: 1
            failureThreshold: 5
```

### Step 5: NodeLocal DNSCache

NodeLocal DNSCache runs a DNS cache on every node, reducing CoreDNS load and improving query isolation — compromised pods on one node cannot observe DNS queries from pods on other nodes:

```yaml
# Deploy NodeLocal DNSCache (DaemonSet).
# Each node runs a local cache on a link-local address (169.254.20.10).
# Pods query the local cache; cache queries CoreDNS for misses.

# Apply from the official manifest.
kubectl apply -f https://raw.githubusercontent.com/kubernetes/kubernetes/master/cluster/addons/dns/nodelocaldns/nodelocaldns.yaml

# Configure kubelet to use NodeLocal DNSCache.
# --cluster-dns=169.254.20.10 in kubelet config.
```

### Step 6: Query Logging and DNS Tunnelling Detection

```
# Corefile: enable query logging for anomaly detection.
.:53 {
    log . {
        class all   # Log all queries (high volume; consider sampling in large clusters).
    }
    # ...
}
```

```python
# dns_tunnel_detector.py — detect DNS tunnelling patterns in CoreDNS logs.
import re
from collections import defaultdict
from datetime import datetime

# CoreDNS log format:
# [INFO] 10.244.0.5:12345 - 1234 "A IN exfil.c2.attacker.com. udp 45 false 512" NOERROR 0 0.001234s

LONG_SUBDOMAIN = re.compile(r'[a-f0-9]{20,}\.')  # Long hex strings (common in tunnels).

def analyse_dns_log(log_line: str) -> bool:
    """Returns True if the query looks like DNS tunnelling."""
    # Extract query name.
    match = re.search(r'"[A-Z]+ IN ([^\s]+)', log_line)
    if not match:
        return False
    
    qname = match.group(1).rstrip('.')
    labels = qname.split('.')
    
    # Indicators:
    # 1. Very long subdomain label (data encoding).
    if any(len(label) > 40 for label in labels):
        return True
    
    # 2. High-entropy subdomain (random-looking base32/hex).
    if LONG_SUBDOMAIN.search(qname):
        return True
    
    # 3. Unusually high query count for same domain (frequency analysis).
    # (Tracked separately in a counter.)
    
    return False
```

### Step 7: Restrict External DNS Plugins

Disable CoreDNS plugins not needed in production:

```
# Do NOT include these plugins unless explicitly required:
# - file: serves arbitrary zone files from disk (lateral movement if writable).
# - auto: auto-loads zone files from a directory (same risk).
# - transfer: allows zone transfers (topology disclosure).
# - rewrite: can redirect cluster DNS internally (misuse potential).
# - template: generates responses from Go templates (injection risk if misconfigured).

# Minimal safe plugin set for a standard Kubernetes cluster:
# errors, health, ready, kubernetes, prometheus, forward, cache, loop, reload, loadbalance
```

### Step 8: Telemetry

```
coredns_dns_requests_total{server, zone, proto, type}           counter
coredns_dns_responses_total{server, zone, rcode}                counter
coredns_dns_request_duration_seconds{server, zone, type}        histogram
coredns_forward_requests_total{to}                              counter
coredns_forward_healthcheck_failures_total{to}                  counter
coredns_cache_hits_total{server, type}                          counter
coredns_dns_do_requests_total{server}                           counter  # DNSSEC queries
```

Alert on:

- `coredns_forward_healthcheck_failures_total` non-zero — upstream resolver unreachable; external DNS resolution failing.
- `coredns_dns_responses_total{rcode="SERVFAIL"}` spike — CoreDNS failing to resolve; may indicate upstream issues or misconfiguration after a Corefile change.
- Query log shows long hex-encoded subdomain labels — potential DNS tunnelling; investigate source pod.
- CoreDNS pod restart — unexpected restarts may indicate OOM from cache exhaustion or a Corefile syntax error after a reload.
- `coredns_dns_requests_total` sudden spike from a single source IP — DNS-based DDoS or rapid service discovery scanning.

## Expected Behaviour

| Signal | Default CoreDNS | Hardened CoreDNS |
|--------|----------------|-----------------|
| DNS rebinding attack | Private IP returned for external domain | ACL plugin blocks private IPs in external responses |
| Upstream response poisoning | Unencrypted UDP; forged response accepted | DNS-over-TLS to upstream; MITM cannot forge responses |
| DNS tunnelling | Queries forwarded silently | Query logging enables detection; high-entropy domains flagged |
| Metrics exposure | Any pod reads cluster service topology | NetworkPolicy restricts metrics to monitoring namespace |
| Zone transfer | Transfer plugin allows read if misconfigured | Transfer plugin excluded from Corefile |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| DNS-over-TLS upstream | Prevents response poisoning | Slightly higher latency (~10ms) than UDP; TLS handshake | NodeLocal DNSCache reduces TLS handshake frequency |
| ACL rebinding protection | Prevents private IP in external responses | May break split-horizon DNS where internal names resolve via external lookup | Explicitly allowlist internal resolver domains; use `kubernetes` plugin for cluster names |
| Full query logging | DNS tunnelling detection | High log volume in large clusters | Log only external forwarded queries; use sampling |
| NodeLocal DNSCache | Reduces cross-node DNS query observation | Additional DaemonSet to manage | Standard add-on; well-maintained |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Corefile syntax error after reload | CoreDNS crashes or refuses to reload | Pod restarts; DNS resolution fails cluster-wide | `coredns -conf /etc/coredns/Corefile -plugins` to validate before applying; roll back ConfigMap |
| Upstream TLS resolver unreachable | External DNS fails; internal still works | `coredns_forward_healthcheck_failures_total`; external service failures | Add fallback resolver: `forward . tls://1.1.1.1 tls://8.8.8.8` (multiple upstreams) |
| ACL blocks legitimate split-horizon | Internal service queried via external name fails | Service discovery failures for specific domains | Add `except` clause for internal domains in ACL; use CoreDNS `file` plugin for internal zones |
| NodeLocal DNSCache DaemonSet OOM | DNS fails on specific nodes | Node-level DNS failure; pod scheduling on that node fails DNS | Increase memory limits for NodeLocal DNSCache DaemonSet |

## Related Articles

- [DNS Security: DNSSEC and CAA Records](/articles/network/dns-security-dnssec-caa/)
- [DNS RPZ and Threat Intelligence Feeds](/articles/network/dns-rpz-threat-intelligence/)
- [Kubernetes Network Policies](/articles/kubernetes/kubernetes-network-policies/)
- [Cilium Network Policy](/articles/kubernetes/cilium-network-policy/)
- [Network Flow Analysis](/articles/observability/network-flow-analysis/)
