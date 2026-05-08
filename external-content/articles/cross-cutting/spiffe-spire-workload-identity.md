---
title: "SPIFFE and SPIRE for Workload Identity Across Clusters and Clouds"
description: "Cryptographic workload identity that survives across Kubernetes clusters, cloud accounts, and on-prem hosts. SPIFFE replaces shared secrets with attestation."
slug: "spiffe-spire-workload-identity"
date: 2026-04-27
lastmod: 2026-04-27
category: "cross-cutting"
tags: ["spiffe", "spire", "workload-identity", "zero-trust", "mtls"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 174
difficulty: "advanced"
estimated_reading_time: 17
published: true
layout: article.njk
permalink: "/articles/cross-cutting/spiffe-spire-workload-identity/index.html"
---

# SPIFFE and SPIRE for Workload Identity Across Clusters and Clouds

## Problem

Workloads need to authenticate to other workloads. The dominant patterns each have a structural problem:

- **Shared API keys / passwords** — leaks live forever, rotation requires redeploys, secrets scattered across CI systems and config files.
- **Cloud IAM roles** — work within one cloud but break at the boundary. A Kubernetes pod in cluster A cannot directly assume an IAM role in cloud B's account without bridging through a shared secret or a federated mechanism that ends up grounding back to a shared secret.
- **mTLS with hand-managed certificates** — operationally heavy at scale; certificate distribution, rotation, and revocation become a job in themselves.
- **Service account tokens (Kubernetes)** — bound to the cluster's signing key; portable only via OIDC federation, and only to systems that accept that issuer.

SPIFFE (Secure Production Identity Framework For Everyone) is an open specification for workload identity. SPIRE (the SPIFFE Runtime Environment) is the most widely-deployed implementation. Together they provide:

- **A cryptographic identity for every workload**, expressed as a SPIFFE ID (a URI like `spiffe://prod.example.com/ns/payments/sa/api`).
- **Short-lived X.509 certificates (SVIDs) and JWT-SVIDs** issued automatically to each workload, rotated continuously, never persisted to disk.
- **Attestation of workloads** based on operating system facts (Kubernetes pod metadata, AWS instance identity, Azure VM identity, hostname signatures) — no shared secrets to bootstrap trust.
- **Federation between trust domains**, allowing identities issued in cluster A to be verified in cluster B or in a different cloud entirely.

By 2026 SPIRE has substantial adoption: Istio uses SPIFFE for service identity, AWS App Mesh ships SPIRE integrations, Tetrate and HPE offer commercial SPIRE deployments, and Tetragon supports SPIFFE-aware policy. The pattern is mature enough for production beyond a single team's pet project.

This article covers SPIRE Server topology, agent placement on Kubernetes and VMs, attestation policies, federation between trust domains, and integration with applications via the Workload API.

**Target systems:** SPIRE 1.10+, Kubernetes 1.28+, optional integrations with Istio 1.22+, Envoy 1.30+, and HashiCorp Vault 1.16+. Federates with cloud OIDC issuers (AWS STS, GCP STS, Azure AD).

## Threat Model

- **Adversary 1 — Compromised pod:** attacker with code execution in pod A wants to impersonate pod B to access B's permissions on a downstream service.
- **Adversary 2 — Cluster-to-cluster pivot:** attacker who has compromised a workload in dev cluster wants to access a service in prod cluster using a stolen credential.
- **Adversary 3 — Insider with cloud-account access:** ops engineer with read access to one cloud account uses it to impersonate workloads in another account.
- **Adversary 4 — Token replay:** attacker captures a JWT-SVID in transit and replays it after the original session ended.
- **Access level:** Adversary 1 has pod-level execution; cannot read other pods' filesystems by default. Adversary 2 has full credential access in their compromised cluster. Adversary 3 has IAM-read in one account. Adversary 4 has passive network capture.
- **Objective:** Authenticate to a service as a different workload. Cross trust boundaries (cluster, cloud, environment). Persist access beyond the legitimate session window.
- **Blast radius:** Without SPIFFE: compromised tokens are usable until rotation (often days/weeks). Cross-cluster pivot succeeds whenever a shared secret bridges environments. With SPIFFE: SVIDs are rotated every hour by default; replay attacks expire quickly. Attestation binds identity to workload-level facts (pod UID, container image), so impersonation requires reproducing those facts.

## Configuration

### Step 1: Deploy SPIRE Server

The Server is the certificate authority for the trust domain. One Server (HA-deployed) per trust domain. Trust domain typically maps to one organizational boundary (`prod.example.com`, `staging.example.com`).

```yaml
# spire-server-statefulset.yaml
# SPIRE Server in HA. Backed by a managed Postgres for HA state.
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: spire-server
  namespace: spire
spec:
  serviceName: spire-server
  replicas: 3
  selector:
    matchLabels:
      app: spire-server
  template:
    metadata:
      labels:
        app: spire-server
    spec:
      serviceAccountName: spire-server
      containers:
        - name: spire-server
          image: ghcr.io/spiffe/spire-server:1.10.0
          args: ["-config", "/run/spire/config/server.conf"]
          ports:
            - containerPort: 8081
              name: grpc
          volumeMounts:
            - name: config
              mountPath: /run/spire/config
              readOnly: true
            - name: data
              mountPath: /run/spire/data
          livenessProbe:
            httpGet:
              path: /live
              port: 8080
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
      volumes:
        - name: config
          configMap:
            name: spire-server-config
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: [ReadWriteOnce]
        resources:
          requests:
            storage: 10Gi
```

```hcl
# server.conf
server {
  bind_address = "0.0.0.0"
  bind_port = "8081"
  trust_domain = "prod.example.com"
  data_dir = "/run/spire/data"
  log_level = "INFO"
  ca_subject = {
    country = ["US"],
    organization = ["Example Corp"],
    common_name = "SPIRE Server CA"
  }
  default_x509_svid_ttl = "1h"
  default_jwt_svid_ttl = "5m"
  ca_ttl = "168h"
  ca_key_type = "ec-p384"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "postgres"
      connection_string = "postgres://spire:..@spire-db:5432/spire?sslmode=require"
    }
  }
  KeyManager "aws_kms" {
    plugin_data {
      region = "us-east-1"
      key_metadata_file = "/run/spire/data/keys.json"
      key_policy_file = "/run/spire/config/key-policy.json"
    }
  }
  NodeAttestor "k8s_psat" {
    plugin_data {
      clusters = {
        "prod-us-east-1" = {
          service_account_allow_list = ["spire:spire-agent"]
        }
      }
    }
  }
  UpstreamAuthority "disk" {
    plugin_data {
      cert_file_path = "/run/spire/config/upstream/intermediate.crt"
      key_file_path = "/run/spire/config/upstream/intermediate.key"
    }
  }
}
```

Key choices:

- `default_x509_svid_ttl = "1h"` — short SVID lifetimes; SPIRE Agents auto-rotate.
- `KeyManager "aws_kms"` — the trust-domain root key lives in KMS, never in plaintext on disk.
- `UpstreamAuthority "disk"` — chains to your organization's PKI so SPIRE-issued SVIDs validate against your existing trust roots.

### Step 2: Deploy SPIRE Agent on Each Node

The Agent runs on every node where SPIRE-aware workloads need identities. On Kubernetes, deploy as a DaemonSet exposing the Workload API as a Unix socket.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: spire
spec:
  selector:
    matchLabels:
      app: spire-agent
  template:
    metadata:
      labels:
        app: spire-agent
    spec:
      serviceAccountName: spire-agent
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: spire-agent
          image: ghcr.io/spiffe/spire-agent:1.10.0
          args: ["-config", "/run/spire/config/agent.conf"]
          volumeMounts:
            - name: config
              mountPath: /run/spire/config
              readOnly: true
            - name: agent-socket
              mountPath: /run/spire/agent-sockets
            - name: kubelet-socket
              mountPath: /var/lib/kubelet/pod-resources
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: spire-agent-config
        - name: agent-socket
          hostPath:
            path: /run/spire/agent-sockets
            type: DirectoryOrCreate
        - name: kubelet-socket
          hostPath:
            path: /var/lib/kubelet/pod-resources
```

```hcl
# agent.conf
agent {
  data_dir = "/run/spire/data"
  log_level = "INFO"
  server_address = "spire-server.spire.svc.cluster.local"
  server_port = "8081"
  socket_path = "/run/spire/agent-sockets/spire-agent.sock"
  trust_bundle_path = "/run/spire/config/bootstrap.crt"
  trust_domain = "prod.example.com"
}

plugins {
  NodeAttestor "k8s_psat" {
    plugin_data {
      cluster = "prod-us-east-1"
    }
  }
  KeyManager "memory" {}
  WorkloadAttestor "k8s" {
    plugin_data {
      kubelet_read_only_port = 0
      skip_kubelet_verification = false
    }
  }
  WorkloadAttestor "unix" {
    plugin_data {
      discover_workload_path = true
    }
  }
}
```

The k8s WorkloadAttestor inspects pod metadata to identify the workload. The unix WorkloadAttestor identifies based on the calling process's UID, GID, and binary path — useful for non-Kubernetes workloads on the same host.

### Step 3: Register Workloads

A registration entry maps an attestation selector (a set of facts about a workload) to a SPIFFE ID. Without a registration, even an attested workload gets no identity.

```bash
# Register the payments-api workload in the payments namespace.
kubectl exec -n spire spire-server-0 -- \
  /opt/spire/bin/spire-server entry create \
    -spiffeID spiffe://prod.example.com/ns/payments/sa/api \
    -parentID spiffe://prod.example.com/spire/agent/k8s_psat/prod-us-east-1/spire-agent \
    -selector k8s:ns:payments \
    -selector k8s:sa:api \
    -selector k8s:container-image:ghcr.io/myorg/payments-api@sha256:abc123 \
    -ttl 3600
```

The selectors specify *what must be true* for the workload to receive this SPIFFE ID. Pinning the container image digest (the third selector) means a tampered or substituted image with a different digest cannot impersonate the workload.

### Step 4: Application Integration via the Workload API

The application connects to the Workload API socket to fetch its SVID. SPIFFE provides language SDKs.

```go
// main.go - Go application using the SPIFFE Workload API.
package main

import (
    "context"
    "log"
    "net/http"
    "github.com/spiffe/go-spiffe/v2/spiffetls"
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
    "github.com/spiffe/go-spiffe/v2/workloadapi"
    "github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
    ctx := context.Background()
    src, err := workloadapi.NewX509Source(ctx)
    if err != nil { log.Fatal(err) }
    defer src.Close()

    // Server: accept only known peer SPIFFE IDs.
    allowedClient := spiffeid.RequireFromString(
        "spiffe://prod.example.com/ns/web/sa/frontend")
    tlsCfg := tlsconfig.MTLSServerConfig(src, src,
        tlsconfig.AuthorizeID(allowedClient))

    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsCfg,
        Handler:   http.HandlerFunc(handler),
    }
    log.Fatal(server.ListenAndServeTLS("", ""))
}

func handler(w http.ResponseWriter, r *http.Request) {
    // r.TLS.PeerCertificates[0] contains the verified peer SVID.
    // SPIFFE ID is in URI SAN.
    w.Write([]byte("OK"))
}
```

The application never touches a private key; never writes a certificate to disk; gets continuous rotation transparently.

### Step 5: Federation Between Trust Domains

To allow workloads in `staging.example.com` to authenticate to services in `prod.example.com`, federate the trust domains. Each Server exports a "trust bundle" (its root CA) to the other.

```bash
# In prod, register the staging trust domain as federated.
spire-server federation create \
  -trustDomain staging.example.com \
  -bundleEndpointURL https://spire-server.staging.example.com/bundle \
  -bundleEndpointProfile https_spiffe \
  -endpointSpiffeID spiffe://staging.example.com/spire/server

# In staging, register prod the same way.
```

Workloads in prod can now configure an authorization policy that accepts SPIFFE IDs from `staging.example.com` for specific use cases — for example, allowing a staging build pipeline to write to a prod artifact bucket via the SPIFFE-authenticated path.

### Step 6: Federation with Cloud OIDC

Federation isn't only between SPIRE deployments. SPIRE issues JWT-SVIDs that are valid OIDC ID tokens; cloud providers can be configured to trust SPIRE as an OIDC issuer.

```bash
# Configure SPIRE Server to expose its OIDC discovery endpoint.
spire-server x509-authority list
# Take the upstream cert.

# Register SPIRE as an OIDC provider in AWS.
aws iam create-open-id-connect-provider \
  --url https://oidc.spire.example.com \
  --client-id-list spiffe://prod.example.com \
  --thumbprint-list <thumbprint-of-spire-jwks-endpoint-cert>

# Trust policy on the AWS role:
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.spire.example.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "oidc.spire.example.com:sub":
        "spiffe://prod.example.com/ns/payments/sa/api"
    }
  }
}
```

The payments API pod now assumes an AWS role using its SPIFFE identity — no AWS-specific credentials, no OIDC bridging through GitHub Actions or another federation provider.

## Expected Behaviour

| Signal | Without SPIFFE | With SPIFFE |
|--------|----------------|-------------|
| Workload-to-workload auth | Shared secret or hand-rolled mTLS | Cryptographic SVID; rotated hourly |
| Cluster-to-cluster auth | Bridged via shared secret or external IdP | Federation between SPIRE trust domains |
| Cloud-to-cloud auth | Per-cloud federation chains | Single SPIFFE identity, multiple cloud OIDC trusts |
| Certificate lifetime | Days to years | 1 hour (default), continuously rotated |
| Compromised pod blast radius | Until secret rotation | Until SVID expires (max 1 hour) |
| Onboarding new service | Issue secret, distribute, monitor | Create registration entry; no secret distribution |

Verify a workload has a valid SPIFFE identity:

```bash
# From inside the pod, query the Workload API.
kubectl exec -n payments deploy/api -- \
  /opt/spire/bin/spire-agent api fetch x509 \
    -socketPath /run/spire/agent-sockets/spire-agent.sock
# SPIFFE ID:        spiffe://prod.example.com/ns/payments/sa/api
# SVID Valid After: 2026-04-27 16:30:00 +0000 UTC
# SVID Valid Until: 2026-04-27 17:30:00 +0000 UTC
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Continuous SVID rotation | Compromised SVIDs expire within an hour | Workloads must use the Workload API rather than reading a static cert | SDK integration via `go-spiffe`, `spiffe-helper` for sidecar injection of cert files. |
| Attestation by image digest | Container substitution does not impersonate | Registration entries pin to digests; image rebuild requires new entry | Automate registration entry updates from your CD pipeline. The pipeline knows the new digest. |
| Multi-trust-domain federation | Services in different clusters can mTLS without shared keys | Operational overhead of bundle endpoints, federation entries | Use the federation bundle endpoint with auto-refresh; SPIRE refreshes bundles on its own schedule. |
| OIDC-based cloud federation | Single identity model across cloud accounts | OIDC providers must trust your SPIRE issuer URL | Run the SPIRE OIDC discovery endpoint behind a stable, public URL (Cloudflare or similar); rotate the JWKS endpoint cert with care. |
| Workload API as a UDS | Simple, fast, no network involvement | Requires hostPath or DaemonSet socket mount | Use a CSI driver (`spiffe-csi`) for ephemeral socket mounts that respect Pod Security Standards. |
| KMS-backed root | Server compromise does not expose root key | KMS API costs and dependency on KMS availability | Use a regional KMS; SPIRE caches the active intermediate, only contacting KMS for rotation. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Workload registration missing | Pod cannot fetch SVID; logs show `no SVID found for...` | `spire-server entry show` for the SPIFFE ID returns nothing | Add the registration entry. Automate via your deploy pipeline so this is not a manual step. |
| Selector mismatch (image digest changed) | Pods after a deploy lose their identity | `spire-server entry show` shows the old digest pinned | Update the registration entry with the new digest before or alongside the deploy. |
| SPIRE Server outage | New SVIDs cannot be issued; existing SVIDs expire within their TTL | Workload error rates rise an hour after Server outage | Run Server in HA (3+ replicas). For multi-region, deploy a Server per region with shared backing store and a federation between them. |
| Federation bundle stale | Cross-domain mTLS fails; remote SVIDs no longer validate | Application logs show `unknown CA` errors for federated SPIFFE IDs | Verify the bundle endpoint is reachable; SPIRE auto-refreshes bundles every 5 minutes by default. Check the federation entry's last-refresh time. |
| Workload API socket inaccessible | Pod cannot find the Unix socket | Pod logs show `connection refused` on the socket path | Verify the SPIRE Agent DaemonSet is running on the node. For new pod templates, ensure the hostPath mount or CSI volume is configured. |
| Time skew breaks SVID validation | Pods report SVID `not yet valid` or `expired` errors | Application errors at handshake; clock disagreement between pods and CA | Run NTP on every node; SPIRE validates against a 30s clock skew tolerance. Investigate node clocks before tuning. |
| Compromised SPIRE Agent | Attacker can issue arbitrary SVIDs to processes on that node | Audit logs show registrations from unexpected selectors | Limit Server-side per-Agent registrations (selectors must be specific). Rotate the Agent's bootstrap credentials. The blast radius is bounded to that node's pods. |

## When SPIFFE Is the Wrong Tool

- **Single-cloud, single-cluster, no cross-boundary identity needed.** The cloud's native IAM (Pod Identity, Workload Identity Federation) is simpler.
- **Workloads cannot integrate with the Workload API.** SPIFFE is most powerful when applications fetch SVIDs directly. For legacy workloads, `spiffe-helper` writes certs to disk; that works but loses the in-memory-only benefit.
- **Trust domain boundaries do not align with operational boundaries.** SPIFFE assumes a logical trust domain hierarchy. If your environment is a flat shared cluster, the value is reduced.

## Related Articles

- [Zero-Trust Networking for Production](/articles/cross-cutting/zero-trust-networking/)
- [mTLS in Service Mesh: Zero-Trust Networking Between Services](/articles/network/mtls-service-mesh/)
- [Multi-Cloud Hardening Patterns](/articles/cross-cutting/multi-cloud-hardening/)
- [Service Account Tokens in Kubernetes](/articles/kubernetes/service-account-tokens/)
- [Post-Quantum Crypto Migration Plan](/articles/cross-cutting/post-quantum-migration/)
