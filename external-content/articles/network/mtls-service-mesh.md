---
title: "mTLS for Service-to-Service Communication: Istio, Linkerd, and DIY with cert-manager"
description: "Internal service-to-service traffic in most Kubernetes clusters is plaintext. Once an attacker compromises a single pod, through a container escape,..."
slug: "mtls-service-mesh"
date: 2026-03-18
lastmod: 2026-03-18
category: "network"
tags: ["mtls", "service-mesh", "istio", "linkerd", "cert-manager", "kubernetes", "zero-trust"]
personas: ["platform-engineer", "security-engineer"]
article_number: 38
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Isovalent"
    id: 54
    category: "service-mesh"
  - name: "Buoyant"
    id: 55
    category: "service-mesh"
  - name: "Solo.io"
    id: 56
    category: "service-mesh"
  - name: "Sysdig"
    id: 122
    category: "monitoring"
premium_pack: "mtls-mesh-configs"
published: true
layout: article.njk
permalink: "/articles/network/mtls-service-mesh/index.html"
---

# mTLS for Service-to-Service Communication: [Istio](https://istio.io), [Linkerd](https://linkerd.io), and DIY with [cert-manager](https://cert-manager.io)

## Problem

Internal service-to-service traffic in most [Kubernetes](https://kubernetes.io) clusters is plaintext. Once an attacker compromises a single pod, through a container escape, a vulnerable dependency, or a misconfigured RBAC rule, they can:

- **Sniff all east-west traffic** on the pod network. Kubernetes network plugins ([Calico](https://www.tigera.io/project-calico/), [Cilium](https://cilium.io), Flannel) do not encrypt traffic by default. A compromised pod with `tcpdump` or a raw socket can capture every request between every service on the same node, and often across nodes.
- **Impersonate any service.** Without mutual authentication, service A has no way to verify that a request claiming to be from service B is genuinely from service B. A compromised pod can send requests to any internal service with a forged `Host` header.
- **Replay captured requests.** Plaintext traffic captured on the wire can be replayed against internal services at any time.
- **Move laterally without detection.** Internal traffic is rarely logged at the same detail level as external traffic. An attacker pivoting between services generates traffic that looks identical to normal inter-service communication.

Mutual TLS (mTLS) addresses all four problems: it encrypts traffic (preventing sniffing), authenticates both client and server via certificates (preventing impersonation), and provides a cryptographic identity per service that can be used for authorization policies and audit logging.

The challenge is operational complexity. Certificate issuance, rotation, trust chain management, and debugging TLS handshake failures across hundreds of services is significant work. Service meshes automate this, but they add sidecar proxies, increase memory usage, and introduce a new failure domain.

**Target systems:** Kubernetes 1.28+ clusters. Istio 1.20+, Linkerd 2.14+, or cert-manager 1.13+ for DIY approaches.

## Threat Model

- **Adversary:** Attacker who has compromised a single pod or container within the cluster. This could be through a vulnerable application dependency, container escape, or compromised CI/CD pipeline that deployed malicious code.
- **Access level:** Network-level access to the pod CIDR. Can send and receive arbitrary TCP/UDP packets to any pod IP. May have limited Kubernetes API access depending on the pod's service account.
- **Objective:** Lateral movement to higher-value services (databases, authentication services, secrets management). Data exfiltration by sniffing traffic containing credentials, tokens, or PII. Privilege escalation by impersonating trusted services.
- **Blast radius:** Without mTLS, the entire cluster's east-west traffic is exposed. With mTLS, the blast radius is limited to what the compromised service's certificate identity is authorized to access.

## Configuration

### Istio: Strict mTLS Mode

Istio provides the most feature-complete mTLS implementation. The [Envoy](https://www.envoyproxy.io) sidecar proxy handles certificate management, rotation, and enforcement transparently.

**Install Istio with strict mTLS defaults:**

```bash
# Install Istio with the default profile.
# The default profile includes istiod (control plane) and ingress gateway.
istioctl install --set profile=default -y

# Enable sidecar injection for your application namespace.
kubectl label namespace production istio-injection=enabled
```

**Enforce strict mTLS cluster-wide:**

```yaml
# strict-mtls-policy.yaml
# This policy requires mTLS for all traffic in the mesh.
# Services without sidecars cannot communicate with meshed services.
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT
```

```bash
kubectl apply -f strict-mtls-policy.yaml
```

**Permissive mode for migration (accepts both plaintext and mTLS):**

```yaml
# permissive-mtls-policy.yaml
# Use during migration. Services can receive both plaintext and mTLS.
# Switch to STRICT after all services have sidecars.
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: PERMISSIVE
```

**Per-namespace override (strict in production, permissive in staging):**

```yaml
# production-strict.yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
---
# staging-permissive.yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: staging
spec:
  mtls:
    mode: PERMISSIVE
```

**Authorization policy (restrict which services can talk to which):**

```yaml
# allow-only-frontend-to-api.yaml
# Only the frontend service can call the API service.
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: api-allow-frontend
  namespace: production
spec:
  selector:
    matchLabels:
      app: api-service
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              - "cluster.local/ns/production/sa/frontend-service"
      to:
        - operation:
            methods: ["GET", "POST"]
            paths: ["/api/*"]
```

### Linkerd: Automatic mTLS (Lightweight)

Linkerd enables mTLS by default with no configuration required. Every proxied connection is automatically encrypted and authenticated.

**Install Linkerd:**

```bash
# Install the Linkerd CLI.
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh

# Validate prerequisites.
linkerd check --pre

# Install Linkerd control plane.
linkerd install --crds | kubectl apply -f -
linkerd install | kubectl apply -f -

# Verify installation.
linkerd check
```

**Inject sidecars into your namespace:**

```bash
# Add annotation to namespace for automatic injection.
kubectl annotate namespace production linkerd.io/inject=enabled

# Or inject into an existing deployment.
kubectl get deploy -n production api-service -o yaml \
  | linkerd inject - \
  | kubectl apply -f -
```

**Verify mTLS is active:**

```bash
# Check that connections between services are using mTLS.
linkerd viz edges deployment -n production

# Expected output shows "secured" for all connections:
# SRC          DST          SRC_NS       DST_NS       SECURED
# frontend     api-service  production   production   true
# api-service  database     production   production   true
```

**Authorization policy (Linkerd Server and ServerAuthorization):**

```yaml
# server.yaml - Define the API service's inbound ports.
apiVersion: policy.linkerd.io/v1beta3
kind: Server
metadata:
  name: api-service-http
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-service
  port: 8080
  proxyProtocol: HTTP/2
---
# authorization.yaml - Only frontend can reach the API service.
apiVersion: policy.linkerd.io/v1alpha1
kind: AuthorizationPolicy
metadata:
  name: api-allow-frontend
  namespace: production
spec:
  targetRef:
    group: policy.linkerd.io
    kind: Server
    name: api-service-http
  requiredAuthenticationRefs:
    - name: frontend-identity
      kind: MeshTLSAuthentication
      group: policy.linkerd.io
---
apiVersion: policy.linkerd.io/v1alpha1
kind: MeshTLSAuthentication
metadata:
  name: frontend-identity
  namespace: production
spec:
  identities:
    - "frontend.production.serviceaccount.identity.linkerd.cluster.local"
```

### DIY: cert-manager with Application-Level TLS

For teams that cannot adopt a service mesh, cert-manager can issue and rotate certificates for direct application-level TLS.

**Install cert-manager:**

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
```

**Create a self-signed CA for internal services:**

```yaml
# internal-ca.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: internal-ca-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: internal-ca
  namespace: cert-manager
spec:
  isCA: true
  commonName: internal-ca
  secretName: internal-ca-secret
  duration: 87600h    # 10 years
  renewBefore: 8760h  # 1 year before expiry
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: internal-ca-issuer
    kind: ClusterIssuer
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: internal-ca
spec:
  ca:
    secretName: internal-ca-secret
```

**Issue certificates for a service:**

```yaml
# api-service-cert.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-service-tls
  namespace: production
spec:
  secretName: api-service-tls
  duration: 720h      # 30 days
  renewBefore: 168h   # 7 days before expiry
  privateKey:
    algorithm: ECDSA
    size: 256
  usages:
    - server auth
    - client auth
  dnsNames:
    - api-service
    - api-service.production
    - api-service.production.svc.cluster.local
  issuerRef:
    name: internal-ca
    kind: ClusterIssuer
```

**Mount certificates into your application pod:**

```yaml
# api-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-service
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-service
  template:
    metadata:
      labels:
        app: api-service
    spec:
      containers:
        - name: api-service
          image: your-registry/api-service:latest
          ports:
            - containerPort: 8443
          env:
            - name: TLS_CERT_PATH
              value: /tls/tls.crt
            - name: TLS_KEY_PATH
              value: /tls/tls.key
            - name: TLS_CA_PATH
              value: /tls/ca.crt
          volumeMounts:
            - name: tls-certs
              mountPath: /tls
              readOnly: true
      volumes:
        - name: tls-certs
          secret:
            secretName: api-service-tls
```

Your application must be configured to use these certificates. Example for a Go service:

```go
// Configure mTLS in your Go application.
caCert, _ := os.ReadFile(os.Getenv("TLS_CA_PATH"))
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

cert, _ := tls.LoadX509KeyPair(
    os.Getenv("TLS_CERT_PATH"),
    os.Getenv("TLS_KEY_PATH"),
)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs:    caCertPool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
    MinVersion:   tls.VersionTLS13,
}

server := &http.Server{
    Addr:      ":8443",
    TLSConfig: tlsConfig,
}
```

### Performance Overhead Comparison

| Metric | Istio | Linkerd | DIY (cert-manager) |
|--------|-------|---------|---------------------|
| Memory per pod | +40-60 MB (Envoy sidecar) | +10-20 MB (Linkerd proxy) | 0 (application handles TLS) |
| CPU per pod | +5-15% | +2-5% | +1-3% (TLS handshake cost) |
| P99 latency added | +2-5ms | +1-2ms | +0.5-1ms |
| Control plane memory | 1-2 GB (istiod) | 200-500 MB | 50-100 MB (cert-manager) |
| Certificate rotation | Automatic (24h default) | Automatic (24h default) | Automatic (configurable) |

## Expected Behaviour

```bash
# Istio: Verify mTLS is enforced.
# From a pod WITHOUT a sidecar, try to reach a meshed service.
kubectl run test-pod --image=curlimages/curl --rm -it --restart=Never \
  -n default -- curl -v http://api-service.production:8080
# Expected (STRICT mode): Connection refused or reset.
# The service only accepts mTLS connections from sidecar proxies.

# Istio: Verify mTLS between meshed services.
kubectl exec -n production deploy/frontend -c frontend -- \
  curl -s -o /dev/null -w "%{http_code}" http://api-service:8080/health
# Expected: 200 (sidecar handles mTLS transparently)

# Istio: Check mTLS status for all services.
istioctl x describe service api-service -n production
# Expected output includes:
# "mTLS mode: STRICT"

# Linkerd: Verify mTLS with tap.
linkerd viz tap deploy/api-service -n production --to deploy/database
# Expected: tls=true on all connections.

# cert-manager: Verify certificate is issued and valid.
kubectl get certificate -n production api-service-tls
# Expected:
# NAME              READY   SECRET            AGE
# api-service-tls   True    api-service-tls   5m

# cert-manager: Check certificate expiry.
kubectl get secret api-service-tls -n production -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -noout -dates
# Expected: notAfter is 30 days from issuance.
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Istio strict mTLS | Full encryption and identity for all traffic | 40-60 MB memory per pod; 2-5ms latency added; complex debugging | Use Linkerd if resource overhead is too high; start with permissive mode |
| Linkerd automatic mTLS | Lightweight encryption with minimal configuration | Fewer features than Istio (no traffic management, limited authorization) | Sufficient if you only need mTLS and basic authorization |
| DIY cert-manager | No sidecar overhead; full control | Every application must handle TLS; certificate rotation requires app reload or file watching | Use libraries that watch certificate files; implement graceful reload |
| STRICT mode cluster-wide | No plaintext traffic possible | Non-meshed services (monitoring agents, legacy apps) cannot communicate | Use namespace-level policies; migrate incrementally |
| Short certificate lifetimes (24h) | Limits blast radius of compromised certificates | Clock skew between nodes causes handshake failures | Sync clocks with NTP; use 72h as minimum if clock skew is a concern |
| Authorization policies | Restricts lateral movement | Misconfigured policies block legitimate traffic; debugging identity strings is error-prone | Deploy in audit mode first; use `istioctl analyze` to validate policies |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Certificate expired (no rotation) | All connections between services fail with TLS handshake errors | Alerts on certificate expiry; sudden spike in 503 errors across multiple services | Verify cert-manager is running; check Certificate resource status; manually renew if needed |
| Clock skew between nodes | Intermittent TLS handshake failures; "certificate is not yet valid" errors | TLS errors appear on some node pairs but not others; NTP monitoring shows drift | Sync clocks with `chronyc` or NTP; consider increasing certificate `notBefore` backdate |
| Sidecar not injected | Service communicates in plaintext; STRICT mode causes connection refusal | Pod has no `istio-proxy` or `linkerd-proxy` container; `kubectl describe pod` shows no init container | Verify namespace label for injection; restart deployment to trigger injection |
| Control plane down (istiod/linkerd) | Existing connections continue working; new connections fail after certificate expiry | Control plane health checks fail; certificate rotation stops | Restore control plane; existing certificates remain valid until expiry |
| Authorization policy too restrictive | Legitimate service-to-service calls return 403 RBAC denied | Application errors; Istio access logs show "RBAC: access denied" | Check `istioctl analyze`; verify service account names in policy match actual deployment |
| Memory pressure from sidecars | Node OOM kills pods; frequent pod evictions | Node memory utilization consistently above 90%; OOM kill events in `dmesg` | Increase node capacity; set sidecar resource limits; consider Linkerd for lower overhead |

## When to Consider a Managed Alternative

**Transition point:** When operating a service mesh control plane across multiple clusters consumes more than 8-16 hours per month, when you need cross-cluster mTLS (multi-region, hybrid cloud), or when debugging mesh networking issues blocks application development.

**What managed providers handle:**

- **[Isovalent](https://isovalent.com):** Cilium-based service mesh that provides mTLS through eBPF without sidecar proxies. Eliminates the per-pod memory and latency overhead of sidecar-based meshes. Enterprise support includes multi-cluster mesh federation.

- **[Buoyant](https://buoyant.io):** The company behind Linkerd. Buoyant Cloud provides a managed control plane for Linkerd with automated upgrades, health monitoring, and multi-cluster support. Reduces operational burden while keeping the lightweight Linkerd data plane.

- **[Solo.io](https://www.solo.io):** Gloo Mesh provides a management plane for Istio across multiple clusters. Simplifies multi-cluster mTLS, certificate management, and policy distribution. Enterprise support for Istio without forking the upstream project.

- **[Sysdig](https://sysdig.com):** Runtime security monitoring that can verify mTLS enforcement, detect plaintext traffic between services, and alert on certificate issues. Complements any mesh implementation.

**What you still control:** Authorization policies (which services can communicate with which) are always your responsibility. The mesh provider handles the TLS infrastructure; you define the access control model. Service identity mapping to Kubernetes service accounts requires your application architecture knowledge.


## Related Articles

- [Protecting Internal APIs: Network Segmentation, Authentication, and Access Logging](/articles/network/internal-api-protection/)
- [Zero Trust Networking: Identity-Based Access Beyond Perimeter Security](/articles/cross-cutting/zero-trust-networking/)
- [gRPC Security in Production: TLS, Authentication, and Interceptor-Based Access Control](/articles/network/grpc-security/)
- [TLS 1.3 Configuration for NGINX and Envoy: Ciphers, Certificates, and OCSP Stapling](/articles/network/tls-nginx-envoy/)
- [IPv6 Security in Production: Hardening Dual-Stack Deployments](/articles/network/ipv6-security/)
