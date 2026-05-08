---
title: "gRPC Load Balancing Security: Client-Side, Proxy, and Service Mesh Patterns"
description: "L4 load balancers break gRPC multiplexing, sending all streams to a single backend. This article covers L7 balancing with Envoy, client-side balancing with xDS, health check hardening, and connection draining for secure gRPC deployments."
slug: "grpc-load-balancing-security"
date: 2026-03-05
lastmod: 2026-03-05
category: "network"
tags: ["grpc", "load-balancing", "envoy", "kubernetes", "xds", "service-mesh"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 147
difficulty: "intermediate"
estimated_reading_time: 18
published: true
layout: article.njk
permalink: "/articles/network/grpc-load-balancing-security/index.html"
---

# gRPC Load Balancing Security: Client-Side, Proxy, and Service Mesh Patterns

## Problem

gRPC uses HTTP/2, which multiplexes many requests over a single TCP connection. This creates a fundamental conflict with traditional load balancing:

- **L4 load balancers route by connection, not by request.** A TCP load balancer assigns a connection to one backend. Because gRPC multiplexes hundreds of RPCs over that single connection, all traffic from one client hits one server. The other backends sit idle while one overloads and eventually crashes.
- **Kubernetes `ClusterIP` services default to L4.** Teams deploy gRPC services behind a standard Kubernetes Service and assume traffic distributes evenly. kube-proxy uses iptables or IPVS to pick a backend per connection. A long-lived gRPC connection pins all RPCs to the same pod for hours or days.
- **Health check endpoints leak service topology.** The gRPC health checking protocol responds to any caller on the serving port. An attacker who gains network access can enumerate every gRPC service, its health status, and infer the number of backends by probing different IPs.
- **No connection draining during deployments.** Rolling updates terminate pods without draining in-flight RPCs. Clients receive RST frames mid-stream, causing data loss and retry storms that amplify the disruption.
- **xDS service discovery runs unauthenticated.** Client-side load balancing with xDS fetches endpoint lists from a control plane. If the xDS stream is unauthenticated, a compromised pod can inject malicious endpoints that redirect traffic.

These problems compound: L4 balancing causes hotspots, hotspots cause failures, and unprotected health checks let attackers map exactly which pods are overloaded.

**Target systems:** gRPC services in [Kubernetes](https://kubernetes.io) using [Envoy](https://www.envoyproxy.io), Istio, or client-side balancing with xDS. Applicable to Go, Java, and Python gRPC stacks.

## Threat Model

- **Adversary:** Compromised pod in the cluster network. Internal attacker with kubectl access to a non-production namespace. External attacker who has breached the perimeter and reached the pod network.
- **Access level:** Network-level access to gRPC ports and potentially to the xDS control plane. May have credentials for one service but not others.
- **Objective:** Overload a single backend pod through connection pinning to cause denial of service. Inject malicious endpoints through an unsecured xDS control plane to redirect traffic. Enumerate service topology and health status through exposed health check endpoints. Intercept traffic by inserting a rogue backend into the endpoint list.
- **Blast radius:** A single pinned connection can take down one backend pod. A poisoned xDS endpoint list can redirect all client traffic to an attacker-controlled server. Health check enumeration reveals the internal service graph.

## Configuration

### Why L4 Breaks gRPC and How to Fix It

Standard Kubernetes Services use L4 (TCP) balancing. For gRPC, you need L7 (HTTP/2) balancing that routes individual requests, not connections. There are three approaches: proxy-based (Envoy or a service mesh sidecar), headless services with client-side balancing, or a dedicated gRPC load balancer.

### Envoy L7 gRPC Load Balancing with Per-Method Routing

```yaml
# envoy-grpc-lb.yaml - L7 load balancing for gRPC with per-method controls
static_resources:
  listeners:
    - name: grpc_lb_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8443
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              common_tls_context:
                tls_params:
                  tls_minimum_protocol_version: TLSv1_3
                tls_certificates:
                  - certificate_chain:
                      filename: /etc/envoy/certs/server.crt
                    private_key:
                      filename: /etc/envoy/certs/server.key
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: grpc_lb
                codec_type: HTTP2
                http2_protocol_options:
                  max_concurrent_streams: 100
                  initial_stream_window_size: 1048576
                route_config:
                  name: grpc_routes
                  virtual_hosts:
                    - name: grpc_backends
                      domains: ["*"]
                      routes:
                        # Unary RPCs: short timeout, ROUND_ROBIN
                        - match:
                            prefix: "/payments.PaymentService/ChargeCard"
                            grpc: {}
                          route:
                            cluster: payments_unary
                            timeout: 5s
                            retry_policy:
                              retry_on: "unavailable,resource-exhausted"
                              num_retries: 2
                              per_try_timeout: 3s

                        # Streaming RPCs: long timeout, LEAST_REQUEST
                        - match:
                            prefix: "/payments.PaymentService/StreamTransactions"
                            grpc: {}
                          route:
                            cluster: payments_streaming
                            timeout: 0s
                            max_stream_duration:
                              max_stream_duration: 3600s

                        # Deny unmatched methods
                        - match:
                            prefix: "/"
                            grpc: {}
                          direct_response:
                            status: 403
                            body:
                              inline_string: "Method not allowed"

                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    # Cluster for unary RPCs - ROUND_ROBIN distributes individual requests
    - name: payments_unary
      connect_timeout: 5s
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options:
              max_concurrent_streams: 100
      load_assignment:
        cluster_name: payments_unary
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: payments-headless.production.svc.cluster.local
                      port_value: 8443
      health_checks:
        - timeout: 2s
          interval: 10s
          unhealthy_threshold: 3
          healthy_threshold: 2
          grpc_health_check:
            service_name: "payments.PaymentService"
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          common_tls_context:
            tls_params:
              tls_minimum_protocol_version: TLSv1_3
            tls_certificates:
              - certificate_chain:
                  filename: /etc/envoy/certs/client.crt
                private_key:
                  filename: /etc/envoy/certs/client.key
            validation_context:
              trusted_ca:
                filename: /etc/envoy/certs/ca.crt

    # Cluster for streaming RPCs - LEAST_REQUEST avoids overloading
    - name: payments_streaming
      connect_timeout: 5s
      type: STRICT_DNS
      lb_policy: LEAST_REQUEST
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options:
              max_concurrent_streams: 50
      load_assignment:
        cluster_name: payments_streaming
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: payments-headless.production.svc.cluster.local
                      port_value: 8443
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          common_tls_context:
            tls_params:
              tls_minimum_protocol_version: TLSv1_3
            tls_certificates:
              - certificate_chain:
                  filename: /etc/envoy/certs/client.crt
                private_key:
                  filename: /etc/envoy/certs/client.key
            validation_context:
              trusted_ca:
                filename: /etc/envoy/certs/ca.crt
```

### Kubernetes Headless Service for gRPC

A headless Service returns individual pod IPs, enabling either client-side balancing or Envoy STRICT_DNS resolution:

```yaml
# kubernetes-grpc-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: payments-headless
  namespace: production
  annotations:
    # Signal to service mesh that this is gRPC
    service.kubernetes.io/app-protocol: "grpc"
spec:
  clusterIP: None  # Headless - returns pod IPs directly
  selector:
    app: payments
  ports:
    - name: grpc
      port: 8443
      targetPort: 8443
      protocol: TCP
    - name: health
      port: 8444
      targetPort: 8444
      protocol: TCP
---
# NetworkPolicy: restrict who can reach the health check port
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-health-check-restrict
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: payments
  policyTypes:
    - Ingress
  ingress:
    # Allow gRPC traffic from Envoy proxy
    - from:
        - podSelector:
            matchLabels:
              app: envoy-proxy
      ports:
        - port: 8443
          protocol: TCP
    # Allow health checks only from kubelet and monitoring
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 8444
          protocol: TCP
    - from:
        - podSelector:
            matchLabels:
              app: prometheus
      ports:
        - port: 8444
          protocol: TCP
```

### Client-Side Load Balancing with Authenticated xDS

For services that use gRPC client-side balancing, the xDS control plane must be authenticated:

```go
// client-xds-auth.go - Client-side balancing with authenticated xDS
package main

import (
    "crypto/tls"
    "crypto/x509"
    "log"
    "os"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    xdscreds "google.golang.org/grpc/credentials/xds"
    _ "google.golang.org/grpc/xds" // Register xDS resolver and balancer
)

func main() {
    // xDS credentials use the certificate from the xDS bootstrap config
    creds, err := xdscreds.NewClientCredentials(
        xdscreds.ClientOptions{
            FallbackCreds: loadMTLSCreds(),
        },
    )
    if err != nil {
        log.Fatalf("failed to create xDS credentials: %v", err)
    }

    // Connect using xDS resolver - discovers endpoints from control plane
    conn, err := grpc.Dial(
        "xds:///payments.production.svc.cluster.local:8443",
        grpc.WithTransportCredentials(creds),
        grpc.WithDefaultServiceConfig(`{
            "loadBalancingConfig": [{"round_robin": {}}],
            "healthCheckConfig": {"serviceName": "payments.PaymentService"}
        }`),
    )
    if err != nil {
        log.Fatalf("failed to connect: %v", err)
    }
    defer conn.Close()
}

func loadMTLSCreds() credentials.TransportCredentials {
    cert, err := tls.LoadX509KeyPair(
        "/etc/certs/client.crt",
        "/etc/certs/client.key",
    )
    if err != nil {
        log.Fatalf("failed to load client cert: %v", err)
    }

    caCert, err := os.ReadFile("/etc/certs/ca.crt")
    if err != nil {
        log.Fatalf("failed to read CA cert: %v", err)
    }
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caCert)

    return credentials.NewTLS(&tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caPool,
        MinVersion:   tls.VersionTLS13,
    })
}
```

The xDS bootstrap file must also use mTLS to authenticate the control plane:

```json
{
  "xds_servers": [
    {
      "server_uri": "xds-control-plane.infrastructure.svc.cluster.local:18000",
      "channel_creds": [
        {
          "type": "tls",
          "config": {
            "ca_certificate_file": "/etc/certs/ca.crt",
            "certificate_file": "/etc/certs/client.crt",
            "private_key_file": "/etc/certs/client.key"
          }
        }
      ],
      "server_features": ["xds_v3"]
    }
  ],
  "node": {
    "id": "payments-client-001",
    "cluster": "production"
  }
}
```

### Health Check Endpoint Hardening

Separate health check endpoints from the serving port so that health probes never traverse the same authentication path as production traffic:

```go
// health-server.go - Separate health check server
package main

import (
    "context"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/health"
    healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func startHealthServer(healthSvc *health.Server) *grpc.Server {
    // Bind to localhost only - kubelet accesses via pod IP,
    // but NetworkPolicy restricts who can reach port 8444
    lis, err := net.Listen("tcp", ":8444")
    if err != nil {
        log.Fatalf("failed to listen on health port: %v", err)
    }

    healthServer := grpc.NewServer(
        // No TLS on health port - internal only
        grpc.MaxRecvMsgSize(1024), // Health checks are tiny
        grpc.MaxConcurrentStreams(10),
    )
    healthpb.RegisterHealthServer(healthServer, healthSvc)
    go healthServer.Serve(lis)
    return healthServer
}

func runWithGracefulShutdown(mainServer *grpc.Server, healthSvc *health.Server) {
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

    <-sigCh
    log.Println("received shutdown signal")

    // Step 1: Mark unhealthy so load balancer stops sending new requests
    healthSvc.SetServingStatus(
        "payments.PaymentService",
        healthpb.HealthCheckResponse_NOT_SERVING,
    )

    // Step 2: Wait for load balancer to detect the health change
    // and remove this backend from rotation
    log.Println("waiting for load balancer drain period...")
    time.Sleep(15 * time.Second)

    // Step 3: Gracefully stop - finishes in-flight RPCs
    log.Println("draining in-flight RPCs...")
    stopped := make(chan struct{})
    go func() {
        mainServer.GracefulStop()
        close(stopped)
    }()

    // Step 4: Hard deadline - do not wait forever
    select {
    case <-stopped:
        log.Println("graceful shutdown complete")
    case <-time.After(30 * time.Second):
        log.Println("forcing shutdown after 30s timeout")
        mainServer.Stop()
    }
}
```

### Kubernetes Deployment with gRPC Draining

```yaml
# deployment-grpc-draining.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments
  namespace: production
spec:
  replicas: 3
  strategy:
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: payments
  template:
    metadata:
      labels:
        app: payments
    spec:
      terminationGracePeriodSeconds: 60  # Must exceed drain delay + RPC timeout
      containers:
        - name: payments
          image: registry.internal.company.com/payments:1.4.2
          ports:
            - containerPort: 8443
              name: grpc
            - containerPort: 8444
              name: health
          livenessProbe:
            grpc:
              port: 8444
            initialDelaySeconds: 10
            periodSeconds: 10
            failureThreshold: 3
          readinessProbe:
            grpc:
              port: 8444
            initialDelaySeconds: 5
            periodSeconds: 5
            failureThreshold: 2
          lifecycle:
            preStop:
              exec:
                # Signal the app to start draining before SIGTERM
                command: ["/bin/sh", "-c", "sleep 5"]
          resources:
            limits:
              cpu: "1"
              memory: "512Mi"
            requests:
              cpu: "250m"
              memory: "256Mi"
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```

## Expected Behaviour

After applying the load balancing configuration:

```bash
# Verify L7 distribution - send 100 unary RPCs and check backend spread
for i in $(seq 1 100); do
  grpcurl \
    -cacert /etc/certs/ca.crt \
    -cert /etc/certs/client.crt \
    -key /etc/certs/client.key \
    envoy-proxy:8443 payments.PaymentService/GetBalance
done
# Expected: Envoy access logs show requests distributed across all 3 pods
# Not expected: All 100 requests hitting a single pod

# Verify health check is not accessible from arbitrary pods
kubectl exec -n default test-pod -- \
  grpcurl -plaintext payments-headless.production.svc.cluster.local:8444 \
  grpc.health.v1.Health/Check
# Expected: Connection refused (NetworkPolicy blocks it)

# Verify graceful shutdown during rolling update
kubectl rollout restart deployment/payments -n production
# During rollout, monitor for errors:
grpcurl -cacert /etc/certs/ca.crt \
  -cert /etc/certs/client.crt \
  -key /etc/certs/client.key \
  envoy-proxy:8443 payments.PaymentService/GetBalance
# Expected: Zero errors during rollout. Requests shift to remaining pods.
# Not expected: RST_STREAM or "transport is closing" errors

# Verify xDS control plane requires authentication
grpcurl -plaintext xds-control-plane.infrastructure:18000 \
  envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources
# Expected: TLS handshake failure (plaintext rejected)
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| L7 proxy (Envoy) for all gRPC | Adds latency (1-3ms per hop) and an infrastructure component to manage | Envoy misconfiguration can black-hole all gRPC traffic | Use Envoy admin interface health checks; canary configuration changes |
| Headless Service + client-side balancing | No proxy latency; clients connect directly to pods | Clients must handle endpoint discovery, health checking, and failover | Use gRPC built-in health checking and xDS; fall back to proxy for simple clients |
| Separate health check port | Requires managing two ports per service | Port misconfiguration can expose health on the serving port or vice versa | Validate with port scan after deployment; use NetworkPolicy to enforce access |
| 15-second drain delay | Adds 15 seconds to every pod shutdown during deployments | Slow deployments; terminationGracePeriodSeconds must accommodate the delay | Tune drain delay based on health check interval; reduce for non-critical services |
| mTLS on xDS channel | Certificate management for the control plane connection | Control plane certificate expiry breaks all service discovery | Use cert-manager with automatic rotation; monitor certificate expiry |
| LEAST_REQUEST for streams | Better distribution for long-lived streams | Requires active request counting; less predictable than ROUND_ROBIN | Monitor per-pod stream counts; fall back to ROUND_ROBIN if distribution is uneven |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| L4 balancer used instead of L7 | One pod receives all traffic; others show zero RPC rate | Per-pod RPC rate metrics diverge significantly; one pod at high CPU while others idle | Switch to headless Service with Envoy or client-side balancing |
| xDS control plane unreachable | Clients use stale endpoint list; new pods are not discovered | xDS stream disconnection metrics; new pods pass health checks but receive no traffic | Ensure xDS control plane is highly available (3+ replicas); clients cache last known good endpoints |
| Health check port exposed externally | Attackers enumerate services and their health status | NetworkPolicy audit shows health port reachable from unexpected sources | Apply NetworkPolicy restricting port 8444 to kube-system and monitoring namespaces |
| terminationGracePeriodSeconds too short | Kubernetes sends SIGKILL before drain completes; in-flight RPCs aborted | Pod logs show "forcing shutdown" message; client-side RST_STREAM errors during rollouts | Increase terminationGracePeriodSeconds to drain delay + max RPC timeout + buffer |
| Envoy max_concurrent_streams exhausted | New RPCs fail with REFUSED_STREAM; clients see "too many streams" | Envoy stats show cx_tx_frames_total increasing while active streams hit limit | Increase max_concurrent_streams or add more Envoy instances; clients should use connection pooling |

## When to Consider a Managed Alternative

**Transition point:** When you are operating Envoy sidecars or a standalone proxy fleet for more than 15 gRPC services and the configuration, certificate management, and debugging overhead exceeds what one platform engineer can maintain.

**What managed alternatives handle:**

- **Service mesh ([Istio](https://istio.io), [Linkerd](https://linkerd.io)):** Automatic L7 load balancing for gRPC through sidecar proxies. Istio DestinationRule configures per-service load balancing policy (ROUND_ROBIN, LEAST_REQUEST, RANDOM) declaratively. Connection draining and health checking are handled by the mesh control plane without application code changes.

- **Cloud load balancers with gRPC support (GCP Internal Load Balancer, AWS ALB):** Managed L7 balancing that understands HTTP/2 framing. Eliminates the need to run your own Envoy fleet. GCP proxyless gRPC with Traffic Director provides xDS-based client-side balancing as a managed service.

**What you still control:** Application-level graceful shutdown logic, health check semantics (what "healthy" means for your service), and per-method routing decisions based on business logic remain your responsibility regardless of the load balancing infrastructure.

## Related Articles

- [gRPC Security in Production: TLS, Authentication, and Interceptor-Based Access Control](/articles/network/grpc-security/)
- [Load Balancer Security: TLS Termination, Header Injection, and Access Control](/articles/network/load-balancer-security/)
- [mTLS in Service Mesh Architectures: Certificate Management, Identity, and Policy Enforcement](/articles/network/mtls-service-mesh/)
- [Rate Limiting at the Ingress Layer: Token Buckets, Sliding Windows, and Distributed Counters](/articles/network/rate-limiting-ingress/)
- [WebSocket Hardening: Origin Validation, Frame Size Limits, and Connection Lifecycle](/articles/network/websocket-hardening/)
