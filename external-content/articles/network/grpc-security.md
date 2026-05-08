---
title: "gRPC Security in Production: TLS, Authentication, and Interceptor-Based Access Control"
description: "gRPC services in production frequently run with security configurations that would never be acceptable for HTTP APIs:"
slug: "grpc-security"
date: 2026-01-08
lastmod: 2026-01-08
category: "network"
tags: ["grpc", "tls", "mtls", "authentication", "interceptors", "envoy", "security"]
personas: ["platform-engineer", "devops-engineer"]
article_number: 45
difficulty: "intermediate"
estimated_reading_time: 22
provider_bridges:
  - name: "Sysdig"
    id: 122
    category: "monitoring"
published: true
layout: article.njk
permalink: "/articles/network/grpc-security/index.html"
---

# gRPC Security in Production: TLS, Authentication, and Interceptor-Based Access Control

## Problem

gRPC services in production frequently run with security configurations that would never be acceptable for HTTP APIs:

- **No TLS because "it's internal."** Service-to-service gRPC calls traverse the pod network in plaintext. Any compromised pod can sniff every protobuf message, including tokens, user data, and internal state.
- **No per-method authorization.** The service exposes 30 RPC methods, and every authenticated caller can invoke all of them. The billing service can call the user deletion RPC because there is no method-level access control.
- **No request size limits.** The default `grpc.max_receive_message_length` in many frameworks is 4MB or unlimited. A malicious or buggy client can send a 2GB protobuf message that crashes the server.
- **No deadline enforcement.** Clients call RPCs without setting deadlines. A slow downstream causes cascading timeouts that consume all available connections and threads.
- **Unauthenticated health check endpoints.** The gRPC health checking protocol is exposed without any access control, leaking service availability information to anyone who can reach the port.

These gaps exist because gRPC services are often developed and deployed behind network boundaries that teams assume are sufficient. They are not.

**Target systems:** gRPC services in Go, Java, Python, or Node.js, running in [Kubernetes](https://kubernetes.io) or on VMs, with or without a service mesh.

## Threat Model

- **Adversary:** Compromised pod or container in the same network segment. Internal attacker with access to the Kubernetes cluster. External attacker who gains access through a different vulnerability.
- **Access level:** Network-level access to the gRPC port. May have valid credentials for one service but not the target.
- **Objective:** Eavesdrop on plaintext gRPC traffic to extract credentials and data. Invoke privileged RPCs by calling methods the attacker's service should not access. Denial of service through oversized messages or deadline-less requests. Enumerate internal services through health check endpoints.
- **Blast radius:** All services in the same network segment for eavesdropping. The specific target service for unauthorized RPC invocation. Cascading failure across dependent services for deadline abuse.

## Configuration

### TLS for gRPC: Server and Client

Server-side TLS in Go:

```go
// server.go - gRPC server with TLS
package main

import (
    "crypto/tls"
    "crypto/x509"
    "log"
    "net"
    "os"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/health"
    healthpb "google.golang.org/grpc/health/grpc_health_v1"
    "google.golang.org/grpc/keepalive"
    "time"
)

func main() {
    // Load server certificate and key
    cert, err := tls.LoadX509KeyPair(
        "/etc/certs/server.crt",
        "/etc/certs/server.key",
    )
    if err != nil {
        log.Fatalf("failed to load server cert: %v", err)
    }

    // Load CA certificate for client verification (mTLS)
    caCert, err := os.ReadFile("/etc/certs/ca.crt")
    if err != nil {
        log.Fatalf("failed to read CA cert: %v", err)
    }
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caCert)

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientAuth:   tls.RequireAndVerifyClientCert,
        ClientCAs:    caPool,
        MinVersion:   tls.VersionTLS13,
    }

    // Server options with security controls
    opts := []grpc.ServerOption{
        grpc.Creds(credentials.NewTLS(tlsConfig)),

        // Maximum message sizes
        grpc.MaxRecvMsgSize(4 * 1024 * 1024),  // 4 MB inbound
        grpc.MaxSendMsgSize(4 * 1024 * 1024),  // 4 MB outbound

        // Keepalive enforcement: disconnect idle clients
        grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
            MinTime:             30 * time.Second,
            PermitWithoutStream: false,
        }),
        grpc.KeepaliveParams(keepalive.ServerParameters{
            MaxConnectionIdle:     5 * time.Minute,
            MaxConnectionAge:      30 * time.Minute,
            MaxConnectionAgeGrace: 10 * time.Second,
            Time:                  1 * time.Minute,
            Timeout:               20 * time.Second,
        }),

        // Connection limits
        grpc.MaxConcurrentStreams(100),
    }

    server := grpc.NewServer(opts...)

    // Register your services
    // pb.RegisterMyServiceServer(server, &myServiceImpl{})

    // Register health service
    healthServer := health.NewServer()
    healthpb.RegisterHealthServer(server, healthServer)
    healthServer.SetServingStatus("myservice", healthpb.HealthCheckResponse_SERVING)

    lis, err := net.Listen("tcp", ":8443")
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }

    log.Println("gRPC server listening on :8443 with mTLS")
    if err := server.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
```

Client-side mTLS in Go:

```go
// client.go - gRPC client with mTLS
package main

import (
    "crypto/tls"
    "crypto/x509"
    "log"
    "os"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func newGRPCConnection(target string) (*grpc.ClientConn, error) {
    // Load client certificate for mTLS
    cert, err := tls.LoadX509KeyPair(
        "/etc/certs/client.crt",
        "/etc/certs/client.key",
    )
    if err != nil {
        return nil, err
    }

    // Load CA to verify server certificate
    caCert, err := os.ReadFile("/etc/certs/ca.crt")
    if err != nil {
        return nil, err
    }
    caPool := x509.NewCertPool()
    caPool.AppendCertsFromPEM(caCert)

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caPool,
        MinVersion:   tls.VersionTLS13,
        ServerName:   "myservice.internal",
    }

    conn, err := grpc.Dial(
        target,
        grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
        // Always set a default timeout for RPCs
        grpc.WithDefaultCallOptions(
            grpc.MaxCallRecvMsgSize(4*1024*1024),
            grpc.MaxCallSendMsgSize(4*1024*1024),
        ),
    )
    if err != nil {
        return nil, err
    }
    return conn, nil
}
```

### Token-Based Authentication with Interceptors

For environments where mTLS is not practical (multi-language teams, third-party callers), use token-based authentication with a unary interceptor:

```go
// auth_interceptor.go - Server-side authentication interceptor
package auth

import (
    "context"
    "strings"

    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/metadata"
    "google.golang.org/grpc/status"
)

// Methods that do not require authentication
var publicMethods = map[string]bool{
    "/grpc.health.v1.Health/Check": true,
    "/grpc.health.v1.Health/Watch": true,
}

// Per-method authorization: which service identities can call which methods
var methodACL = map[string][]string{
    "/mypackage.MyService/GetUser":    {"api-gateway", "admin-service"},
    "/mypackage.MyService/DeleteUser": {"admin-service"},
    "/mypackage.MyService/ListUsers":  {"api-gateway", "admin-service", "reporting-service"},
    "/mypackage.MyService/UpdateUser": {"api-gateway", "admin-service"},
}

func UnaryAuthInterceptor(tokenValidator TokenValidator) grpc.UnaryServerInterceptor {
    return func(
        ctx context.Context,
        req interface{},
        info *grpc.UnaryServerInfo,
        handler grpc.UnaryHandler,
    ) (interface{}, error) {
        // Skip auth for public methods
        if publicMethods[info.FullMethod] {
            return handler(ctx, req)
        }

        // Extract token from metadata
        md, ok := metadata.FromIncomingContext(ctx)
        if !ok {
            return nil, status.Error(codes.Unauthenticated, "missing metadata")
        }

        authHeader := md.Get("authorization")
        if len(authHeader) == 0 {
            return nil, status.Error(codes.Unauthenticated, "missing authorization header")
        }

        token := strings.TrimPrefix(authHeader[0], "Bearer ")

        // Validate token and extract caller identity
        callerIdentity, err := tokenValidator.Validate(ctx, token)
        if err != nil {
            return nil, status.Error(codes.Unauthenticated, "invalid token")
        }

        // Per-method authorization check
        allowedCallers, exists := methodACL[info.FullMethod]
        if !exists {
            // Method not in ACL: deny by default
            return nil, status.Error(codes.PermissionDenied, "method not authorized")
        }

        authorized := false
        for _, allowed := range allowedCallers {
            if callerIdentity.ServiceName == allowed {
                authorized = true
                break
            }
        }
        if !authorized {
            return nil, status.Errorf(
                codes.PermissionDenied,
                "service %s not authorized for %s",
                callerIdentity.ServiceName,
                info.FullMethod,
            )
        }

        // Add caller identity to context for downstream use
        ctx = context.WithValue(ctx, callerKey, callerIdentity)
        return handler(ctx, req)
    }
}

// Streaming interceptor for streaming RPCs
func StreamAuthInterceptor(tokenValidator TokenValidator) grpc.StreamServerInterceptor {
    return func(
        srv interface{},
        ss grpc.ServerStream,
        info *grpc.StreamServerInfo,
        handler grpc.StreamHandler,
    ) error {
        if publicMethods[info.FullMethod] {
            return handler(srv, ss)
        }

        md, ok := metadata.FromIncomingContext(ss.Context())
        if !ok {
            return status.Error(codes.Unauthenticated, "missing metadata")
        }

        authHeader := md.Get("authorization")
        if len(authHeader) == 0 {
            return status.Error(codes.Unauthenticated, "missing authorization header")
        }

        token := strings.TrimPrefix(authHeader[0], "Bearer ")
        _, err := tokenValidator.Validate(ss.Context(), token)
        if err != nil {
            return status.Error(codes.Unauthenticated, "invalid token")
        }

        return handler(srv, ss)
    }
}
```

Register interceptors on the server:

```go
server := grpc.NewServer(
    grpc.Creds(credentials.NewTLS(tlsConfig)),
    grpc.ChainUnaryInterceptor(
        UnaryAuthInterceptor(tokenValidator),
        UnaryLoggingInterceptor(),
    ),
    grpc.ChainStreamInterceptor(
        StreamAuthInterceptor(tokenValidator),
        StreamLoggingInterceptor(),
    ),
    grpc.MaxRecvMsgSize(4 * 1024 * 1024),
    grpc.MaxConcurrentStreams(100),
)
```

### Deadline Enforcement

Every gRPC call must have a deadline. Without one, a slow backend causes the caller to wait indefinitely, consuming a connection and a goroutine. Enforce deadlines on both client and server:

```go
// Client-side: always set a deadline
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

resp, err := client.GetUser(ctx, &pb.GetUserRequest{UserId: "123"})
if err != nil {
    // Handle context.DeadlineExceeded specifically
    if status.Code(err) == codes.DeadlineExceeded {
        log.Println("GetUser timed out after 5 seconds")
    }
}
```

```go
// Server-side interceptor: enforce a maximum deadline
func DeadlineInterceptor(maxDeadline time.Duration) grpc.UnaryServerInterceptor {
    return func(
        ctx context.Context,
        req interface{},
        info *grpc.UnaryServerInfo,
        handler grpc.UnaryHandler,
    ) (interface{}, error) {
        // If client did not set a deadline, impose one
        if _, hasDeadline := ctx.Deadline(); !hasDeadline {
            var cancel context.CancelFunc
            ctx, cancel = context.WithTimeout(ctx, maxDeadline)
            defer cancel()
        }
        return handler(ctx, req)
    }
}
```

### [Envoy](https://www.envoyproxy.io) gRPC Proxy Hardening

When Envoy fronts your gRPC services, apply these security controls:

```yaml
# Envoy configuration for gRPC proxy
static_resources:
  listeners:
    - name: grpc_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8443
      filter_chains:
        - transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
              require_client_certificate: true
              common_tls_context:
                tls_params:
                  tls_minimum_protocol_version: TLSv1_3
                tls_certificates:
                  - certificate_chain:
                      filename: /etc/envoy/certs/server.crt
                    private_key:
                      filename: /etc/envoy/certs/server.key
                validation_context:
                  trusted_ca:
                    filename: /etc/envoy/certs/ca.crt
          filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: grpc_ingress
                codec_type: HTTP2

                # gRPC-specific timeout
                stream_idle_timeout: 300s

                http2_protocol_options:
                  max_concurrent_streams: 100
                  initial_stream_window_size: 1048576
                  initial_connection_window_size: 1048576

                route_config:
                  name: grpc_route
                  virtual_hosts:
                    - name: grpc_services
                      domains: ["*"]
                      routes:
                        # Per-method routing with timeouts
                        - match:
                            prefix: "/mypackage.MyService/GetUser"
                            grpc: {}
                          route:
                            cluster: myservice
                            timeout: 5s
                            max_stream_duration:
                              max_stream_duration: 5s
                        - match:
                            prefix: "/mypackage.MyService/StreamUpdates"
                            grpc: {}
                          route:
                            cluster: myservice
                            timeout: 0s
                            max_stream_duration:
                              max_stream_duration: 3600s
                        # Default: deny unmatched methods
                        - match:
                            prefix: "/"
                            grpc: {}
                          direct_response:
                            status: 403
                            body:
                              inline_string: "Method not allowed"

                http_filters:
                  # Rate limiting per method
                  - name: envoy.filters.http.local_ratelimit
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
                      stat_prefix: grpc_rate_limit
                      token_bucket:
                        max_tokens: 100
                        tokens_per_fill: 50
                        fill_interval: 1s
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

  clusters:
    - name: myservice
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
        cluster_name: myservice
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: 10.0.1.10
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

### Health Check Endpoint Security

Restrict health check access to internal monitoring systems only:

```go
// Option 1: Serve health checks on a separate port
// Health check listener on internal-only port
healthLis, _ := net.Listen("tcp", "127.0.0.1:8444")
healthServer := grpc.NewServer() // No TLS, localhost only
healthpb.RegisterHealthServer(healthServer, healthSvc)
go healthServer.Serve(healthLis)

// Main service on external port with full security
mainLis, _ := net.Listen("tcp", ":8443")
mainServer := grpc.NewServer(opts...)
pb.RegisterMyServiceServer(mainServer, &impl{})
mainServer.Serve(mainLis)
```

```yaml
# Kubernetes: health check on a separate port
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: myservice
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
      readinessProbe:
        grpc:
          port: 8444
        initialDelaySeconds: 5
        periodSeconds: 5
```

## Expected Behaviour

After applying the gRPC security configuration:

```bash
# Verify TLS is required (plaintext connection should fail)
grpcurl -plaintext localhost:8443 list
# Expected: "Failed to dial target" or "connection refused"

# Verify mTLS works with valid client cert
grpcurl \
  -cacert /etc/certs/ca.crt \
  -cert /etc/certs/client.crt \
  -key /etc/certs/client.key \
  localhost:8443 grpc.health.v1.Health/Check
# Expected: {"status":"SERVING"}

# Verify unauthorized method is rejected
grpcurl \
  -cacert /etc/certs/ca.crt \
  -cert /etc/certs/client.crt \
  -key /etc/certs/client.key \
  -H "authorization: Bearer <reporting-service-token>" \
  -d '{"user_id": "123"}' \
  localhost:8443 mypackage.MyService/DeleteUser
# Expected: "PermissionDenied: service reporting-service not authorized for /mypackage.MyService/DeleteUser"

# Verify message size limit
# Generate a 5MB payload (exceeds 4MB limit)
grpcurl \
  -cacert /etc/certs/ca.crt \
  -cert /etc/certs/client.crt \
  -key /etc/certs/client.key \
  -d "$(python3 -c 'print("{\"data\":\"" + "A"*5000000 + "\"}")')" \
  localhost:8443 mypackage.MyService/ProcessData
# Expected: "ResourceExhausted: grpc: received message larger than max"
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| mTLS for all gRPC services | Certificate management overhead; every service needs a cert | Certificate rotation failures cause outages | Use [cert-manager](https://cert-manager.io) with short-lived certificates (24h); automate rotation |
| Per-method ACL in interceptors | Requires updating the ACL map when adding new RPCs | New RPCs are inaccessible until ACL is updated (default deny) | Store ACL in a ConfigMap or external config; fail-open for development environments only |
| `MaxRecvMsgSize(4MB)` | Limits maximum protobuf message size | Legitimate large payloads (file transfer, batch operations) are rejected | Use streaming RPCs for large data; increase limit per-method where necessary |
| Deadline enforcement (5s default) | Slow operations time out | Complex queries or batch operations exceed the default deadline | Set per-RPC deadlines appropriate to each method's expected latency |
| `MaxConcurrentStreams(100)` | Limits parallel RPCs per connection | High-throughput clients may exhaust stream capacity | Clients should use connection pooling; increase limit for known high-throughput callers |
| Health check on separate port | Requires managing an additional port | Port misconfiguration exposes health on the main port | Validate with a network scan after deployment; use Kubernetes NetworkPolicy to restrict health port access |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Certificate expired | All gRPC connections fail with TLS handshake error | Certificate monitoring alerts; connection error rate spikes to 100% | Renew certificate; consider cert-manager with automatic renewal |
| ACL missing new service identity | New service cannot call any RPCs; receives PermissionDenied | Service deployment fails health checks; logs show PermissionDenied for the new service | Add the service identity to the methodACL map and redeploy |
| MaxRecvMsgSize too small | Legitimate large requests fail with ResourceExhausted | Application logs show ResourceExhausted for specific RPCs; client error reports | Increase limit per-method using `grpc.MaxRecvMsgSize` in the handler registration |
| No deadline set by client | Server goroutines accumulate; memory grows; eventually OOM | Goroutine count in metrics increases steadily; memory usage climbs without releasing | Deploy the DeadlineInterceptor to enforce server-side maximums; fix clients to set deadlines |
| Keepalive too aggressive | Clients on high-latency networks get disconnected | Connection resets from clients in remote regions; increased reconnection rate | Increase `MinTime` in KeepaliveEnforcementPolicy; adjust based on client network conditions |

## When to Consider a Managed Alternative

**Transition point:** When managing certificates, interceptors, and per-method ACLs across 20+ gRPC services becomes a full-time maintenance task, or when you need consistent security policy enforcement that cannot rely on every service team correctly implementing interceptors.

**What managed alternatives handle:**

- **Service mesh ([Istio](https://istio.io), [Linkerd](https://linkerd.io)):** Automatic mTLS between all services without application code changes. Sidecar proxies handle TLS termination, certificate rotation, and mutual authentication. Istio AuthorizationPolicy provides per-method access control declaratively, without modifying application interceptors.

- **[Sysdig](https://sysdig.com):** Runtime monitoring for gRPC traffic patterns, detecting anomalous RPC calls, unexpected callers, and unusual message sizes. Provides visibility into service-to-service communication that application-level logging may miss.

**What you still control:** Business logic authorization (which user can delete which resource), request validation (is this protobuf message semantically valid), and application-level rate limiting based on business rules remain in your application code regardless of mesh or monitoring provider.
