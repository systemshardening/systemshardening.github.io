---
title: "gRPC-Go HTTP/2 Path Authorization Bypass: CVE-2026-33186"
description: "CVE-2026-33186 (CVSS 9.1) allows attackers to bypass path-based gRPC authorization by omitting the leading slash from the :path pseudo-header. Upgrade to gRPC-Go 1.79.3 and audit authorization interceptors for deny-list patterns."
slug: grpc-go-path-auth-bypass
date: 2026-05-04
lastmod: 2026-05-04
category: kubernetes
tags:
  - grpc
  - authorization-bypass
  - cve
  - microservices
  - http2
personas:
  - platform-engineer
  - security-engineer
article_number: 440
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/kubernetes/grpc-go-path-auth-bypass/
---

# gRPC-Go HTTP/2 Path Authorization Bypass: CVE-2026-33186

## The Problem

CVE-2026-33186 (CVSS 9.1, disclosed March 19 2026) allows any client with a valid gRPC authentication credential to invoke gRPC methods they are explicitly denied access to, by omitting the mandatory leading slash from the HTTP/2 `:path` pseudo-header. The fix ships in gRPC-Go 1.79.3.

RFC 7540 §8.1.2.3 is unambiguous: the `:path` pseudo-header for HTTP/2 requests MUST begin with `/`. A conforming gRPC method path looks like `/admin.AdminService/DeleteUser`. gRPC-Go 1.79.2 and earlier accepted the slash-less form `admin.AdminService/DeleteUser` without error, routed the request to the correct handler (routing strips the leading slash when indexing service descriptors), and propagated the slash-less string as `info.FullMethod` to every interceptor in the chain.

Authorization interceptors built on top of gRPC-Go rely on `info.FullMethod` to decide who can call what. The dominant real-world pattern in incrementally secured services is a deny list: enumerate the sensitive paths that require elevated privileges, reject callers that lack them, and allow everything else to pass. A representative interceptor looks like this:

```go
func authInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    adminPaths := []string{
        "/admin.AdminService/DeleteUser",
        "/admin.AdminService/ResetPassword",
        "/admin.AdminService/GrantRole",
    }
    for _, p := range adminPaths {
        if info.FullMethod == p {
            if err := requireAdminToken(ctx); err != nil {
                return nil, status.Error(codes.PermissionDenied, "admin token required")
            }
            return handler(ctx, req)
        }
    }
    return handler(ctx, req)
}
```

When an attacker sends `:path: admin.AdminService/DeleteUser` (no leading slash), `info.FullMethod` is set to `"admin.AdminService/DeleteUser"`. The deny-list loop compares it against `"/admin.AdminService/DeleteUser"` — the strings do not match. The loop completes without finding a match, the function reaches the final `return handler(ctx, req)`, and the call executes as though no authorization check applied. The attacker's non-admin token is never validated against the admin endpoint.

The same bypass applies to prefix-based checks. A check written as `strings.HasPrefix(info.FullMethod, "/admin.")` fails silently when `info.FullMethod` begins with `"admin."` rather than `"/admin."`. Pattern-matching libraries, regex matchers, and switch statements all share this vulnerability if they were written against the canonical slash-prefixed form.

The fix in gRPC-Go 1.79.3 normalises incoming `:path` values in the transport layer before constructing the `UnaryServerInfo` struct. Any request arriving with a slash-less path is rewritten to its canonical form — or rejected outright — before any interceptor receives the `info.FullMethod` value. Interceptors written against the canonical `/Service/Method` format then behave as intended.

The vulnerability specifically targets deny-list interceptors. An allowlist interceptor — one that explicitly names every method a caller is permitted to invoke and returns `PermissionDenied` for everything not on the list — is not vulnerable: a slash-less path that does not match any allowlist entry hits the catch-all deny, which is the correct behaviour. Deny-list interceptors are the vulnerable class because their fallback is allow.

**Target systems:** `google.golang.org/grpc` < 1.79.3, Go 1.21+, Kubernetes microservices using path-based deny-list authorization interceptors.

## Threat Model

- **Attacker with a valid but low-privilege credential** — a compromised microservice holding a JWT or mTLS certificate scoped to read-only operations sends a gRPC request with `:path: admin.AdminService/DeleteUser`. The application-layer interceptor's deny rule never fires. The admin handler executes under the low-privilege identity.

- **Internal service-to-service lateral movement** — a compromised pod in the cluster establishes a direct gRPC connection to an internal admin service. Cluster-internal services frequently skip TLS and rely on Kubernetes NetworkPolicy plus application-layer authorization as their security boundary. The path bypass eliminates the application-layer boundary while NetworkPolicy does not inspect HTTP/2 headers.

- **Service mesh bypass at the application layer** — Envoy and Istio sidecar authorization policies parse HTTP/2 headers independently using their own HTTP/2 codec, which enforces RFC 7540 compliance. A slash-less `:path` sent to an Envoy sidecar is rejected or normalised at the proxy layer before reaching the application. However, services that accept gRPC connections directly (without a sidecar, or on a management port that bypasses the mesh) have no proxy to enforce path validity. Application-level gRPC interceptors are the only protection layer for those connections.

- **Impact scope** — unrestricted access to gRPC admin endpoints, data mutation RPCs, internal management APIs, and any other method protected solely by a deny-list interceptor. In Kubernetes environments, admin gRPC services commonly include cluster-scoped operations: node drain, secret rotation, configuration reload, and certificate issuance.

## Hardening Configuration

### 1. Upgrade gRPC-Go to 1.79.3

Update the direct dependency and rebuild:

```bash
go get google.golang.org/grpc@v1.79.3
go mod tidy
go list -m google.golang.org/grpc
```

Verify the resolved version is `v1.79.3` or later. Transitive dependencies — Kubernetes client-go, Istio libraries, etcd client — may pull in an older version through their own `require` directives. Inspect the full module graph:

```bash
go mod graph | grep 'google.golang.org/grpc v1\.' | sort -t@ -k2 -V
```

If any transitive path resolves an older version, add an explicit minimum override in `go.mod`:

```go
require (
    google.golang.org/grpc v1.79.3
)
```

Confirm no open vulnerabilities remain:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

`govulncheck` performs call-graph analysis. It will flag CVE-2026-33186 only if the vulnerable code path is reachable from your binary — a clean result after upgrading confirms the fix is compiled in, not just present in `go.sum`.

### 2. Audit Authorization Interceptor Patterns

Locate all gRPC interceptors in the codebase:

```bash
grep -rn "UnaryInterceptor\|StreamInterceptor" --include="*.go" .
```

For each interceptor found, review whether the authorization logic uses a deny-list pattern: does it enumerate specific paths to protect and then fall through to an allow for everything else? Common tell-tale patterns to look for:

```bash
grep -rn "FullMethod\|fullMethod" --include="*.go" .
```

Any file that references `FullMethod` in an `if`, `switch`, or string comparison is a candidate for review. Confirm the fallback behaviour: if no path matches the deny rules, is the default `handler(ctx, req)` (allow) or `status.Error(codes.PermissionDenied, ...)` (deny)?

### 3. Convert Deny-List Interceptors to Allowlist Interceptors

The structurally secure fix is converting deny-list interceptors to allowlists. An allowlist interceptor denies any method not explicitly permitted, making it immune to path normalisation bypasses and any future path manipulation:

```go
func allowlistAuthInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    type rule struct {
        method      string
        requireAdmin bool
    }

    allowlist := []rule{
        {method: "/api.UserService/GetUser", requireAdmin: false},
        {method: "/api.UserService/ListUsers", requireAdmin: false},
        {method: "/admin.AdminService/DeleteUser", requireAdmin: true},
        {method: "/admin.AdminService/ResetPassword", requireAdmin: true},
    }

    for _, r := range allowlist {
        if info.FullMethod == r.method {
            if r.requireAdmin {
                if err := requireAdminToken(ctx); err != nil {
                    return nil, status.Error(codes.PermissionDenied, "admin token required")
                }
            } else {
                if err := requireValidToken(ctx); err != nil {
                    return nil, status.Error(codes.Unauthenticated, "valid token required")
                }
            }
            return handler(ctx, req)
        }
    }

    return nil, status.Errorf(codes.PermissionDenied, "method %q not permitted", info.FullMethod)
}
```

The final `return nil, status.Errorf(codes.PermissionDenied, ...)` is the critical difference from a deny-list interceptor. An unrecognised path — whether slash-less, malformed, or simply not in the policy — is denied rather than allowed. New gRPC methods added to the service are denied by default until an explicit allowlist entry is added, which is the correct secure-by-default behaviour.

Apply the same pattern to the stream interceptor:

```go
func allowlistStreamInterceptor(
    srv interface{},
    ss grpc.ServerStream,
    info *grpc.StreamServerInfo,
    handler grpc.StreamHandler,
) error {
    permitted := map[string]bool{
        "/api.DataService/StreamEvents": true,
        "/api.DataService/WatchUpdates": true,
    }

    if !permitted[info.FullMethod] {
        return status.Errorf(codes.PermissionDenied, "method %q not permitted", info.FullMethod)
    }

    if err := requireValidToken(ss.Context()); err != nil {
        return status.Error(codes.Unauthenticated, "valid token required")
    }

    return handler(srv, ss)
}
```

Register both interceptors on the server:

```go
grpcServer := grpc.NewServer(
    grpc.ChainUnaryInterceptor(
        loggingInterceptor,
        allowlistAuthInterceptor,
    ),
    grpc.ChainStreamInterceptor(
        streamLoggingInterceptor,
        allowlistStreamInterceptor,
    ),
)
```

### 4. Enforce HTTP/2 Path Validation at the Ingress

Configure ingress-nginx or Envoy to reject gRPC requests where `:path` does not begin with `/`. This provides a defence-in-depth layer for cluster-internal traffic that reaches gRPC services without a sidecar proxy.

For Envoy, use an `HttpConnectionManager` filter with a route match that rejects non-conforming paths:

```yaml
name: envoy.filters.network.http_connection_manager
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
  codec_type: HTTP2
  http2_protocol_options:
    allow_connect: false
  route_config:
    virtual_hosts:
      - name: grpc_backend
        domains: ["*"]
        routes:
          - match:
              prefix: "/"
            route:
              cluster: grpc_upstream
        request_headers_to_remove: []
  http_filters:
    - name: envoy.filters.http.router
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

Envoy's HTTP/2 codec enforces RFC 7540 path requirements by default in strict mode. Confirm strict mode is not disabled:

```yaml
http2_protocol_options:
  override_stream_error_on_invalid_http_message: false
```

Setting `override_stream_error_on_invalid_http_message: false` (the default) causes Envoy to reset streams with malformed HTTP/2 headers, including slash-less `:path` values, rather than forwarding them to the upstream.

For ingress-nginx, add a server-level snippet to validate gRPC path format:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-service-ingress
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
    nginx.ingress.kubernetes.io/server-snippet: |
      grpc_set_header Content-Type application/grpc;
      if ($request_uri !~ ^/) {
        return 400;
      }
spec:
  ingressClassName: nginx
  rules:
    - host: grpc.example.internal
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: grpc-service
                port:
                  number: 50051
```

### 5. Add Integration Tests for Path-Based Auth

Add a test case that sends a gRPC request using a slash-less path and verifies the server rejects it. Use a raw HTTP/2 client to bypass gRPC-Go's own path normalisation on the client side:

```go
package integration_test

import (
    "context"
    "crypto/tls"
    "net/http"
    "testing"
    "time"

    "golang.org/x/net/http2"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

func TestSlashlessPathIsRejected(t *testing.T) {
    transport := &http2.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        AllowHTTP:       false,
    }
    client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

    req, err := http.NewRequestWithContext(
        context.Background(),
        http.MethodPost,
        "https://localhost:50051/admin.AdminService/DeleteUser",
        nil,
    )
    if err != nil {
        t.Fatalf("build request: %v", err)
    }

    req.URL.Opaque = "admin.AdminService/DeleteUser"
    req.Header.Set("Content-Type", "application/grpc")
    req.Header.Set("TE", "trailers")
    req.Header.Set("Authorization", "Bearer "+lowPrivilegeTestToken)

    resp, err := client.Do(req)
    if err != nil {
        t.Fatalf("send request: %v", err)
    }
    defer resp.Body.Close()

    grpcStatus := resp.Trailer.Get("Grpc-Status")
    if grpcStatus != "7" {
        t.Errorf("expected gRPC status 7 (PermissionDenied), got %q", grpcStatus)
    }
}

func TestCanonicalPathWithDeniedCredentialIsRejected(t *testing.T) {
    conn, err := grpc.Dial("localhost:50051",
        grpc.WithTransportCredentials(insecure.NewCredentials()),
        grpc.WithPerRPCCredentials(lowPrivCreds{}),
    )
    if err != nil {
        t.Fatalf("dial: %v", err)
    }
    defer conn.Close()

    client := adminpb.NewAdminServiceClient(conn)
    _, err = client.DeleteUser(context.Background(), &adminpb.DeleteUserRequest{UserId: "test"})

    st, _ := status.FromError(err)
    if st.Code() != codes.PermissionDenied {
        t.Errorf("expected PermissionDenied, got %v", st.Code())
    }
}
```

The first test case (`TestSlashlessPathIsRejected`) uses a raw HTTP/2 client to send the malformed path directly, bypassing the gRPC-Go client's own path construction. The second test case confirms that the canonical path form is also rejected for a low-privilege caller — preventing a regression where the allowlist interceptor stops working for the normal code path.

## Expected Behaviour After Hardening

After upgrading to gRPC-Go 1.79.3: a request with `:path: admin.AdminService/DeleteUser` (no leading slash) is normalised to `/admin.AdminService/DeleteUser` in the transport layer before `UnaryServerInfo.FullMethod` is populated. The deny rule — or the allowlist check — operates against the canonical form. The request is rejected with `codes.PermissionDenied`.

After converting to an allowlist interceptor: any path not in the explicit allowlist returns `codes.PermissionDenied` regardless of leading slash, path casing, or any other normalisation variant. The fallback is deny, not allow. A slash-less path for a method that is not on the allowlist is denied on two separate grounds: it is not in the allowlist, and after upgrade it would also be normalised before reaching the interceptor.

Both remediations are complementary. The upgrade closes the specific CVE-2026-33186 transport-layer gap. The allowlist conversion closes the structural vulnerability class — deny-list fallthrough — that made the transport-layer gap exploitable.

## Trade-offs and Operational Considerations

Upgrading gRPC-Go requires rebuilding and redeploying every Go service that embeds the library. In a microservices environment with independent deployment pipelines, this means coordinating upgrades across teams. `go mod graph` will reveal which services have a direct or transitive dependency on `google.golang.org/grpc`. Prioritise services that expose admin or internal management gRPC endpoints; services that only act as gRPC clients are not affected by the server-side path handling bug.

Converting existing interceptors from deny-list to allowlist patterns requires auditing every gRPC method defined across each service's protobuf service descriptors to enumerate the expected callers and their required token scopes. The effort is proportional to the number of gRPC services and the granularity of the token scope model. Start with the highest-privilege services — admin APIs, data mutation endpoints, secret management — and work toward lower-privilege services. Automated tooling such as `protoc-gen-go` source generation combined with static analysis can produce an initial list of all `FullMethod` values, which becomes the skeleton of the allowlist.

Service mesh sidecar authorization (Istio `AuthorizationPolicy`) provides a network-level protection layer but does not replace application-layer interceptors. Sidecar policies operate on the attributes Envoy extracts from the HTTP/2 frame before forwarding to the upstream container. For most Istio configurations, `:path` matching in an `AuthorizationPolicy` uses Envoy's normalised path, which would block the slash-less form. However, this is a defence-in-depth layer: misconfigurations in the Istio policy (wrong selector, wrong namespace, allow-all fallback) eliminate sidecar protection without providing any indication at the application layer. Application-layer interceptors must be treated as an independent enforcement point, not a fallback for sidecar misconfiguration.

## Failure Modes

**Upgraded `go.mod` but vendor directory not refreshed.** Running `go get google.golang.org/grpc@v1.79.3` and `go mod tidy` updates `go.mod` and `go.sum`. If the project uses a vendor directory (`vendor/`), the old sources remain until `go mod vendor` is also run. Builds that use `-mod=vendor` (the default when a `vendor/` directory exists) compile the old library. Confirm with `go list -mod=vendor -m google.golang.org/grpc` after running `go mod vendor`.

**Allowlist interceptor applied to unary calls but not streaming calls.** `grpc.ChainUnaryInterceptor` and `grpc.ChainStreamInterceptor` are registered separately. Applying the allowlist interceptor only to the unary chain leaves the stream interceptor chain using the old deny-list pattern (or no authorization at all). Server streaming, client streaming, and bidirectional streaming RPCs are all routed through the stream interceptor chain — they are not covered by the unary chain. Grep the server registration for both `ChainUnaryInterceptor` and `ChainStreamInterceptor` and confirm both chains include the authorization interceptor.

**Integration test only tests the canonical path form.** A test that sends `/admin.AdminService/DeleteUser` and verifies it is rejected only confirms the interceptor logic is working for the normal request format. It does not verify that the slash-less bypass is blocked. Without a test using the raw HTTP/2 client to send the slash-less path, a future regression — a new interceptor that re-introduces deny-list fallthrough — will not be caught until it reaches production.

## Related Articles

- [gRPC Security](/articles/network/grpc-security/)
- [gRPC Go Authorization Security](/articles/kubernetes/grpc-go-authorization-security/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [Istio RBAC Header Security](/articles/network/istio-rbac-header-security/)
- [Kubernetes Admission Control](/articles/kubernetes/kubernetes-admission-control/)
