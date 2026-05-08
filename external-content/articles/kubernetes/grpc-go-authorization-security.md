---
title: "gRPC-Go HTTP/2 Authorization Bypass Hardening"
description: "Harden gRPC-Go services against CVE-2026-33186-class authorization bypass via malformed :path pseudo-headers, and track silent fixes in fast-moving google.golang.org/grpc releases."
slug: grpc-go-authorization-security
date: 2026-05-02
lastmod: 2026-05-02
category: kubernetes
tags: ["grpc", "grpc-go", "cve-2026-33186", "authorization", "http2", "path-header", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 360
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/kubernetes/grpc-go-authorization-security/index.html"
---

# gRPC-Go HTTP/2 Authorization Bypass Hardening

## Problem

`google.golang.org/grpc` — commonly called gRPC-Go — is the official Go implementation of gRPC and the transport backbone of the Kubernetes control plane. `kube-apiserver`, `etcd`, `kubelet`, `kube-scheduler`, and `kube-controller-manager` all speak gRPC internally. Beyond Kubernetes itself, gRPC-Go is the dominant choice for Go microservices in cloud-native architectures: service meshes expose their xDS management APIs over it, admission webhooks frequently run as gRPC servers behind a thin HTTP/JSON shim, and internal platform APIs use it for its efficient binary framing and strongly typed protobuf contracts. gRPC uses HTTP/2 as its transport layer. Method routing is driven by the `:path` pseudo-header, which takes the form `/<package>.<Service>/<Method>` — for example, `/api.UserService/GetUser`. Everything about gRPC's authorization model assumes this path is well-formed.

CVE-2026-33186 was disclosed in April–May 2026. The vulnerability is precise: gRPC-Go accepted `:path` pseudo-headers that did not begin with a mandatory leading slash. RFC 7540 §8.1.2.3 is explicit — HTTP/2 request paths for the REQUEST pseudo-header field MUST begin with `/`. gRPC-Go's transport layer failed to enforce this constraint before handing the path to application-layer interceptors. A client could therefore send a request with `:path: api.UserService/AdminOperation` (no leading slash) and the gRPC framework would route it to the correct handler, because the routing table lookup stripped the slash anyway when indexing service descriptors.

The consequence for authorization middleware is critical. The dominant pattern for gRPC authorization in Go is an interceptor that inspects `info.FullMethod` (which mirrors the `:path` value the framework received) and makes an allow/deny decision. Consider this representative check:

```go
func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    // Public methods do not require authentication.
    if info.FullMethod == "/api.UserService/GetPublicData" {
        return handler(ctx, req)
    }
    // Everything else requires a valid token.
    if err := validateToken(ctx); err != nil {
        return nil, status.Error(codes.Unauthenticated, "missing or invalid token")
    }
    return handler(ctx, req)
}
```

When the client sends `:path: api.UserService/AdminOperation` (no leading slash), `info.FullMethod` is set to `"api.UserService/AdminOperation"`. The exact-match check `info.FullMethod == "/api.UserService/GetPublicData"` fails — which is correct — but a prefix check such as `strings.HasPrefix(info.FullMethod, "/api.AdminService/")` also fails, because the path does not start with `/`. In frameworks that implement a list of protected prefixes and default-allow anything that doesn't match, the malformed path bypasses all protection and the request reaches the handler unauthenticated.

The attack impact extends beyond simple API services. Kubernetes admission webhooks implemented in gRPC-Go use the `:path` header to route incoming webhook calls to the appropriate validation or mutation logic. If the webhook server's own authorization layer (separate from Kubernetes RBAC) uses path-based access control, a malformed path can bypass it. Service mesh control planes and data planes that rely on gRPC external authorization — where an Envoy sidecar sends a `CheckRequest` to an authorization server built with gRPC-Go — are also in scope. OPA's gRPC server, when used as an external authorization endpoint, evaluated policy against the path it received; if the authorization server is the vulnerable component rather than the evaluated service, the chain breaks.

The open-source supply-chain angle makes this vulnerability representative of a class of risk that is systematically underestimated. `google.golang.org/grpc` is one of the most used Go modules on the internet, yet its security advisory process has been inconsistent. CVE-2026-33186 was patched in a minor release of gRPC-Go with commit messages and release notes that read "improve HTTP/2 :path header validation" — no `SECURITY` label, no GitHub security advisory filed at the time of the patch, and no entry in the Go vulnerability database (`pkg.go.dev/vuln`) until several weeks later. Operators relying on Dependabot or Renovate received an automatic pull request for the minor version bump, but the PR carried no security label and was treated by many teams as a routine dependency update. This pattern is not new: the HTTP/2 CONTINUATION flood mitigations merged into gRPC-Go in 2024 followed the same trajectory — fix merged to `main`, cherry-picked to `release-1.x` branches, shipped in a patch release, CVE assigned weeks after users had already shipped the vulnerable version to production.

The monitoring posture for gRPC-Go security fixes therefore cannot rely solely on GitHub security advisories or the go vulnerability database having real-time coverage. Platform engineers need layered monitoring: `govulncheck ./...` in CI to catch vulnerabilities once they reach the database; a GitHub watch on `https://github.com/grpc/grpc-go/security/advisories` for advisory notifications; and — for teams with higher risk tolerance — automated scanning of commits to `internal/transport/` and `server.go` in the gRPC-Go repository, where the transport and server path validation code lives, to detect suspicious changes before they're formally classified.

**Target systems:** `google.golang.org/grpc` < the fixed version for CVE-2026-33186, Go 1.21+, Kubernetes services using gRPC interceptors for authorization.

## Threat Model

1. **Unauthenticated external client.** A client sends a gRPC request with `:path: api.AdminService/DeleteUser` (no leading slash) to an Internet-facing or cluster-internal gRPC service. The server's interceptor chain contains `if strings.HasPrefix(info.FullMethod, "/api.AdminService/") { requireAdmin() }`. Because `info.FullMethod` is `"api.AdminService/DeleteUser"` rather than `"/api.AdminService/DeleteUser"`, the prefix check does not match. The request is treated as an unprotected route and the handler executes without credential validation.

2. **Kubernetes admission webhook bypass.** A gRPC-Go-based admission webhook server routes incoming admission review requests by `:path`. The webhook server implements its own pre-authorization check (separate from the Kubernetes API server's authentication of the webhook call) to restrict which service accounts can trigger which admission paths. An attacker with any valid kubeconfig — including a low-privilege service account token — crafts a direct HTTP/2 request to the webhook's gRPC port with a malformed `:path`, bypassing the webhook's internal authorization before the admission logic itself runs.

3. **Patch-gap attacker.** A researcher or attacker reads the gRPC-Go minor release diff on GitHub. The `:path` validation change in `internal/transport/http2_server.go` is immediately visible. They cross-reference it against known patterns of gRPC-Go authorization interceptors in open-source Kubernetes operators, service mesh control planes, and cloud-native API frameworks. Using gRPC server reflection (`grpc.reflection.v1alpha.ServerReflection`) — which many production services leave enabled — they enumerate service descriptors and method paths on running services, then probe each method with a no-slash variant of its path to identify which ones bypass authorization.

4. **Service mesh external authorization loop.** Envoy sends a `CheckRequest` (itself a gRPC call) to an external authorization service built with gRPC-Go. If the authorization service is also vulnerable, an attacker who can influence the `CheckRequest` path (e.g., through a crafted downstream HTTP request that Envoy's `:path` normalization does not fully sanitize before passing to the ext-authz filter) can cause the authorization service's own interceptor to fail to match, returning an allow decision that should have been a deny.

The blast radius of a successful exploit scales with the authorization pattern in use. Services using middleware that denies by default and explicitly allows known paths are unaffected by no-slash paths (the deny-by-default catches the miss). Services using middleware that allows by default and explicitly blocks known paths — a common pattern when adding authorization incrementally to an existing service — are fully bypassed for any method the attacker probes. In Kubernetes environments, a bypassed admission webhook can result in pods being scheduled without security policy validation, privileged containers being created without review, or secrets being mounted that the admission controller was designed to prevent.

## Configuration / Implementation

### Upgrading gRPC-Go

The first remediation step is upgrading to the patched release. Check the current version and upgrade:

```bash
# Check the currently resolved version
go list -m google.golang.org/grpc

# Upgrade to latest (includes the CVE-2026-33186 fix)
go get google.golang.org/grpc@latest

# Tidy the module graph
go mod tidy

# Verify the resolved version after upgrade
go list -m google.golang.org/grpc
```

Transitive dependencies — particularly Kubernetes client-go, etcd client libraries, and Istio libraries — may pin their own `google.golang.org/grpc` requirement. Inspect the full dependency graph to confirm no older version is being brought in through a transitive path:

```bash
# Show all paths through the module graph that involve grpc
go mod graph | grep google.golang.org/grpc

# Show which modules require older grpc versions
go mod graph | grep 'google.golang.org/grpc v1\.' | sort -t@ -k2 -V
```

If a transitive dependency pins an older version, add an explicit `require` override in `go.mod`:

```go
// go.mod — force the patched version even when transitive deps want older
require (
    google.golang.org/grpc v1.X.Y // minimum: patched version for CVE-2026-33186
)
```

Confirm that `govulncheck` reports no open vulnerabilities:

```bash
# Install or update govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Run against the entire module
govulncheck ./...
```

A clean `govulncheck` output after the upgrade confirms CVE-2026-33186 is resolved at the binary call-graph level, not just the module version.

### Path Normalization in Authorization Interceptors

Upgrading gRPC-Go resolves the transport-layer validation gap. However, defence in depth requires that application-layer interceptors also validate the path they receive, because:

- The gRPC-Go version in a transitive dependency may lag the direct dependency.
- The same interceptor pattern may be copied into services that run on other gRPC runtimes.
- Future vulnerabilities may introduce path manipulation through other mechanisms.

Add an explicit leading-slash check at the start of every authorization interceptor:

```go
import (
    "context"
    "strings"

    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

func authInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    // Normalize: reject any path that does not conform to gRPC's /<pkg>.<Svc>/<Method> format.
    // This catches CVE-2026-33186-class bypass on older gRPC-Go versions and any future
    // path manipulation that reaches application code.
    if !strings.HasPrefix(info.FullMethod, "/") {
        return nil, status.Errorf(codes.InvalidArgument, "malformed method path: %q", info.FullMethod)
    }

    // Standard path-based authorization logic follows.
    if info.FullMethod == "/api.UserService/GetPublicData" {
        return handler(ctx, req)
    }
    if err := validateToken(ctx); err != nil {
        return nil, status.Error(codes.Unauthenticated, "missing or invalid token")
    }
    return handler(ctx, req)
}
```

For streaming RPCs, apply the same check in a stream interceptor:

```go
func streamAuthInterceptor(
    srv interface{},
    ss grpc.ServerStream,
    info *grpc.StreamServerInfo,
    handler grpc.StreamHandler,
) error {
    if !strings.HasPrefix(info.FullMethod, "/") {
        return status.Errorf(codes.InvalidArgument, "malformed method path: %q", info.FullMethod)
    }
    // ... authorization logic ...
    return handler(srv, ss)
}
```

### Server-Side Path Validation Middleware

Rather than adding path validation to each interceptor individually, add a dedicated path validation interceptor that runs first in the chain. This ensures the check is applied uniformly regardless of which downstream interceptors are registered:

```go
// pathValidationInterceptor must be the first interceptor in the chain.
// It rejects any request whose FullMethod does not begin with '/', conforming
// to RFC 7540 §8.1.2.3 and gRPC's own path format requirements.
func pathValidationInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    if !strings.HasPrefix(info.FullMethod, "/") {
        return nil, status.Errorf(codes.InvalidArgument, "malformed path: %q", info.FullMethod)
    }
    return handler(ctx, req)
}

func pathValidationStreamInterceptor(
    srv interface{},
    ss grpc.ServerStream,
    info *grpc.StreamServerInfo,
    handler grpc.StreamHandler,
) error {
    if !strings.HasPrefix(info.FullMethod, "/") {
        return status.Errorf(codes.InvalidArgument, "malformed path: %q", info.FullMethod)
    }
    return handler(srv, ss)
}

// Register the server with path validation first.
grpcServer := grpc.NewServer(
    grpc.ChainUnaryInterceptor(
        pathValidationInterceptor, // MUST be first
        loggingInterceptor,
        authInterceptor,
        rateLimitInterceptor,
    ),
    grpc.ChainStreamInterceptor(
        pathValidationStreamInterceptor, // MUST be first
        streamAuthInterceptor,
    ),
)
```

The interceptor ordering is critical. If `authInterceptor` runs before `pathValidationInterceptor`, the bypass is still possible even with the validation in place — the chain is only protected at the point where validation executes.

### Using gRPC Reflection Carefully

gRPC server reflection (`google.golang.org/grpc/reflection`) exposes the full service descriptor tree, including all service names, method names, and message schemas. In the context of CVE-2026-33186, an attacker uses reflection to enumerate the complete method surface before probing each method with a no-slash path variant.

Disable reflection in production builds using a build tag:

```go
//go:build dev

package main

import "google.golang.org/grpc/reflection"

func registerReflection(s *grpc.Server) {
    reflection.Register(s)
}
```

```go
//go:build !dev

package main

import "google.golang.org/grpc"

func registerReflection(s *grpc.Server) {
    // Reflection is disabled in non-dev builds.
    // Method enumeration by external clients is not supported.
}
```

In your `Makefile` or build script:

```bash
# Development build — reflection enabled
go build -tags dev -o bin/server ./cmd/server

# Production build — reflection disabled (default)
go build -o bin/server ./cmd/server
```

If disabling reflection breaks internal tooling (e.g., `grpcurl` for health checks in staging), restrict it at the network level rather than the application level: expose the gRPC reflection port only on a loopback or management interface, never on the interface that handles external traffic.

### Envoy-Side gRPC Path Enforcement

Envoy validates the `:path` pseudo-header for HTTP/2 requests it proxies and enforces RFC 7540 compliance before forwarding to upstream gRPC services. Placing Envoy in front of all gRPC services provides a defence-in-depth layer that blocks malformed paths even when the upstream service is running a vulnerable gRPC-Go version.

Ensure Envoy's HTTP/2 codec strict mode is active, and add a route-level path matcher to enforce the leading slash:

```yaml
# Envoy listener filter chain — HTTP/2 codec with strict mode
listeners:
  - name: grpc_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8443
    filter_chains:
      - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              codec_type: HTTP2
              http2_protocol_options:
                # Enforce RFC 7540 compliance; reject malformed pseudo-headers
                allow_connect: false
              route_config:
                name: grpc_routes
                virtual_hosts:
                  - name: grpc_backend
                    domains: ["*"]
                    routes:
                      - match:
                          # Only match paths that begin with /
                          # Envoy's regex match applies before upstream forwarding
                          safe_regex:
                            regex: "^/[^/].*"
                        route:
                          cluster: grpc_upstream
                      - match:
                          # Catch-all: reject anything that doesn't match above
                          prefix: ""
                        direct_response:
                          status: 400
                          body:
                            inline_string: "malformed gRPC path"
```

For Envoy-based external authorization, ensure the ext-authz filter is positioned to receive normalized paths:

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc:
          cluster_name: ext_authz_cluster
      # Path normalization happens in codec before ext_authz sees the request
      transport_api_version: V3
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

### Monitoring gRPC-Go for Silent Security Fixes

Given the pattern of security fixes landing in gRPC-Go without prominent security labelling, add automated monitoring to catch fixes before they reach the vulnerability database:

**CI pipeline — govulncheck on every push:**

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: ["main", "release-*"]
  pull_request:

jobs:
  govulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - name: Run govulncheck
        run: govulncheck ./...
```

**Watch gRPC-Go commits for security-relevant changes:**

```bash
# List recent gRPC-Go commits touching transport/server path handling
gh api repos/grpc/grpc-go/commits \
  --jq '.[] | select(.commit.message | test("path|header|security|auth|validate"; "i")) | {sha: .sha[0:8], message: .commit.message[0:120]}'

# Watch specific files for changes (run in a cron job or GitHub Actions schedule)
gh api "repos/grpc/grpc-go/commits?path=internal/transport/http2_server.go&per_page=5" \
  --jq '.[] | {sha: .sha[0:8], date: .commit.author.date, message: .commit.message[0:100]}'
```

**Renovate configuration — group gRPC upgrades and enforce security labels:**

```json
{
  "packageRules": [
    {
      "matchPackageNames": ["google.golang.org/grpc"],
      "groupName": "grpc",
      "labels": ["dependencies", "grpc"],
      "reviewers": ["@security-team"],
      "automerge": false,
      "prPriority": 10
    }
  ]
}
```

Subscribe to GitHub Security Advisories for grpc-go: navigate to `https://github.com/grpc/grpc-go/security/advisories` and enable notifications, or use the GitHub API to poll for new advisories in a scheduled workflow.

### Testing Authorization Bypass Resistance

Write integration tests that assert the server correctly rejects malformed paths. The standard `grpc.Dial` + generated stub path will always include the leading slash — to test without it you must use the lower-level `ClientConn.Invoke` with an explicit method string:

```go
package server_test

import (
    "context"
    "testing"

    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/grpc/status"
)

func TestMalformedPathRejected(t *testing.T) {
    // Connect to the test server (started in TestMain or a helper)
    conn, err := grpc.Dial(testServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        t.Fatalf("dial: %v", err)
    }
    defer conn.Close()

    ctx := context.Background()

    // Attempt to invoke AdminOperation without the leading slash.
    // A hardened server must return InvalidArgument or Unauthenticated —
    // never OK or any success code.
    var reply interface{}
    err = conn.Invoke(ctx, "api.AdminService/DeleteUser", nil, &reply)
    if err == nil {
        t.Fatal("expected error for malformed path, got nil")
    }

    code := status.Code(err)
    if code != codes.InvalidArgument && code != codes.Unauthenticated {
        t.Errorf("expected InvalidArgument or Unauthenticated, got %v", code)
    }
}

func TestWellFormedPathSucceeds(t *testing.T) {
    conn, err := grpc.Dial(testServerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        t.Fatalf("dial: %v", err)
    }
    defer conn.Close()

    ctx := context.Background()

    // The correctly-formed path must still work.
    var reply interface{}
    err = conn.Invoke(ctx, "/api.UserService/GetPublicData", nil, &reply)
    // Expect OK or a domain error, not InvalidArgument from path validation.
    if status.Code(err) == codes.InvalidArgument {
        t.Errorf("well-formed path incorrectly rejected: %v", err)
    }
}
```

Run these tests in CI against both the development build (with reflection) and the production build (without), to confirm the interceptor chain behaves identically regardless of reflection registration.

## Expected Behaviour

| Signal | Vulnerable gRPC-Go | Patched + Path Validation |
|---|---|---|
| Client sends `:path: api.AdminService/DeleteUser` (no leading slash) | Request routed to handler; interceptor prefix check misses; request executes unauthenticated | Server returns `codes.InvalidArgument` from `pathValidationInterceptor`; request never reaches auth or handler |
| gRPC reflection enabled in production | Attacker enumerates full service descriptor tree; all method names available for targeted no-slash probing | Reflection disabled via build tag; method surface is not enumerable from outside the cluster |
| Envoy in front of gRPC service receives malformed `:path` | Envoy may forward (depending on codec strictness); upstream vulnerable gRPC-Go processes request | Envoy's HTTP/2 codec validation rejects request with 400 before it reaches the upstream |
| `govulncheck ./...` in CI | CVE-2026-33186 reported at the call-graph level if the vulnerable code path is reachable | Clean output after upgrade to patched version; CI passes |
| Renovate creates PR for `google.golang.org/grpc` minor version bump | PR appears with no security label; treated as routine; merged slowly | `packageRules` configuration assigns security team as reviewers, sets `prPriority: 10`, blocks automerge; team reviews promptly |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Path validation interceptor (first in chain) | Eliminates authorization bypass for all CVE-2026-33186-class path manipulation; defence in depth independent of gRPC-Go version | Any client sending non-slash method paths receives `InvalidArgument` — breaks legacy or non-conformant clients | Audit existing clients for malformed paths before enabling; treat client breakage as a client bug to fix, not a server bug to accommodate |
| Disabling gRPC reflection in production | Removes method enumeration capability from attackers; reduces the attack surface mapping step | `grpcurl`, `Evans`, and other gRPC tooling cannot introspect the server; health check scripts that use reflection break | Use build tags to keep reflection in dev/staging; restrict reflection port to management network at the infra layer |
| `govulncheck ./...` in CI | Detects CVEs once they reach the Go vulnerability database with call-graph precision (fewer false positives than module-level checks) | Adds approximately 20–40 seconds to the CI pipeline per run; requires internet access to the vuln database | Cache the vulnerability database in CI (govulncheck supports `GONOSUMCHECK` env var); run as a non-blocking advisory check on branches, blocking only on main |
| Strict interceptor ordering (path validation first) | Guarantees path check runs before any logic that could be bypassed | Requires team discipline and code review to enforce; a new interceptor added before the path validator silently breaks the guarantee | Enforce via a server constructor function that always prepends the path validation interceptors; document the ordering constraint in the codebase |
| Pinning `go.mod` to minimum patched gRPC-Go version | Prevents transitive dependencies from downgrading the gRPC-Go version below the security fix | `go mod tidy` or dependency upgrades may conflict if other libraries have tight version constraints | Use `go mod why google.golang.org/grpc` to trace which module drives the version; negotiate upgrades with transitive dependency maintainers |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Existing client sends non-slash method path | Client receives `codes.InvalidArgument` after path validation interceptor is deployed; previously working calls start failing | Client error logs show `InvalidArgument` with "malformed path" message; server access logs show rejections at the path validation layer | Identify and fix the client code: all gRPC clients should use generated stubs or explicitly include the leading slash in method strings; treat as a client conformance bug |
| `govulncheck` reports a false positive on an indirect dependency | CI blocks on a vulnerability that exists in an indirect dependency the binary never actually calls | Run `govulncheck -show verbose ./...` to see the call graph path; if the vulnerable symbol is not reachable, it is a false positive | Add the module to `govulncheck`'s exclusion list with a documented rationale, or upgrade the indirect dependency to its patched version regardless |
| Renovate's gRPC upgrade PR breaks API compatibility | Compilation errors or test failures after merging the gRPC minor version bump PR; generated protobuf code may not be compatible with a new gRPC-Go minor version | CI fails on the Renovate PR; error messages reference mismatched gRPC version constraints in generated `.pb.go` files | Pin the gRPC version in `go.mod` until generated code is regenerated with the matching `protoc-gen-go-grpc` version; regenerate protos with `buf generate` against the new gRPC version |
| Path validation interceptor registered after auth interceptor | `pathValidationInterceptor` runs after `authInterceptor`; no-slash paths still bypass auth before validation | Malformed-path test in CI passes against the correct interceptor order but production deployment uses a different server constructor; bypass remains exploitable | Add an integration test that specifically checks the interceptor invocation order using a mock handler that records which interceptors fire; enforce constructor-level ordering |
| gRPC-Go security fix not yet in Go vulnerability database | `govulncheck` reports no issues but the module version predates a known fix | Cross-reference the current `go list -m google.golang.org/grpc` version against gRPC-Go release notes and GitHub commit history; do not rely solely on govulncheck for zero-day gaps | Subscribe to `https://github.com/grpc/grpc-go/security/advisories`; run the commit-monitoring `gh api` query weekly; use Renovate with security-team review on all gRPC bumps |

## Related Articles

- [gRPC Security Hardening](/articles/network/grpc-security/)
- [gRPC API Gateway Patterns](/articles/network/grpc-api-gateway-patterns/)
- [Kubernetes RBAC Design Patterns](/articles/kubernetes/rbac-design-patterns/)
- [mTLS and Service Mesh Security](/articles/network/mtls-service-mesh/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
