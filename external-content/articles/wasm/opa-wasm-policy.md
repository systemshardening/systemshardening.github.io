---
title: "Open Policy Agent with WASM: Policy Compilation, Sandboxed Evaluation, and Performance"
description: "OPA compiles Rego policies to WebAssembly for embedding in applications, edge functions, and API gateways without a sidecar. The compiled bundle evaluates policies in a WASM sandbox, but the sandbox's security depends on correct bundle signing, input validation, and cache isolation."
slug: "opa-wasm-policy"
date: 2026-05-01
lastmod: 2026-05-01
category: "wasm"
tags: ["opa", "wasm", "rego", "policy", "authorisation", "sandbox"]
personas: ["platform-engineer", "security-engineer"]
article_number: 294
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/opa-wasm-policy/index.html"
---

# Open Policy Agent with WASM: Policy Compilation, Sandboxed Evaluation, and Performance

## Problem

Open Policy Agent (OPA) is the standard policy engine for cloud-native infrastructure. In the typical deployment model, OPA runs as a sidecar or standalone daemon that applications call via HTTP. This adds network latency (1-5ms per decision) and a dependency on a running service.

OPA's WASM target compiles Rego policies to a `.wasm` bundle that can be embedded directly in applications, API gateways, edge functions, and Kubernetes admission webhooks — eliminating the sidecar dependency and reducing decision latency to microseconds.

The WASM deployment model introduces its own security considerations:

- **Bundle authenticity.** The `.wasm` bundle contains compiled policy logic. If an attacker can substitute a malicious bundle, they can make all `allow` decisions return `true` regardless of input, or exfiltrate input data via OPA's built-in HTTP capabilities.
- **Input injection.** The application constructs the policy input document (user identity, request attributes, resource metadata) and passes it to the WASM evaluator. If input construction is insecure, an attacker can manipulate their own decision context — changing their user role, resource labels, or request attributes before they reach the policy engine.
- **External data in policy.** Rego policies can reference external data (data documents, HTTP lookups). In the WASM model, external data is bundled at compile time or injected at evaluation time. Stale data (a revoked role that is still in the data document) causes incorrect authorisation decisions.
- **Decision cache poisoning.** OPA supports decision caching for performance. If the cache key does not include all decision-relevant inputs, a cached `allow` decision for one user is returned for another.
- **Policy logic errors.** Rego's default-deny semantics are correct, but logic errors in complex policies produce incorrect `allow` decisions that are not immediately visible. Policy testing and audit logging are required to catch these.

**Target systems:** OPA 0.64+ (WASM target); opa build for bundle compilation; Go SDK (opa/rego package), Rust and Python OPA WASM bindings; Envoy ext_proc filter for OPA WASM; Kubernetes admission webhook with embedded OPA WASM.

## Threat Model

- **Adversary 1 — Bundle substitution:** An attacker replaces the OPA WASM bundle with a modified version that always returns `allow: true`. The application loads the bundle from a storage path the attacker can write to, or via a URL they can MITM.
- **Adversary 2 — Input document manipulation:** An attacker intercepts or modifies the policy input document before it reaches the WASM evaluator. They change their role from `viewer` to `admin`, or add resource labels that trigger allow conditions.
- **Adversary 3 — Stale role data decision:** OPA's data document contains a user's roles. The data was bundled 6 hours ago. An employee was terminated and their access revoked 3 hours ago, but the data document still shows them as active. OPA incorrectly grants access.
- **Adversary 4 — Cache key collision:** Two users share a partial cache key. A cached `allow` decision for a privileged user is returned for a less-privileged user whose request happens to match the cache key (partial input match).
- **Adversary 5 — Policy logic error producing overly permissive decision:** A Rego policy has a logic error that causes `allow` to be `true` for inputs that should be denied. Without policy unit tests and decision audit logging, the error is not detected.
- **Access level:** Adversaries 1 and 2 need write access to bundle storage or the input pipeline. Adversary 3 exploits a process gap. Adversaries 4 and 5 exploit software defects.
- **Objective:** Authorisation bypass, privilege escalation, access to resources that should be denied.
- **Blast radius:** An OPA policy returning `allow: true` for all requests bypasses all authorisation controls — complete access control failure for every resource protected by that policy.

## Configuration

### Step 1: Compile and Sign OPA WASM Bundles

```bash
# Install OPA CLI.
curl -L -o opa https://openpolicyagent.org/downloads/v0.64.0/opa_linux_amd64_static
chmod +x opa && mv opa /usr/local/bin/

# Write a Rego policy.
# policies/authz.rego
cat > policies/authz.rego << 'EOF'
package authz

import future.keywords.if
import future.keywords.in

# Default deny — explicit deny for safety.
default allow := false

# Allow if user has the required role for the action.
allow if {
    required_role := action_roles[input.action]
    required_role in input.user.roles
}

# Define which roles are required for each action.
action_roles := {
    "read":   "viewer",
    "write":  "editor",
    "delete": "admin",
    "admin":  "admin",
}

# Deny explicitly (belt-and-suspenders for sensitive actions).
deny if {
    input.action == "admin"
    input.user.account_status != "active"
}
```

```bash
# Compile to WASM bundle.
opa build \
  --target wasm \
  --entrypoint authz/allow \
  --bundle policies/ \
  --output bundle.tar.gz

# Sign the bundle with a private key.
# Generate signing key pair.
openssl genrsa -out bundle-signing.key 2048
openssl rsa -in bundle-signing.key -pubout -out bundle-signing.pub

# Sign with OPA's built-in bundle signing.
opa build \
  --target wasm \
  --entrypoint authz/allow \
  --bundle policies/ \
  --signing-key bundle-signing.key \
  --signing-alg RS256 \
  --output bundle.tar.gz

# Verify signature before use.
opa bundle verify \
  --verification-key bundle-signing.pub \
  bundle.tar.gz
echo "Bundle signature: $?"   # 0 = valid.
```

### Step 2: Load and Evaluate WASM Bundle in Go

```go
// main.go — embed OPA WASM in a Go application.
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "os"

    "github.com/open-policy-agent/opa/rego"
    "github.com/open-policy-agent/opa/bundle"
    "github.com/open-policy-agent/opa/keys"
)

type AuthzDecision struct {
    Allow bool `json:"allow"`
    Deny  bool `json:"deny"`
}

type PolicyEvaluator struct {
    query         rego.PreparedEvalQuery
    verificationKey *keys.Config
}

func NewPolicyEvaluator(bundlePath string, verificationKeyPath string) (*PolicyEvaluator, error) {
    // 1. Load and verify the bundle signature before using it.
    verificationKey, err := keys.NewConfig(verificationKeyPath, "RS256", "")
    if err != nil {
        return nil, fmt.Errorf("load verification key: %w", err)
    }

    bundleBytes, err := os.ReadFile(bundlePath)
    if err != nil {
        return nil, fmt.Errorf("read bundle: %w", err)
    }

    b, err := bundle.Read(bytes.NewReader(bundleBytes))
    if err != nil {
        return nil, fmt.Errorf("parse bundle: %w", err)
    }

    // Verify bundle signature.
    if err := bundle.Verify(b, verificationKey, []string{"authz/allow"}); err != nil {
        return nil, fmt.Errorf("bundle signature verification FAILED: %w", err)
    }

    // 2. Prepare the evaluation query (compile once; evaluate many times).
    r := rego.New(
        rego.Query("data.authz.allow"),
        rego.LoadBundle(bundlePath),
    )

    query, err := r.PrepareForEval(context.Background())
    if err != nil {
        return nil, fmt.Errorf("prepare query: %w", err)
    }

    return &PolicyEvaluator{query: query, verificationKey: verificationKey}, nil
}

func (e *PolicyEvaluator) Evaluate(input map[string]interface{}) (bool, error) {
    results, err := e.query.Eval(context.Background(), rego.EvalInput(input))
    if err != nil {
        // Policy evaluation error: default to DENY.
        return false, fmt.Errorf("policy evaluation: %w", err)
    }

    if len(results) == 0 || len(results[0].Expressions) == 0 {
        // No result: default to DENY.
        return false, nil
    }

    allowed, ok := results[0].Expressions[0].Value.(bool)
    if !ok {
        return false, nil
    }

    return allowed, nil
}
```

### Step 3: Input Document Construction Security

The input document must be constructed from server-side trusted data only:

```go
// authz/input_builder.go

type AuthzInput struct {
    User     UserContext     `json:"user"`
    Resource ResourceContext `json:"resource"`
    Action   string          `json:"action"`
    Context  RequestContext  `json:"context"`
}

type UserContext struct {
    ID            string   `json:"id"`
    Roles         []string `json:"roles"`
    AccountStatus string   `json:"account_status"`
}

// GOOD: build input from server-side authoritative sources only.
func BuildInput(r *http.Request, userID string, action string) (*AuthzInput, error) {
    // 1. Look up user roles from authoritative store (database, IdP).
    // NEVER take roles from user-supplied JWT claims without verification.
    user, err := userStore.GetUser(r.Context(), userID)
    if err != nil {
        return nil, err
    }

    // 2. Verify JWT and extract claims — don't trust unverified claims.
    claims, err := jwtVerifier.Verify(r.Header.Get("Authorization"))
    if err != nil {
        return nil, fmt.Errorf("invalid token: %w", err)
    }

    // 3. Cross-check: JWT userID must match the authenticated session.
    if claims.Subject != userID {
        return nil, fmt.Errorf("token subject mismatch")
    }

    // 4. Build input from verified server-side data.
    return &AuthzInput{
        User: UserContext{
            ID:            user.ID,
            Roles:         user.Roles,    // From database, not from request.
            AccountStatus: user.Status,
        },
        Resource: ResourceContext{
            ID:     extractResourceID(r),
            Labels: lookupResourceLabels(r),  // From resource store, not request headers.
        },
        Action:  action,
        Context: RequestContext{
            IPAddress: r.RemoteAddr,
            Timestamp: time.Now().UTC().Unix(),
        },
    }, nil
}

// BAD: trusting user-supplied input for authorisation decisions.
func BuildInputInsecure(r *http.Request) *AuthzInput {
    return &AuthzInput{
        User: UserContext{
            Roles: r.Header["X-User-Roles"],    // NEVER: user controls this header.
        },
        // ...
    }
}
```

### Step 4: Data Document Freshness

External data bundled into OPA can become stale. Manage refresh:

```go
// policy/data_refresher.go

type DataRefresher struct {
    evaluator  *PolicyEvaluator
    store      DataStore
    refreshInterval time.Duration
}

func (d *DataRefresher) Start(ctx context.Context) {
    ticker := time.NewTicker(d.refreshInterval)
    for {
        select {
        case <-ticker.C:
            if err := d.refresh(ctx); err != nil {
                log.Error("data refresh failed", "err", err)
                metric_data_refresh_failures.Inc()
            }
        case <-ctx.Done():
            return
        }
    }
}

func (d *DataRefresher) refresh(ctx context.Context) error {
    // Fetch current roles, permissions, and resource metadata.
    roles, err := d.store.GetAllRoles(ctx)
    if err != nil {
        return err
    }

    // Update the OPA data document.
    // For WASM, this means rebuilding the bundle or using OPA's partial eval.
    return d.evaluator.UpdateData(ctx, map[string]interface{}{
        "roles":       roles,
        "permissions": permissions,
        "updated_at":  time.Now().UTC().Unix(),
    })
}
```

For critical access revocations (terminated employee, compromised account):

```go
// Immediate revocation: bypass cache; force data refresh.
func RevokeUserAccess(ctx context.Context, userID string) error {
    // 1. Update the data store immediately.
    if err := userStore.DeactivateUser(ctx, userID); err != nil {
        return err
    }

    // 2. Invalidate decision cache for this user.
    decisionCache.InvalidateUser(userID)

    // 3. Trigger immediate data document refresh.
    go dataRefresher.refresh(ctx)

    // 4. Invalidate any active sessions.
    return sessionStore.InvalidateAllSessions(ctx, userID)
}
```

### Step 5: Decision Caching Security

```go
// policy/decision_cache.go

type DecisionCache struct {
    cache *sync.Map
    ttl   time.Duration
}

type CacheKey struct {
    UserID     string
    ResourceID string
    Action     string
    // Include ALL decision-relevant fields.
    // Never use a partial key that could collide.
    DataVersion string   // Version of the data document used.
}

type CachedDecision struct {
    Allow     bool
    CreatedAt time.Time
}

func (c *DecisionCache) Get(input *AuthzInput, dataVersion string) (bool, bool) {
    key := CacheKey{
        UserID:      input.User.ID,
        ResourceID:  input.Resource.ID,
        Action:      input.Action,
        DataVersion: dataVersion,
    }
    // Use a hash of the full key — not just userID.
    keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%+v", key))))

    if val, ok := c.cache.Load(keyHash); ok {
        decision := val.(CachedDecision)
        if time.Since(decision.CreatedAt) < c.ttl {
            return decision.Allow, true
        }
        c.cache.Delete(keyHash)
    }
    return false, false
}

// Short TTL for cache entries — stale data risk.
// For high-security decisions, set TTL to 0 (no caching).
func NewDecisionCache(ttl time.Duration) *DecisionCache {
    if ttl > 5*time.Minute {
        panic("Decision cache TTL must not exceed 5 minutes for security-relevant decisions")
    }
    return &DecisionCache{ttl: ttl}
}
```

### Step 6: Policy Testing

Every policy must have tests. OPA's test runner executes Rego test files:

```rego
# policies/authz_test.rego
package authz_test

import data.authz

test_viewer_can_read if {
    authz.allow with input as {
        "user": {"id": "u1", "roles": ["viewer"], "account_status": "active"},
        "action": "read",
        "resource": {"id": "r1"}
    }
}

test_viewer_cannot_write if {
    not authz.allow with input as {
        "user": {"id": "u1", "roles": ["viewer"], "account_status": "active"},
        "action": "write",
        "resource": {"id": "r1"}
    }
}

test_inactive_user_denied_admin if {
    not authz.allow with input as {
        "user": {"id": "u2", "roles": ["admin"], "account_status": "suspended"},
        "action": "admin",
        "resource": {"id": "r1"}
    }
}

test_unknown_action_denied if {
    not authz.allow with input as {
        "user": {"id": "u1", "roles": ["admin"], "account_status": "active"},
        "action": "unknown_action",
        "resource": {"id": "r1"}
    }
}
```

```bash
# Run policy tests in CI.
opa test policies/ -v

# Check coverage.
opa test policies/ --coverage | jq '.coverage'
# Target: 100% rule coverage before deployment.

# Integration with CI.
# .github/workflows/policy-test.yml
- name: Test OPA policies
  run: |
    opa test policies/ -v
    EXIT=$?
    if [ $EXIT -ne 0 ]; then
      echo "Policy tests failed — do not deploy"
      exit 1
    fi
```

### Step 7: Decision Audit Logging

Every authorisation decision must be logged:

```go
// authz/audit_logger.go

type DecisionLog struct {
    DecisionID  string                 `json:"decision_id"`
    Timestamp   time.Time              `json:"timestamp"`
    UserID      string                 `json:"user_id"`
    Action      string                 `json:"action"`
    ResourceID  string                 `json:"resource_id"`
    Allow       bool                   `json:"allow"`
    PolicyRules []string               `json:"policy_rules"`  // Which rules fired.
    DataVersion string                 `json:"data_version"`
    LatencyMs   int64                  `json:"latency_ms"`
}

func LogDecision(input *AuthzInput, result bool, latency time.Duration) {
    log.Info("authz_decision",
        "decision_id", uuid.New().String(),
        "user_id",     input.User.ID,
        "action",      input.Action,
        "resource_id", input.Resource.ID,
        "allow",       result,
        "latency_ms",  latency.Milliseconds(),
    )
    // Ship to SIEM for access pattern analysis and anomaly detection.
}
```

### Step 8: Telemetry

```
opa_decision_total{action, result}                         counter
opa_decision_duration_ms{action}                           histogram
opa_bundle_load_total{status}                              counter
opa_bundle_signature_failure_total{}                       counter
opa_data_refresh_total{status}                             counter
opa_data_age_seconds{}                                     gauge
opa_cache_hit_total{}                                      counter
opa_cache_miss_total{}                                     counter
opa_policy_test_pass_total{}                               gauge
```

Alert on:

- `opa_bundle_signature_failure_total` non-zero — bundle failed signature verification; do not load; investigate bundle source.
- `opa_data_age_seconds` > 300 — data document is more than 5 minutes old; access revocations may not be reflected.
- `opa_decision_total{result="allow"}` sudden increase — unexpected spike in allowed decisions; possible policy regression or input manipulation.
- `opa_data_refresh_total{status="failure"}` — data refresh failing; decisions use stale data.
- Any decision where `allow=true` for a user with `account_status != "active"` — policy logic error; immediate investigation.

## Expected Behaviour

| Signal | Unsigned bundle | Signed bundle with input validation |
|--------|----------------|-------------------------------------|
| Bundle substitution attack | Malicious bundle loads silently | Signature verification fails; bundle rejected |
| User manipulates own role in input | Attacker-supplied role grants access | Input built from server-side store; user role not taken from request |
| Stale revocation in data | Terminated employee still has access | Data refresh interval bounds staleness; revocation triggers immediate refresh |
| Cache key collision | Privileged decision returned for unprivileged user | Full-key hash prevents partial collisions |
| Policy logic error | Silent access control failure | Policy tests in CI catch logic errors before deployment |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| WASM vs sidecar | Microsecond decisions; no network hop | Bundle must be rebuilt and redeployed for policy changes | CI/CD pipeline for policy updates; staged rollout |
| Bundle signing | Prevents substitution attack | Key management overhead | Store signing key in HSM or secrets manager; automate rotation |
| No decision cache | No staleness risk | Higher CPU for every decision | Short TTL (60s) is acceptable for most use cases |
| Data bundled at compile time | Fast; no external dependency | Stale data for access control decisions | Use runtime data injection (OPA storage API) for frequently changing data |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Bundle verification key mismatch | Application refuses to start (or load new bundle) | Startup failure log; `opa_bundle_load_total{status="failure"}` | Ensure verification key matches the key used to sign the bundle |
| Data document refresh fails | Decisions use stale role data | `opa_data_age_seconds` alert; `opa_data_refresh_total{status="failure"}` | Investigate connectivity to data store; fall back to conservative deny if data too stale |
| Policy test failure in CI | Deployment blocked | CI pipeline fails | Fix the policy logic; do not bypass tests |
| Rego logic error in production | Unexpected allow/deny decisions | Audit log anomaly; user reports access denied when should be allowed | Revert to previous bundle; fix and redeploy |
| Cache TTL too long | Revoked access still allowed during TTL window | Access log shows revoked user activity | Reduce TTL; trigger explicit cache invalidation on revocation |

## Related Articles

- [Extism Plugin Security](/articles/wasm/extism-plugin-security/)
- [WASM Component Model Security](/articles/wasm/wasm-component-model-security/)
- [Kyverno Policy Development and Testing](/articles/kubernetes/kyverno-policy-development/)
- [Validating Admission Policy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [SPIFFE and SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
