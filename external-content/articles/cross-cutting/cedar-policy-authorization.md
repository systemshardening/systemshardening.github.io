---
title: "Fine-Grained Authorization with Cedar Policy Language"
description: "Implement fine-grained, auditable authorization using Amazon Cedar's policy language and AWS Verified Permissions, with formal verification and policy-as-data patterns."
slug: cedar-policy-authorization
date: 2026-05-01
lastmod: 2026-05-01
category: cross-cutting
tags: ["cedar", "authorization", "policy", "aws", "verified-permissions", "rbac", "abac", "policy-as-code"]
personas: ["security-engineer", "platform-engineer", "systems-engineer"]
article_number: 325
difficulty: intermediate
estimated_reading_time: 15
published: true
layout: article.njk
permalink: "/articles/cross-cutting/cedar-policy-authorization/index.html"
---

# Fine-Grained Authorization with Cedar Policy Language

## Problem

Role-based access control is the right starting point for most systems, but it breaks down the moment product requirements get specific. A user should be able to read their own documents but not a colleague's. A support agent can view tickets assigned to their team but must not update billing fields. An automated pipeline can write to a staging bucket but not production. These requirements are real and common, yet RBAC's coarse-grained `user.role == "admin"` model cannot express them without either collapsing every nuance into a flat permission list or proliferating roles until the role graph is unmanageable.

Attribute-based access control (ABAC) addresses this by evaluating policies against attributes of the principal, the action, and the resource at decision time. Open Policy Agent's Rego language is the dominant open-source implementation: flexible, integrable, and widely adopted in Kubernetes admission control. However, Rego is a Datalog-inspired language that allows arbitrary recursive rules, external HTTP data fetches inside policy evaluation, and complex iteration — properties that make it expressive but also difficult to audit formally. It is non-trivial to prove statically that a set of Rego policies does not contain a rule that grants access it should not, or that two policies never conflict.

IAM policies on AWS and GCP are JSON documents that look structured but are actually strings from the perspective of your application code. There is no type system validating that `arn:aws:s3:::my-bucket/*` matches the resource you intend, no IDE that warns when you typo an action name, and no tool that checks that your new policy does not shadow an existing deny. The authorization logic exists in a separate plane from the code that calls it, with no compile-time bridge between them.

The most common pattern in web applications is still ad-hoc: an `if` statement in a route handler that checks `request.user.role` or queries the database for group membership inline. These checks drift. A new code path is added and the check is not duplicated. A refactor moves a handler and the middleware guard is not carried along. The result is privilege escalation — not from a sophisticated attacker but from an incomplete authorization path that nobody noticed because it was never centrally documented.

Cedar is Amazon's open-source policy language, released publicly in 2023 and now the enforcement engine behind AWS Verified Permissions and the authorization layer in Amazon Cognito. Cedar is designed from first principles for authorization: it evaluates a principal-action-resource triple against a set of policies and an entity graph, returns `Allow` or `Deny`, and nothing else. It has a static type system, a formally specified semantics, and a verifier backed by the Z3 SMT solver that can prove properties like "no policy in this set can grant a `DeleteDocument` permission to a principal who is not in the `Admin` group." That is a claim you cannot make about an arbitrary set of Rego policies.

Cedar compares to its contemporaries along a clear spectrum. OPA/Rego is maximally expressive and integrates with anything but resists formal analysis. Common Expression Language (CEL) is Google's safe, side-effect-free expression language used in Kubernetes Validating Admission Policy — faster and more analyzable than Rego but not a standalone authorization system. Casbin is a library with multiple model files (ACL, RBAC, ABAC) and broad language support, but the model definition format is informal and there is no schema validation or SMT-backed verification. Cedar occupies the space between CEL's safety guarantees and Rego's expressiveness, purpose-built for the authorization problem specifically.

Target systems: Cedar SDK 3.x (Rust, Go, Java, Python bindings), AWS Verified Permissions (managed policy store), applications running on AWS or self-hosted that need auditable fine-grained authorization. The Rust SDK is the reference implementation; the Go, Java, and Python SDKs bind to it or implement the same specification.

## Threat Model

**1. Policy drift from hardcoded checks.** A developer writes `if user.role == "admin": allow()` in a new endpoint, duplicating logic that already exists in a central policy. Six months later the central policy is updated to add a `superadmin` exemption and the inline check is not. Two code paths, two policies, one of them stale. Cedar eliminates this by making all authorization decisions go through a single `IsAuthorized` call against the policy store — there is no inline alternative.

**2. Time-of-check to time-of-use (TOCTOU) between authorization and resource access.** An authorization check runs at request ingress, but by the time the database write executes, the user's group membership has changed (they were just suspended). Policy-as-code evaluated at the point of the action — with an entity snapshot passed to Cedar — closes this gap because the decision and the entity state are evaluated atomically from the same snapshot.

**3. Insider escalation via unauthorized policy mutation.** An engineer with write access to the policy store adds a `permit` policy granting themselves access to a sensitive resource. Without an audit trail keyed to policy IDs, this mutation is invisible. Cedar policies carry stable IDs; every `IsAuthorized` response includes the IDs of matching policies. Storing these in structured logs provides an evidence trail: "policy `p::abc123` was the reason this decision was Allow."

**4. Confused deputy — service-to-service calls on behalf of unauthenticated principals.** Service A is permitted to call Service B's admin endpoint for legitimate orchestration tasks. An external request reaches Service A through an unauthenticated path. Service A forwards it to Service B, implicitly lending its identity. In Cedar, the `principal` in the authorization request must be the actual end-user entity, not the calling service. Structuring policy around user identity rather than service identity forces the caller to thread the original principal through and prevents the confused deputy pattern.

The blast radius of a misconfigured Cedar policy depends on scope. A wildcard resource (`resource is Document`) in a `permit` policy matches all documents in the entity store. Schema validation and the `cedar analyze` tool catch over-broad policies in CI before they reach production. Verified Permissions policy stores are scoped per application, limiting cross-application blast radius by design.

## Configuration / Implementation

### Cedar Policy Language Basics

A Cedar policy is a `permit` or `forbid` statement over a `principal`, `action`, and `resource`, with optional `when` and `unless` conditions. The evaluation model is deny-by-default: unless a `permit` statement fires and no `forbid` statement fires, the decision is `Deny`.

```cedar
// Allow a user to read their own documents
permit (
  principal,
  action == Action::"Read",
  resource
)
when {
  resource.owner == principal
};

// Allow members of the Admin group to read any document
permit (
  principal in Group::"Admin",
  action == Action::"Read",
  resource is Document
);

// Forbid access to archived documents outside business hours
// (context carries the request time as an epoch integer)
forbid (
  principal,
  action == Action::"Read",
  resource
)
when {
  resource.archived == true &&
  (context.hour < 8 || context.hour > 18)
};
```

Cedar is intentionally not Turing-complete. There are no loops, no recursion, no external calls inside a policy. Every policy terminates in bounded time, which is what enables the SMT-backed verifier.

### Schema Definition

Cedar schemas define the entity types, their attributes, and the action groups that can appear in policies. Type-checking policies against the schema catches typos and structural errors before runtime.

```json
{
  "ExampleApp": {
    "entityTypes": {
      "User": {
        "memberOfTypes": ["Group"],
        "shape": {
          "type": "Record",
          "attributes": {
            "department": { "type": "String" },
            "clearance": { "type": "Long" }
          }
        }
      },
      "Group": {
        "memberOfTypes": [],
        "shape": { "type": "Record", "attributes": {} }
      },
      "Document": {
        "memberOfTypes": [],
        "shape": {
          "type": "Record",
          "attributes": {
            "owner": { "type": "Entity", "name": "User" },
            "classification": { "type": "String" },
            "archived": { "type": "Boolean" }
          }
        }
      }
    },
    "actions": {
      "Read": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Document"]
        }
      },
      "Write": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Document"]
        }
      },
      "Delete": {
        "appliesTo": {
          "principalTypes": ["User"],
          "resourceTypes": ["Document"]
        }
      }
    }
  }
}
```

Save this as `schema.json` and validate policies against it:

```bash
# Validate policies against schema
cedar validate --schema schema.json --policies policies/

# Analyze for over-permissive rules or unreachable policies
cedar analyze --schema schema.json --policies policies/

# Check a specific authorization request for debugging
cedar authorize \
  --schema schema.json \
  --policies policies/ \
  --entities entities.json \
  --principal 'ExampleApp::User::"alice"' \
  --action 'ExampleApp::Action::"Read"' \
  --resource 'ExampleApp::Document::"doc-001"'
```

### Entity Store Design

Entities are the runtime data that Cedar evaluates policies against. Every user, group, document, and resource is an entity with a typed UID and a set of attributes. Group membership is expressed through the `parents` field, enabling Cedar's `in` operator to traverse the hierarchy.

```json
[
  {
    "uid": { "type": "ExampleApp::User", "id": "alice" },
    "attrs": {
      "department": "engineering",
      "clearance": 2
    },
    "parents": [
      { "type": "ExampleApp::Group", "id": "Engineers" }
    ]
  },
  {
    "uid": { "type": "ExampleApp::Group", "id": "Engineers" },
    "attrs": {},
    "parents": []
  },
  {
    "uid": { "type": "ExampleApp::Document", "id": "doc-001" },
    "attrs": {
      "owner": { "__entity": { "type": "ExampleApp::User", "id": "alice" } },
      "classification": "internal",
      "archived": false
    },
    "parents": []
  }
]
```

The entity store is a snapshot: you load entities relevant to the request (the principal and their group memberships, the target resource) and pass them to Cedar at authorization time. This is intentional — Cedar does not reach out to a database. Your application layer is responsible for fetching and assembling the entity slice.

### Integrating Cedar SDK in Go

The `cedar-go` module provides a pure-Go implementation of the Cedar evaluator.

```go
package authz

import (
    "context"
    "fmt"

    cedar "github.com/cedar-policy/cedar-go"
)

type Authorizer struct {
    policies *cedar.PolicySet
    schema   cedar.Schema
}

func NewAuthorizer(policyDir, schemaPath string) (*Authorizer, error) {
    ps, err := cedar.NewPolicySetFromDirectory(policyDir)
    if err != nil {
        return nil, fmt.Errorf("loading policies: %w", err)
    }
    schema, err := cedar.NewSchemaFromFile(schemaPath)
    if err != nil {
        return nil, fmt.Errorf("loading schema: %w", err)
    }
    return &Authorizer{policies: ps, schema: schema}, nil
}

// IsAuthorized returns true if the principal may perform action on resource.
// entities must include the principal, resource, and all relevant group nodes.
func (a *Authorizer) IsAuthorized(
    ctx context.Context,
    principalUID, actionUID, resourceUID string,
    entities cedar.Entities,
    requestContext cedar.Record,
) (bool, []string, error) {
    req := cedar.Request{
        Principal: cedar.NewEntityUID(principalUID),
        Action:    cedar.NewEntityUID(actionUID),
        Resource:  cedar.NewEntityUID(resourceUID),
        Context:   requestContext,
    }

    decision, diag := a.policies.IsAuthorized(entities, req)
    if diag.HasErrors() {
        return false, nil, fmt.Errorf("authorization error: %v", diag.Errors())
    }

    matchedPolicyIDs := make([]string, 0, len(diag.Reasons()))
    for _, reason := range diag.Reasons() {
        matchedPolicyIDs = append(matchedPolicyIDs, reason.PolicyID())
    }

    allowed := decision == cedar.Allow
    return allowed, matchedPolicyIDs, nil
}
```

```go
// In an HTTP handler
func (h *Handler) GetDocument(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value(ctxUserID).(string)
    docID := chi.URLParam(r, "docID")

    entities, err := h.entityStore.Fetch(r.Context(), userID, docID)
    if err != nil {
        http.Error(w, "entity fetch failed", http.StatusInternalServerError)
        return
    }

    reqCtx := cedar.NewRecord(cedar.RecordMap{
        "hour": cedar.Long(time.Now().UTC().Hour()),
    })

    allowed, policyIDs, err := h.authz.IsAuthorized(
        r.Context(),
        "ExampleApp::User::\""+userID+"\"",
        "ExampleApp::Action::\"Read\"",
        "ExampleApp::Document::\""+docID+"\"",
        entities,
        reqCtx,
    )
    if err != nil || !allowed {
        h.audit.Log(r.Context(), userID, "Read", docID, "Deny", policyIDs)
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }

    h.audit.Log(r.Context(), userID, "Read", docID, "Allow", policyIDs)
    // proceed with document fetch
}
```

### Integrating Cedar SDK in Python

```python
import cedar_policy  # cedar-policy PyPI package

def build_authorizer(policy_text: str, schema_json: str):
    schema = cedar_policy.Schema(schema_json)
    policy_set = cedar_policy.PolicySet(policy_text)
    return cedar_policy.Authorizer(policy_set, schema)


def is_authorized(
    authorizer: cedar_policy.Authorizer,
    principal: str,
    action: str,
    resource: str,
    entities_json: str,
    context_json: str,
) -> tuple[bool, list[str]]:
    request = cedar_policy.Request(
        principal=cedar_policy.EntityUid.from_str(principal),
        action=cedar_policy.EntityUid.from_str(action),
        resource=cedar_policy.EntityUid.from_str(resource),
        context=cedar_policy.Context.from_json(context_json),
    )
    entities = cedar_policy.Entities.from_json(entities_json)

    response = authorizer.is_authorized(request, entities)
    allowed = response.decision == cedar_policy.Decision.Allow
    matched_ids = [r.policy_id for r in response.diagnostics.reasons]
    return allowed, matched_ids
```

### AWS Verified Permissions Integration

Verified Permissions is a managed Cedar policy store. Policies live in AWS; your application calls the AVP API for authorization decisions instead of running the Cedar SDK locally.

```bash
# Create a policy store for your application
aws verifiedpermissions create-policy-store \
  --validation-settings '{"mode":"STRICT"}' \
  --query 'policyStoreId' \
  --output text

# Upload the Cedar schema
aws verifiedpermissions put-schema \
  --policy-store-id ps-abc123 \
  --definition file://schema.json

# Create a static policy from a Cedar policy file
aws verifiedpermissions create-policy \
  --policy-store-id ps-abc123 \
  --definition '{
    "static": {
      "description": "Document owners can read their own documents",
      "statement": "permit(principal, action == ExampleApp::Action::\"Read\", resource) when { resource.owner == principal };"
    }
  }'

# Make an authorization decision
aws verifiedpermissions is-authorized \
  --policy-store-id ps-abc123 \
  --principal '{"entityType":"ExampleApp::User","entityId":"alice"}' \
  --action '{"actionType":"ExampleApp::Action","actionId":"Read"}' \
  --resource '{"entityType":"ExampleApp::Document","entityId":"doc-001"}' \
  --entities '{"entityList":[...]}'
```

For applications using Amazon Cognito, use `IsAuthorizedWithToken` instead. AVP validates the JWT, extracts the Cognito identity claims, maps them to Cedar principal attributes, and evaluates the policy — eliminating a manual JWT-to-entity mapping step.

```bash
aws verifiedpermissions is-authorized-with-token \
  --policy-store-id ps-abc123 \
  --identity-token "$ID_TOKEN" \
  --action '{"actionType":"ExampleApp::Action","actionId":"Read"}' \
  --resource '{"entityType":"ExampleApp::Document","entityId":"doc-001"}'
```

### Policy Lifecycle Management

Treat Cedar policies as code stored in Git. Each policy is a `.cedar` file; the schema is `schema.json`. A pull request modifying a policy triggers a CI pipeline that validates and analyzes the change before merge.

```yaml
# .github/workflows/cedar-policy.yml
name: Cedar Policy Validation
on: [pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Cedar CLI
        run: |
          curl -Lo cedar.tar.gz \
            https://github.com/cedar-policy/cedar/releases/latest/download/cedar-linux-amd64.tar.gz
          tar -xf cedar.tar.gz
          sudo mv cedar /usr/local/bin/

      - name: Validate policies against schema
        run: cedar validate --schema schema.json --policies policies/

      - name: Analyze for over-permissive or unreachable policies
        run: cedar analyze --schema schema.json --policies policies/

      - name: Run authorization regression tests
        run: cedar test --schema schema.json --policies policies/ --tests tests/
```

Policy test files (`.cedartest`) define expected `Allow`/`Deny` decisions for specific principal-action-resource triples. Regression tests catch unintended permission changes when policies are modified.

### Audit Logging

Every authorization decision should be logged with enough context to reconstruct what happened and why. Cedar's `IsAuthorized` response includes the IDs of `permit` and `forbid` policies that matched, enabling exact attribution.

```go
type AuthzEvent struct {
    Timestamp  time.Time `json:"timestamp"`
    TraceID    string    `json:"trace_id"`
    Principal  string    `json:"principal"`
    Action     string    `json:"action"`
    Resource   string    `json:"resource"`
    Decision   string    `json:"decision"`
    PolicyIDs  []string  `json:"policy_ids"`
    LatencyMs  int64     `json:"latency_ms"`
}

func (a *AuditLogger) Log(
    ctx context.Context,
    principal, action, resource, decision string,
    policyIDs []string,
) {
    event := AuthzEvent{
        Timestamp: time.Now().UTC(),
        TraceID:   tracing.TraceIDFromContext(ctx),
        Principal: principal,
        Action:    action,
        Resource:  resource,
        Decision:  decision,
        PolicyIDs: policyIDs,
    }
    a.writer.Write(event) // structured JSON to your logging pipeline
}
```

Ship these events to your SIEM. Alert on `Deny` decisions from principals who have historically seen only `Allow` for the same action (behavioral anomaly) and on `Allow` decisions citing a policy ID that was created or modified in the past 24 hours (new policy in production).

## Expected Behaviour

| Signal | Without Cedar | With Cedar |
|---|---|---|
| User accesses another user's document | Depends on whether the ad-hoc check was correctly coded for that path | `Deny` with matched policy IDs in audit log |
| New endpoint added without authorization check | No check runs; request proceeds | Deny-by-default: no `permit` fires, request blocked |
| Policy drift detected | Manual code review required; often missed until a bug report | `cedar analyze` in CI flags unreachable or shadowed policies before merge |
| Privilege escalation attempt via role manipulation | Application-specific; depends on database query correctness | Entity store snapshot is immutable per request; manipulation requires changing the entity store, which is audited separately |
| Audit trail for a specific Deny event | Log line with user ID and HTTP 403; no decision rationale | Log line includes `principal`, `action`, `resource`, `decision`, and exact `policy_ids` that fired |
| Formal proof that `Delete` cannot be granted to non-Admins | Not possible without exhaustive integration testing | `cedar analyze --query` with SMT verification returns a counter-example or proves the invariant |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Limited expressiveness | Policies are analyzable and formally verifiable; no hidden side effects | Cannot call external APIs or databases from inside a policy; all data must be in the entity store or context | Pre-fetch required attributes into the entity snapshot before calling `IsAuthorized`; use context for request-time data (IP, time, request size) |
| Authorization latency | Single function call for Cedar SDK (microseconds); structured caching possible | AVP API adds ~10–30 ms per call; SDK requires loading entity data before the call | Cache entity slices with short TTLs (30–60 s); use AVP batch authorization for bulk decisions; run Cedar SDK in-process for latency-sensitive paths |
| Entity store synchronization lag | Entity data is explicit and auditable | Group membership changes (user suspended, role revoked) may not be reflected in cached entity snapshots immediately | Use short cache TTLs for high-risk attributes; trigger cache invalidation on group membership events; for critical actions, fetch fresh entity data |
| Vendor lock-in (AVP) | Fully managed: no SDK to upgrade, no policy store to operate | AWS-specific; migrating to self-hosted Cedar requires porting the policy store and integration code | Maintain policies and schema as Cedar files in Git (portable); keep SDK-based integration path working alongside AVP for easy switch |
| Schema rigidity | Type errors caught at policy-load time | Schema changes require careful migration; adding a required attribute is a breaking change for existing entities | Version schemas explicitly; use optional attributes for new fields; validate schema changes in staging before production promotion |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Entity store out of sync (stale group membership) | Recently suspended user continues to receive `Allow` decisions because their group membership is still in the cache | Alert on authorization decisions for principals whose status changed in the last N minutes; cross-reference with identity provider events | Invalidate entity cache on group membership change events (e.g., SCIM provisioning webhook); reduce TTL for suspension-related attributes to zero (always-fresh fetch) |
| Policy syntax error blocks policy load | All authorization calls fail with an error; application falls back to deny-all or, worse, allow-all if error handling is wrong | Startup health check that validates policy set loads successfully; CI validates before deployment | Load policies from Git via immutable artifact; use the previous policy set on load failure; alert immediately on policy load error |
| Cedar SDK version mismatch with policy store schema | Policies using schema features added in a newer Cedar version fail to validate against an older SDK | Version-pin SDK and schema compatibility matrix in CI; test with the same SDK version used in production | Pin Cedar SDK version in `go.mod`/`requirements.txt`; update SDK and schema together in a coordinated deployment; test in staging first |
| Verified Permissions API throttling | `IsAuthorized` calls return `ThrottlingException`; application returns HTTP 503 | CloudWatch metric `ThrottledRequests` for the AVP API; alert at >1% throttle rate | Implement exponential backoff with jitter; cache `Allow` decisions for low-sensitivity resources with a 30-second TTL; request an AVP quota increase for high-throughput applications |
| Over-broad `permit` policy merged without review | Unintended principals gain access to resources they should not | `cedar analyze` in CI catches overly broad policies; SIEM alert on spike in `Allow` decisions citing the new policy ID | Revert the policy commit immediately; use Verified Permissions policy versioning or Git revert to restore the previous policy set; review the change control process |

## Related Articles

- [RBAC Design Patterns for Kubernetes](/articles/kubernetes/rbac-design-patterns/)
- [Validating Admission Policy with CEL](/articles/kubernetes/validating-admission-policy-cel/)
- [OAuth2 and OIDC Hardening](/articles/cross-cutting/oauth2-oidc-hardening/)
- [Compliance-as-Code](/articles/cross-cutting/compliance-as-code/)
- [AI Governance Pipeline](/articles/ai-landscape/ai-governance-pipeline/)
