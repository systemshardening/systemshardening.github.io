---
title: "Secure Architecture Patterns: Defence-in-Depth, Least Privilege, and Fail-Safe Defaults"
description: "Security is architecturally expensive to retrofit but cheap to design in. Core patterns — defence-in-depth, least privilege, fail-safe defaults, separation of duties, complete mediation — prevent entire vulnerability classes when applied consistently. This guide covers each principle with concrete implementation examples and common anti-patterns."
slug: secure-architecture-patterns
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - secure-architecture
  - defence-in-depth
  - least-privilege
  - security-design
  - threat-modeling
personas:
  - security-engineer
  - platform-engineer
article_number: 615
difficulty: Intermediate
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cross-cutting/secure-architecture-patterns/
---

# Secure Architecture Patterns: Defence-in-Depth, Least Privilege, and Fail-Safe Defaults

## Problem

Security controls added after a system is built are always more expensive, always less complete, and always subject to the constraint that they cannot break what already works. A firewall rule added to compensate for a service that never authenticated its callers is a patch, not a fix. The caller-authentication gap remains; the firewall just narrows the surface exposed to it.

The inverse is also true: security properties designed into a system's architecture are often free to operate. An API that requires a valid JWT on every request has no additional runtime cost beyond the verification operation itself. A network segment that carries only database traffic between two services cannot be used to exfiltrate data from a third service because the topology makes it physically impossible.

This gap — between retrofitted compensating controls and designed-in security properties — is what architectural security principles address. The canonical framing comes from Saltzer and Schroeder's 1975 paper "The Protection of Information in Computer Systems," which enumerated eight design principles that remain as applicable to cloud-native microservice architectures as they were to timesharing systems. Every major vulnerability class exploited in modern breaches can be traced to a violation of one or more of these principles.

This article covers the principles with concrete implementations and the anti-patterns that arise when they are ignored.

## The Saltzer-Schroeder Principles

Saltzer and Schroeder's eight principles are not a checklist. They are orthogonal properties that, when applied together, produce systems where the security is structural rather than painted on.

**Economy of mechanism** — keep the security-relevant code as simple as possible. Complexity is the enemy of verification. A custom authentication layer with 4,000 lines of hand-rolled code is harder to audit than one that delegates to a well-tested library. Every line of security-relevant code is a potential vulnerability; minimise the count.

**Fail-safe defaults** — the default condition should be denial of access. A subject without explicit permission is refused, not permitted. The firewall rule base starts with `deny all`; rules are added to permit. The Kubernetes RBAC policy starts with no bindings; permissions are granted explicitly.

**Complete mediation** — every access to every protected resource must be checked against the current access policy, without exception. No cached authorisation decisions that bypass the check. No API endpoints that "don't need auth" because they're "internal." No file paths exempt from access control because they were assumed to be unreachable.

**Open design** — the security of the system must not depend on secrecy of the mechanism. Algorithms, protocols, and architecture can be public; keys and credentials cannot. A system whose security relies on an attacker not knowing the API endpoint, the URL structure, or the encryption algorithm is one discovery away from failure.

**Separation of privilege** — where feasible, access to a protected object should require satisfying more than one condition. A single key should not unlock the system; requiring two factors, two approvers, or two independent checks raises the bar for compromise proportionally.

**Least privilege** — every subject should operate with the minimum permissions necessary to perform its function, and no more. A service reading from a database should have `SELECT` on its own tables, not `db_owner` on the cluster. A CI pipeline deploying to staging should not have credentials for production.

**Least common mechanism** — minimise shared mechanisms between subjects with different privilege levels. A function that multiple users or services share becomes a covert channel or an escalation path if it has access to any user's data. Prefer isolated execution contexts.

**Psychological acceptability** — security controls that make the system unusable are bypassed. Security mechanisms must not impose excessive burden, or the humans operating the system will find workarounds that defeat them.

## Defence-in-Depth: Independent Layers

Defence-in-depth is the architectural application of a single insight: assume each individual control will fail, and design so that no single failure is sufficient for a full compromise.

The word "independent" matters. Layers that share a failure mode are not independent. If your network firewall and your application firewall both trust a header injected by a load balancer, compromising the load balancer defeats both layers simultaneously. True depth requires that compromise of one layer does not provide the attacker with leverage over adjacent layers.

A concrete four-layer example for a service handling sensitive data:

**Layer 1 — Network segmentation.** The service sits in a VPC subnet with no inbound internet access. Traffic reaches it only via an internal load balancer. Security group rules permit ingress only from the application tier, not from the management plane, not from other services.

**Layer 2 — Host hardening.** The container image runs as a non-root user, has a read-only filesystem except for `/tmp`, has all Linux capabilities dropped, and runs with a seccomp profile that blocks unused syscalls. If an attacker achieves code execution inside the container, they cannot write to disk, cannot call `ptrace`, and cannot pivot using setuid binaries.

**Layer 3 — Application-level authentication and authorisation.** Every request carries a short-lived JWT. The service verifies the signature, checks the `exp` claim, and enforces RBAC on the specific operation requested. Unauthenticated requests receive `401` before any business logic executes.

**Layer 4 — Audit logging.** Every request — successful or not — is logged with the caller identity, the operation, the resource, and the outcome. Logs are written to an append-only sink that the application has write-only access to. Compromise of the application cannot erase the evidence of what it did.

These four layers are independent in the relevant sense. An attacker who bypasses network segmentation via a misconfigured peer route still faces host hardening, application auth, and audit logging. An attacker who compromises application auth (perhaps via a stolen JWT) still cannot escape the container, still cannot reach the database directly, and still generates an audit trail. The blast radius of any single-layer failure is contained by the remaining layers.

## Fail-Safe Defaults in Practice

Fail-safe defaults is not just about firewall rule ordering. It is a pervasive architectural property that should appear at every layer where access decisions are made.

**Firewalls and security groups.** The default rule is `deny all`. Permitted traffic is explicitly allowlisted. This is standard practice, but the failure mode is worth examining: when a new service is deployed and nobody adds firewall rules, the service is unreachable. That is a visible operational failure, quickly corrected. The alternative — a default-allow rule — means a new service is reachable from everywhere until someone adds deny rules. That silent permissiveness is rarely caught before it becomes a problem.

**Kubernetes RBAC.** A ServiceAccount with no RoleBinding has no permissions. A pod that needs to read ConfigMaps in its own namespace must be explicitly granted that access. The failure mode of missing RBAC is the same as missing firewall rules: the application breaks in a visible way. Architects sometimes resist this because it "creates more YAML," but the alternative — broad default ClusterRoles, or assigning `cluster-admin` because it "just works" — is a structural vulnerability.

```yaml
# Explicit minimal grant — the right pattern
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: config-reader
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["payments-config"]
    verbs: ["get"]
---
# cluster-admin binding for an application pod — the anti-pattern
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: payments-cluster-admin  # never do this
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: payments-sa
    namespace: payments
```

**Feature flags and configuration.** Security-relevant features should be opt-out, not opt-in. TLS on a database connection should be the default; an explicit flag should be required to disable it (and that flag should be audited in CI). Encryption at rest should be enabled by default on new storage volumes. Audit logging should be on by default. Making secure behaviour the default eliminates the class of vulnerabilities caused by "I didn't know I had to turn that on."

**Application-level access control.** New API endpoints should require authentication by default. The developer explicitly marks an endpoint as unauthenticated (for public health checks, for example), rather than explicitly marking endpoints as requiring auth. Many web frameworks invert this, requiring the developer to add an `[Authorize]` attribute per route — which means any route added without the attribute is open. Architectural convention should enforce the inverse.

## Least Privilege in Architecture

Least privilege fails most visibly at the boundaries between services and their dependencies.

**Database credentials.** In a microservice architecture, each service should have its own database credentials scoped to its own schema. A `SELECT`-only credential for a service that only reads data. An `INSERT, UPDATE, SELECT` credential scoped to the specific tables the service writes to. No service should use a credential with DDL rights in production except migrations running under a controlled deployment step.

The common failure mode is a shared `db_admin` password passed to all services via an environment variable. When one service is compromised — via a deserialization vulnerability, a dependency with a known CVE, or an SSRF — the attacker has full access to the entire database cluster, including tables that service never needed to touch.

```sql
-- Least-privilege setup per service
CREATE ROLE payments_service LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE appdb TO payments_service;
GRANT USAGE ON SCHEMA payments TO payments_service;
GRANT SELECT, INSERT, UPDATE ON payments.transactions TO payments_service;
GRANT SELECT ON payments.customers TO payments_service;
-- No access to other schemas, no DELETE, no DDL
```

**Cloud IAM roles.** An EC2 instance or a Kubernetes pod should have an IAM role scoped to what it actually does. A service that reads from one S3 bucket and writes to a DynamoDB table should have `s3:GetObject` on that specific bucket ARN and `dynamodb:PutItem` on that specific table ARN. Not `s3:*` on `*`. Not `AdministratorAccess` because it was the path of least resistance.

**Secret access.** Services should access only the secrets they own. In Vault, this is enforced by path-based ACL policies. A service at path `secret/data/payments/*` cannot read `secret/data/auth/*`. The policy is written narrowly, not `secret/data/*`.

## Separation of Privilege

Separation of privilege requires that consequential operations need multiple independent approvals or factors — not because any one approver is untrustworthy, but because the architecture should not permit unilateral action on high-value targets.

**Two-person rule for production access.** Production environment changes — deploys, database migrations, secret rotations — require approval from a second engineer before execution. This is enforced by tooling (the deployment pipeline requires a second approver on the PR, the bastion host requires a second SSO session approval) rather than by policy document. Policy documents are bypassed under pressure; tooling is not.

**Multi-factor for privileged operations.** Administrative operations — adding new IAM users, modifying firewall rules, accessing the secrets management UI — require MFA re-authentication even if the user is already authenticated. The first factor establishes identity; the second factor establishes intent for the specific high-value action.

**Separation of the deploy pipeline from production credentials.** The CI/CD system can build, test, and deploy to staging automatically. Deploying to production requires an additional approval step with a different credential that CI does not hold by default. Compromise of the CI/CD pipeline — a real and common attack vector — does not automatically yield production access.

## Complete Mediation

Complete mediation is violated in subtle ways that are difficult to detect without explicit architectural audit.

**Cached authorisation without expiry.** A service checks group membership at session start and caches the result for the lifetime of the session. A user is added to a restricted group — or removed from one — and the change does not take effect until the session expires. In a long-running service with persistent connections, the effective access control is the state as it was when the connection was established, not the current state.

The correct pattern: authorisation checks are performed per-request against a current-state source of truth, or the cache has a short TTL (seconds, not hours) with explicit invalidation on policy change.

**Bypassed endpoints.** An API has authentication middleware applied globally, but a path prefix for "legacy" routes is excluded because "those are only called internally." An attacker who can reach the service — perhaps via SSRF from another internal service, perhaps via a misconfigured load balancer rule — can call the legacy routes with no authentication.

The complete mediation pattern: no endpoint is exempt from the authorisation check. Internal-only routes are protected by network controls and by application-level auth. An endpoint accessible on the network can be called; its only protection should not be the assumption that no one will find it.

**Admin panels on the same port.** Mounting an admin interface on the same listener as the application API, and relying on URL-path-based access control to protect it, violates complete mediation at the network layer. The admin interface should be on a separate listener, bound to a separate network interface, reachable only from a restricted management network — not just behind a URL check on the public listener.

## Security-in-Depth for Data

Data protection mirrors the layered approach: encrypt at rest, in transit, and — where feasible — in use, treating each as an independent control.

**Encryption at rest.** Protects against physical media theft and certain cloud provider insider threat scenarios. Implemented at the storage volume layer (AWS EBS, GCP Persistent Disk) and separately at the application layer (field-level encryption for the most sensitive fields — PAN, SSN, health data). The two layers use different keys managed independently, so compromise of the storage-layer key does not expose application-layer ciphertext.

**Encryption in transit.** Every network connection carrying data uses TLS, including internal service-to-service connections. The "it's internal" justification for plaintext internal traffic fails when a single compromised host on the internal network can read all traffic on that segment. A service mesh (Istio, Linkerd) enforces mTLS for all east-west traffic automatically, making the correct behaviour the default without requiring every service team to configure TLS independently.

**Key isolation.** Encryption keys are stored separately from the data they encrypt. An attacker who can read the database cannot read the keys (stored in a dedicated KMS or HSM), and an attacker who can read the keys cannot read the database (because the database is also subject to access controls). The two controls must be independent: a single IAM role with access to both the database and the KMS key eliminates the independence of the layers.

## Architectural Anti-Patterns

### Ambient Authority

Ambient authority is the condition where operations carry implicit permissions derived from global state rather than explicit per-operation grants. The classic form is the confused deputy: a web server running as root that can read any file on the filesystem. An HTTP request for `/etc/shadow` succeeds because the process has the authority, even though the request should not.

In modern architectures, ambient authority appears as:

- A service account with broad IAM permissions attached to every pod in the cluster, regardless of what each pod needs.
- A database connection established at application startup with a privileged credential, available to every request handler in the process.
- A JWT with a long lifetime and broad scopes, cached in a global variable, used for all downstream API calls regardless of which upstream user initiated the request.

The fix is explicit, per-operation grant: the pod assumes an IAM role for the specific AWS API call it is making, with the IAM role scoped to that call. The database credential is scoped to what the current operation needs. The downstream JWT is derived from the upstream user's identity, with scopes narrowed to what the downstream call requires.

### Confused Deputy

The confused deputy problem occurs when a service (the deputy) acts on behalf of a caller but with the deputy's own permissions rather than the caller's. The deputy has access to resources the caller does not — and the caller can use the deputy to access those resources indirectly.

In microservices: Service A calls Service B, passing a resource identifier. Service B fetches the resource using its own credential — which has access to all resources of that type, not just the ones A is authorised to access. An attacker who controls the resource identifier passed by A can cause B to fetch resources it was never intended to access.

The fix: Service B must authorise the operation against the caller's identity, not its own. The caller passes a token (JWT or similar) representing its own authorised scope, and B validates the operation against that token before acting. B's own credential is used only for the technical act of retrieval; the authorisation check uses the caller's identity.

### Flat Network

A flat network — where all services can reach all other services on any port — fails defence-in-depth at the network layer. Lateral movement after compromise is trivial: the attacker pivots from the first compromised service to any reachable service using the same network access.

The correct pattern is micro-segmentation: each service or service tier is in its own network segment. Ingress to the segment is permitted only from the specific services or tiers that legitimately call it. The database segment allows ingress only from the application tier, not from the logging tier, not from the CI/CD runner, not from the monitoring agent on a port it doesn't need.

In Kubernetes, this is implemented with NetworkPolicy objects:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-ingress
  namespace: payments
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: payments-api
      ports:
        - protocol: TCP
          port: 5432
```

No other pod in the cluster can reach `postgres:5432`, regardless of what credentials it holds or what namespace it is in.

## Applying Patterns in Practice

Principles become architectural decisions at specific integration points. Three that deserve explicit attention:

**API gateway as enforcement point.** An API gateway placed at the edge of a service mesh or cluster is the right place to enforce authentication and coarse-grained authorisation for all inbound traffic. Every request passes through it; the gateway verifies the JWT, checks the caller is in the permitted audience, and passes the verified identity downstream in a trusted header. Services behind the gateway can trust the identity header without re-verifying the JWT signature on every hop. This is complete mediation at the edge, combined with least common mechanism (the verification logic lives in one place, not in every service).

**Service mesh for internal mTLS.** A service mesh enforces mutual TLS for all service-to-service communication without requiring each service to configure TLS. The mesh issues short-lived certificates to each workload (via SPIFFE/SPIRE or the mesh's own CA), verifies them on each connection, and can enforce that Service A is not permitted to call Service B by policy. This provides encryption in transit (defence-in-depth for data), workload identity (least privilege — each service has a verifiable identity), and connection-level authorisation (complete mediation).

**Kubernetes admission control.** Admission webhooks (OPA Gatekeeper, Kyverno) enforce workload security policy at deploy time. A policy that blocks pods running as root, blocks pods with `hostPID` or `hostNetwork`, requires that images come from approved registries, and requires resource limits — enforced at admission — means that a misconfigured workload never runs, rather than running insecurely and being detected by a runtime scanner later. This is fail-safe defaults applied to the container orchestration layer: the default is rejection; the pod must satisfy all policy constraints to be admitted.

## Conclusion

Saltzer and Schroeder's principles are not theoretical. Each one maps directly to an architectural decision made (or avoided) when designing real systems. The common thread is that secure architecture is about structure, not about controls layered on top of an insecure structure after the fact.

The test for any design decision: if this component is compromised, what does the attacker gain? If the answer is "access to everything," the architecture has failed at defence-in-depth. If the answer is "the ability to call any API they want," the architecture has failed at least privilege. If the answer is "whatever the cached session allowed three hours ago," the architecture has failed at complete mediation.

Apply the principles during design review, when changing them is cheap. The cost of a principle applied at design time is a conversation. The cost of retrofitting it after a breach is measured in weeks of engineering work, reputational damage, and the residual insecurity of compensating controls that can never fully close the gap the missing principle left open.
