---
title: "Securing Multi-Tenant Prometheus Deployments with Thanos"
description: "Single Prometheus instances per cluster give every tenant shared access to every metric with no isolation, no long-term retention controls, and no cross-cluster query security. Thanos solves the scaling problem but introduces its own attack surface: exposed gRPC endpoints, cross-tenant query leakage, object storage misconfigurations, and PII in time-series labels. This guide hardens every Thanos component."
slug: thanos-prometheus-multitenancy-security
date: 2026-05-07
lastmod: 2026-05-07
category: observability
tags:
  - thanos
  - prometheus
  - multi-tenancy
  - metrics-security
  - long-term-storage
personas:
  - security-engineer
  - platform-engineer
article_number: 549
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/observability/thanos-prometheus-multitenancy-security/
---

# Securing Multi-Tenant Prometheus Deployments with Thanos

## Problem

A single Prometheus instance per Kubernetes cluster is the default starting point for most platform teams. It works until you have multiple product teams sharing a cluster, multiple clusters that need correlated alerting, and retention requirements measured in months rather than hours. At that point the standard setup breaks down — not just operationally but from a security perspective.

The fundamental problem with one Prometheus per cluster in a multi-tenant environment is that Prometheus has no concept of tenancy. Every scrape target, every recording rule, every raw metric is visible to anyone who can query the Prometheus HTTP API. In a shared cluster this means a developer in the `payments` namespace can write a PromQL query that returns memory usage, request rates, and error counts for the `identity` team's services. Prometheus does not enforce namespace isolation on queries.

Thanos extends Prometheus to solve the scaling problems: it adds long-term storage by shipping blocks to object storage, enables cross-cluster querying through a federated Querier layer, and provides global alerting via the Ruler component. But Thanos introduces its own attack surface. Components communicate over gRPC without mutual TLS by default. The Receive component, which accepts remote-write traffic, does not enforce tenant label integrity unless explicitly configured. Object storage buckets default to permissive ACLs if you do not set them. The Querier exposes a PromQL HTTP interface that is unauthenticated by default.

This article addresses each component in the Thanos architecture from a security hardening perspective — not as a survey of features, but as a structured analysis of what can go wrong and what configuration prevents it.

**Affected versions:** Thanos v0.35+ (all components); Prometheus v2.45+ and v3.x; kube-prometheus-stack Helm chart with Thanos integration.

## Threat Model

- **Adversary 1 — Cross-tenant metric exfiltration:** A developer in team A queries the Thanos Querier without authentication and reads metric labels that include internal service names, user identifiers, or request parameters belonging to team B. This requires no exploit — just an unauthenticated HTTP endpoint and knowledge of PromQL.
- **Adversary 2 — Tenant label spoofing:** A compromised workload sends remote-write traffic to Thanos Receive with a forged `tenant_id` label, injecting metrics into another tenant's namespace. This corrupts tenant billing data, triggers another tenant's alerts, and can mask the attacker's own resource usage.
- **Adversary 3 — Object storage data exfiltration:** An attacker with read access to the Thanos object storage bucket — through an overly permissive IAM policy, a misconfigured bucket ACL, or a stolen service account key — downloads historical metric blocks covering months of production telemetry. Metric data that includes PII-bearing labels (user IDs, session identifiers, email addresses in trace labels) represents a data breach.
- **Adversary 4 — Alert rule injection:** A user with write access to Thanos Ruler rule files injects a custom alerting rule that silences existing security alerts via inhibition, or that causes alert storms to exhaust on-call capacity.
- **Adversary 5 — gRPC interception:** An attacker with network access between Thanos components captures unencrypted gRPC traffic between the Sidecar and Store Gateway, or between the Querier and Store Gateway, and reconstructs metric series from the wire. In Kubernetes this is achievable via a compromised pod with network packet capture capability.

## Architecture Security Overview: Which Components Are Exposed

Understanding the Thanos component exposure boundary is the first step in hardening. Not all components need external access.

**Thanos Sidecar** runs alongside each Prometheus pod. It uploads TSDB blocks to object storage and serves the Store API over gRPC to the Querier. The Sidecar should be cluster-internal only. It should never be reachable from outside the cluster. Its gRPC port (default 10901) should accept connections only from the Querier.

**Thanos Store Gateway** reads historical blocks from object storage and serves them over the gRPC Store API. It is purely internal. No external access. Restrict inbound connections to the Querier's pod CIDR or service account using a NetworkPolicy.

**Thanos Querier** is the federation layer. It exposes an HTTP API (default port 10902) that accepts PromQL queries and fans them out across Store API endpoints. This is the component that users and Grafana access. It is the primary external-facing attack surface and requires authentication and authorisation.

**Thanos Receive** accepts Prometheus remote-write traffic (HTTP, port 19291) and optionally exposes a Store API (gRPC, port 10901). The remote-write endpoint must be reachable from Prometheus instances — potentially across clusters. This is the second external-facing attack surface and the one most relevant to tenant isolation.

**Thanos Compactor** runs batch jobs against object storage — compacting and downsampling blocks. It requires write access to the object storage bucket. It should have no inbound network exposure; it initiates all outbound connections.

**Thanos Ruler** evaluates alerting and recording rules against the Querier and routes alerts to Alertmanager. It should be cluster-internal. Rule files must be access-controlled because they contain PromQL expressions that execute against the full metric store.

## Mutual TLS for All gRPC Communication

Thanos components communicate over gRPC for the Store API. By default this communication is unencrypted. In a Kubernetes environment where pod-to-pod traffic is not encrypted at the network layer (i.e., no Cilium WireGuard, no Istio mTLS), gRPC traffic between the Querier and Store Gateways carries raw metric series in plaintext.

Enable TLS on all gRPC endpoints. For production deployments, use mutual TLS — both server and client certificates — so that a rogue component cannot connect to a Store Gateway and exfiltrate metrics.

Generate a CA and component certificates using cert-manager or your PKI. Configure each component:

```yaml
# Thanos Store Gateway - server side
args:
  - store
  - --grpc-server-tls-cert=/certs/tls.crt
  - --grpc-server-tls-key=/certs/tls.key
  - --grpc-server-tls-client-ca=/certs/ca.crt  # enforces mutual TLS
```

```yaml
# Thanos Querier - client side (connecting to Store Gateway and Sidecar)
args:
  - query
  - --grpc-client-tls-secure
  - --grpc-client-tls-cert=/certs/tls.crt
  - --grpc-client-tls-key=/certs/tls.key
  - --grpc-client-tls-ca=/certs/ca.crt
  - --grpc-client-tls-server-name=thanos-store-gateway.monitoring.svc.cluster.local
```

The `--grpc-server-tls-client-ca` flag on the server side is what enforces mutual TLS. Without it, the server presents its certificate but accepts connections from any client. With it, the server rejects connections whose client certificate is not signed by the specified CA. This prevents a compromised pod from connecting to the Store Gateway even if it has network access.

Apply the same pattern to Thanos Sidecar (as a gRPC server for the Querier to connect to) and to Thanos Receive (for inter-receive-node routing traffic).

For certificate rotation, use cert-manager's `Certificate` resource with a short `duration` (90 days) and `renewBefore` (30 days). Mount the certificate Secret as a volume and configure Thanos with the file paths — Thanos reloads TLS certificates on SIGHUP without restarting.

## Per-Tenant Metric Isolation with Thanos Receive

Thanos Receive is the write path for multi-tenant deployments. It accepts remote-write traffic from multiple Prometheus instances and routes each write to the appropriate tenant's storage. Without explicit multi-tenancy configuration, all writes land in the same bucket prefix with no tenant isolation.

Enable the multi-tenancy router with the `--receive.tenant-header` flag, which instructs Receive to read the tenant identifier from an HTTP header on the remote-write request:

```yaml
args:
  - receive
  - --receive.tenant-header=THANOS-TENANT
  - --receive.default-tenant-id=default
  - --receive.tenant-label-name=tenant_id
  - --receive.split-tenant-label-name=tenant_id
  - --tsdb.path=/data
  - --objstore.config-file=/etc/thanos/objstore.yaml
```

The `--receive.tenant-label-name` flag causes Receive to inject the tenant identifier as a label on every incoming metric. This is the enforcement mechanism: even if a Prometheus instance sends metrics with a forged `tenant_id` label, Receive overwrites it with the value from the HTTP header. A Prometheus instance cannot inject metrics into another tenant's namespace by crafting label values.

The header itself (`THANOS-TENANT`) must be set by a trusted component, not by the Prometheus instance directly. Place an authenticating reverse proxy — nginx with header injection, Envoy with JWT-to-header extraction, or an OAuth2-proxy with tenant claim mapping — in front of Thanos Receive. The proxy authenticates the Prometheus remote-write client (via mTLS client certificate or bearer token), determines the tenant from the authenticated identity, and sets the `THANOS-TENANT` header before forwarding to Receive. The Prometheus instance never sets this header itself.

For the query path, tenant isolation requires that the Querier enforces the `tenant_id` label filter on all queries. This is not automatic. Without additional controls at the query layer, a user who can reach the Querier can query metrics across all tenants by omitting the `tenant_id` filter. The correct architecture is to never expose the Thanos Querier directly; route all queries through Grafana with organisation-scoped datasources, or through a query proxy that injects mandatory label matchers before forwarding to the Querier.

The Grafana Phlare project and tools like `cortex-tenant` can serve as query proxies that inject `{tenant_id="<authenticated-tenant>"}` into every PromQL query before it reaches the Querier, preventing cross-tenant reads.

## Object Storage Security

Thanos stores metric blocks in object storage: S3, GCS, Azure Blob, or compatible alternatives. The object storage bucket is the most durable and highest-value target in the Thanos architecture. It contains months or years of metric history and is accessible to anyone with the appropriate credentials.

**Bucket policy and IAM.** Apply least-privilege IAM policies to each Thanos component's service account. The Compactor needs read and write access to compact and delete expired blocks. The Store Gateway needs read-only access. The Sidecar needs write access to upload new blocks but not to delete existing ones. Never use a single IAM role with full bucket access for all components.

For AWS S3, a restrictive bucket policy for the Store Gateway looks like:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ThanosStoreGatewayReadOnly",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:role/thanos-store-gateway"
      },
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::thanos-metrics-bucket",
        "arn:aws:s3:::thanos-metrics-bucket/*"
      ]
    }
  ]
}
```

The Compactor role additionally needs `s3:DeleteObject` and `s3:PutObject`. The Sidecar role needs `s3:PutObject` but not `s3:DeleteObject` — the Compactor is the only component that should delete blocks.

**Separate buckets per tenant.** For strong tenant isolation, provision a separate S3 bucket per tenant. This ensures that an IAM misconfiguration affecting one tenant's bucket cannot expose another tenant's data. It also simplifies data deletion and retention management: deleting a tenant's data is a bucket deletion rather than a prefix scan. The operational overhead is higher but the security boundary is clean.

If shared buckets with per-tenant prefixes are used instead, ensure that bucket policies use condition keys on the object prefix (`s3:prefix`) to restrict each component's service account to its tenant's prefix only.

**Encryption at rest.** Enable server-side encryption for the bucket. For S3, use SSE-S3 as a baseline or SSE-KMS with a customer-managed key for additional control and audit trail (KMS CloudTrail logs every decrypt operation). Do not rely on the Thanos Compactor's block-level encryption — use storage-layer encryption as the primary control.

**Block public access.** Explicitly enable the S3 Block Public Access settings at both the bucket and account level. This prevents ACL misconfigurations or a future API call from accidentally making the bucket public.

## Querier Authentication

The Thanos Querier HTTP API is unauthenticated by default. It provides full PromQL access to all metrics across all tenants visible to the connected Store endpoints. Every query is the equivalent of `SELECT *` across the entire metric database with no WHERE clause — unless the caller adds label filters.

Do not expose the Thanos Querier directly to end users or Grafana without authentication. Place it behind an authenticating proxy.

The recommended pattern is `oauth2-proxy` in front of the Querier with an OIDC provider:

```yaml
# oauth2-proxy deployment
args:
  - --provider=oidc
  - --oidc-issuer-url=https://your-oidc-provider.example.com
  - --client-id=thanos-querier
  - --client-secret=$(OAUTH2_CLIENT_SECRET)
  - --upstream=http://thanos-querier:10902
  - --email-domain=yourdomain.com
  - --cookie-secret=$(COOKIE_SECRET)
  - --pass-access-token=true
  - --pass-user-headers=true
```

For service-to-service access (Grafana, recording rule evaluators), use bearer token authentication with short-lived tokens from the OIDC provider rather than static credentials.

Restrict the Thanos Querier's Kubernetes NetworkPolicy to accept inbound connections only from the oauth2-proxy pod and from the Thanos Ruler. Block direct access from application namespaces and developer workstations to the Querier's pod IP.

## PII in Metric Labels: Data Governance

Prometheus and Thanos store metric data as time-series with label sets. Labels are freeform key-value pairs attached at scrape time or by recording rules. The security and compliance risk is that labels can contain sensitive data — and often do, inadvertently.

Common PII leakage patterns in metric labels:

- `user_id` labels on request-rate metrics that use actual user identifiers rather than opaque session hashes
- `email` or `username` labels attached to authentication failure metrics (`auth_failures_total{email="user@example.com"}`)
- URL path labels that include query parameters containing tokens or identifiers (`http_request_duration_seconds{path="/api/reset?token=abc123"}`)
- Trace IDs or correlation IDs that can be joined against application logs to reconstruct user behaviour

Each unique label combination creates a new time series. A label that includes unbounded values — user IDs, session tokens, request paths with variable segments — causes cardinality explosion: Prometheus memory usage grows without bound as new time series are created for each unique label value.

Enforce metric label governance at the Prometheus scrape layer using `metric_relabel_configs` to drop or redact sensitive labels before they are stored:

```yaml
# prometheus.yml scrape config
metric_relabel_configs:
  # Drop user_id label entirely
  - action: labeldrop
    regex: user_id

  # Redact path segments after /api/users/
  - source_labels: [path]
    regex: '/api/users/[^/]+(.*)'
    replacement: '/api/users/REDACTED$1'
    target_label: path
    action: replace
```

At the Thanos Receive layer, you can apply relabeling via the `--receive.relabel-config` flag to enforce global label sanitisation across all tenants before metrics are written to TSDB.

Audit metric label cardinality regularly. A sudden increase in unique series count for a given metric is both a security indicator (PII leak) and a stability risk. Thanos Querier exposes a `/api/v1/label/__name__/values` endpoint that returns all metric names, and per-metric cardinality can be assessed with:

```promql
topk(20, count by (__name__)({__name__=~".+"}))
```

Establish a cardinality budget per tenant (e.g., 500,000 active series) and alert when a tenant approaches it. This both protects Thanos stability and prompts investigation that often uncovers inadvertent PII in new label dimensions.

## Thanos Ruler Security

Thanos Ruler evaluates alerting and recording rules against the Querier at regular intervals and routes firing alerts to Alertmanager. The Ruler is a privileged component: it runs PromQL queries with no tenant restrictions (unless you implement per-tenant Ruler instances), and it has write access to Alertmanager's silence and alert ingestion APIs.

**Rule file access control.** Ruler reads rule files from a specified directory or from Kubernetes ConfigMaps. Restrict write access to rule files to a small group (the platform team's CI/CD pipeline). Do not allow application teams to write directly to the Ruler rule directory; instead, use a GitOps workflow where rule files are reviewed and merged through a pull request process before they reach the Ruler.

Alert rule injection is a realistic attack vector. A malicious or compromised rule file can introduce a recording rule that evaluates an expensive PromQL query causing CPU exhaustion on the Querier, an inhibition-like recording rule that creates a metric series which silences existing alerts, or exfiltration rules that use `remote_write` to send metric data to an attacker-controlled endpoint.

**Per-tenant Ruler isolation.** For strong multi-tenant deployments, run a separate Thanos Ruler instance per tenant with a Querier that has the tenant's `tenant_id` label matcher pre-injected. This prevents a tenant's rules from accidentally querying another tenant's metrics and limits the blast radius of a rule file compromise.

**Alertmanager authentication.** Configure the Ruler to authenticate to Alertmanager using mTLS or a bearer token. The Ruler's connection to Alertmanager carries alert data, and an unauthenticated connection allows any process that can reach the Alertmanager port to inject arbitrary alerts. Set `--alertmanager.url` with TLS and use `--alertmanager.http-client.tls-cert` for mutual authentication.

## Retention Policy Security and Data Minimisation

Thanos Compactor manages block compaction and retention deletion in object storage. The `--retention.resolution-raw` flag controls how long raw (undownsampled) data is retained. Misconfigured retention keeps data indefinitely — which is a data governance and compliance risk, not just a storage cost.

Set explicit retention values aligned with your data classification policy:

```yaml
args:
  - compact
  - --retention.resolution-raw=90d
  - --retention.resolution-5m=365d
  - --retention.resolution-1h=3y
  - --objstore.config-file=/etc/thanos/objstore.yaml
  - --wait
  - --wait-interval=3h
```

Raw data at 90 days means that high-cardinality label combinations — including any inadvertent PII — are retained for at most 90 days before the blocks are deleted by the Compactor. Downsampled data (5-minute and 1-hour resolution) retains only aggregated values, which contain no individual label series and therefore represent lower PII risk.

For tenants subject to GDPR's right to erasure, retain only the minimum resolution needed for their SLA dashboards and set short raw retention. A `payments` tenant that needs 13 months of trend data for quarterly reviews needs 1-hour resolution for 13 months, not raw data for 13 months. The distinction is the difference between storing aggregated throughput trends and storing per-request label series that could identify users.

Document retention policy decisions in your threat model. Auditors will ask how long metric data containing user identifiers is retained. Having explicit `--retention.resolution-raw` values set in configuration (and version-controlled) is evidence of intentional data minimisation.

## Grafana Multi-Tenancy with Thanos

Grafana is typically the query interface for Thanos in production. Its organisation model maps cleanly to Thanos tenancy but requires deliberate configuration to enforce isolation.

Create a separate Grafana organisation per tenant. Within each organisation, configure a Thanos datasource with a fixed additional label filter in the datasource configuration:

```ini
# Grafana datasource provisioning (values.yaml for grafana Helm chart)
datasources:
  - name: Thanos (Tenant A)
    type: prometheus
    url: http://thanos-querier:10902
    orgId: 2
    jsonData:
      customQueryParameters: "tenant_id=tenant-a"
      httpMethod: POST
```

The `customQueryParameters` field appends a mandatory label matcher to every query made through this datasource. A user in Grafana org 2 who writes a PromQL query without a `tenant_id` filter will have `tenant_id=tenant-a` appended by the datasource configuration before the query reaches the Querier.

This is a defence-in-depth measure, not a primary isolation control. A user who bypasses Grafana and queries the Querier API directly (e.g., via `kubectl port-forward`) bypasses this filter. The primary isolation control is the query proxy that injects mandatory label matchers and requires authentication, as described in the Querier section above.

Restrict Grafana organisation administration to the platform team. Application teams should be Grafana Viewers or Editors within their own organisation, not Organisation Admins. An Org Admin can modify the datasource configuration and remove the mandatory label filter.

## Verification Checklist

Run these checks after deploying the hardened configuration:

```bash
# Verify gRPC TLS is active - should see TLS handshake, not plaintext
openssl s_client -connect thanos-store-gateway:10901 -starttls grpc

# Attempt unauthenticated query to Querier - should return 401 or redirect
curl -v http://thanos-querier:10902/api/v1/query?query=up

# Verify Receive rejects remote-write without tenant header
curl -X POST http://thanos-receive:19291/api/v1/receive \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @test-samples.pb
# Should return 400 if --receive.default-tenant-id is not set, or assign to default

# Check object storage bucket is not publicly accessible (AWS)
aws s3api get-bucket-acl --bucket thanos-metrics-bucket
aws s3api get-public-access-block --bucket thanos-metrics-bucket

# Audit high-cardinality series that might contain PII
curl "http://thanos-querier:10902/api/v1/query" \
  --data-urlencode 'query=topk(10, count by (__name__, tenant_id)({__name__=~".+"}))'
```

Add these checks to your CI/CD pipeline's integration test suite and to a periodic security audit cron job. Cardinality checks in particular should run weekly — new services being onboarded are the most common source of PII label introduction.

## Summary

Securing a multi-tenant Thanos deployment requires controls at every layer of the architecture. Single Prometheus per cluster fails at scale because it provides no tenant isolation at the query layer and no long-term storage access controls. Thanos solves the scaling problems but introduces a larger attack surface: external gRPC endpoints, a remote-write ingestion path, object storage, and a federated query interface.

The critical controls are: mutual TLS on all gRPC communication between components, tenant label enforcement via Thanos Receive with a trusted header proxy, least-privilege IAM for object storage with encryption at rest, authentication on the Querier via oauth2-proxy or equivalent, access-controlled rule files for the Ruler, and metric label auditing to prevent PII accumulation in time-series labels.

Grafana organisation scoping and mandatory label filters in datasource configuration add defence-in-depth for the user-facing query path, but the binding controls are in the Querier proxy layer and the Receive tenant header enforcement — where authentication happens before any metric data is returned or stored.
