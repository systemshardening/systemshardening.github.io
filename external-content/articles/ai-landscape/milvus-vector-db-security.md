---
title: "Milvus Vector Database Security Hardening"
description: "Harden Milvus against CVE-2026-26190 unauthenticated REST API on port 9091, weak predictable debug tokens, and the broader pattern of AI infrastructure exposed without authentication."
slug: milvus-vector-db-security
date: 2026-05-03
lastmod: 2026-05-03
category: ai-landscape
tags: ["milvus", "vector-database", "cve-2026-26190", "unauthenticated-api", "rag", "ai-security", "etcd"]
personas: ["ml-engineer", "security-engineer", "platform-engineer"]
article_number: 388
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/ai-landscape/milvus-vector-db-security/index.html"
---

# Milvus Vector Database Security Hardening

## Problem

Milvus is an open-source vector database purpose-built for AI and machine learning applications. Rather than storing structured rows or JSON documents, Milvus stores high-dimensional embeddings — the dense floating-point vectors produced by models such as BERT, CLIP, and OpenAI's embedding APIs — and executes approximate nearest-neighbour searches across billions of these vectors at low latency. The semantic similarity that makes modern AI applications feel intelligent (a RAG pipeline that surfaces relevant documents, a recommendation system that suggests content a user has not explicitly searched for, a multimodal search that finds images matching a text description) is, at the infrastructure layer, a Milvus query returning the top-k nearest vectors to a query embedding. Milvus is available as a self-hosted deployment (Milvus Standalone for single-node and Milvus Distributed for production clusters) and as Zilliz Cloud, the managed offering from the project's primary commercial sponsor. The project has accumulated significant adoption among enterprise AI teams and is a first-class integration target for LangChain, LlamaIndex, and most other LLM orchestration frameworks.

**CVE-2026-26190**, disclosed on February 13, 2026 with a CVSS score of 9.8 (Critical), identified that Milvus exposed a fully featured REST API on port 9091 — a port documented as the Milvus metrics and management endpoint — without any authentication requirement. This was not a limited health-check or metrics-scraping surface; the unauthenticated API on port 9091 provided access to the complete set of Milvus management operations: listing, creating, and deleting collections; managing users and roles; creating and modifying database schemas; reading and writing vector data; and executing arbitrary vector similarity queries. Separately, the same port exposed a `/expr` debug endpoint that accepted a token for access — but that token was derived deterministically from the etcd `rootPath` configuration value, which defaults to `"by-dev"` in all standard Milvus deployments. An attacker who knows (or guesses) this value can trivially derive the debug token and access the endpoint. An unauthenticated remote attacker with network access to port 9091 could achieve full exfiltration of all stored embeddings and associated metadata, arbitrary user account manipulation, and file writes via certain API endpoints. The vulnerability was fixed in Milvus 2.5.27 and 2.6.10.

The scope of exposure in a vector database breach is qualitatively different from a conventional database breach, and this distinction deserves emphasis. Vector databases in production AI pipelines do not store bare numerical arrays — they store embeddings alongside structured metadata. For a RAG system, that metadata typically includes source document identifiers, chunk text or summaries, timestamps, access-control labels, and customer or user identifiers. For a recommendation system, it includes user profile data and interaction history. For a customer support system, it may include conversation summaries that contain PII. Even the raw embedding vectors carry information: model inversion techniques, which apply optimisation against a known embedding model, can partially reconstruct the original text from its embedding representation. A complete Milvus exfiltration via CVE-2026-26190 is therefore not just a database breach — it is a breach of every piece of content that was ever processed by the embedding pipeline, and in some threat models, a breach that enables downstream reconstruction of that content.

CVE-2026-26190 fits a well-documented pattern in AI infrastructure tooling. Milvus was not the first AI infrastructure component to ship with an unauthenticated management port as a default, and it will not be the last. Ollama binds its full inference API on port 11434 with no authentication. ChromaDB exposes its HTTP API on port 8000 without credentials. Qdrant serves its management API on port 6333 unauthenticated. In each case, the design rationale is the same: the tool was built for local development and single-developer usage, the frictionless experience was prioritised, and the port that was exposed was documented with a functional label ("metrics", "management") that obscured the depth of access it provided. Security scanning of public cloud environments routinely surfaces thousands of these endpoints accessible from the internet. Milvus port 9091 was no exception, and the predictable `by-dev` token made mass exploitation straightforward to automate.

The open-source disclosure history of CVE-2026-26190 provides useful context for risk assessment. The Milvus security advisory was published at `https://github.com/milvus-io/milvus/security/advisories/GHSA-7ppg-37fh-vcr6` on the same day the patched releases were made available — a relatively responsible coordinated disclosure by the Zilliz security team. However, the underlying issue of unauthenticated access on port 9091 had been present in Milvus for years and had been discussed in public GitHub issues as a "known limitation for development environments." The official documentation described port 9091 as the "metrics port" without clearly stating that it also exposed the full management API. The fix was visible in a public pull request on the Milvus GitHub repository before the advisory was formally published, and the predictable `by-dev` token had been noted by external security researchers in published blog posts months before the CVE was assigned. For operators, this timeline means the patch-gap period — between public knowledge of the vulnerability and operator action — was effectively longer than the formal CVE disclosure date suggests.

Monitoring Milvus for future security advisories requires active subscription rather than passive waiting. The advisory feed at `https://github.com/milvus-io/milvus/security/advisories` provides GitHub Security Advisory notifications when subscribed via repository watch settings. The Milvus changelog, available at `https://github.com/milvus-io/milvus/releases`, should be reviewed for authentication-related changes between releases. To filter relevant commits programmatically:

```bash
gh api repos/milvus-io/milvus/commits \
  --jq '.[] | select(.commit.message | test("auth|security|CVE|port.*9091|token|credential"; "i")) | {sha: .sha[0:8], msg: .commit.message}'
```

The `osv.dev` API provides a machine-queryable CVE feed for the Milvus package in the Go ecosystem, suitable for integration into vulnerability management pipelines.

Target systems: Milvus < 2.5.27 and < 2.6.10 (CVE-2026-26190); Milvus Standalone and Milvus Distributed self-hosted deployments; Zilliz Cloud is unaffected.

## Threat Model

1. **CVE-2026-26190 — unauthenticated port 9091**: An external attacker or a compromised pod with network connectivity to the Milvus host makes a direct HTTP request to enumerate all collections: `GET http://milvus:9091/api/v1/collections`. With collection names in hand, the attacker iterates through each collection performing a full table scan: `GET http://milvus:9091/api/v1/entities?collection_name=user_embeddings&limit=10000`. This returns all stored vectors and their associated metadata fields — the entire vector knowledge base — without any credential requirement. A single scripted loop against an unpatched Milvus instance exfiltrates gigabytes of embedding data in minutes. No exploitation of memory corruption or binary vulnerabilities is required; the attack is a series of well-formed HTTP GET requests.

2. **Predictable `/expr` debug token**: An attacker who has obtained a Milvus configuration file — a common outcome when Milvus deployment manifests are committed to Git repositories without secret management — can read the etcd `rootPath` value. In default deployments this value is `"by-dev"`, but even in customised deployments the value is often a short, human-readable identifier. The debug token is derived from this value using a deterministic algorithm. With the derived token, the attacker accesses the `/expr` debug endpoint and executes arbitrary filter expressions against the Milvus data store, enabling targeted data extraction based on metadata field predicates rather than requiring a full collection scan.

3. **Patch-gap attacker exploiting public disclosure**: The technical details of the unauthenticated port 9091 issue were visible in public GitHub issues and researcher blog posts before the CVE was assigned. Automated scanners (Shodan, Censys, masscan) routinely identify hosts with Milvus ports 19530 (gRPC) and 9091 (HTTP management) open. An attacker maintaining such a scan database can correlate CVE-2026-26190 disclosure with hosts running exposed port 9091 and execute bulk exfiltration against unpatched instances during the window between CVE publication on February 13, 2026 and the date operators complete their patch deployment. This is a race condition that favours a well-prepared attacker over an unprepared operator.

4. **RAG pipeline poisoning via write API**: An attacker with write access to the unauthenticated Milvus management API — trivially obtained via CVE-2026-26190 on an unpatched instance — inserts crafted vectors into one or more collections. These vectors are engineered to be nearest neighbours to the query embeddings generated by specific user inputs. When the RAG system retrieves context for those inputs, the poisoned vectors are returned alongside or instead of legitimate context documents, and the poisoned content is included in the LLM prompt. The LLM processes the injected content as authoritative retrieved context, producing attacker-controlled outputs: fabricated answers, harmful instructions embedded in responses, or exfiltration payloads targeted at users who trigger the affected queries. This is indirect prompt injection executed at the vector storage layer rather than the application layer, making it substantially harder to detect than injection in application-layer inputs.

The blast radius of a Milvus compromise on an unpatched instance with port 9091 accessible is effectively unbounded within the scope of the application it serves. Every collection, every vector, and every metadata field is readable and writable. Downstream consequences include data breach of all embedded content, integrity violation of all RAG-generated responses, and account takeover of all Milvus user accounts. In a multi-tenant Milvus deployment, a single CVE-2026-26190 exploitation event compromises all tenants simultaneously.

## Configuration / Implementation

### Upgrading Milvus

Patch to a fixed version as the first priority action. This is the only complete remediation for CVE-2026-26190. All other controls in this section are defence-in-depth measures that reduce exposure on unpatched instances, but they do not replace the patch.

For Helm-managed deployments:

```bash
helm upgrade milvus milvus/milvus \
  --version 2.6.10 \
  --namespace milvus \
  --reuse-values
```

For Docker Compose deployments, update the image tag in `docker-compose.yml`:

```yaml
services:
  standalone:
    image: milvusdb/milvus:v2.6.10
    # remaining configuration unchanged
```

Then apply the update:

```bash
docker compose pull && docker compose up -d
```

After upgrading, verify that port 9091 now requires authentication by confirming that an unauthenticated request returns a 401 or equivalent error:

```bash
curl -v http://localhost:9091/api/v1/collections
# Expected on patched version: HTTP 401 Unauthorized
# Expected on unpatched version: HTTP 200 with collection list
```

Check the running version via the gRPC API:

```bash
curl http://milvus:19530/api/v1/version
```

### Network Isolation for Port 9091

Regardless of patch status, port 9091 should be accessible only to the monitoring systems that require it — specifically, the Prometheus scraper. All other inbound access to port 9091 should be blocked at the network layer.

For Linux hosts using iptables:

```bash
# Allow Prometheus scraper access to port 9091
iptables -A INPUT -p tcp --dport 9091 -s <monitoring-ip> -j ACCEPT

# Deny all other access to port 9091
iptables -A INPUT -p tcp --dport 9091 -j DROP
```

Make these rules persistent across reboots using `iptables-save` and the appropriate distribution-specific persistence mechanism.

For Kubernetes deployments, apply a NetworkPolicy that limits ingress to port 9091 to the Prometheus scraper pod exclusively:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: milvus-restrict-port-9091
  namespace: milvus
spec:
  podSelector:
    matchLabels:
      app: milvus
  ingress:
    # Allow gRPC API from application pods
    - ports:
        - port: 19530
          protocol: TCP
    # Allow metrics scraping from Prometheus only
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
          podSelector:
            matchLabels:
              app: prometheus
      ports:
        - port: 9091
          protocol: TCP
  policyTypes:
    - Ingress
```

Verify the restriction is in effect by attempting a connection to port 9091 from an application pod:

```bash
kubectl exec -n default deploy/ml-service -- \
  nmap -p 9091 milvus.milvus.svc.cluster.local
# Expected: filtered or closed — no response
```

### Milvus Authentication Configuration

Milvus 2.5.x and 2.6.x include built-in role-based access control that is disabled by default. Enable it explicitly in `milvus.yaml`:

```yaml
common:
  security:
    authorizationEnabled: true
    superUsers: root

# Configure the default root account password (change immediately after first deploy)
milvus:
  useragent:
    username: root
    password: "<strong-randomly-generated-password>"
```

After enabling authentication, create dedicated service accounts for each application rather than sharing the root credential:

```bash
# Using the Milvus CLI (pymilvus must be installed)
python3 - <<'EOF'
from pymilvus import connections, utility

connections.connect(
    host="localhost",
    port="19530",
    user="root",
    password="<root-password>"
)

# Create a service account for the ML inference service
utility.create_user("ml-svc", "<strong-service-password>")

# Grant collection-level read access only (no management operations)
utility.grant_role("ml-svc", "ml_reader")
EOF
```

Update all SDK clients to supply credentials. For the Python SDK:

```python
from pymilvus import connections, Collection

connections.connect(
    alias="default",
    host="milvus.internal",
    port="19530",
    user="ml-svc",
    password="<service-account-password>",
    secure=True,          # enforce TLS
    server_name="milvus.internal"
)

collection = Collection("user_embeddings")
results = collection.search(
    data=[query_embedding],
    anns_field="embedding",
    param={"metric_type": "COSINE", "params": {"ef": 64}},
    limit=10,
    output_fields=["document_id", "chunk_text"]
)
```

For Java and Go SDK clients, equivalent credential parameters exist in the `ConnectParam.Builder` and `client.NewGrpcClient` calls respectively — consult the Milvus SDK documentation for the target language.

### Changing the etcd rootPath

The default etcd `rootPath` value of `"by-dev"` is the basis for the predictable `/expr` debug token. Change it to a non-guessable string in `milvus.yaml` before initial deployment, or during a planned maintenance window on an existing cluster:

```yaml
etcd:
  rootPath: "<randomly-generated-alphanumeric-string-32-chars>"
  metaSubPath: meta
  kvSubPath: kv
```

**Important**: this value must be recorded in a secrets manager (HashiCorp Vault, AWS Secrets Manager, or equivalent) before applying it. If the `rootPath` value is lost, the cluster cannot locate its etcd metadata and all data becomes inaccessible without manual etcd key inspection. The change takes effect on Milvus restart. After restart, verify that the cluster initialises successfully and that all collections are visible before considering the change complete.

For clusters that are already in production with the default `"by-dev"` rootPath, treat this change as a migration requiring a full backup of etcd state prior to the restart.

### Monitoring Milvus Access

Configure Prometheus to scrape Milvus metrics from port 9091 using the credentials required after patching. In `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: milvus
    static_configs:
      - targets: ["milvus.milvus.svc.cluster.local:9091"]
    basic_auth:
      username: prometheus-scraper
      password_file: /etc/prometheus/secrets/milvus-scraper-password
    metrics_path: /metrics
```

Ship Milvus access logs to your SIEM. Key events to alert on:

- Any access to the `/expr` endpoint from a source IP other than known administrative hosts
- Collection deletion or schema modification operations outside approved maintenance windows
- User account creation or role modification operations
- High-volume entity read operations that do not match normal application query patterns

A Kubernetes-native log query to identify unexpected port 9091 activity:

```bash
kubectl logs -n milvus milvus-0 \
  | grep "9091" \
  | grep -v "prometheus" \
  | grep -v "healthz"
```

### Monitoring Milvus for Security Advisories

Subscribe to the Milvus GitHub security advisory feed and check the advisory list programmatically:

```bash
gh api repos/milvus-io/milvus/security/advisories \
  --jq '.[].summary'
```

Query the installed version against the OSV vulnerability database:

```bash
curl -s "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"milvus","ecosystem":"Go"},"version":"2.5.26"}' \
  | jq '.vulns[].id'
```

Use Renovate or Dependabot to track the Milvus Helm chart version and receive automated pull requests when new chart versions are published. Configure minimum version pinning to the patched releases (2.5.27 or 2.6.10) and treat Milvus chart version updates as high-priority security patches, not routine maintenance.

## Expected Behaviour

| Signal | Default Milvus (unpatched) | Patched + auth + network isolation |
|---|---|---|
| `GET http://milvus:9091/api/v1/collections` from application pod | HTTP 200 with full collection list — no credentials required | Connection refused or timed out — NetworkPolicy blocks access from application pods |
| `GET http://milvus:9091/api/v1/collections` from Prometheus pod | HTTP 200 with full collection list — no credentials required | HTTP 401 Unauthorized — authentication required even for scraper |
| `/expr` debug endpoint access using `by-dev`-derived token | Token accepted — arbitrary filter expressions execute against data store | Token rejected — etcd rootPath changed, derived token no longer valid |
| Prometheus metrics scrape on port 9091 | Succeeds unauthenticated | Succeeds with configured `basic_auth` credentials — metrics pipeline intact |
| RAG pipeline vector write via unauthenticated management API | Write accepted — any caller can insert, update, or delete vectors | Write rejected with HTTP 401 — service account credentials required, RBAC enforced |
| Shodan scan discovers port 9091 open | Port visible, full API accessible — appears in mass-scan results | Port filtered — does not respond to external probes, not indexed by scanners |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Enabling Milvus authentication (`authorizationEnabled: true`) | Eliminates unauthenticated access to the management API; enforces role-based access control | Every SDK client across every service must be updated with credentials; application deployments must manage secrets; connection errors occur for clients not yet updated | Use a secrets manager (Vault, AWS Secrets Manager) to distribute credentials; deploy credentials to all services before enabling auth; use a phased rollout with auth enabled in staging first |
| Network isolation of port 9091 via NetworkPolicy | Eliminates network-layer access to the management API from all pods except the Prometheus scraper; reduces attack surface from any compromised pod | Ad-hoc debugging from a kubectl exec shell is blocked; developers cannot curl port 9091 directly from inside the cluster during incident investigation | Maintain a documented break-glass procedure — temporarily modify the NetworkPolicy during active incident investigation, then restore it immediately after |
| Non-default etcd `rootPath` | Invalidates the predictable `/expr` debug token; prevents token-derivation attacks | If the rootPath value is lost, cluster recovery requires manual etcd key inspection; increases operational complexity for disaster recovery | Store the rootPath in a secrets manager with multiple authorised readers; include it in the DR runbook with clear recovery instructions |
| Milvus upgrade to 2.5.27 or 2.6.10 | Eliminates CVE-2026-26190 at the source; receives future security patches via the supported release branch | The embedding API surface or index behaviour may change between minor versions; existing vectors built with an older index configuration may require re-indexing | Test in a staging environment with a representative dataset before production upgrade; review the Milvus release notes for API and index compatibility changes; maintain a rollback plan with the previous image tag pinned |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Authentication enabled but SDK clients not updated | Application pods receive `connection refused` or `authentication failed` errors from the Milvus SDK; RAG queries fail with exceptions; ML inference degrades or stops entirely | Application error rate spike in monitoring; gRPC error codes in Milvus logs (`UNAUTHENTICATED`); SDK exception traces in application logs | Roll back `authorizationEnabled` to `false` as an emergency measure; update SDK clients with credentials from secrets manager; re-enable authentication after all clients are confirmed updated |
| NetworkPolicy blocks legitimate Prometheus scraper | Milvus metrics disappear from Prometheus; Grafana dashboards show "No data"; alerting rules based on Milvus metrics stop firing | Prometheus scrape error for the Milvus target (`context deadline exceeded`); Grafana panel shows data gap aligned with NetworkPolicy deployment timestamp | Verify the Prometheus pod's namespace label matches the `namespaceSelector` in the NetworkPolicy; verify the pod label matches the `podSelector`; correct the policy and apply — scraping resumes immediately |
| etcd rootPath change causes data inaccessibility | Milvus fails to start after restart; all collections appear missing; Milvus logs show etcd key-not-found errors for the new path | Milvus pod in CrashLoopBackOff with etcd-related error messages; `kubectl describe pod` shows failed readiness probe | Revert `milvus.yaml` to the previous rootPath value and restart Milvus — data remains intact in etcd under the original path; restore the correct rootPath from the secrets manager and retry the migration with proper etcd backup in place |
| Milvus upgrade changes embedding API or index format | Existing similarity search results are incorrect or produce dimension mismatch errors; new vectors cannot be inserted into collections built under the old version | SDK exceptions mentioning dimension mismatch or index incompatibility; search result quality degradation in application-layer monitoring | Pin the image to the previous version to restore service; rebuild affected collections with the new index format; re-embed affected documents with the current embedding model; cut over collection-by-collection with zero-downtime using dual-collection writes during migration |

## Related Articles

- [Vector Database Security in Kubernetes](/articles/kubernetes/vector-database-security/)
- [RAG Pipeline Security](/articles/kubernetes/rag-security/)
- [vLLM Production Security Hardening](/articles/ai-landscape/vllm-production-security/)
- [API Gateway Security](/articles/network/api-gateway-security/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
