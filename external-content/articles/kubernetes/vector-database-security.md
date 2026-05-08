---
title: "Vector Database Security: Access Control, Embedding Protection, and Query Isolation"
description: "Vector databases are the backbone of RAG (Retrieval-Augmented Generation) systems."
slug: "vector-database-security"
date: 2026-02-18
lastmod: 2026-02-18
category: "kubernetes"
tags: ["vector-database", "qdrant", "weaviate", "embeddings", "rag", "ai-security"]
personas: ["ai-ml-engineer", "security-engineer", "platform-engineer"]
article_number: 120
difficulty: "intermediate"
estimated_reading_time: 18
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Snyk"
    id: 48
    category: "container-security"
premium_pack: "vector-db-security-configs"
published: true
layout: article.njk
permalink: "/articles/kubernetes/vector-database-security/index.html"
---

# [Vector](https://vector.dev) Database Security: Access Control, Embedding Protection, and Query Isolation

## Problem

Vector databases are the backbone of RAG (Retrieval-Augmented Generation) systems. They store document embeddings that encode the semantic content of proprietary data: internal documentation, customer records, legal documents, and codebases. Unlike traditional databases, vector stores are often deployed with minimal security because they are treated as "just a cache" or "an index." Most self-hosted deployments of Qdrant, Weaviate, or Milvus ship with no authentication, no TLS, and no namespace isolation.

An attacker who gains access to a vector database can reconstruct sensitive information from embeddings, query across tenant boundaries in multi-tenant RAG systems, poison the retrieval pipeline by injecting malicious documents, or exhaust resources through expensive nearest-neighbor queries. Because embeddings are dense numerical representations, traditional DLP tools do not flag them as sensitive data, even though they encode proprietary content.

**Target systems:** Self-hosted Qdrant, Weaviate, or Milvus on [Kubernetes](https://kubernetes.io). Also applies to managed services (Pinecone, Zilliz) where client-side controls are needed.

## Threat Model

- **Adversary:** Internal user with network access to the vector database, or external attacker who has compromised an application with database connectivity.
- **Objective:** Embedding extraction (download embeddings to reconstruct source documents). Cross-tenant data access (query one tenant's data from another tenant's context). Retrieval poisoning (inject embeddings that cause the RAG pipeline to retrieve misleading content). Denial of service (run expensive similarity searches that exhaust CPU/memory).
- **Blast radius:** Proprietary data reconstructed from embeddings (confidentiality). RAG pipeline returns poisoned results (integrity). Vector database unavailable due to resource exhaustion (availability).

## Configuration

### Qdrant Authentication and TLS

Qdrant supports API key authentication starting from version 1.7. Enable it alongside TLS.

```yaml
# qdrant-config.yaml - hardened Qdrant configuration
apiVersion: v1
kind: ConfigMap
metadata:
  name: qdrant-config
  namespace: vector-db
data:
  config.yaml: |
    service:
      host: 0.0.0.0
      http_port: 6333
      grpc_port: 6334

      # Enable API key authentication
      api_key: "${QDRANT_API_KEY}"

      # Enable read-only API key for query-only clients
      read_only_api_key: "${QDRANT_READ_ONLY_KEY}"

      # TLS configuration
      enable_tls: true
      tls:
        cert: /certs/tls.crt
        key: /certs/tls.key
        ca_cert: /certs/ca.crt

      # Request size limits
      max_request_size_mb: 32

    storage:
      # Storage path on the encrypted volume
      storage_path: /qdrant/storage

      # Snapshot security
      snapshots_path: /qdrant/snapshots

      # Performance tuning that also limits resource abuse
      optimizers:
        max_optimization_threads: 2
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: qdrant
  namespace: vector-db
spec:
  serviceName: qdrant
  replicas: 1
  selector:
    matchLabels:
      app: qdrant
  template:
    metadata:
      labels:
        app: qdrant
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: qdrant
          image: qdrant/qdrant:v1.12.0
          ports:
            - containerPort: 6333
              name: http
            - containerPort: 6334
              name: grpc
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            - name: QDRANT_API_KEY
              valueFrom:
                secretKeyRef:
                  name: qdrant-credentials
                  key: api-key
            - name: QDRANT_READ_ONLY_KEY
              valueFrom:
                secretKeyRef:
                  name: qdrant-credentials
                  key: read-only-key
          resources:
            requests:
              cpu: "2"
              memory: "4Gi"
            limits:
              cpu: "4"
              memory: "8Gi"
          volumeMounts:
            - name: data
              mountPath: /qdrant/storage
            - name: snapshots
              mountPath: /qdrant/snapshots
            - name: config
              mountPath: /qdrant/config/config.yaml
              subPath: config.yaml
              readOnly: true
            - name: certs
              mountPath: /certs
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: qdrant-config
        - name: certs
          secret:
            secretName: qdrant-tls
            defaultMode: 0440
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 100Gi
        storageClassName: encrypted-gp3  # Encryption at rest via storage class
    - metadata:
        name: snapshots
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 50Gi
        storageClassName: encrypted-gp3
```

### Weaviate Authentication and Multi-Tenancy

```yaml
# weaviate-config.yaml - hardened Weaviate with OIDC and multi-tenancy
apiVersion: v1
kind: ConfigMap
metadata:
  name: weaviate-config
  namespace: vector-db
data:
  conf.yaml: |
    authentication:
      # OIDC authentication for production
      oidc:
        enabled: true
        issuer: https://auth.example.com/realms/ml
        client_id: weaviate
        username_claim: email
        groups_claim: groups

      # API key authentication as fallback
      apikey:
        enabled: true
        allowed_keys:
          - "${WEAVIATE_ADMIN_KEY}"
          - "${WEAVIATE_READONLY_KEY}"
        users:
          - admin@example.com
          - readonly@example.com

    authorization:
      # Role-based access control
      rbac:
        enabled: true
        admins:
          - admin@example.com
        viewers:
          - readonly@example.com
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: weaviate
  namespace: vector-db
spec:
  serviceName: weaviate
  replicas: 1
  selector:
    matchLabels:
      app: weaviate
  template:
    metadata:
      labels:
        app: weaviate
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: weaviate
          image: cr.weaviate.io/semitechnologies/weaviate:1.27.0
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 50051
              name: grpc
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            - name: AUTHENTICATION_OIDC_ENABLED
              value: "true"
            - name: AUTHENTICATION_OIDC_ISSUER
              value: "https://auth.example.com/realms/ml"
            - name: AUTHENTICATION_OIDC_CLIENT_ID
              value: "weaviate"
            - name: AUTHORIZATION_RBAC_ENABLED
              value: "true"
            - name: QUERY_DEFAULTS_LIMIT
              value: "100"  # Limit default query results
            - name: QUERY_MAXIMUM_RESULTS
              value: "1000"  # Hard cap on returned results
            - name: LIMIT_RESOURCES
              value: "true"
          resources:
            requests:
              cpu: "2"
              memory: "4Gi"
            limits:
              cpu: "4"
              memory: "8Gi"
          volumeMounts:
            - name: data
              mountPath: /var/lib/weaviate
      volumes: []
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 100Gi
        storageClassName: encrypted-gp3
```

### Namespace Isolation for Multi-Tenant RAG

Use Qdrant collections or Weaviate tenants to isolate data per customer, combined with application-level enforcement.

```python
# tenant_isolation.py - application-level tenant isolation for Qdrant
from functools import wraps
from typing import Optional

from flask import Flask, g, jsonify, request
from qdrant_client import QdrantClient
from qdrant_client.http.models import (
    Distance,
    Filter,
    FieldCondition,
    MatchValue,
    PointStruct,
    VectorParams,
)

app = Flask(__name__)

qdrant = QdrantClient(
    url="https://qdrant.vector-db.svc.cluster.local:6333",
    api_key="<from-secret>",
    https=True,
)


def require_tenant(f):
    """Extract and validate tenant ID from the authenticated request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Tenant ID comes from the verified JWT (set by gateway)
        tenant_id = request.headers.get("X-Tenant-Id")
        if not tenant_id:
            return jsonify({"error": "tenant ID required"}), 400

        # Validate tenant ID format (prevent injection)
        if not tenant_id.isalnum() or len(tenant_id) > 64:
            return jsonify({"error": "invalid tenant ID"}), 400

        g.tenant_id = tenant_id
        return f(*args, **kwargs)
    return decorated


def get_tenant_collection(tenant_id: str) -> str:
    """Map tenant ID to a dedicated Qdrant collection."""
    return f"tenant_{tenant_id}_embeddings"


def ensure_tenant_collection(tenant_id: str):
    """Create a collection for a tenant if it does not exist."""
    collection_name = get_tenant_collection(tenant_id)
    collections = [c.name for c in qdrant.get_collections().collections]
    if collection_name not in collections:
        qdrant.create_collection(
            collection_name=collection_name,
            vectors_config=VectorParams(size=1536, distance=Distance.COSINE),
        )


@app.route("/api/v1/search", methods=["POST"])
@require_tenant
def search():
    """Search within the tenant's isolated collection only."""
    data = request.get_json()
    query_vector = data.get("vector")
    top_k = min(data.get("top_k", 10), 100)  # Cap results

    collection_name = get_tenant_collection(g.tenant_id)

    results = qdrant.search(
        collection_name=collection_name,  # Tenant-scoped collection
        query_vector=query_vector,
        limit=top_k,
        with_payload=True,
        with_vectors=False,  # Never return raw embeddings to clients
    )

    return jsonify({
        "results": [
            {
                "id": str(r.id),
                "score": r.score,
                "metadata": r.payload,
                # Embeddings are NOT included in the response
            }
            for r in results
        ]
    })


@app.route("/api/v1/ingest", methods=["POST"])
@require_tenant
def ingest():
    """Ingest embeddings into the tenant's isolated collection."""
    data = request.get_json()
    points = data.get("points", [])

    if len(points) > 1000:  # Batch size limit
        return jsonify({"error": "max 1000 points per request"}), 400

    collection_name = get_tenant_collection(g.tenant_id)
    ensure_tenant_collection(g.tenant_id)

    qdrant_points = [
        PointStruct(
            id=p["id"],
            vector=p["vector"],
            payload={
                **p.get("metadata", {}),
                "tenant_id": g.tenant_id,  # Always stamp tenant ID
            },
        )
        for p in points
    ]

    qdrant.upsert(collection_name=collection_name, points=qdrant_points)
    return jsonify({"status": "ok", "count": len(qdrant_points)})
```

### Network Policy for Vector Database

```yaml
# vector-db-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: qdrant-access
  namespace: vector-db
spec:
  podSelector:
    matchLabels:
      app: qdrant
  policyTypes:
    - Ingress
  ingress:
    # Only allow access from the RAG application namespace
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: rag-application
          podSelector:
            matchLabels:
              component: retrieval-service
      ports:
        - port: 6333
          protocol: TCP
        - port: 6334
          protocol: TCP
    # Allow access from the ingestion pipeline namespace
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: data-ingestion
          podSelector:
            matchLabels:
              component: embedding-pipeline
      ports:
        - port: 6333
          protocol: TCP
```

### Query Rate Limiting

Prevent resource exhaustion from expensive similarity searches.

```yaml
# rate-limit-policy.yaml - Istio rate limiting for vector DB queries
apiVersion: networking.istio.io/v1
kind: EnvoyFilter
metadata:
  name: qdrant-rate-limit
  namespace: vector-db
spec:
  workloadSelector:
    labels:
      app: qdrant
  configPatches:
    - applyTo: HTTP_FILTER
      match:
        context: SIDECAR_INBOUND
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.local_ratelimit
          typed_config:
            "@type": type.googleapis.com/udpa.type.v1.TypedStruct
            type_url: type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
            value:
              stat_prefix: qdrant_rate_limit
              token_bucket:
                max_tokens: 100
                tokens_per_fill: 50
                fill_interval: 60s
              filter_enabled:
                runtime_key: local_rate_limit_enabled
                default_value:
                  numerator: 100
                  denominator: HUNDRED
              filter_enforced:
                runtime_key: local_rate_limit_enforced
                default_value:
                  numerator: 100
                  denominator: HUNDRED
              response_headers_to_add:
                - append_action: OVERWRITE_IF_EXISTS_OR_ADD
                  header:
                    key: x-ratelimit-limit
                    value: "100"
```

### Audit Logging for Vector Database Operations

```python
# vector_audit.py - audit logging middleware
import json
import logging
import time
from datetime import datetime, timezone
from functools import wraps

from flask import g, request

audit_logger = logging.getLogger("vector.audit")
handler = logging.FileHandler("/var/log/vector-db/audit.jsonl")
audit_logger.addHandler(handler)
audit_logger.setLevel(logging.INFO)


def audit_log(operation: str):
    """Decorator to log vector database operations."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = f(*args, **kwargs)
                duration = time.time() - start
                entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "operation": operation,
                    "tenant_id": getattr(g, "tenant_id", "unknown"),
                    "source_ip": request.remote_addr,
                    "user_agent": request.headers.get("User-Agent", ""),
                    "duration_ms": round(duration * 1000, 2),
                    "status": "success",
                    "collection": getattr(g, "collection", "unknown"),
                    "result_count": _extract_count(result),
                }
                audit_logger.info(json.dumps(entry))
                return result
            except Exception as e:
                duration = time.time() - start
                entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "operation": operation,
                    "tenant_id": getattr(g, "tenant_id", "unknown"),
                    "source_ip": request.remote_addr,
                    "duration_ms": round(duration * 1000, 2),
                    "status": "error",
                    "error": str(e),
                }
                audit_logger.error(json.dumps(entry))
                raise
        return wrapper
    return decorator


def _extract_count(response) -> int:
    """Extract result count from a Flask response."""
    try:
        data = json.loads(response.get_data(as_text=True))
        return len(data.get("results", []))
    except (json.JSONDecodeError, AttributeError):
        return 0
```

### Preventing Embedding Extraction

Configure the retrieval API to never return raw embedding vectors. Clients should only receive metadata and relevance scores.

```python
# safe_search.py - search endpoint that strips embeddings
from qdrant_client import QdrantClient


def safe_search(
    client: QdrantClient,
    collection: str,
    query_vector: list[float],
    top_k: int = 10,
) -> list[dict]:
    """
    Search that never returns raw embeddings.

    Even if the client requests with_vectors=True, we override it.
    Embeddings are internal representations and should not leave
    the retrieval service.
    """
    results = client.search(
        collection_name=collection,
        query_vector=query_vector,
        limit=min(top_k, 100),
        with_payload=True,
        with_vectors=False,  # Never expose embeddings
    )

    return [
        {
            "id": str(r.id),
            "score": r.score,
            "metadata": {
                k: v
                for k, v in r.payload.items()
                if k not in ("_tenant_id", "_internal_tags")
            },
        }
        for r in results
    ]
```

## Expected Behaviour

- Vector database requires API key or OIDC authentication for all operations
- All connections use TLS; data at rest is encrypted via the storage class
- Each tenant's embeddings are stored in isolated collections; cross-tenant queries are impossible at the application layer
- Raw embedding vectors are never returned to clients; only metadata and relevance scores
- Query rate limiting prevents resource exhaustion from expensive similarity searches
- All search, ingest, and delete operations are audit-logged with tenant ID, source IP, and duration
- Network policies restrict access to the vector database to only the retrieval service and ingestion pipeline

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Per-tenant collections | More collections to manage; higher memory usage | Collection count grows linearly with tenants | Use Weaviate multi-tenancy (single collection, tenant isolation) for high tenant counts. Qdrant collection-per-tenant works up to hundreds of tenants. |
| Never returning embeddings | Clients cannot cache or reuse embeddings locally | Increases query load since clients must re-query for similar searches | Implement server-side caching. Provide a "re-rank" API that operates on IDs rather than vectors. |
| API key authentication | Simpler than OIDC but less granular | Single key compromise exposes all data | Rotate keys regularly. Use OIDC for user-facing access. Use separate read-only keys for query workloads. |
| Query rate limiting | Prevents abuse but may throttle legitimate batch operations | Data ingestion pipelines hit rate limits | Use separate rate limit tiers per client type. Exempt the ingestion pipeline service account from search rate limits. |
| Encrypted storage class | Slight I/O overhead (typically under 5%) | Performance impact on high-throughput vector search | Modern storage encryption (AES-NI) has negligible overhead. Profile before and after to confirm. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Embedding extraction via API | Attacker downloads large batches of embeddings | Audit logs show bulk queries with unusually high result counts; rate limit alerts fire | Revoke the compromised API key. Verify `with_vectors=False` is enforced server-side. Review audit logs for data scope. |
| Cross-tenant data leakage | Tenant A's search returns results from Tenant B | Application logs show collection name mismatch; integration tests detect cross-tenant results | Fix the tenant-to-collection mapping. Audit all queries from the affected time window. Notify affected tenants. |
| Retrieval poisoning | RAG pipeline returns misleading or harmful content | Output quality metrics degrade; users report incorrect answers | Identify poisoned embeddings via ingestion audit log. Delete the malicious points. Re-ingest from clean source. |
| Rate limit too aggressive | Legitimate queries are rejected with 429 errors | Application error rates spike; client-side retry storms | Increase rate limits. Implement client-side backoff. Use separate limits for different API paths (search vs. ingest). |
| Vector database OOM | Qdrant/Weaviate crashes under memory pressure | Pod restarts; OOMKilled events in Kubernetes | Increase memory limits. Enable disk-based indexing (Qdrant: on_disk=true). Reduce the number of loaded collections. |

## When to Consider a Managed Alternative

Managed vector databases handle authentication, encryption, scaling, and multi-tenancy.

- **Pinecone:** Fully managed vector database with built-in RBAC, encryption, and namespace isolation.
- **Zilliz Cloud:** Managed Milvus with authentication, TLS, and role-based access.
- **Weaviate Cloud:** Managed Weaviate with OIDC, RBAC, and automatic backups.
- **[Cloudflare](https://www.cloudflare.com):** Vectorize for edge-deployed vector search with built-in security.
- **[Snyk](https://snyk.io):** Scan vector database container images for vulnerabilities.

**Premium content pack:** Hardened Qdrant and Weaviate Kubernetes manifests, tenant isolation middleware, audit logging configurations, network policies, and rate limiting templates.


## Related Articles

- [Securing RAG Pipelines: Vector Database Access Control, Document Poisoning, and Retrieval Filtering](/articles/kubernetes/rag-security/)
- [Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration](/articles/kubernetes/model-serving-hardening/)
- [RLHF Data Protection: Securing Human Feedback Loops, Preference Data, and Reward Models](/articles/kubernetes/rlhf-data-protection/)
- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [Securing Fine-Tuning Pipelines: Data Isolation, Checkpoint Integrity, and Access Control](/articles/kubernetes/fine-tuning-pipeline-security/)
