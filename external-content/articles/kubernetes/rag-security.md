---
title: "Securing RAG Pipelines: Vector Database Access Control, Document Poisoning, and Retrieval Filtering"
description: "Retrieval-Augmented Generation (RAG) adds a knowledge base to LLM applications, the model retrieves relevant documents before generating a response."
slug: "rag-security"
date: 2026-02-24
lastmod: 2026-02-24
category: "kubernetes"
tags: ["rag", "vector-database", "document-poisoning", "retrieval", "ai-security"]
personas: ["ai-ml-engineer", "security-engineer"]
article_number: 81
difficulty: "advanced"
estimated_reading_time: 16
provider_bridges:
  - name: "Weaviate"
    id: 148
    category: "vector-databases"
  - name: "Qdrant"
    id: 149
    category: "vector-databases"
  - name: "Pinecone"
    id: 147
    category: "vector-databases"
premium_pack: "vector-db-hardening-configs"
published: true
layout: article.njk
permalink: "/articles/kubernetes/rag-security/index.html"
---

# Securing RAG Pipelines: [Vector](https://vector.dev) Database Access Control, Document Poisoning, and Retrieval Filtering

## Problem

Retrieval-Augmented Generation (RAG) adds a knowledge base to LLM applications, the model retrieves relevant documents before generating a response. This introduces a new attack surface: the vector database. An attacker who can poison the knowledge base controls what the model retrieves and references. Unauthorized access to the vector database exposes all indexed documents. Adversarial queries can extract sensitive information through careful retrieval manipulation.

Most RAG deployments treat the vector database as an internal service with no authentication, no access control, and no monitoring.

## Threat Model

- **Adversary:** (1) Attacker with write access to the indexing pipeline (can poison documents). (2) Attacker who can send queries to the RAG endpoint (can probe for sensitive data). (3) Internal user with broader access than intended (can query documents from other teams/tenants).
- **Objective:** Document poisoning (inject content that changes model behaviour), data extraction (retrieve confidential documents through the RAG pipeline), or knowledge base enumeration (map what documents exist).

## Configuration

### Vector Database Authentication

**[Weaviate](https://weaviate.io):**

```yaml
# weaviate-config.yaml
authentication:
  oidc:
    enabled: true
    issuer: "https://auth.example.com"
    client_id: "weaviate-rag"
    username_claim: "email"
    groups_claim: "groups"
  api_key:
    enabled: true
    allowed_keys:
      - "readonly-key-for-inference"
      - "readwrite-key-for-indexing"
    users:
      - "readonly-key-for-inference": readonly
      - "readwrite-key-for-indexing": admin

authorization:
  admin_list:
    enabled: true
    users:
      - "admin@example.com"
    read_only_users:
      - "inference@example.com"
```

**[Qdrant](https://qdrant.tech):**

```yaml
# qdrant-config.yaml
service:
  api_key: "${QDRANT_API_KEY}"
  enable_tls: true
  tls:
    cert: /certs/tls.crt
    key: /certs/tls.key
```

```python
# Python client with authentication
from qdrant_client import QdrantClient

client = QdrantClient(
    host="qdrant.internal",
    port=6333,
    api_key="${QDRANT_API_KEY}",
    https=True,
)
```

### Document Poisoning Prevention

```python
# indexing_validator.py - validate documents before indexing

import hashlib
from typing import Dict, Optional

class DocumentValidator:
    """Validate documents before they enter the vector database."""

    def __init__(self, allowed_sources: list, max_document_size: int = 100000):
        self.allowed_sources = allowed_sources
        self.max_document_size = max_document_size
        self.indexed_hashes = set()

    def validate(self, document: Dict) -> Optional[str]:
        """Returns None if valid, error message if invalid."""

        # 1. Source validation: only index from approved sources
        source = document.get("source", "")
        if not any(source.startswith(s) for s in self.allowed_sources):
            return f"Rejected: source '{source}' not in allowed sources"

        # 2. Size limit: prevent oversized documents that could skew retrieval
        content = document.get("content", "")
        if len(content) > self.max_document_size:
            return f"Rejected: document size {len(content)} exceeds limit {self.max_document_size}"

        # 3. Duplicate detection: prevent re-indexing the same content
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        if content_hash in self.indexed_hashes:
            return f"Rejected: duplicate content (hash {content_hash[:12]})"
        self.indexed_hashes.add(content_hash)

        # 4. Content safety: basic checks for injected instructions
        # More sophisticated: use a classifier model
        injection_patterns = [
            "ignore previous instructions",
            "you are now",
            "system prompt:",
            "IMPORTANT: override",
        ]
        content_lower = content.lower()
        for pattern in injection_patterns:
            if pattern in content_lower:
                return f"Rejected: potential injection pattern detected: '{pattern}'"

        return None  # Valid

# Usage:
validator = DocumentValidator(
    allowed_sources=["s3://docs-bucket/", "https://internal-wiki.example.com/"],
    max_document_size=100000
)
```

### Retrieval Filtering

```python
# retrieval_filter.py - filter retrieved documents before passing to the model

def filter_retrieval_results(results: list, user_context: dict) -> list:
    """Filter retrieval results based on user permissions and safety."""
    filtered = []

    for doc in results:
        # 1. Permission check: does this user have access to this document's classification?
        doc_classification = doc.metadata.get("classification", "public")
        user_clearance = user_context.get("clearance", "public")

        classification_hierarchy = ["public", "internal", "confidential", "restricted"]
        if classification_hierarchy.index(doc_classification) > classification_hierarchy.index(user_clearance):
            continue  # User doesn't have clearance for this document

        # 2. Relevance threshold: drop low-relevance results
        if doc.score < 0.7:  # Minimum similarity threshold
            continue

        # 3. Source attribution: add source metadata for transparency
        doc.metadata["retrieved_for"] = user_context.get("user_id")
        doc.metadata["retrieved_at"] = datetime.utcnow().isoformat()

        filtered.append(doc)

    return filtered
```

### Network Isolation for Vector Database

```yaml
# vector-db-network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: qdrant-access
  namespace: ai-data
spec:
  podSelector:
    matchLabels:
      app: qdrant
  policyTypes:
    - Ingress
  ingress:
    # Only allow inference service to query (read)
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ai-inference
          podSelector:
            matchLabels:
              app: rag-service
      ports:
        - port: 6333
          protocol: TCP
    # Only allow indexing pipeline to write
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ai-indexing
          podSelector:
            matchLabels:
              app: indexing-pipeline
      ports:
        - port: 6333
          protocol: TCP
```

### Query Monitoring

```yaml
# Prometheus alert: detect adversarial query patterns
groups:
  - name: rag-security
    rules:
      - alert: HighQueryVolume
        expr: rate(rag_queries_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Unusual RAG query volume: {{ $value | humanize }}/sec, possible data extraction attempt"

      - alert: LowRelevanceQuerySpike
        expr: >
          rate(rag_retrieval_score_below_threshold_total[5m])
          > 0.5 * rate(rag_queries_total[5m])
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "50%+ of RAG queries returning low-relevance results, possible probing"
```

## Expected Behaviour

- Vector database requires authentication for all queries and writes
- Only the inference service can read; only the indexing pipeline can write
- Documents validated before indexing (source, size, duplicate, injection patterns)
- Retrieved documents filtered by user permission level before passing to model
- Query monitoring detects unusual volume and low-relevance probing patterns
- Network policies restrict vector database access to authorized pods only

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Document validation at indexing | Adds 10-50ms per document; rejects some valid documents | Overly aggressive pattern matching blocks legitimate content | Tune injection patterns. Review rejections weekly. |
| Retrieval filtering by permission | Adds 1-5ms per query; reduces available knowledge base per user | Users see fewer results; may reduce answer quality | Set relevance threshold carefully. Monitor answer quality per permission level. |
| TLS for vector database | 1-5% throughput reduction | Adds certificate management for internal service | Use [cert-manager](https://cert-manager.io) for automatic certificate lifecycle. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Document poisoning succeeds | Model generates incorrect or manipulated responses | Output monitoring detects unexpected content; user reports incorrect answers | Identify and remove poisoned documents. Re-index from trusted sources. Review indexing pipeline access controls. |
| Permission filter too restrictive | Users get empty or poor-quality answers | Answer quality metrics drop for specific user groups | Review permission mappings. Adjust document classification levels. |
| Vector DB auth misconfigured | Unauthenticated access possible | Security scan detects open port; unauthorized queries in audit log | Fix authentication configuration. Rotate API keys. Audit access during exposure window. |

## When to Consider a Managed Alternative

Self-managed vector databases require HA, backup, access control, and capacity management.

- **[Pinecone](https://www.pinecone.io):** Fully managed, lowest operational overhead. Built-in authentication and access control.
- **[Weaviate](https://weaviate.io) Cloud:** Managed Weaviate with built-in auth and backup. From $25/month.
- **[Qdrant](https://qdrant.tech) Cloud:** Managed Qdrant with API key auth and TLS. From $25/month.

**Premium content pack:** Vector database hardening configuration pack. authentication configs for Weaviate, Qdrant, and [Milvus](https://milvus.io), document validation middleware, retrieval filtering library, [Kubernetes](https://kubernetes.io) network policies, and monitoring alert rules.


## Related Articles

- [Vector Database Security: Access Control, Embedding Protection, and Query Isolation](/articles/kubernetes/vector-database-security/)
- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration](/articles/kubernetes/model-serving-hardening/)
- [Securing Fine-Tuning Pipelines: Data Isolation, Checkpoint Integrity, and Access Control](/articles/kubernetes/fine-tuning-pipeline-security/)
- [RLHF Data Protection: Securing Human Feedback Loops, Preference Data, and Reward Models](/articles/kubernetes/rlhf-data-protection/)
