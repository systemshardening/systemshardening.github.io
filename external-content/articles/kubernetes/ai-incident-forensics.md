---
title: "AI Incident Forensics: Reconstructing What an AI System Did, Why, and What Data It Accessed"
description: "When a traditional application causes an incident, you examine logs, traces, and database queries to reconstruct what happened."
slug: "ai-incident-forensics"
date: 2026-03-19
lastmod: 2026-03-19
category: "kubernetes"
tags: ["incident-forensics", "ai-security", "logging", "audit-trail", "trace-reconstruction"]
personas: ["security-engineer", "sre", "ai-ml-engineer"]
article_number: 135
difficulty: "advanced"
estimated_reading_time: 18
provider_bridges:
  - name: "Grafana Cloud"
    id: 108
    category: "observability"
  - name: "Elastic"
    id: 129
    category: "observability"
premium_pack: "ai-forensics-toolkit"
published: true
layout: article.njk
permalink: "/articles/kubernetes/ai-incident-forensics/index.html"
---

# AI Incident Forensics: Reconstructing What an AI System Did, Why, and What Data It Accessed

## Problem

When a traditional application causes an incident, you examine logs, traces, and database queries to reconstruct what happened. When an AI system causes an incident, the standard logs show "user sent request, model returned response." They do not tell you which documents the model retrieved, what the model's reasoning was, whether guardrails were bypassed, or what training data influenced the output.

AI incident forensics is harder than traditional forensics because: (1) Model behaviour is non-deterministic, the same input may not reproduce the same output. (2) Context is distributed, the model's response depends on system prompt, conversation history, retrieved documents, tool call results, and temperature settings, none of which are captured by default. (3) Evidence is ephemeral, streaming responses, in-memory context windows, and transient tool calls are not persisted unless explicitly logged.

Without forensic logging, when an AI system generates harmful content, leaks data, or takes unauthorized actions, you cannot answer the basic incident response questions: what happened, why, and what was the impact.

## Threat Model

- **Adversary:** This article addresses incident response capability, not a specific adversary. The "adversary" is any event that requires forensic reconstruction: safety violations, data leaks, unauthorized actions, compliance investigations, or user complaints.
- **Objective:** Build the logging and tracing infrastructure needed to reconstruct any AI system action after the fact. Answer: what input triggered it, what context influenced it, what the model did, what data it accessed, and what output reached the user.
- **Blast radius:** Without forensic capability: incidents cannot be investigated, root causes cannot be identified, regulatory inquiries cannot be answered, and repeat incidents cannot be prevented.

## Configuration

### Comprehensive AI Action Logging

```python
# ai_forensic_logger.py - structured logging for AI system actions
import json
import uuid
import time
import hashlib
from typing import Optional, List, Any
from dataclasses import dataclass, field, asdict

@dataclass
class AIForensicLog:
    """
    Structured forensic log entry for a single AI interaction.
    Captures the full context needed to reconstruct what happened.
    """
    # Identity
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    span_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_span_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    # Request context
    user_id: str = ""
    session_id: str = ""
    api_key_hash: str = ""  # hash, never log actual key
    source_ip: str = ""
    endpoint: str = ""

    # Model context
    model_name: str = ""
    model_version: str = ""
    system_prompt_hash: str = ""  # hash for integrity verification
    temperature: float = 0.0
    max_tokens: int = 0

    # Input/Output capture
    user_input: str = ""
    user_input_hash: str = ""
    conversation_history_length: int = 0
    retrieved_documents: List[dict] = field(default_factory=list)
    tool_calls: List[dict] = field(default_factory=list)
    model_output: str = ""
    model_output_hash: str = ""
    output_tokens: int = 0
    input_tokens: int = 0

    # Guardrails results
    pre_filter_result: dict = field(default_factory=dict)
    post_filter_result: dict = field(default_factory=dict)
    output_modified: bool = False
    original_output_hash: Optional[str] = None

    # Timing
    total_latency_ms: float = 0.0
    inference_latency_ms: float = 0.0
    guardrail_latency_ms: float = 0.0
    retrieval_latency_ms: float = 0.0


class AIForensicLogger:
    """
    Logger that captures forensic-grade records of AI system actions.
    Writes structured JSON logs that can be queried for incident investigation.
    """

    def __init__(self, log_output: str = "stdout", retention_days: int = 90):
        self.log_output = log_output
        self.retention_days = retention_days

    def _hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def create_log(self, user_id: str, session_id: str, api_key: str,
                   endpoint: str, source_ip: str) -> AIForensicLog:
        return AIForensicLog(
            user_id=user_id,
            session_id=session_id,
            api_key_hash=self._hash_content(api_key),
            endpoint=endpoint,
            source_ip=source_ip,
        )

    def record_input(self, log: AIForensicLog, user_input: str,
                     system_prompt: str, conversation_history: list):
        log.user_input = user_input
        log.user_input_hash = self._hash_content(user_input)
        log.system_prompt_hash = self._hash_content(system_prompt)
        log.conversation_history_length = len(conversation_history)

    def record_retrieval(self, log: AIForensicLog, documents: list,
                         latency_ms: float):
        log.retrieved_documents = [
            {
                "doc_id": doc.get("id", "unknown"),
                "source": doc.get("source", "unknown"),
                "similarity_score": doc.get("score", 0.0),
                "content_hash": self._hash_content(doc.get("content", "")),
                "content_preview": doc.get("content", "")[:200],
            }
            for doc in documents
        ]
        log.retrieval_latency_ms = latency_ms

    def record_tool_calls(self, log: AIForensicLog, tool_calls: list):
        log.tool_calls = [
            {
                "tool_name": tc.get("name", "unknown"),
                "arguments": tc.get("arguments", {}),
                "result_hash": self._hash_content(str(tc.get("result", ""))),
                "result_preview": str(tc.get("result", ""))[:200],
                "timestamp": tc.get("timestamp", time.time()),
                "success": tc.get("success", True),
            }
            for tc in tool_calls
        ]

    def record_output(self, log: AIForensicLog, model_output: str,
                      filtered_output: str, inference_latency_ms: float,
                      input_tokens: int, output_tokens: int,
                      pre_filter: dict, post_filter: dict):
        log.model_output = filtered_output
        log.model_output_hash = self._hash_content(filtered_output)
        log.inference_latency_ms = inference_latency_ms
        log.input_tokens = input_tokens
        log.output_tokens = output_tokens
        log.pre_filter_result = pre_filter
        log.post_filter_result = post_filter

        if model_output != filtered_output:
            log.output_modified = True
            log.original_output_hash = self._hash_content(model_output)

    def emit(self, log: AIForensicLog):
        log.total_latency_ms = (time.time() - log.timestamp) * 1000
        log_dict = asdict(log)
        log_dict["@timestamp"] = log.timestamp
        log_dict["log_type"] = "ai_forensic"

        if self.log_output == "stdout":
            print(json.dumps(log_dict))
        else:
            with open(self.log_output, "a") as f:
                f.write(json.dumps(log_dict) + "\n")
```

### Trace Reconstruction from Distributed Logs

```python
# trace_reconstructor.py - reconstruct AI interaction traces from distributed logs
from typing import List, Optional
from dataclasses import dataclass
import json

@dataclass
class ReconstructedTrace:
    trace_id: str
    spans: List[dict]
    timeline: List[dict]
    data_accessed: List[dict]
    guardrails_applied: List[dict]
    anomalies: List[str]

class TraceReconstructor:
    """
    Reconstruct a complete AI interaction trace from distributed logs.
    Correlates logs across services using trace_id.
    """

    def reconstruct(self, trace_id: str, log_entries: List[dict]) -> ReconstructedTrace:
        """
        Given a trace_id and all log entries matching it,
        reconstruct the full interaction timeline.
        """
        # Sort by timestamp
        sorted_entries = sorted(log_entries, key=lambda e: e.get("timestamp", 0))

        spans = []
        timeline = []
        data_accessed = []
        guardrails_applied = []
        anomalies = []

        for entry in sorted_entries:
            log_type = entry.get("log_type", "unknown")

            # Build timeline
            timeline.append({
                "timestamp": entry.get("timestamp"),
                "service": entry.get("service", "unknown"),
                "action": entry.get("action", log_type),
                "span_id": entry.get("span_id"),
                "details": self._extract_key_details(entry),
            })

            # Track spans
            spans.append({
                "span_id": entry.get("span_id"),
                "parent_span_id": entry.get("parent_span_id"),
                "service": entry.get("service"),
                "duration_ms": entry.get("total_latency_ms", 0),
            })

            # Track data access
            if entry.get("retrieved_documents"):
                for doc in entry["retrieved_documents"]:
                    data_accessed.append({
                        "type": "document_retrieval",
                        "doc_id": doc.get("doc_id"),
                        "source": doc.get("source"),
                        "timestamp": entry.get("timestamp"),
                    })

            if entry.get("tool_calls"):
                for tc in entry["tool_calls"]:
                    data_accessed.append({
                        "type": "tool_call",
                        "tool": tc.get("tool_name"),
                        "arguments": tc.get("arguments"),
                        "timestamp": tc.get("timestamp"),
                    })

            # Track guardrails
            if entry.get("pre_filter_result"):
                guardrails_applied.append({
                    "stage": "pre-processing",
                    "result": entry["pre_filter_result"],
                    "timestamp": entry.get("timestamp"),
                })
            if entry.get("post_filter_result"):
                guardrails_applied.append({
                    "stage": "post-processing",
                    "result": entry["post_filter_result"],
                    "timestamp": entry.get("timestamp"),
                })

            # Detect anomalies
            if entry.get("output_modified"):
                anomalies.append(
                    f"Output was modified by post-processing at {entry.get('timestamp')}"
                )
            if entry.get("pre_filter_result", {}).get("blocked"):
                anomalies.append(
                    f"Request was blocked by pre-processing: "
                    f"{entry['pre_filter_result'].get('reason')}"
                )

        return ReconstructedTrace(
            trace_id=trace_id,
            spans=spans,
            timeline=timeline,
            data_accessed=data_accessed,
            guardrails_applied=guardrails_applied,
            anomalies=anomalies,
        )

    def _extract_key_details(self, entry: dict) -> dict:
        return {
            "user_input_hash": entry.get("user_input_hash"),
            "output_hash": entry.get("model_output_hash"),
            "model": entry.get("model_name"),
            "tokens": entry.get("output_tokens"),
        }

    def generate_forensic_report(self, trace: ReconstructedTrace) -> dict:
        return {
            "trace_id": trace.trace_id,
            "span_count": len(trace.spans),
            "timeline_events": len(trace.timeline),
            "data_access_events": len(trace.data_accessed),
            "guardrails_stages": len(trace.guardrails_applied),
            "anomalies_found": len(trace.anomalies),
            "anomaly_details": trace.anomalies,
            "timeline": trace.timeline,
            "data_accessed": trace.data_accessed,
        }
```

### Evidence Preservation

```yaml
# forensic-logging-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-forensic-collector
  namespace: ai-services
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ai-forensic-collector
  template:
    metadata:
      labels:
        app: ai-forensic-collector
    spec:
      containers:
        - name: collector
          image: internal-registry/ai-forensic-collector:1.2.0
          ports:
            - containerPort: 8080
          env:
            - name: LOG_RETENTION_DAYS
              value: "90"
            - name: STORAGE_BACKEND
              value: "elasticsearch"
            - name: ES_URL
              value: "http://elasticsearch.logging.svc:9200"
            - name: ES_INDEX_PREFIX
              value: "ai-forensic"
            - name: HASH_PII
              value: "true"
            - name: CAPTURE_FULL_OUTPUT
              value: "true"
          resources:
            requests:
              cpu: 500m
              memory: 1Gi
            limits:
              cpu: "1"
              memory: 2Gi
          volumeMounts:
            - name: buffer
              mountPath: /data/buffer
      volumes:
        - name: buffer
          emptyDir:
            sizeLimit: 5Gi
---
# Elasticsearch index template for forensic logs
apiVersion: v1
kind: ConfigMap
metadata:
  name: forensic-index-template
  namespace: ai-services
data:
  template.json: |
    {
      "index_patterns": ["ai-forensic-*"],
      "settings": {
        "number_of_shards": 3,
        "number_of_replicas": 1,
        "index.lifecycle.name": "ai-forensic-retention",
        "index.lifecycle.rollover_alias": "ai-forensic"
      },
      "mappings": {
        "properties": {
          "@timestamp": {"type": "date"},
          "trace_id": {"type": "keyword"},
          "span_id": {"type": "keyword"},
          "user_id": {"type": "keyword"},
          "session_id": {"type": "keyword"},
          "api_key_hash": {"type": "keyword"},
          "model_name": {"type": "keyword"},
          "model_version": {"type": "keyword"},
          "system_prompt_hash": {"type": "keyword"},
          "user_input": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
          "user_input_hash": {"type": "keyword"},
          "model_output": {"type": "text"},
          "model_output_hash": {"type": "keyword"},
          "output_modified": {"type": "boolean"},
          "original_output_hash": {"type": "keyword"},
          "input_tokens": {"type": "integer"},
          "output_tokens": {"type": "integer"},
          "total_latency_ms": {"type": "float"},
          "inference_latency_ms": {"type": "float"},
          "retrieved_documents": {"type": "nested"},
          "tool_calls": {"type": "nested"},
          "pre_filter_result": {"type": "object"},
          "post_filter_result": {"type": "object"}
        }
      }
    }
```

### Timeline Reconstruction Queries

```python
# forensic_queries.py - common forensic queries for incident investigation
from datetime import datetime, timedelta
from typing import Optional

class ForensicQueryBuilder:
    """
    Build Elasticsearch queries for common forensic investigation scenarios.
    """

    def __init__(self, es_client, index_prefix: str = "ai-forensic"):
        self.es = es_client
        self.index = f"{index_prefix}-*"

    def find_by_trace_id(self, trace_id: str) -> dict:
        """Reconstruct a single interaction by trace ID."""
        return self.es.search(
            index=self.index,
            body={
                "query": {"term": {"trace_id": trace_id}},
                "sort": [{"@timestamp": "asc"}],
                "size": 100,
            },
        )

    def find_safety_violations(self, hours: int = 24) -> dict:
        """Find all interactions where guardrails blocked or modified output."""
        return self.es.search(
            index=self.index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                            {"bool": {"should": [
                                {"term": {"output_modified": True}},
                                {"exists": {"field": "post_filter_result.blocked_reason"}},
                            ]}},
                        ]
                    }
                },
                "sort": [{"@timestamp": "desc"}],
                "size": 500,
            },
        )

    def find_user_interactions(self, user_id: str,
                                start: Optional[datetime] = None,
                                end: Optional[datetime] = None) -> dict:
        """Find all interactions for a specific user (e.g., for compliance review)."""
        must = [{"term": {"user_id": user_id}}]
        if start:
            must.append({"range": {"@timestamp": {"gte": start.isoformat()}}})
        if end:
            must.append({"range": {"@timestamp": {"lte": end.isoformat()}}})

        return self.es.search(
            index=self.index,
            body={
                "query": {"bool": {"must": must}},
                "sort": [{"@timestamp": "asc"}],
                "size": 1000,
            },
        )

    def find_data_access(self, doc_id: str) -> dict:
        """Find all interactions that accessed a specific document (for data breach investigation)."""
        return self.es.search(
            index=self.index,
            body={
                "query": {
                    "nested": {
                        "path": "retrieved_documents",
                        "query": {"term": {"retrieved_documents.doc_id": doc_id}},
                    }
                },
                "sort": [{"@timestamp": "desc"}],
                "size": 500,
            },
        )

    def find_tool_usage(self, tool_name: str, hours: int = 24) -> dict:
        """Find all interactions that called a specific tool."""
        return self.es.search(
            index=self.index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                            {"nested": {
                                "path": "tool_calls",
                                "query": {"term": {"tool_calls.tool_name": tool_name}},
                            }},
                        ]
                    }
                },
                "sort": [{"@timestamp": "desc"}],
                "size": 500,
            },
        )
```

### [Prometheus](https://prometheus.io) Alerting for Forensic Infrastructure

```yaml
# prometheus-forensic-infra.yaml
groups:
  - name: forensic-infrastructure
    interval: 1m
    rules:
      # Alert if forensic logging stops
      - alert: ForensicLoggingGap
        expr: >
          rate(ai_forensic_logs_total[5m]) == 0
          and
          rate(llm_requests_total[5m]) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "AI forensic logging has stopped while requests continue"
          description: >
            LLM requests are being processed but forensic logs are not being written.
            This creates a gap in forensic coverage. Investigate immediately.

      # Alert on log ingestion lag
      - alert: ForensicIngestionLag
        expr: ai_forensic_ingestion_lag_seconds > 60
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Forensic log ingestion is lagging by {{ $value | humanize }}s"

      # Alert on missing fields in forensic logs
      - alert: ForensicLogIncomplete
        expr: >
          rate(ai_forensic_incomplete_logs_total[5m])
          / rate(ai_forensic_logs_total[5m]) > 0.05
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: ">5% of forensic logs are missing required fields"
```

## Expected Behaviour

- Every AI interaction produces a structured forensic log with trace ID, input, output, context, and guardrail results
- Retrieved documents are logged with ID, source, similarity score, and content hash
- Tool calls are logged with name, arguments, result hash, and timestamp
- Output modifications by guardrails are recorded with both original and filtered output hashes
- Forensic logs are retained for 90 days minimum (configurable for compliance)
- Traces can be reconstructed by trace ID within seconds
- Forensic logging gaps trigger critical alerts within 5 minutes

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| Full input/output capture | Complete forensic record of every interaction | Storage costs scale with request volume and response length | Use tiered storage (hot for 7 days, warm for 90 days). Compress logs. Sample low-risk interactions. |
| PII in forensic logs | Logs contain user PII and potentially model-generated PII | Forensic logs themselves become a data breach target | Hash PII fields. Encrypt logs at rest. Restrict access to forensic logs via RBAC. |
| Content hashing | Enables integrity verification without storing full content | Hash collisions are theoretically possible | Use SHA-256 (collision-resistant). Store full content for high-risk interactions. |
| 90-day retention | Covers most incident investigation timelines | Regulatory requirements may mandate longer retention | Configure retention per compliance requirement. Some regulations require 7 years. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Forensic logger crash | Requests processed without logging | Logging gap alert fires; forensic log rate drops to zero | Logger should run as a sidecar with automatic restart. Queue logs in local buffer during outages. |
| Elasticsearch storage full | New logs rejected; ingestion fails | Ingestion lag alert; ES cluster health yellow/red | Expand storage. Enforce ILM (index lifecycle management) policies. Delete expired indices. |
| Missing trace correlation | Logs from different services cannot be correlated | Trace reconstruction returns incomplete timeline | Ensure all services propagate trace_id in headers. Validate trace_id presence in all log entries. |
| PII logged in cleartext | Forensic logs contain unmasked PII | Compliance audit; automated PII scanner flags log entries | Retroactively hash PII in existing logs. Fix the logging pipeline to hash before writing. |

## When to Consider a Managed Alternative

AI forensic logging requires reliable ingestion, long-term storage, fast querying, and access control. Building this on self-managed Elasticsearch is feasible but operationally demanding.

- **[Grafana Cloud](https://grafana.com/cloud):** Managed log storage with [Loki](https://grafana.com/oss/loki/). Long-term retention. Integration with [Grafana](https://grafana.com) dashboards for forensic investigation.
- **[Elastic](https://www.elastic.co):** Managed Elasticsearch with ILM, RBAC, and audit logging. Purpose-built for log storage and querying at scale.

**Premium content pack:** AI forensics toolkit. Forensic logger library (Python), trace reconstructor, Elasticsearch index templates and ILM policies, forensic query library, [Kubernetes](https://kubernetes.io) deployment manifests, evidence preservation scripts, and incident investigation runbook template.


## Related Articles

- [AI Red Teaming Methodology: Structured Adversarial Testing for LLM Applications](/articles/kubernetes/ai-red-teaming/)
- [Securing RAG Pipelines: Vector Database Access Control, Document Poisoning, and Retrieval Filtering](/articles/kubernetes/rag-security/)
- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration](/articles/kubernetes/model-serving-hardening/)
- [Securing Fine-Tuning Pipelines: Data Isolation, Checkpoint Integrity, and Access Control](/articles/kubernetes/fine-tuning-pipeline-security/)
