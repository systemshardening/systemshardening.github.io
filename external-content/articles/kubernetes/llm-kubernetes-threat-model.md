---
title: "LLMs on Kubernetes: Understanding the Threat Model and Deploying an LLM Gateway"
description: "Kubernetes orchestrates LLM workloads but has no awareness of what those workloads do. An Ollama pod with healthy readiness probes and stable resource usage can still leak secrets, execute prompt injection, and grant models excessive agency over internal services. This article covers the LLM-specific threat model for Kubernetes and implements an LLM gateway as the policy enforcement layer."
slug: "llm-kubernetes-threat-model"
date: 2026-04-23
lastmod: 2026-04-23
category: "kubernetes"
tags: ["llm", "threat-model", "owasp", "ollama", "llm-gateway", "litellm", "prompt-injection", "ai-security", "kubernetes"]
personas: ["platform-engineer", "security-engineer", "ai-ml-engineer"]
article_number: 156
difficulty: "advanced"
estimated_reading_time: 26
provider_bridges:
  - name: "Kong"
    id: 86
    category: "api-gateways"
  - name: "Lakera"
    id: 142
    category: "llm-security"
  - name: "Sysdig"
    id: 122
    category: "runtime-security"
premium_pack: "llm-gateway-security-pack"
published: true
layout: article.njk
permalink: "/articles/kubernetes/llm-kubernetes-threat-model/index.html"
---

# LLMs on Kubernetes: Understanding the Threat Model and Deploying an LLM Gateway

## Problem

A standard [Ollama](https://ollama.com) deployment on [Kubernetes](https://kubernetes.io) looks operationally sound: pods are healthy, readiness probes pass, resource usage is stable, logs are clean. The cluster is doing its job. The problem is that Kubernetes has no idea what the workload inside those pods is doing.

[Kubernetes](https://kubernetes.io) excels at scheduling, isolation, networking, and resource management. It does not understand that the workload behind a healthy pod is a programmable system sitting in front of your internal services, tools, logs, and potentially credentials. A language model with tool access is not a stateless web application. It interprets natural language, makes probabilistic decisions, and can be manipulated through its input to perform actions its operators never intended.

This creates a security gap that standard Kubernetes hardening does not close:

- **Network policies** control which pods can communicate, but they cannot inspect whether a prompt contains an injection attack.
- **RBAC** controls which service accounts can access Kubernetes resources, but it does not control what a model does with the API keys mounted in its pod.
- **Pod security contexts** prevent privilege escalation at the OS level, but they do not prevent a model from leaking secrets through its generated output.
- **Resource quotas** limit CPU and memory, but they do not prevent a model from consuming $10,000 in GPU hours from a flood of oversized prompts.

The OWASP Top 10 for LLM Applications provides the threat framework. This article maps those threats to Kubernetes deployments and implements the architectural control that closes the gap: an LLM gateway that enforces policy between clients and inference engines.

**Reference:** This article builds on the CNCF blog series "[LLMs on Kubernetes Part 1: Understanding the Threat Model](https://www.cncf.io/blog/2026/03/30/llms-on-kubernetes-part-1-understanding-the-threat-model/)" by Nigel Douglas.

## Threat Model

### The OWASP Top 10 for LLM Applications

The [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) defines ten risk categories. Four of these are directly relevant to Kubernetes operators:

| # | Risk | Kubernetes Impact |
|---|------|-------------------|
| LLM01 | **Prompt Injection** | Untrusted user input manipulates model behaviour. The LLM equivalent of SQL injection. Standard input validation does not apply because model behaviour is probabilistic, not deterministic. |
| LLM02 | **Sensitive Information Disclosure** | Models memorise patterns from training data and system prompts. A prompt like "show me an example configuration file" can return real credentials from training data or mounted secrets. |
| LLM03 | **Supply Chain** | Models are opaque binary artefacts. Unlike source code, they cannot be inspected for backdoors, hidden biases, or conditional malicious behaviours. `llama3.2:latest` today may behave differently from `llama3.2:latest` next month. |
| LLM06 | **Excessive Agency** | Models with tool access (database queries, API calls, kubectl, shell execution) gain the ability to perform real operations based on probabilistic decisions. This violates least-privilege principles. |

The remaining six risks (data/model poisoning, improper output handling, system prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption) are covered in depth in related articles linked at the end.

### Adversary Model

- **Adversary:** Any user who can submit prompts to the LLM application, externally via web UI or API, or internally via shared cluster services.
- **Access level:** Authenticated or unauthenticated access to the LLM inference endpoint (depends on deployment). No Kubernetes cluster access required.
- **Objective:** Extract sensitive information from model context (system prompts, RAG documents, mounted secrets). Override model safety instructions (jailbreak). Abuse tool access for unauthorised actions. Exhaust GPU resources (cost attack).
- **Blast radius:** Depends on what the model can reach. A chatbot with no tool access: reputation damage. A model with database access or kubectl: data breach, infrastructure compromise. A model with unrestricted API keys: financial damage from compute abuse.

### The Architecture Gap

**Without an LLM gateway:**

```
User → Open WebUI (pod) → Ollama Service → Ollama pod (model)
```

Ollama's job is to load models and generate responses efficiently. It should not also be deciding whether a prompt is safe, whether output contains secrets, or whether a tool call should be allowed. This is the same principle as separating routing (NGINX) from application logic (your code) from policy enforcement (WAF).

**With an LLM gateway:**

```
User → Open WebUI (pod) → LLM Gateway (pod) → Ollama Service → Ollama pod (model)
```

The gateway is a policy enforcement layer that inspects prompts, filters outputs, enforces rate limits, controls model access, and restricts tool use. It sits between clients and inference engines, just as an API gateway sits between clients and backend services.

## Configuration

### 1. Deploy Ollama with Hardened Defaults

Start with a locked-down Ollama deployment. Ollama should be reachable only from the LLM gateway, not from any other pod or external client.

```yaml
# ollama-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ollama
  namespace: ai-inference
  labels:
    app: ollama
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ollama
  template:
    metadata:
      labels:
        app: ollama
    spec:
      serviceAccountName: ollama
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: ollama
          image: ollama/ollama:0.6.2
          ports:
            - containerPort: 11434
              name: http
          env:
            # Bind to all interfaces within the pod (gateway connects via service)
            - name: OLLAMA_HOST
              value: "0.0.0.0:11434"
            # Restrict model storage to the mounted volume
            - name: OLLAMA_MODELS
              value: "/models"
            # Disable debug mode
            - name: OLLAMA_DEBUG
              value: "false"
          resources:
            requests:
              memory: "4Gi"
              cpu: "2"
            limits:
              memory: "8Gi"
              cpu: "4"
              nvidia.com/gpu: "1"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: models
              mountPath: /models
            - name: tmp
              mountPath: /tmp
          readinessProbe:
            httpGet:
              path: /api/tags
              port: 11434
            initialDelaySeconds: 10
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /api/tags
              port: 11434
            initialDelaySeconds: 30
            periodSeconds: 30
      volumes:
        - name: models
          persistentVolumeClaim:
            claimName: ollama-models
        - name: tmp
          emptyDir:
            sizeLimit: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: ollama
  namespace: ai-inference
spec:
  selector:
    app: ollama
  ports:
    - port: 11434
      targetPort: 11434
      name: http
  type: ClusterIP
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ollama
  namespace: ai-inference
  annotations:
    # No cloud IAM role binding - Ollama does not need cloud API access
    description: "Service account for Ollama inference server. No external permissions."
```

```bash
# Create the namespace and deploy
kubectl create namespace ai-inference
kubectl apply -f ollama-deployment.yaml
```

### 2. Network Policies: Isolate the Inference Engine

Only the LLM gateway should be able to reach Ollama. No other pod, namespace, or external client should have access.

```yaml
# network-policies.yaml
# Default deny all traffic in the ai-inference namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: ai-inference
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
  ingress: []
  egress: []
---
# Allow LLM gateway to reach Ollama on port 11434 only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-gateway-to-ollama
  namespace: ai-inference
spec:
  podSelector:
    matchLabels:
      app: ollama
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: llm-gateway
      ports:
        - protocol: TCP
          port: 11434
---
# Allow LLM gateway egress to Ollama and DNS only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-gateway-egress
  namespace: ai-inference
spec:
  podSelector:
    matchLabels:
      app: llm-gateway
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: ollama
      ports:
        - protocol: TCP
          port: 11434
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
---
# Allow ingress to the LLM gateway from the web UI only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-webui-to-gateway
  namespace: ai-inference
spec:
  podSelector:
    matchLabels:
      app: llm-gateway
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: open-webui
      ports:
        - protocol: TCP
          port: 4000
```

```bash
kubectl apply -f network-policies.yaml
```

### 3. Deploy LiteLLM as the LLM Gateway

[LiteLLM](https://github.com/BerriAI/litellm) is an open-source LLM gateway that provides a unified OpenAI-compatible API across 100+ model providers. It handles rate limiting, cost tracking, model access control, and request/response logging. Deploy it as the policy enforcement layer between clients and Ollama.

```yaml
# litellm-config.yaml
# LiteLLM configuration: model allowlist, rate limits, and logging.
apiVersion: v1
kind: ConfigMap
metadata:
  name: litellm-config
  namespace: ai-inference
data:
  config.yaml: |
    model_list:
      # Explicit model allowlist - only these models can be accessed.
      # This prevents users from loading arbitrary models via the API.
      - model_name: llama3.2
        litellm_params:
          model: ollama/llama3.2:1b
          api_base: http://ollama.ai-inference.svc.cluster.local:11434
          # Set maximum tokens to prevent resource exhaustion
          max_tokens: 4096
          # Timeout to prevent hanging requests consuming GPU
          timeout: 120

    litellm_settings:
      # Drop any request parameters not in the allowlist
      drop_params: true
      # Log all requests and responses for audit
      store_model_in_db: false
      # Set a global request timeout
      request_timeout: 120
      # Disable caching to prevent data leakage between users
      cache: false

    general_settings:
      # Master key for admin operations (stored in secret)
      master_key: os.environ/LITELLM_MASTER_KEY
      # Enable request/response logging
      store_model_in_db: false
```

```yaml
# litellm-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-gateway
  namespace: ai-inference
  labels:
    app: llm-gateway
spec:
  replicas: 2
  selector:
    matchLabels:
      app: llm-gateway
  template:
    metadata:
      labels:
        app: llm-gateway
    spec:
      serviceAccountName: llm-gateway
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: litellm
          image: ghcr.io/berriai/litellm:main-v1.61.12
          args:
            - "--config"
            - "/app/config.yaml"
            - "--port"
            - "4000"
          ports:
            - containerPort: 4000
              name: http
          env:
            - name: LITELLM_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: litellm-secrets
                  key: master-key
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          volumeMounts:
            - name: config
              mountPath: /app/config.yaml
              subPath: config.yaml
              readOnly: true
            - name: tmp
              mountPath: /tmp
          readinessProbe:
            httpGet:
              path: /health/readiness
              port: 4000
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health/liveliness
              port: 4000
            initialDelaySeconds: 10
            periodSeconds: 30
      volumes:
        - name: config
          configMap:
            name: litellm-config
        - name: tmp
          emptyDir:
            sizeLimit: 100Mi
---
apiVersion: v1
kind: Service
metadata:
  name: llm-gateway
  namespace: ai-inference
spec:
  selector:
    app: llm-gateway
  ports:
    - port: 4000
      targetPort: 4000
      name: http
  type: ClusterIP
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: llm-gateway
  namespace: ai-inference
```

```bash
# Create the master key secret
kubectl create secret generic litellm-secrets \
  -n ai-inference \
  --from-literal=master-key="$(openssl rand -hex 32)"

# Deploy the gateway
kubectl apply -f litellm-config.yaml
kubectl apply -f litellm-deployment.yaml
```

### 4. Enforce Model Supply Chain Controls

Models are opaque binary artefacts. Unlike container images, you cannot inspect a model file for backdoors or hidden behaviours. `llama3.2:latest` today may produce different outputs from `llama3.2:latest` next month due to upstream updates.

**Pin model versions with checksums:**

```bash
# Pull a specific model version and record its digest
kubectl exec -n ai-inference deploy/ollama -- ollama pull llama3.2:1b

# Record the model digest for verification
kubectl exec -n ai-inference deploy/ollama -- ollama show llama3.2:1b --modelfile
```

**Enforce model allowlist with OPA Gatekeeper:**

```yaml
# constraint-template-model-allowlist.yaml
# Prevent Ollama from loading models not in the approved list.
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sllmmodelallowlist
spec:
  crd:
    spec:
      names:
        kind: K8sLLMModelAllowlist
      validation:
        openAPIV3Schema:
          type: object
          properties:
            allowedModels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sllmmodelallowlist

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.name == "ollama"
          env := container.env[_]
          env.name == "OLLAMA_MODELS_ALLOWED"
          not env.value in input.parameters.allowedModels
          msg := sprintf("Model not in allowlist: %v. Allowed: %v", [env.value, input.parameters.allowedModels])
        }
```

**Block direct API access to Ollama's model management endpoints:**

```yaml
# The LiteLLM gateway configuration already restricts which models
# are accessible. But if someone bypasses the gateway and reaches
# Ollama directly, they can load any model.
#
# Network policies (applied above) prevent this by ensuring only
# the gateway pod can reach Ollama. Verify:
```

```bash
# Verify no other pod can reach Ollama directly
# From a pod that is NOT the gateway:
kubectl run test-access --rm -it --image=busybox -n ai-inference -- wget -q -O- http://ollama.ai-inference.svc.cluster.local:11434/api/tags
# Expected: connection timed out (blocked by NetworkPolicy)
```

### 5. Implement Output Filtering for Sensitive Data

Models can leak secrets from their context, training data, system prompts, or mounted environment variables. Filter outputs before they reach the user.

```python
#!/usr/bin/env python3
# output-filter-sidecar/filter.py
# Sidecar container that intercepts LLM responses and redacts sensitive patterns.
# Deployed alongside the LLM gateway.

import json
import re
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen, Request

UPSTREAM_URL = "http://localhost:4000"

# Patterns to redact from model output
REDACTION_PATTERNS = [
    # AWS access keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), '[REDACTED_AWS_KEY]'),
    # AWS secret keys
    (re.compile(r'[A-Za-z0-9/+=]{40}(?=\s|$|")'), '[REDACTED_POSSIBLE_SECRET]'),
    # Generic API keys (hex strings 32+ chars)
    (re.compile(r'\b[a-fA-F0-9]{32,}\b'), '[REDACTED_HEX_TOKEN]'),
    # Bearer tokens
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*'), 'Bearer [REDACTED]'),
    # Private keys
    (re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    # Connection strings with passwords
    (re.compile(r'(postgres|mysql|mongodb)://\S+:\S+@'), r'\1://[REDACTED]@'),
    # JWT tokens
    (re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'), '[REDACTED_JWT]'),
    # Kubernetes service account tokens
    (re.compile(r'eyJhbGciOiJSUzI1NiI[A-Za-z0-9_-]+'), '[REDACTED_K8S_TOKEN]'),
]


def redact_output(text: str) -> tuple[str, int]:
    """Redact sensitive patterns from model output. Returns (redacted_text, redaction_count)."""
    count = 0
    for pattern, replacement in REDACTION_PATTERNS:
        text, n = pattern.subn(replacement, text)
        count += n
    return text, count


class FilterHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        # Forward request to upstream (LiteLLM)
        req = Request(
            f"{UPSTREAM_URL}{self.path}",
            data=body,
            headers={k: v for k, v in self.headers.items()},
            method='POST',
        )

        try:
            with urlopen(req) as resp:
                response_body = resp.read().decode('utf-8')

                # Parse and filter the response
                try:
                    response_json = json.loads(response_body)
                    if 'choices' in response_json:
                        for choice in response_json['choices']:
                            if 'message' in choice and 'content' in choice['message']:
                                content = choice['message']['content']
                                filtered, redaction_count = redact_output(content)
                                choice['message']['content'] = filtered
                                if redaction_count > 0:
                                    sys.stderr.write(
                                        f"SECURITY: Redacted {redaction_count} sensitive patterns from response\n"
                                    )
                    response_body = json.dumps(response_json)
                except json.JSONDecodeError:
                    response_body, _ = redact_output(response_body)

                self.send_response(resp.status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body.encode('utf-8'))

        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Gateway error: {e}".encode('utf-8'))

    def log_message(self, format, *args):
        sys.stderr.write(f"output-filter: {format % args}\n")


if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 4001), FilterHandler)
    sys.stderr.write("Output filter listening on :4001\n")
    server.serve_forever()
```

### 6. Rate Limiting to Prevent Unbounded Consumption

GPU-backed inference is expensive. Without rate limiting, a single user or automated script can exhaust GPU resources and accumulate thousands of dollars in compute costs.

```yaml
# litellm-config-with-rate-limits.yaml
# Add to the LiteLLM ConfigMap under litellm_settings:
apiVersion: v1
kind: ConfigMap
metadata:
  name: litellm-config
  namespace: ai-inference
data:
  config.yaml: |
    model_list:
      - model_name: llama3.2
        litellm_params:
          model: ollama/llama3.2:1b
          api_base: http://ollama.ai-inference.svc.cluster.local:11434
          max_tokens: 4096
          timeout: 120
          # Maximum input tokens to prevent oversized prompts
          max_input_tokens: 8192

    litellm_settings:
      drop_params: true
      request_timeout: 120
      cache: false
      # Rate limiting per API key
      max_budget: 10.0           # Maximum $10 per key per month
      budget_duration: "30d"
      max_parallel_requests: 5   # Maximum 5 concurrent requests per key
      tpm_limit: 100000          # 100K tokens per minute per key
      rpm_limit: 60              # 60 requests per minute per key

    general_settings:
      master_key: os.environ/LITELLM_MASTER_KEY
```

```bash
# Update the ConfigMap
kubectl apply -f litellm-config-with-rate-limits.yaml

# Restart the gateway to pick up new configuration
kubectl rollout restart deployment/llm-gateway -n ai-inference
```

### 7. Restrict Tool Access (Excessive Agency)

If models have tool access (function calling, agent actions), restrict which tools are available and require approval for destructive operations.

```yaml
# tool-restrictions.yaml
# If using Open WebUI's function calling / tool-use features,
# restrict which tools the model can invoke.
# This is an Open WebUI configuration example.
apiVersion: v1
kind: ConfigMap
metadata:
  name: open-webui-config
  namespace: ai-inference
data:
  # Disable tools that grant infrastructure access
  ENABLE_RAG_WEB_SEARCH: "false"
  ENABLE_IMAGE_GENERATION: "false"
  # Disable code execution (prevents arbitrary command execution)
  ENABLE_CODE_EXECUTION: "false"
  # Disable community tool installation (supply chain risk)
  ENABLE_COMMUNITY_SHARING: "false"
```

**For custom agents with tool access, enforce least-privilege:**

```yaml
# agent-rbac.yaml
# If an AI agent needs Kubernetes API access, create a minimal role.
# Never use cluster-admin for AI agents.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ai-agent-readonly
  namespace: production
rules:
  # Read-only access to pods and services only
  - apiGroups: [""]
    resources: ["pods", "services"]
    verbs: ["get", "list"]
  # No access to secrets, configmaps, or any write operations
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ai-agent-readonly-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: ai-agent
    namespace: ai-inference
roleRef:
  kind: Role
  name: ai-agent-readonly
  apiGroup: rbac.authorization.k8s.io
```

### 8. Request and Response Logging for Audit

Log every prompt and response for incident investigation, compliance, and prompt injection analysis.

```yaml
# fluent-bit-sidecar.yaml
# Ship LLM gateway logs to a centralised logging system.
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: ai-inference
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         5
        Daemon        Off
        Log_Level     info

    [INPUT]
        Name          tail
        Path          /var/log/litellm/*.log
        Tag           llm.gateway
        Parser        json

    [FILTER]
        Name          modify
        Match         llm.gateway
        Add           cluster ${CLUSTER_NAME}
        Add           namespace ai-inference
        Add           component llm-gateway

    [OUTPUT]
        Name          forward
        Match         *
        Host          fluentd.logging.svc.cluster.local
        Port          24224
```

```yaml
# prometheus-metrics.yaml
# Monitor LLM gateway metrics for cost tracking and abuse detection.
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: llm-gateway-metrics
  namespace: ai-inference
spec:
  selector:
    matchLabels:
      app: llm-gateway
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
```

```yaml
# alerting-rules.yaml
# Alert on suspicious LLM usage patterns.
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: llm-gateway-alerts
  namespace: ai-inference
spec:
  groups:
    - name: llm-security
      interval: 1m
      rules:
        # Alert if a single user exceeds 100 requests in 5 minutes
        - alert: LLMHighRequestRate
          expr: |
            sum by (api_key) (
              rate(litellm_requests_total[5m])
            ) > 20
          for: 2m
          labels:
            severity: warning
          annotations:
            summary: "High LLM request rate from {{ $labels.api_key }}"
            runbook: "Check if this is automated abuse or legitimate batch processing."

        # Alert if output filtering redacts secrets
        - alert: LLMSecretLeakAttempt
          expr: |
            sum(rate(litellm_output_redactions_total[5m])) > 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "LLM output contained sensitive data that was redacted"
            runbook: "Investigate the prompt that triggered the leak. Check if system prompt or RAG context contains secrets."

        # Alert on request timeout spikes (potential resource exhaustion)
        - alert: LLMTimeoutSpike
          expr: |
            sum(rate(litellm_request_timeouts_total[5m])) > 5
          for: 3m
          labels:
            severity: warning
          annotations:
            summary: "High rate of LLM request timeouts"
            runbook: "Check GPU utilisation. Verify no oversized prompts are consuming resources."
```

```bash
kubectl apply -f prometheus-metrics.yaml
kubectl apply -f alerting-rules.yaml
```

## Expected Behaviour

After implementing the full LLM gateway architecture:

- **Network isolation:** Ollama is reachable only from the LLM gateway pod. No other pod, namespace, or external client can reach the inference engine directly.
- **Model allowlist:** Only explicitly approved models (pinned versions) can be served. Requests for unlisted models return an error.
- **Rate limiting:** Each API key is limited to 60 requests per minute, 100K tokens per minute, and $10 per month. Requests exceeding limits receive 429 responses.
- **Output filtering:** Sensitive patterns (API keys, tokens, private keys, connection strings) are redacted from model responses before reaching the user.
- **Tool restrictions:** Code execution, web search, and community tool installation are disabled. Agent tool access is limited to read-only operations via dedicated RBAC roles.
- **Audit logging:** Every request and response is logged to a centralised system. Alerts fire on high request rates, output redactions, and timeout spikes.

**Verification:**

```bash
# Verify Ollama is only reachable from the gateway
kubectl run test --rm -it --image=busybox -n default -- wget -q -O- --timeout=5 http://ollama.ai-inference.svc.cluster.local:11434/api/tags
# Expected: connection timed out (blocked by NetworkPolicy)

# Verify the gateway is serving requests
kubectl exec -n ai-inference deploy/llm-gateway -- curl -s http://localhost:4000/health/readiness
# Expected: {"status": "healthy"}

# Verify rate limiting
for i in $(seq 1 70); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer test-key" \
    http://llm-gateway.ai-inference.svc.cluster.local:4000/v1/chat/completions \
    -d '{"model":"llama3.2","messages":[{"role":"user","content":"hello"}]}'
done
# Expected: 200 for the first 60, then 429 (rate limited)

# Verify network policies
kubectl get networkpolicies -n ai-inference
# Expected: 4 policies (default-deny, gateway-to-ollama, gateway-egress, webui-to-gateway)
```

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| LLM gateway (LiteLLM) | Adds a network hop and processing latency (5-20ms per request) | Gateway becomes a single point of failure for all LLM traffic | Deploy 2+ replicas with pod anti-affinity. Health checks with automatic restart. |
| Network policy isolation | Prevents direct access to Ollama for debugging and testing | Cannot run ad-hoc queries against Ollama during development | Create a separate development namespace with relaxed policies. Never relax production policies. |
| Output filtering (regex-based) | Catches common secret patterns (AWS keys, JWTs, connection strings) | Cannot catch all secrets (custom token formats, base64-encoded secrets) | Supplement regex with AI-based output classification for high-security deployments. |
| Model version pinning | Prevents unexpected behaviour changes from upstream model updates | Requires manual process to update to newer model versions | Schedule quarterly model reviews. Test new versions in staging before production. |
| Rate limiting per API key | Prevents cost exhaustion from individual users | Legitimate batch workloads may hit rate limits | Create separate API keys with higher limits for batch workloads. Monitor and adjust limits based on usage patterns. |
| Tool access restrictions | Prevents models from performing unauthorised actions | Limits the usefulness of AI agents that need tool access | Define explicit tool allowlists per use case. Implement approval workflows for destructive operations. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| LLM gateway crashes | All LLM requests fail with 502/503 | Gateway health check fails; users report errors | Kubernetes restarts the pod automatically (liveness probe). If persistent: check gateway logs, increase resource limits if OOM. |
| Network policy blocks legitimate traffic | New service cannot reach the LLM gateway | Service reports connection timeout to gateway | Add a NetworkPolicy allowing ingress from the new service. Test in staging first. |
| Rate limit too restrictive | Users receive 429 errors during normal usage | High rate of 429 responses in gateway metrics | Increase rate limits for affected API keys. Monitor actual usage patterns before setting limits. |
| Output filter false positive | Legitimate content redacted from model response | Users report missing content in responses; redaction logs show high volume | Review redacted content. Add exception patterns for known false positives. Tune regex patterns to be more specific. |
| Ollama OOM with large model | Ollama pod killed by Kubernetes OOM killer | Pod enters CrashLoopBackOff; events show OOMKilled | Increase memory limits. Use a smaller model variant. Ensure resource requests match model memory requirements. |
| Model version drift after update | Model produces different outputs after Ollama restart pulls new version | Users report behaviour changes; output quality metrics shift | Pin model versions by digest. Never use `:latest` tags. Test model updates in staging. |
| Secret leaked despite output filter | Sensitive data in a format not covered by regex patterns reaches the user | Post-incident review reveals leaked credentials | Rotate the leaked credential immediately. Add the new pattern to the output filter. Consider AI-based output classification. |

## When to Consider a Managed Alternative

**Transition point:** When operating 3+ models across multiple teams with different access requirements, the operational overhead of managing LiteLLM configuration, rate limit tuning, output filter maintenance, and audit log review exceeds 8 hours per week.

**Recommended providers:**

- **[Kong AI Gateway](https://konghq.com):** Enterprise API gateway with native LLM traffic management. Brings prompt inspection, rate limiting, cost tracking, and model routing into the existing Kong ecosystem. If you already use Kong for API management, the AI Gateway plugin extends it to LLM traffic without a separate tool.
- **[Lakera](https://www.lakera.ai):** Purpose-built LLM security. Prompt injection detection, PII filtering, content moderation, and jailbreak prevention as an API. Achieves higher accuracy on prompt injection detection than regex-based filtering because it uses a trained classifier. Integrates as a pre-processing step in the LLM gateway pipeline.
- **[Sysdig](https://sysdig.com):** Runtime security for Kubernetes with AI workload visibility. Detects anomalous behaviour from LLM pods (unexpected network connections, file system access, process execution) that Kubernetes native tooling misses.

**What you still control:** Network policy design (which services can reach the LLM gateway). Model selection and version pinning. Tool access permissions and RBAC design. Rate limit thresholds. These are security decisions that managed providers cannot make for you.

**Premium content pack:** LLM gateway security templates. Complete Kubernetes manifests for Ollama + LiteLLM + output filter deployment. Network policies for LLM workload isolation. Prometheus alerting rules for LLM cost and security monitoring. OPA Gatekeeper constraints for model allowlisting.

## Related Articles

- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration](/articles/kubernetes/model-serving-hardening/)
- [LLM Rate Limiting and Cost Controls: Protecting GPU Resources from Abuse](/articles/kubernetes/llm-rate-limiting/)
- [LLM Observability in Production: Latency, Token Usage, and Error Tracking](/articles/kubernetes/llm-observability/)
- [Securing AI Agents in Production: Tool-Use Boundaries, Credential Scoping, and Output Verification](/articles/ai-landscape/securing-ai-agents/)
- [AI Supply Chain Attack Surface: Models, Datasets, and Inference Dependencies](/articles/ai-landscape/ai-supply-chain-attack-surface/)
