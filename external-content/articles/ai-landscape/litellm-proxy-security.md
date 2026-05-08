---
title: "LiteLLM Proxy Security Hardening"
description: "Harden LiteLLM proxy deployments with master key protection, virtual key scoping, spend controls, model aliasing restrictions, and audit logging for multi-provider LLM routing."
slug: litellm-proxy-security
date: 2026-05-02
lastmod: 2026-05-02
category: ai-landscape
tags: ["litellm", "llm-proxy", "api-security", "rate-limiting", "spend-controls", "multi-provider"]
personas: ["ml-engineer", "security-engineer", "platform-engineer"]
article_number: 332
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/ai-landscape/litellm-proxy-security/index.html"
---

# LiteLLM Proxy Security Hardening

## Problem

LiteLLM has become the dominant open-source LLM proxy for teams that need to route requests across multiple model providers from a single, unified endpoint. It presents an OpenAI-compatible API surface — `/v1/chat/completions`, `/v1/embeddings`, `/v1/models` — and translates calls transparently to 100+ upstream providers: OpenAI, Anthropic Claude, AWS Bedrock, Azure OpenAI, Google Vertex AI, Cohere, Mistral, and self-hosted inference servers running vLLM or Ollama. Organisations deploy it to centralise API key management, enforce cost controls, implement model failover logic, and insulate application code from provider-specific SDK differences. On paper, this is a sound architecture. In practice, the default configuration makes LiteLLM one of the most dangerous services in a production AI stack.

The root problem is that `LITELLM_MASTER_KEY` defaults to unset. When the master key is absent, the proxy accepts all requests without any authentication check — any process that can reach port 4000 can call any configured model, create virtual keys, inspect spend data, and modify proxy configuration at runtime. This is not a misconfiguration edge case; it is the out-of-the-box behaviour documented in the quickstart guide. Teams following that quickstart deploy an unauthenticated gateway in front of their most expensive cloud API keys within minutes.

Beyond authentication, the proxy exposes several management endpoints without access control by default. The `/health` and `/health/readiness` endpoints return detailed information about which upstream providers are reachable and their current status — valuable reconnaissance for an attacker. The `/models` endpoint enumerates every configured model alias and its upstream provider mapping. The `/metrics` endpoint exposes Prometheus-format counters including per-model request counts, token volumes, and latency distributions, all of which reveal usage patterns and provider cost exposure. None of these endpoints require authentication unless explicitly configured.

The PostgreSQL database that backs a production LiteLLM deployment stores every virtual key, team budget, and spend record. The `DATABASE_URL` connection string is typically placed in `config.yaml` or passed as a plain environment variable, meaning it appears in pod specs, ConfigMaps, or version-controlled configuration files. That connection string — if exposed — gives an attacker direct read/write access to the keys table, where they can read all virtual keys and their associated provider credentials, or insert new keys granting themselves full access without ever touching the LiteLLM API.

Model aliasing is a feature that creates a severe redirect risk. LiteLLM allows operators to define a `model_list` in which a friendly alias — say `gpt-3.5-turbo` — maps to an upstream provider and model. An attacker who can modify `config.yaml`, inject into the proxy's model list via the `/model/new` admin endpoint, or exploit a wildcard passthrough configuration can redirect requests from cheap models to expensive ones. A production application calling `gpt-3.5-turbo` at $0.50 per million tokens could silently be routed to `claude-opus-4-7` at $15 per million tokens, burning budget at 30x the expected rate with no immediate error to alert operators.

The admin UI at `/ui` presents a further risk. It exposes a browser-based dashboard for key management, spend visualisation, and model configuration. Without network-level restrictions in front of it, this UI is reachable by anyone who can reach the pod, and it operates without role-based access control — any user who can authenticate to the UI has equivalent admin capability to the master key holder. The `/logs` endpoint is equally sensitive: it exposes full prompt and completion text for every request that has passed through the proxy, allowing anyone with access to read other users' conversation history in full.

**Target systems:** LiteLLM Proxy 1.40+, PostgreSQL 15+ for production deployments, Kubernetes with a dedicated namespace for the LiteLLM control plane.

---

## Threat Model

**Adversary 1 — Unauthenticated network attacker.** An attacker with network access to an unauthenticated LiteLLM proxy endpoint calls `POST /key/generate` to create a new virtual key with no spend limit, then uses that key to make arbitrary LLM API calls billed to the organisation's cloud provider accounts. Because LiteLLM holds the actual provider API keys, the attacker never needs those credentials directly. The attack requires no authentication token, no prior knowledge of the deployment, and leaves no trail unless request logging is explicitly enabled.

**Adversary 2 — Developer abusing an unlimited virtual key.** A developer receives a valid virtual key during onboarding. The key has no spend limit, no model restrictions, and no expiry. The developer — intentionally or accidentally — runs a script that generates thousands of completions with high `max_tokens` values, exhausting the organisation's monthly cloud LLM budget before the end of the first week. Standard cloud provider billing alerts may not fire until the damage is done. This adversary does not need to escalate privileges; the misconfiguration grants them the capability from the start.

**Adversary 3 — Insider accessing the `/logs` endpoint.** A team member with any valid virtual key uses the `/logs` endpoint (or the `/ui` dashboard) to read the full prompt and completion history of other users' requests. In regulated industries this constitutes a privacy violation under GDPR, HIPAA, or equivalent frameworks. The attacker sees not only conversation content but also the virtual key IDs of all other users, enabling them to identify high-value keys for targeted abuse.

**Adversary 4 — Supply chain attacker modifying `config.yaml`.** An attacker who compromises a CI/CD pipeline, a GitOps repository, or the infrastructure tooling that renders LiteLLM's config adds a model alias entry pointing to an attacker-controlled HTTPS endpoint that mimics an OpenAI-compatible API. All traffic for a given model alias is routed to the attacker's server, which records full prompt and completion content, returns synthetic responses, and forwards requests to the real provider — a transparent man-in-the-middle. The attack is passive and leaves no LiteLLM-side alerts.

The blast radius of a compromised LiteLLM instance is unusually wide: it spans every upstream provider API key the proxy holds, every team's budget, every user's conversation history, and potentially the PostgreSQL database storing all of this data. A single misconfigured deployment is a single point of compromise for an organisation's entire multi-provider LLM investment.

---

## Configuration / Implementation

### Master Key and Authentication

The master key is the administrative credential for the LiteLLM control plane. Generating and injecting it correctly is the first and most critical step.

Generate a cryptographically strong master key:

```bash
# Generate a 32-byte random master key
python3 -c "import secrets; print('sk-' + secrets.token_hex(32))"
```

Store it as a Kubernetes Secret, never in `config.yaml` or a ConfigMap:

```yaml
# kubernetes/litellm-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: litellm-master-key
  namespace: litellm
type: Opaque
stringData:
  LITELLM_MASTER_KEY: "sk-<your-generated-value>"
```

Reference the secret in the LiteLLM deployment:

```yaml
# kubernetes/litellm-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: litellm-proxy
  namespace: litellm
spec:
  replicas: 2
  selector:
    matchLabels:
      app: litellm-proxy
  template:
    metadata:
      labels:
        app: litellm-proxy
    spec:
      containers:
        - name: litellm
          image: ghcr.io/berriai/litellm:main-v1.40.0
          env:
            - name: LITELLM_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: litellm-master-key
                  key: LITELLM_MASTER_KEY
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: litellm-db-credentials
                  key: DATABASE_URL
          ports:
            - containerPort: 4000
```

Enable master key enforcement in `config.yaml`:

```yaml
# config.yaml
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  master_key_auth: true
  disable_master_key_return: true
```

To rotate the master key, generate a replacement, update the Kubernetes Secret, and perform a rolling restart. All virtual keys remain valid through rotation — only the admin credential changes. Plan the rotation with all admin users present and verify API access with the new key before completing the rollout.

### Virtual Key Scoping

Virtual keys are the primary access mechanism for end users and services. Every key should be scoped to the minimum necessary privileges.

Create team-scoped keys with spend limits, model restrictions, and rate limits via the LiteLLM API:

```bash
# Create a scoped virtual key for a team
curl -X POST "https://litellm.internal/key/generate" \
  -H "Authorization: Bearer ${LITELLM_MASTER_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "key_alias": "team-ml-research",
    "team_id": "team-ml-research",
    "max_budget": 100.0,
    "budget_duration": "30d",
    "duration": "30d",
    "allowed_models": ["gpt-4o", "claude-sonnet-4-6", "text-embedding-3-small"],
    "tpm_limit": 500000,
    "rpm_limit": 100,
    "max_parallel_requests": 10,
    "metadata": {
      "created_by": "platform-team",
      "purpose": "ml-research-experiments"
    }
  }'
```

Key parameters:
- `max_budget`: hard spend limit in USD for the key lifetime
- `budget_duration`: resets the budget counter on this cadence (`"30d"`, `"7d"`, `"1d"`)
- `duration`: key expiry — after this interval the key is invalid regardless of spend
- `allowed_models`: explicit allowlist; requests for any other model alias are rejected with 403
- `tpm_limit`: tokens per minute cap enforced per key
- `rpm_limit`: requests per minute cap enforced per key
- `max_parallel_requests`: concurrent in-flight requests allowed for this key

List and audit existing keys regularly:

```bash
# List all active virtual keys
curl "https://litellm.internal/key/list" \
  -H "Authorization: Bearer ${LITELLM_MASTER_KEY}"

# Check spend for a specific key
curl "https://litellm.internal/key/info?key=sk-..." \
  -H "Authorization: Bearer ${LITELLM_MASTER_KEY}"
```

### Spend Controls and Alerts

Global spend controls provide a safety net independent of per-key limits:

```yaml
# config.yaml
litellm_settings:
  max_budget: 2000.0
  budget_duration: "30d"
  success_callback: ["langfuse"]
  failure_callback: ["langfuse"]

general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  alerting: ["slack"]
  alerting_threshold: 300
  spend_report_frequency: "1d"
```

Configure Slack alerting for budget thresholds by adding the webhook to the LiteLLM Secret:

```yaml
# kubernetes/litellm-secrets.yaml (append)
stringData:
  SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T.../B.../..."
```

And reference it in `config.yaml`:

```yaml
general_settings:
  alerting: ["slack"]
  alerting_args:
    slack_webhook_url: os.environ/SLACK_WEBHOOK_URL
    budget_alert_threshold: 0.8
```

With `budget_alert_threshold: 0.8`, LiteLLM sends a Slack notification when 80% of the budget is consumed, giving operators time to respond before the limit is hit and traffic is blocked.

### Model Aliasing Restrictions

An explicit `model_list` with no wildcard passthrough is the primary control against model redirect attacks:

```yaml
# config.yaml
model_list:
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY
      max_tokens: 4096

  - model_name: claude-sonnet-4-6
    litellm_params:
      model: anthropic/claude-sonnet-4-6
      api_key: os.environ/ANTHROPIC_API_KEY
      max_tokens: 4096

  - model_name: text-embedding-3-small
    litellm_params:
      model: openai/text-embedding-3-small
      api_key: os.environ/OPENAI_API_KEY

litellm_settings:
  drop_params: true
  model_alias_map: {}

general_settings:
  allow_requests_on_db_unavailable: false
  disable_add_transform_inline_image_block: true
```

Do not configure `model: *` or `model: openai/*` wildcard entries. Each model entry must point to a specific, pinned provider model ID — `openai/gpt-4o`, not `gpt-4o` alone — to prevent LiteLLM's internal alias resolution from substituting unexpected models.

Disable the `/model/new` admin endpoint in production to prevent runtime model list modification:

```yaml
general_settings:
  disable_add_model_via_api: true
```

### Endpoint Protection

Place an nginx reverse proxy in front of LiteLLM to restrict access to sensitive management endpoints:

```nginx
# nginx/litellm-proxy.conf
upstream litellm {
    server litellm-proxy.litellm.svc.cluster.local:4000;
}

# Block management endpoints from external traffic
server {
    listen 443 ssl;
    server_name litellm.example.com;

    ssl_certificate     /etc/ssl/certs/litellm.crt;
    ssl_certificate_key /etc/ssl/private/litellm.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Restrict UI, metrics, and health to internal RFC1918 ranges
    location ~ ^/(ui|metrics|health/readiness|health/liveness)(/|$) {
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny  all;
        proxy_pass http://litellm;
    }

    # Restrict admin endpoints to ops CIDR only
    location ~ ^/(key|model|team|user|config)(/|$) {
        allow 10.10.0.0/16;
        deny  all;
        proxy_pass http://litellm;
    }

    # Allow inference endpoints to all authenticated callers
    location ~ ^/v1/ {
        proxy_pass http://litellm;
        proxy_set_header Authorization $http_authorization;
        proxy_read_timeout 120s;
    }

    location / {
        return 404;
    }
}
```

Disable the `/logs` spend log endpoint in production deployments where prompt content must not be stored or accessible:

```yaml
general_settings:
  disable_spend_logs: true
```

Complement nginx ACLs with Kubernetes NetworkPolicy:

```yaml
# kubernetes/litellm-networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: litellm-ingress
  namespace: litellm
spec:
  podSelector:
    matchLabels:
      app: litellm-proxy
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              litellm-access: allowed
      ports:
        - protocol: TCP
          port: 4000
  egress:
    # Allow only HTTPS to upstream provider APIs
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443
    # Allow PostgreSQL access within cluster
    - to:
        - namespaceSelector:
            matchLabels:
              app: postgresql
      ports:
        - protocol: TCP
          port: 5432
```

### Database Security

The PostgreSQL connection string must never appear in `config.yaml` or a version-controlled file:

```yaml
# config.yaml — correct pattern: env var reference only
general_settings:
  database_url: os.environ/DATABASE_URL
```

Store the full connection string — including SSL mode — in a Kubernetes Secret:

```yaml
# kubernetes/litellm-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: litellm-db-credentials
  namespace: litellm
type: Opaque
stringData:
  DATABASE_URL: "postgresql://litellm_user:changeme@postgres.litellm.svc:5432/litellm?sslmode=require&sslrootcert=/etc/ssl/certs/ca.crt"
```

Create a PostgreSQL role with the minimum necessary permissions — no superuser, no table creation outside the `litellm` schema:

```sql
-- PostgreSQL setup
CREATE ROLE litellm_user WITH LOGIN PASSWORD 'changeme';
CREATE DATABASE litellm OWNER litellm_user;
\c litellm
GRANT USAGE ON SCHEMA public TO litellm_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO litellm_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO litellm_user;
REVOKE CREATE ON SCHEMA public FROM litellm_user;
```

Enable SSL on the PostgreSQL server and verify the LiteLLM pod can reach it with the certificate:

```bash
# Verify SSL connection from within the pod
psql "${DATABASE_URL}" -c "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();"
```

### Audit Logging

Configure callbacks to emit structured events for every request without storing full prompt content:

```yaml
# config.yaml
litellm_settings:
  success_callback: ["langfuse"]
  failure_callback: ["langfuse", "slack"]

  # Log metadata only — exclude prompt and completion text
  redact_user_api_key_info: true
```

For custom SIEM integration, use a webhook callback:

```yaml
litellm_settings:
  success_callback: ["webhook"]
  webhook_url: os.environ/SIEM_WEBHOOK_URL
```

The webhook payload includes `key_alias`, `model`, `usage.prompt_tokens`, `usage.completion_tokens`, `response_time_ms`, and `status` — sufficient for cost attribution and anomaly detection without capturing prompt content.

Ship access logs from the nginx layer to your SIEM and alert on 401/403 spike patterns:

```bash
# Example: alert if 403s exceed 50 per minute (Prometheus alerting rule)
# prometheus/litellm-alerts.yaml
groups:
  - name: litellm-security
    rules:
      - alert: LiteLLMHighAuthFailureRate
        expr: |
          rate(nginx_http_requests_total{
            job="litellm-nginx",
            status=~"40[13]"
          }[5m]) > 0.8
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "LiteLLM auth failure spike — possible key scanning"
```

### TLS and Network Isolation

Terminate TLS at nginx or Envoy; do not expose the LiteLLM port directly through a Kubernetes Service of type LoadBalancer:

```yaml
# kubernetes/litellm-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: litellm-proxy
  namespace: litellm
spec:
  type: ClusterIP
  selector:
    app: litellm-proxy
  ports:
    - port: 4000
      targetPort: 4000
      protocol: TCP
```

Set a request timeout in `config.yaml` to prevent slow-response upstream providers from holding goroutines open indefinitely:

```yaml
proxy_server_settings:
  request_timeout: 120
```

If using Envoy as the gateway (for example in a service mesh), enforce mTLS between the nginx/Envoy layer and the LiteLLM pod. The LiteLLM pod itself does not need to terminate TLS — the sidecar handles it — but the traffic must be encrypted in transit across the cluster.

---

## Expected Behaviour

| Signal | Without hardening | With hardening |
|---|---|---|
| Unauthenticated virtual key creation | Any caller with network access to port 4000 can `POST /key/generate` and receive a valid key immediately | `POST /key/generate` returns 401; only requests bearing the master key can create keys |
| Spend exhaustion attack | A single virtual key with no limit can call `gpt-4o` at maximum throughput indefinitely, exhausting cloud API budget | Key-level `max_budget` and `tpm_limit` block requests once limits are reached; Slack alert fires at 80% |
| Prompt log access | Any caller can `GET /logs` and read full prompt and completion text for all users | `/logs` is disabled in production (`disable_spend_logs: true`); nginx ACL blocks the endpoint at the proxy layer |
| Model redirect attack | `config.yaml` modification or `/model/new` API call can reroute `gpt-3.5-turbo` to `claude-opus-4-7` | Explicit `model_list` with pinned provider IDs and `disable_add_model_via_api: true` prevent runtime model aliasing |

---

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Strict model allowlist | Prevents model redirect attacks and budget surprises from unexpected model routing | New model adoption requires a config change and deployment cycle; blocks ad-hoc experimentation | Maintain a staging LiteLLM instance with looser allowlists; use GitOps PR review to approve new model additions |
| Per-key spend limits | Caps the blast radius of any single compromised or misused key | Legitimate workloads that exceed monthly estimates are blocked, potentially interrupting production pipelines | Set limits conservatively at 2x expected spend; configure alerts at 80% to allow budget reviews before blocking occurs |
| Disabling `/logs` endpoint | Prevents prompt content exposure across users; reduces privacy risk | Debugging production issues becomes harder without access to request/response history | Use Langfuse or a dedicated observability backend with row-level access control for per-team log isolation |
| Database SSL overhead | Encrypts all key and spend data in transit to PostgreSQL | Adds ~2–5ms per database operation; requires certificate management | Use a PgBouncer connection pool in front of PostgreSQL to amortise SSL handshake cost; automate certificate rotation with cert-manager |

---

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Master key rotation breaks all virtual keys | All API calls return 401 immediately after rotation; all virtual keys appear invalid | Spike in 401 responses on the LiteLLM access log and SIEM alert | Virtual keys are stored in PostgreSQL and remain valid — only the admin credential changed. Roll back the Kubernetes Secret to the previous master key value, then re-rotate with all teams informed. Virtual keys do not need to be reissued. |
| PostgreSQL connection string rotation requires restart | LiteLLM logs `Connection refused` or `password authentication failed` after a database credential rotation; inference requests fail with 500 | Health check endpoint returns unhealthy; pod readiness probe fails | Update the `litellm-db-credentials` Secret with the new `DATABASE_URL`, then perform a rolling restart of the LiteLLM Deployment. Connections are re-established on startup. |
| Budget limit blocks production traffic at month-end | Legitimate inference requests return 429 with `Budget exceeded` after the monthly reset date; client applications surface errors to users | Slack budget alert was not acted on; on-call receives client-facing error reports | Reset or increase the budget via `PUT /key/update` or `PUT /budget/update` using the master key; increase `max_budget` or advance `budget_duration` reset. Review spend spike root cause before increasing limits. |
| Model alias misconfiguration routes to wrong provider | Cost anomaly — spend on an unexpected provider spikes; model behaviour changes (different capabilities, context window, refusal patterns) | Langfuse spend dashboard shows unexpected provider charges; budget alerts fire earlier than expected | Correct the `model_list` entry in `config.yaml` and redeploy. Audit all recent request logs in Langfuse to identify affected traffic volume. File a cost dispute with the provider if requests were routed to a more expensive model due to misconfiguration. |

---

## When to Consider a Managed Alternative

For organisations with compliance obligations or insufficient platform engineering capacity to operate a self-hosted proxy with PostgreSQL, consider:

- **AWS Bedrock API Gateway** — native model routing across Bedrock-supported foundation models with IAM-based access control, CloudWatch spend tracking, and AWS-managed infrastructure. Appropriate when all required models are available through Bedrock and the team is already standardised on AWS.
- **Azure AI Studio model routing** — managed endpoint routing across Azure OpenAI and GitHub Models with Entra ID authentication, content filtering, and Azure Monitor integration. Appropriate when the organisation is committed to an Azure-first strategy and needs SOC 2 Type II vendor SLA coverage.
- **Google Cloud Vertex AI endpoints** — managed routing across Gemini models, Anthropic Claude on Vertex, and Model Garden third-party models with VPC Service Controls and Cloud Audit Logs. Appropriate when Vertex-available models cover the use case and GCP is the primary cloud.
- **Portkey.ai** — managed LiteLLM-compatible proxy offered as a SaaS product with built-in RBAC, spend controls, and observability. Appropriate when teams want LiteLLM's multi-provider feature set but lack capacity to operate the database and configuration management layer.

Prefer a managed alternative when: compliance requires a vendor with a SOC 2 Type II attestation covering the proxy layer itself; the security team cannot staff 24/7 response to a compromise of the proxy's PostgreSQL instance; the engineering team responsible for LiteLLM has fewer than two people who understand its operational model deeply.

---

## Related Articles

- [vLLM Production Security Hardening](/articles/ai-landscape/vllm-production-security/)
- [LLM Deployment Security](/articles/ai-landscape/llm-deployment-security/)
- [API Gateway Security](/articles/network/api-gateway-security/)
- [API Key Lifecycle Management](/articles/cross-cutting/api-key-lifecycle/)
- [LLM Rate Limiting on Kubernetes](/articles/kubernetes/llm-rate-limiting/)
