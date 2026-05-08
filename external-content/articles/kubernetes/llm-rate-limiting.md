---
title: "LLM Rate Limiting in Production: Token Budgets, Per-User Quotas, and Abuse Detection"
description: "Request-count rate limiting fails for LLM workloads because a single request can consume 100K tokens. Token-based rate limiting with per-user quotas and abuse detection prevents runaway costs and catches prompt injection probing before it escalates."
slug: "llm-rate-limiting"
date: 2026-04-03
lastmod: 2026-04-03
category: "kubernetes"
tags: ["ai", "rate-limiting", "tokens", "redis", "envoy", "abuse-detection", "kong"]
personas: ["platform-engineer", "ai-ml-engineer", "devops-engineer"]
article_number: 151
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Kong"
    id: 86
    category: "api-gateway"
  - name: "Envoy"
    id: 87
    category: "service-proxy"
premium_pack: "llm-rate-limiting-policy-templates"
published: true
layout: article.njk
permalink: "/articles/kubernetes/llm-rate-limiting/index.html"
---

# LLM Rate Limiting in Production: Token Budgets, Per-User Quotas, and Abuse Detection

## Problem

Traditional API rate limiting counts requests. One request equals one unit. This assumption collapses with large language models. A single LLM request can range from 50 tokens (a quick classification) to 128,000 tokens (a full-context document analysis). Treating both as equal in a rate limiter means a user sending cheap classification requests gets throttled at the same threshold as a user running full-context summarizations that cost 2,000 times more.

The consequences are both financial and operational. A user who discovers they can send 60 requests per minute to a GPT-4 class model, each consuming 100K input tokens and generating 4K output tokens, runs up thousands of dollars in provider charges within an hour. Request-count rate limiting sees 60 requests per minute and considers it normal. Token-based metering sees 6.24 million tokens per minute and flags it immediately.

The problem compounds across user tiers. Free-tier users should get different token budgets than enterprise customers. Teams running batch summarization jobs need higher burst capacity than interactive chatbot users. A single rate limiting policy applied uniformly either throttles legitimate enterprise users or leaves the door open for free-tier abuse.

Abuse detection adds another layer. Prompt injection probing follows a distinctive pattern: high input token counts (long, crafted prompts) paired with short output tokens (the model refuses or returns an error). Request-count rate limiting cannot distinguish this pattern from legitimate usage. Token-aware rate limiting can.

**Target systems:** API gateways proxying LLM inference endpoints. Internal model serving infrastructure (vLLM, TGI, Triton). Applications consuming external AI provider APIs (OpenAI, Anthropic, Cohere). Redis or equivalent state store for distributed token counters.

## Threat Model

- **Adversary:** External user abusing free or trial-tier access. Compromised internal service account making unchecked model calls. Automated bot scripting bulk inference requests. Attacker probing for prompt injection vulnerabilities via rapid prompt iteration.
- **Objective:** Consume disproportionate compute resources without paying. Generate excessive provider API charges billed to the organization. Probe model behavior through high-volume prompt injection attempts. Denial-of-wallet attack that exhausts monthly budgets.
- **Blast radius:** Without token-based rate limiting, a single user or compromised service can exhaust an entire team's monthly AI budget in hours. At $0.01 per 1K input tokens and $0.03 per 1K output tokens for frontier models, 10 million tokens of abuse costs $100-300. At scale, with multiple abusers or a coordinated attack, monthly budgets of $10,000+ can be drained before anyone notices.

## Configuration

### Token Counting Middleware

Build token counting into the request/response pipeline. The gateway must inspect both the request (to count input tokens) and the response (to count output tokens) before updating rate limit counters.

```python
# token_counter.py
# Middleware for counting tokens in LLM requests and responses
import tiktoken
import redis
import time
import json
from datetime import datetime

class TokenRateLimiter:
    def __init__(self, redis_url="redis://redis.llm-gateway.svc.cluster.local:6379"):
        self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self.encoder = tiktoken.get_encoding("cl100k_base")

    def count_input_tokens(self, request_body: dict) -> int:
        """Count tokens in the request payload."""
        messages = request_body.get("messages", [])
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total += len(self.encoder.encode(content))
            elif isinstance(content, list):
                # Multimodal: estimate image tokens separately
                for part in content:
                    if part.get("type") == "text":
                        total += len(self.encoder.encode(part["text"]))
                    elif part.get("type") == "image_url":
                        total += 765  # Base cost for low-detail image
        return total

    def check_and_update(self, user_id: str, tier: str,
                         input_tokens: int, model: str) -> dict:
        """Check if user is within token budget. Returns allow/deny decision."""
        limits = self._get_tier_limits(tier, model)
        now = datetime.utcnow()

        # Keys for different time windows
        minute_key = f"tokens:{user_id}:{model}:{now.strftime('%Y%m%d%H%M')}"
        hour_key = f"tokens:{user_id}:{model}:{now.strftime('%Y%m%d%H')}"
        day_key = f"tokens:{user_id}:{model}:{now.strftime('%Y%m%d')}"
        month_key = f"tokens:{user_id}:{model}:{now.strftime('%Y%m')}"

        pipe = self.redis.pipeline()
        pipe.get(minute_key)
        pipe.get(hour_key)
        pipe.get(day_key)
        pipe.get(month_key)
        results = pipe.execute()

        current = {
            "minute": int(results[0] or 0),
            "hour": int(results[1] or 0),
            "day": int(results[2] or 0),
            "month": int(results[3] or 0),
        }

        # Check all windows
        for window, key in [("minute", minute_key), ("hour", hour_key),
                            ("day", day_key), ("month", month_key)]:
            if current[window] + input_tokens > limits[window]:
                return {
                    "allowed": False,
                    "reason": f"{window}_limit_exceeded",
                    "current": current[window],
                    "limit": limits[window],
                    "retry_after": self._retry_after(window),
                }

        # Pre-deduct input tokens (output tokens added after response)
        pipe = self.redis.pipeline()
        for key, ttl in [(minute_key, 120), (hour_key, 7200),
                         (day_key, 172800), (month_key, 2764800)]:
            pipe.incrby(key, input_tokens)
            pipe.expire(key, ttl)
        pipe.execute()

        return {"allowed": True, "input_tokens_reserved": input_tokens}

    def record_output_tokens(self, user_id: str, model: str,
                             output_tokens: int):
        """Record output tokens after response is received."""
        now = datetime.utcnow()
        keys = [
            (f"tokens:{user_id}:{model}:{now.strftime('%Y%m%d%H%M')}", 120),
            (f"tokens:{user_id}:{model}:{now.strftime('%Y%m%d%H')}", 7200),
            (f"tokens:{user_id}:{model}:{now.strftime('%Y%m%d')}", 172800),
            (f"tokens:{user_id}:{model}:{now.strftime('%Y%m')}", 2764800),
        ]
        pipe = self.redis.pipeline()
        for key, ttl in keys:
            pipe.incrby(key, output_tokens)
            pipe.expire(key, ttl)
        pipe.execute()

    def _get_tier_limits(self, tier: str, model: str) -> dict:
        """Token limits per time window by tier and model cost class."""
        cost_multiplier = self._model_cost_multiplier(model)
        base_limits = {
            "free":       {"minute": 10000, "hour": 100000,
                           "day": 500000, "month": 5000000},
            "pro":        {"minute": 50000, "hour": 1000000,
                           "day": 10000000, "month": 100000000},
            "enterprise": {"minute": 200000, "hour": 5000000,
                           "day": 50000000, "month": 500000000},
        }
        limits = base_limits.get(tier, base_limits["free"])
        # Expensive models get tighter limits (inverse of cost)
        return {k: int(v / cost_multiplier) for k, v in limits.items()}

    def _model_cost_multiplier(self, model: str) -> float:
        """Higher multiplier = more expensive model = tighter token limit."""
        model_costs = {
            "gpt-4o": 1.0,
            "gpt-4o-mini": 0.2,
            "claude-sonnet": 0.6,
            "claude-opus": 3.0,
            "llama-3-70b": 0.15,
        }
        return model_costs.get(model, 1.0)

    def _retry_after(self, window: str) -> int:
        """Seconds until the rate limit window resets."""
        return {"minute": 60, "hour": 3600,
                "day": 86400, "month": 2592000}[window]
```

### Kong Plugin for Token-Based Rate Limiting

```yaml
# kong-token-rate-limiting.yaml
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: llm-token-rate-limit
  namespace: llm-gateway
plugin: pre-function
config:
  access:
    - |
      local redis = require "resty.redis"
      local cjson = require "cjson"

      local function count_tokens_estimate(text)
        -- Rough estimate: 1 token per 4 characters for English text
        -- Production systems should use a proper tokenizer
        if not text then return 0 end
        return math.ceil(#text / 4)
      end

      local body = kong.request.get_raw_body()
      if not body then return end

      local ok, parsed = pcall(cjson.decode, body)
      if not ok then return end

      local input_tokens = 0
      if parsed.messages then
        for _, msg in ipairs(parsed.messages) do
          if type(msg.content) == "string" then
            input_tokens = input_tokens + count_tokens_estimate(msg.content)
          end
        end
      end

      local consumer = kong.client.get_consumer()
      if not consumer then
        return kong.response.exit(401, { error = "authentication required" })
      end

      local red = redis:new()
      red:set_timeout(100)
      local ok, err = red:connect("redis.llm-gateway.svc.cluster.local", 6379)
      if not ok then
        kong.log.err("Redis connection failed: ", err)
        return  -- fail open if Redis is down (configurable)
      end

      local tier = consumer.custom_id or "free"
      local model = parsed.model or "default"
      local window_key = consumer.id .. ":" .. model .. ":"
                         .. os.date("%Y%m%d%H")

      local current = red:get(window_key)
      current = tonumber(current) or 0

      local limits = {
        free = 100000, pro = 1000000, enterprise = 5000000
      }
      local limit = limits[tier] or limits["free"]

      if current + input_tokens > limit then
        red:set_keepalive(10000, 100)
        return kong.response.exit(429, {
          error = "token_limit_exceeded",
          current_tokens = current,
          limit = limit,
          retry_after = 3600
        }, {
          ["Retry-After"] = "3600",
          ["X-RateLimit-Tokens-Remaining"] = tostring(limit - current),
          ["X-RateLimit-Tokens-Limit"] = tostring(limit)
        })
      end

      red:incrby(window_key, input_tokens)
      red:expire(window_key, 7200)
      red:set_keepalive(10000, 100)

      -- Store input token count for response phase
      kong.ctx.shared.input_tokens = input_tokens
  log:
    - |
      -- Record output tokens from the response
      local cjson = require "cjson"
      local redis = require "resty.redis"

      local body = kong.service.response.get_raw_body()
      if not body then return end

      local ok, parsed = pcall(cjson.decode, body)
      if not ok then return end

      local output_tokens = 0
      if parsed.usage then
        output_tokens = parsed.usage.completion_tokens or 0
      end

      if output_tokens > 0 then
        local consumer = kong.client.get_consumer()
        if not consumer then return end
        local model = "default"
        if parsed.model then model = parsed.model end

        local red = redis:new()
        red:set_timeout(100)
        local ok, err = red:connect(
          "redis.llm-gateway.svc.cluster.local", 6379
        )
        if ok then
          local window_key = consumer.id .. ":" .. model .. ":"
                             .. os.date("%Y%m%d%H")
          red:incrby(window_key, output_tokens)
          red:set_keepalive(10000, 100)
        end
      end
```

### Envoy ext_proc Filter for Token Counting

```yaml
# envoy-token-ratelimit.yaml
# Envoy configuration using ext_proc for token-aware rate limiting
static_resources:
  listeners:
    - name: llm_listener
      address:
        socket_address:
          address: 0.0.0.0
          port_value: 8080
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: llm_gateway
                route_config:
                  name: llm_routes
                  virtual_hosts:
                    - name: llm_backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/v1/chat/completions"
                          route:
                            cluster: llm_backend
                http_filters:
                  - name: envoy.filters.http.ext_proc
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
                      grpc_service:
                        envoy_grpc:
                          cluster_name: token_ratelimit_service
                      processing_mode:
                        request_body_mode: BUFFERED
                        response_body_mode: BUFFERED
                      message_timeout: 2s
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: token_ratelimit_service
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {}
      load_assignment:
        cluster_name: token_ratelimit_service
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: token-ratelimit.llm-gateway.svc.cluster.local
                      port_value: 50051
    - name: llm_backend
      type: STRICT_DNS
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: llm_backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: inference.ml-serving.svc.cluster.local
                      port_value: 8000
```

### Abuse Detection Rules

Detect prompt injection probing and other abuse patterns through token consumption analysis.

```yaml
# prometheus-token-abuse-alerts.yaml
groups:
  - name: llm-token-abuse
    rules:
      # High input tokens with very short outputs: prompt injection probing
      - alert: LLMPromptInjectionProbing
        expr: >
          (
            sum by (user_id) (
              rate(llm_input_tokens_total[10m])
            )
            /
            (sum by (user_id) (
              rate(llm_output_tokens_total[10m])
            ) + 1)
          ) > 50
          and
          sum by (user_id) (
            rate(llm_request_total[10m])
          ) > 0.5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: >
            Possible prompt injection probing by {{ $labels.user_id }}.
            Input/output token ratio exceeds 50:1 over 10 minutes.
          runbook: >
            Review request logs for this user. High input with minimal
            output indicates the user is testing prompt boundaries.
            Consider blocking the user and reviewing submitted prompts.

      # Single user consuming disproportionate share of token budget
      - alert: LLMTokenBudgetHog
        expr: >
          sum by (user_id) (
            increase(llm_tokens_total[1h])
          )
          /
          sum(increase(llm_tokens_total[1h]))
          > 0.5
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: >
            User {{ $labels.user_id }} consuming over 50 percent of
            total token budget in the last hour.

      # Rapid request pattern: many requests in tight succession
      - alert: LLMAutomatedAbuse
        expr: >
          sum by (user_id) (
            rate(llm_request_total[1m])
          ) > 10
          and
          stddev_over_time(
            sum by (user_id) (
              rate(llm_request_total[1m])
            )[10m:1m]
          ) < 0.5
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: >
            User {{ $labels.user_id }} sending requests at a constant
            automated rate (>10/min with low variance). Likely scripted.

      # Sudden model upgrade: user switches from cheap to expensive model
      - alert: LLMModelUpgradeAbuse
        expr: >
          sum by (user_id) (
            rate(llm_tokens_total{model=~".*opus.*|.*gpt-4o$"}[15m])
          )
          > 5 *
          avg_over_time(
            sum by (user_id) (
              rate(llm_tokens_total{model=~".*opus.*|.*gpt-4o$"}[15m])
            )[7d:1h]
          )
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: >
            User {{ $labels.user_id }} suddenly using 5x more tokens on
            expensive models compared to 7-day average.
```

### Kubernetes Deployment with Redis State Store

```yaml
# llm-ratelimit-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-rate-limiter
  namespace: llm-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: llm-rate-limiter
  template:
    metadata:
      labels:
        app: llm-rate-limiter
    spec:
      containers:
        - name: rate-limiter
          image: llm-gateway/token-rate-limiter:1.4.0
          ports:
            - containerPort: 50051
              name: grpc
            - containerPort: 9090
              name: metrics
          env:
            - name: REDIS_URL
              value: "redis://redis-master.llm-gateway.svc.cluster.local:6379"
            - name: FAIL_OPEN
              value: "false"
            - name: LOG_LEVEL
              value: "info"
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
          readinessProbe:
            grpc:
              port: 50051
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            grpc:
              port: 50051
            initialDelaySeconds: 10
            periodSeconds: 15
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-master
  namespace: llm-gateway
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
      role: master
  template:
    metadata:
      labels:
        app: redis
        role: master
    spec:
      containers:
        - name: redis
          image: redis:7.2-alpine
          ports:
            - containerPort: 6379
          args:
            - "--maxmemory"
            - "512mb"
            - "--maxmemory-policy"
            - "volatile-ttl"
            - "--save"
            - ""
            - "--appendonly"
            - "no"
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 640Mi
---
apiVersion: v1
kind: Service
metadata:
  name: redis-master
  namespace: llm-gateway
spec:
  selector:
    app: redis
    role: master
  ports:
    - port: 6379
      targetPort: 6379
---
apiVersion: v1
kind: Service
metadata:
  name: llm-rate-limiter
  namespace: llm-gateway
spec:
  selector:
    app: llm-rate-limiter
  ports:
    - name: grpc
      port: 50051
      targetPort: 50051
    - name: metrics
      port: 9090
      targetPort: 9090
```

### Prometheus Metrics for Token Usage

```yaml
# prometheus-token-metrics-scrape.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: llm-rate-limiter
  namespace: llm-gateway
spec:
  selector:
    matchLabels:
      app: llm-rate-limiter
  endpoints:
    - port: metrics
      interval: 15s
      path: /metrics
      metricRelabelings:
        - sourceLabels: [__name__]
          regex: "llm_(input_tokens|output_tokens|tokens|request)_(total|bucket)"
          action: keep
```

```python
# metrics.py
# Prometheus metrics exported by the token rate limiter
from prometheus_client import Counter, Histogram, Gauge

# Token counters by user, model, and tier
llm_input_tokens_total = Counter(
    "llm_input_tokens_total",
    "Total input tokens processed",
    ["user_id", "model", "tier", "org_id"]
)

llm_output_tokens_total = Counter(
    "llm_output_tokens_total",
    "Total output tokens generated",
    ["user_id", "model", "tier", "org_id"]
)

llm_tokens_total = Counter(
    "llm_tokens_total",
    "Total tokens (input + output)",
    ["user_id", "model", "tier", "org_id"]
)

# Rate limit decisions
llm_ratelimit_decisions_total = Counter(
    "llm_ratelimit_decisions_total",
    "Rate limit decisions",
    ["user_id", "tier", "decision", "reason"]
)

# Token usage per request (for percentile analysis)
llm_request_tokens = Histogram(
    "llm_request_tokens",
    "Tokens per request",
    ["model", "tier", "direction"],
    buckets=[100, 500, 1000, 5000, 10000, 50000, 100000, 200000]
)

# Current usage as percentage of limit
llm_budget_utilization = Gauge(
    "llm_budget_utilization_ratio",
    "Current token usage as ratio of limit (0-1)",
    ["user_id", "tier", "window"]
)
```

## Expected Behaviour

- Every LLM request is metered by input and output token count, not just request count
- Free-tier users are limited to approximately 5 million tokens per month; pro-tier to 100 million; enterprise to 500 million
- Expensive models (Claude Opus, GPT-4o) have proportionally tighter token limits than cheaper models (GPT-4o-mini, Llama 3 70B)
- Users hitting their token limit receive HTTP 429 with a Retry-After header and their current usage in response headers
- Prompt injection probing (high input, low output ratio) triggers an alert within 5 minutes
- Automated scripting (constant request rate with low variance) is detected and flagged within 3 minutes
- Token counters in Redis survive individual pod restarts; data loss on Redis restart only affects the current time window
- Prometheus metrics enable per-user, per-model, per-tier dashboards showing token consumption trends

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| Token counting at the gateway | Adds 10-50ms latency for request body parsing and tokenization | Tokenizer library may count differently than the model provider | Use the same tokenizer the provider uses (tiktoken for OpenAI, provider SDKs where available). Accept 5-10% variance. True count comes from provider response and is reconciled. |
| Redis for distributed state | Enables consistent rate limiting across multiple gateway replicas | Redis failure blocks all rate limiting decisions | Configure fail-open or fail-closed based on risk tolerance. Run Redis with Sentinel for HA. Rate limiter pods cache last-known limits for 60 seconds on Redis failure. |
| Cost-aware model multipliers | Prevents users from draining budgets on expensive models | Multipliers need manual updates when provider pricing changes | Store multipliers in a ConfigMap. Alert when provider pricing pages change (external monitoring). Review quarterly. |
| Pre-deducting input tokens | Prevents users from exceeding limits by sending parallel requests | If the request fails upstream, the user loses tokens from their budget | Implement a reconciliation job that credits back tokens for failed requests (HTTP 5xx from upstream). Run every 5 minutes. |
| Per-minute burst windows | Allows short bursts of legitimate high-volume usage | Overly tight minute limits frustrate interactive users | Set minute limits high enough for 3-5 concurrent large requests. Use the hourly and daily windows as the real enforcement boundaries. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Redis unavailable | Rate limiter cannot check or update token counters | Redis health check fails; rate limiter logs connection errors | If configured fail-open: requests pass without rate limiting (risky but maintains availability). If fail-closed: all LLM requests return 503 until Redis recovers. Sentinel-managed Redis failover should complete within 30 seconds. |
| Tokenizer mismatch | Gateway counts differ from provider counts; users get throttled early or late | Compare gateway token counts against provider-reported usage.completion_tokens over time. Alert if drift exceeds 15%. | Update tokenizer library. Switch to provider-reported token counts as the source of truth for billing reconciliation. |
| Rate limit too aggressive for tier | Legitimate enterprise customers hit limits during normal batch processing | Support tickets. HTTP 429 rate increases for enterprise consumers. | Review actual usage patterns for the affected tier. Adjust limits in the ConfigMap. Consider dedicated rate limit profiles for batch workloads. |
| Abuse detection false positive | Legitimate user flagged as prompt injection prober (e.g., they send long documents for summarization) | User complaint. Review of flagged requests shows benign content. | Tune the input/output ratio threshold. Add exceptions for known document-processing use cases. Require manual review before automated blocking. |

## When to Consider a Managed Alternative

[Kong](https://konghq.com) Konnect with the AI Gateway plugin provides built-in token-aware rate limiting without custom plugin development. [Cloudflare](https://www.cloudflare.com) AI Gateway offers per-user token metering and cost tracking as a managed service in front of major AI providers. [Portkey](https://portkey.ai) provides a unified AI gateway with token budgets, caching, and abuse detection built in.

**Premium content pack:** LLM rate limiting policy templates. Token counting middleware for Envoy ext_proc and Kong, Redis schema for distributed counters, Prometheus alert rules for abuse detection, and Grafana dashboards for per-user token consumption.

## Related Articles

- [AI API Key Management: Rotation, Scoping, and Abuse Detection](/articles/kubernetes/ai-api-key-management/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [GPU Cost and Security Monitoring: Prometheus, Grafana, and Alerting](/articles/kubernetes/gpu-cost-security-monitoring/)
- [AI Guardrails Implementation: Content Filtering, Output Validation, and Safety Layers](/articles/kubernetes/ai-guardrails-implementation/)
- [Prometheus Security Metrics: What to Measure and How to Alert](/articles/observability/prometheus-security-metrics/)
