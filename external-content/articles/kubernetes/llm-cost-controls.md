---
title: "LLM Cost Controls: Budget Enforcement, Token Metering, and Spend Alerting"
description: "Without enforced budgets, a single team can exhaust an organization's entire AI spend in days. Token metering with per-team budgets, automatic request rejection at limits, model routing by cost, and chargeback dashboards turn LLM spending from a surprise into a managed line item."
slug: "llm-cost-controls"
date: 2026-03-28
lastmod: 2026-03-28
category: "kubernetes"
tags: ["ai", "cost-controls", "budgets", "metering", "grafana", "prometheus", "kubernetes"]
personas: ["platform-engineer", "ai-ml-engineer", "devops-engineer", "finops"]
article_number: 152
difficulty: "intermediate"
estimated_reading_time: 15
provider_bridges:
  - name: "Kong"
    id: 86
    category: "api-gateway"
  - name: "Grafana"
    id: 42
    category: "observability"
premium_pack: "llm-cost-controls-budget-templates"
published: true
layout: article.njk
permalink: "/articles/kubernetes/llm-cost-controls/index.html"
---

# LLM Cost Controls: Budget Enforcement, Token Metering, and Spend Alerting

## Problem

LLM costs are unpredictable by default. A single API call to a frontier model can cost $0.001 or $2.00 depending on input length, output length, and model selection. Teams integrating LLMs into production services often discover their actual spend only when the monthly invoice arrives. By then, a misconfigured batch job, an unexpected traffic spike, or a developer testing with the wrong model has already consumed the budget.

The core difficulty is that LLM pricing is multi-dimensional. Cost depends on the model (GPT-4o costs 15x more per token than GPT-4o-mini), the direction (output tokens cost 2-4x more than input tokens), and the volume. Traditional cloud cost controls that set monthly spending caps at the account level are too coarse. A $10,000 monthly cap across all teams tells you nothing about which team is responsible for which portion of the spend, and it cannot enforce per-team accountability.

Without per-team budgets, cost conversations devolve into blame. The ML team says their experiments are essential. The product team says the chatbot feature drives revenue. The data team says their summarization pipeline saves analyst time. None of them have visibility into what they actually spend, and no mechanism exists to enforce limits before the money is gone.

Cost estimation before request execution adds another dimension. If the gateway can estimate the cost of a request before forwarding it to the model, it can reject requests that would push a team over budget, route expensive requests to cheaper models, or warn users that their request will consume a significant portion of their remaining budget.

**Target systems:** API gateways proxying LLM inference requests. Kubernetes clusters running model serving infrastructure. Prometheus and Grafana for metrics and dashboards. Custom resource definitions (CRDs) for budget policies. Redis for real-time spend tracking.

## Threat Model

- **Adversary:** Internal teams without cost awareness making unconstrained API calls. Misconfigured automation sending requests in a loop. Developers using expensive models for tasks that cheaper models handle adequately. Shadow AI usage where teams bypass the managed gateway to call providers directly.
- **Objective (from a risk perspective):** Uncontrolled spend that blows through quarterly AI budgets. Inability to attribute costs to specific teams for chargeback. No early warning before budget exhaustion. Financial exposure from compromised credentials used for bulk inference.
- **Blast radius:** Without cost controls, a single team running a document processing pipeline against Claude Opus at $15 per 1M input tokens and $75 per 1M output tokens can consume $5,000 in a single weekend. Across an organization with 10 teams, unmanaged monthly AI spend routinely exceeds 3-5x the planned budget.

## Configuration

### Kubernetes CRD for Budget Definitions

Define per-team, per-model budgets as Kubernetes custom resources. A controller watches these resources and pushes budget configuration to the gateway.

```yaml
# llm-budget-crd.yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: llmbudgets.ai.systemhardening.com
spec:
  group: ai.systemhardening.com
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                team:
                  type: string
                monthlyBudgetUSD:
                  type: number
                alertThresholds:
                  type: array
                  items:
                    type: object
                    properties:
                      percent:
                        type: integer
                      action:
                        type: string
                        enum: ["alert", "alert_and_downgrade", "reject"]
                      notifyChannel:
                        type: string
                modelLimits:
                  type: array
                  items:
                    type: object
                    properties:
                      modelPattern:
                        type: string
                      maxMonthlyUSD:
                        type: number
                      allowedApps:
                        type: array
                        items:
                          type: string
                defaultModel:
                  type: string
                costRouting:
                  type: object
                  properties:
                    enabled:
                      type: boolean
                    cheapModel:
                      type: string
                    expensiveModel:
                      type: string
                    complexityThreshold:
                      type: integer
            status:
              type: object
              properties:
                currentSpendUSD:
                  type: number
                lastUpdated:
                  type: string
                budgetUtilization:
                  type: number
      additionalPrinterColumns:
        - name: Team
          type: string
          jsonPath: .spec.team
        - name: Budget
          type: number
          jsonPath: .spec.monthlyBudgetUSD
        - name: Spent
          type: number
          jsonPath: .status.currentSpendUSD
        - name: Utilization
          type: number
          jsonPath: .status.budgetUtilization
  scope: Namespaced
  names:
    plural: llmbudgets
    singular: llmbudget
    kind: LLMBudget
    shortNames:
      - lb
```

```yaml
# example-budget-ml-team.yaml
apiVersion: ai.systemhardening.com/v1
kind: LLMBudget
metadata:
  name: ml-team-budget
  namespace: ml-platform
spec:
  team: ml-team
  monthlyBudgetUSD: 8000
  alertThresholds:
    - percent: 50
      action: alert
      notifyChannel: "#ml-team-costs"
    - percent: 80
      action: alert_and_downgrade
      notifyChannel: "#ml-team-costs"
    - percent: 100
      action: reject
      notifyChannel: "#ml-team-costs"
  modelLimits:
    - modelPattern: "claude-opus*"
      maxMonthlyUSD: 3000
      allowedApps: ["research-assistant", "code-review"]
    - modelPattern: "gpt-4o"
      maxMonthlyUSD: 2000
      allowedApps: ["chatbot", "summarizer"]
    - modelPattern: "gpt-4o-mini"
      maxMonthlyUSD: 1000
    - modelPattern: "llama-3*"
      maxMonthlyUSD: 500
  defaultModel: "gpt-4o-mini"
  costRouting:
    enabled: true
    cheapModel: "gpt-4o-mini"
    expensiveModel: "gpt-4o"
    complexityThreshold: 500  # input tokens below this use cheap model
```

### Real-Time Cost Metering Service

```python
# cost_metering.py
# Calculates real-time cost from token usage and enforces budgets
import redis
import json
from datetime import datetime
from prometheus_client import Counter, Gauge

# Per-model pricing (USD per 1M tokens)
MODEL_PRICING = {
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "claude-opus": {"input": 15.00, "output": 75.00},
    "claude-sonnet": {"input": 3.00, "output": 15.00},
    "claude-haiku": {"input": 0.25, "output": 1.25},
    "llama-3-70b": {"input": 0.59, "output": 0.79},
    "llama-3-8b": {"input": 0.05, "output": 0.08},
}

# Prometheus metrics
llm_cost_total = Counter(
    "llm_cost_usd_total",
    "Total LLM cost in USD",
    ["team", "app", "model"]
)
llm_budget_remaining = Gauge(
    "llm_budget_remaining_usd",
    "Remaining monthly budget in USD",
    ["team"]
)
llm_budget_utilization = Gauge(
    "llm_budget_utilization_ratio",
    "Budget utilization as a ratio (0.0 to 1.0)",
    ["team"]
)
llm_cost_estimate = Counter(
    "llm_cost_estimate_usd_total",
    "Pre-request cost estimates in USD",
    ["team", "app", "model"]
)
llm_requests_rejected = Counter(
    "llm_requests_rejected_budget_total",
    "Requests rejected due to budget limits",
    ["team", "reason"]
)


class CostMeter:
    def __init__(self, redis_url, budgets: dict):
        self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self.budgets = budgets  # team -> LLMBudget spec

    def estimate_cost(self, model: str, input_tokens: int,
                      max_output_tokens: int = None) -> float:
        """Estimate the cost of a request before execution."""
        pricing = MODEL_PRICING.get(model)
        if not pricing:
            pricing = MODEL_PRICING["gpt-4o"]  # conservative default

        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        # Estimate output cost using max_tokens or a default
        est_output = max_output_tokens or min(input_tokens, 4096)
        output_cost = (est_output / 1_000_000) * pricing["output"]

        return input_cost + output_cost

    def check_budget(self, team: str, app: str, model: str,
                     estimated_cost: float) -> dict:
        """Check if the request fits within the team's remaining budget."""
        budget_spec = self.budgets.get(team)
        if not budget_spec:
            return {"allowed": True, "reason": "no_budget_defined"}

        month_key = f"spend:{team}:{datetime.utcnow().strftime('%Y%m')}"
        model_key = f"spend:{team}:{model}:{datetime.utcnow().strftime('%Y%m')}"

        current_spend = float(self.redis.get(month_key) or 0)
        model_spend = float(self.redis.get(model_key) or 0)

        monthly_limit = budget_spec["monthlyBudgetUSD"]
        utilization = current_spend / monthly_limit if monthly_limit > 0 else 0

        # Update Prometheus gauges
        llm_budget_remaining.labels(team=team).set(
            monthly_limit - current_spend
        )
        llm_budget_utilization.labels(team=team).set(utilization)

        # Check model-specific limits
        for ml in budget_spec.get("modelLimits", []):
            if self._model_matches(model, ml["modelPattern"]):
                if model_spend + estimated_cost > ml["maxMonthlyUSD"]:
                    llm_requests_rejected.labels(
                        team=team, reason="model_limit"
                    ).inc()
                    return {
                        "allowed": False,
                        "reason": "model_budget_exceeded",
                        "model": model,
                        "model_spend": model_spend,
                        "model_limit": ml["maxMonthlyUSD"],
                    }
                # Check allowed apps
                allowed_apps = ml.get("allowedApps", [])
                if allowed_apps and app not in allowed_apps:
                    llm_requests_rejected.labels(
                        team=team, reason="app_not_allowed"
                    ).inc()
                    return {
                        "allowed": False,
                        "reason": "app_not_allowed_for_model",
                        "model": model,
                        "app": app,
                        "allowed_apps": allowed_apps,
                    }

        # Check alert thresholds
        action = "allow"
        for threshold in sorted(
            budget_spec.get("alertThresholds", []),
            key=lambda t: t["percent"]
        ):
            pct = threshold["percent"] / 100.0
            if (current_spend + estimated_cost) / monthly_limit >= pct:
                action = threshold["action"]

        if action == "reject":
            llm_requests_rejected.labels(
                team=team, reason="budget_exceeded"
            ).inc()
            return {
                "allowed": False,
                "reason": "monthly_budget_exceeded",
                "current_spend": current_spend,
                "budget": monthly_limit,
                "utilization": utilization,
            }

        downgrade_model = None
        if action == "alert_and_downgrade":
            default = budget_spec.get("defaultModel", "gpt-4o-mini")
            if model != default:
                downgrade_model = default

        return {
            "allowed": True,
            "action": action,
            "downgrade_model": downgrade_model,
            "current_spend": current_spend,
            "budget": monthly_limit,
            "estimated_cost": estimated_cost,
            "utilization": utilization,
        }

    def record_actual_cost(self, team: str, app: str, model: str,
                           input_tokens: int, output_tokens: int):
        """Record actual cost after response is received."""
        pricing = MODEL_PRICING.get(model, MODEL_PRICING["gpt-4o"])
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        total_cost = input_cost + output_cost

        month = datetime.utcnow().strftime("%Y%m")
        month_key = f"spend:{team}:{month}"
        model_key = f"spend:{team}:{model}:{month}"
        app_key = f"spend:{team}:{app}:{month}"

        pipe = self.redis.pipeline()
        pipe.incrbyfloat(month_key, total_cost)
        pipe.expire(month_key, 2764800)  # 32 days
        pipe.incrbyfloat(model_key, total_cost)
        pipe.expire(model_key, 2764800)
        pipe.incrbyfloat(app_key, total_cost)
        pipe.expire(app_key, 2764800)
        pipe.execute()

        # Update Prometheus counters
        llm_cost_total.labels(
            team=team, app=app, model=model
        ).inc(total_cost)

    def _model_matches(self, model: str, pattern: str) -> bool:
        """Simple glob matching for model patterns."""
        if pattern.endswith("*"):
            return model.startswith(pattern[:-1])
        return model == pattern
```

### Cost-Aware Model Routing

Route requests to cheaper or more expensive models based on query complexity and remaining budget.

```python
# model_router.py
# Routes requests to appropriate models based on cost and complexity
import tiktoken


class ModelRouter:
    def __init__(self, cost_meter):
        self.cost_meter = cost_meter
        self.encoder = tiktoken.get_encoding("cl100k_base")

    def route(self, team: str, app: str, requested_model: str,
              request_body: dict, budget_spec: dict) -> dict:
        """Determine which model should handle this request."""
        if not budget_spec.get("costRouting", {}).get("enabled", False):
            return {"model": requested_model, "routed": False}

        messages = request_body.get("messages", [])
        input_tokens = sum(
            len(self.encoder.encode(m.get("content", "")))
            for m in messages
            if isinstance(m.get("content"), str)
        )

        threshold = budget_spec["costRouting"].get(
            "complexityThreshold", 500
        )
        cheap_model = budget_spec["costRouting"]["cheapModel"]
        expensive_model = budget_spec["costRouting"]["expensiveModel"]

        # Simple requests go to the cheap model
        if input_tokens < threshold:
            target = cheap_model
            reason = "simple_query"
        else:
            target = expensive_model
            reason = "complex_query"

        # Budget pressure override: if above 80%, always use cheap model
        budget_check = self.cost_meter.check_budget(
            team, app, requested_model, 0
        )
        utilization = budget_check.get("utilization", 0)

        if utilization > 0.8:
            target = cheap_model
            reason = "budget_pressure"

        return {
            "model": target,
            "routed": target != requested_model,
            "reason": reason,
            "original_model": requested_model,
            "input_tokens": input_tokens,
            "utilization": utilization,
        }
```

### Spend Alert Rules

```yaml
# prometheus-spend-alerts.yaml
groups:
  - name: llm-cost-alerts
    rules:
      # 50% budget consumed
      - alert: LLMBudget50Percent
        expr: llm_budget_utilization_ratio > 0.5
        for: 5m
        labels:
          severity: info
        annotations:
          summary: >
            Team {{ $labels.team }} has consumed 50 percent of their
            monthly LLM budget. Current utilization:
            {{ $value | humanizePercentage }}.

      # 80% budget consumed - start downgrading models
      - alert: LLMBudget80Percent
        expr: llm_budget_utilization_ratio > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: >
            Team {{ $labels.team }} has consumed 80 percent of their
            monthly LLM budget. Model downgrading is now active.
            Remaining: ${{ printf "%.2f"
            (query "llm_budget_remaining_usd" | first | value) }}.
          runbook: >
            Review high-cost requests. Consider pausing non-critical
            batch jobs until next billing cycle.

      # 100% budget consumed - rejecting requests
      - alert: LLMBudget100Percent
        expr: llm_budget_utilization_ratio >= 1.0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: >
            Team {{ $labels.team }} has exhausted their monthly LLM
            budget. All requests are being rejected. Contact platform
            team for budget increase or wait for next billing cycle.

      # Rapid spend rate: on track to exhaust budget in under 7 days
      - alert: LLMBudgetBurnRate
        expr: >
          (
            rate(llm_cost_usd_total[6h]) * 720
          ) > 2 * llm_budget_remaining_usd
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: >
            Team {{ $labels.team }} is spending at a rate that will
            exhaust their remaining budget in less than 7 days.

      # Single app consuming disproportionate share
      - alert: LLMAppCostSpike
        expr: >
          sum by (team, app) (
            rate(llm_cost_usd_total[1h])
          )
          > 0.7 *
          sum by (team) (
            rate(llm_cost_usd_total[1h])
          )
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: >
            App {{ $labels.app }} in team {{ $labels.team }} is
            consuming over 70 percent of the team's hourly LLM spend.
```

### Grafana Chargeback Dashboard

```json
{
  "dashboard": {
    "title": "LLM Cost Chargeback",
    "tags": ["llm", "cost", "finops"],
    "timezone": "utc",
    "panels": [
      {
        "title": "Monthly Spend by Team",
        "type": "barchart",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
        "targets": [
          {
            "expr": "sum by (team) (llm_cost_usd_total)",
            "legendFormat": "{{ team }}"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "currencyUSD"
          }
        }
      },
      {
        "title": "Budget Utilization by Team",
        "type": "gauge",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
        "targets": [
          {
            "expr": "llm_budget_utilization_ratio",
            "legendFormat": "{{ team }}"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percentunit",
            "thresholds": {
              "steps": [
                {"value": 0, "color": "green"},
                {"value": 0.5, "color": "yellow"},
                {"value": 0.8, "color": "orange"},
                {"value": 1.0, "color": "red"}
              ]
            }
          }
        }
      },
      {
        "title": "Spend by Model (All Teams)",
        "type": "piechart",
        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 8},
        "targets": [
          {
            "expr": "sum by (model) (rate(llm_cost_usd_total[30d]))",
            "legendFormat": "{{ model }}"
          }
        ],
        "fieldConfig": {
          "defaults": {"unit": "currencyUSD"}
        }
      },
      {
        "title": "Spend by App per Team",
        "type": "table",
        "gridPos": {"h": 8, "w": 16, "x": 8, "y": 8},
        "targets": [
          {
            "expr": "sum by (team, app, model) (increase(llm_cost_usd_total[30d]))",
            "format": "table",
            "instant": true
          }
        ],
        "fieldConfig": {
          "defaults": {"unit": "currencyUSD"},
          "overrides": [
            {
              "matcher": {"id": "byName", "options": "Value"},
              "properties": [
                {"id": "displayName", "value": "Monthly Cost (USD)"}
              ]
            }
          ]
        }
      },
      {
        "title": "Daily Spend Trend",
        "type": "timeseries",
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 16},
        "targets": [
          {
            "expr": "sum by (team) (increase(llm_cost_usd_total[1d]))",
            "legendFormat": "{{ team }}"
          }
        ],
        "fieldConfig": {
          "defaults": {"unit": "currencyUSD"}
        }
      },
      {
        "title": "Requests Rejected (Budget Limits)",
        "type": "stat",
        "gridPos": {"h": 4, "w": 12, "x": 0, "y": 24},
        "targets": [
          {
            "expr": "sum by (team) (increase(llm_requests_rejected_budget_total[24h]))",
            "legendFormat": "{{ team }}"
          }
        ]
      },
      {
        "title": "Model Routing Decisions",
        "type": "timeseries",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 24},
        "targets": [
          {
            "expr": "sum by (reason) (rate(llm_model_routing_total[1h]))",
            "legendFormat": "{{ reason }}"
          }
        ]
      }
    ]
  }
}
```

### Budget Controller Deployment

```yaml
# budget-controller-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-budget-controller
  namespace: llm-gateway
spec:
  replicas: 2
  selector:
    matchLabels:
      app: llm-budget-controller
  template:
    metadata:
      labels:
        app: llm-budget-controller
    spec:
      serviceAccountName: llm-budget-controller
      containers:
        - name: controller
          image: llm-gateway/budget-controller:1.2.0
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9090
              name: metrics
          env:
            - name: REDIS_URL
              value: "redis://redis-master.llm-gateway.svc.cluster.local:6379"
            - name: WATCH_NAMESPACE
              value: ""  # empty = all namespaces
            - name: RECONCILE_INTERVAL
              value: "30s"
            - name: SLACK_WEBHOOK_URL
              valueFrom:
                secretKeyRef:
                  name: llm-budget-secrets
                  key: slack-webhook
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 250m
              memory: 256Mi
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: llm-budget-controller
  namespace: llm-gateway
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: llm-budget-controller
rules:
  - apiGroups: ["ai.systemhardening.com"]
    resources: ["llmbudgets"]
    verbs: ["get", "list", "watch", "update", "patch"]
  - apiGroups: ["ai.systemhardening.com"]
    resources: ["llmbudgets/status"]
    verbs: ["update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: llm-budget-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: llm-budget-controller
subjects:
  - kind: ServiceAccount
    name: llm-budget-controller
    namespace: llm-gateway
```

## Expected Behaviour

- Every team has a defined monthly LLM budget expressed in USD, managed via a Kubernetes CRD (`kubectl get llmbudgets`)
- Token consumption is converted to cost in real time using per-model pricing tables
- At 50% budget utilization, the team receives an informational Slack notification
- At 80% utilization, alerts fire and requests are automatically downgraded to cheaper models where cost routing is enabled
- At 100% utilization, all LLM requests for the team return HTTP 429 with a clear error message explaining the budget is exhausted
- Per-model limits prevent a single expensive model from consuming the entire budget (e.g., Claude Opus limited to $3,000 of an $8,000 budget)
- Cost-aware routing sends simple queries (under 500 input tokens) to cheap models and complex queries to capable models
- Grafana dashboards show per-team, per-app, per-model spend updated in near real time
- Monthly chargeback reports can be generated from Prometheus data showing exactly what each team spent

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| CRD-based budget definitions | GitOps-friendly, auditable budget changes through version control | CRD updates require cluster access; non-engineering stakeholders cannot modify budgets directly | Build a simple UI or Slack bot that creates PRs to update budget CRDs. Finance team approves via PR review. |
| Pre-request cost estimation | Prevents budget overruns by rejecting requests before execution | Estimates may be inaccurate (output token count is unknown before execution) | Use conservative estimates (assume max_tokens output). Reconcile with actual cost post-response. Allow 5% budget overshoot to avoid rejecting requests that barely exceed the limit. |
| Automatic model downgrading at 80% | Preserves availability while reducing cost | Users may receive lower-quality responses without realizing why | Include response headers (X-Model-Downgraded: true, X-Budget-Utilization: 0.85) so applications can communicate the downgrade to users. |
| Hard rejection at 100% | Prevents any budget overrun | Critical workflows stop if they depend on LLM APIs | Define essential applications that get a 10% emergency buffer. Require VP approval to increase budget mid-cycle. Budget increase takes effect within 5 minutes via CRD update. |
| Redis for spend tracking | Low-latency cost lookups across distributed gateway replicas | Redis failure means cost tracking is unavailable | If Redis is unavailable, fail-open with aggressive logging. Run a reconciliation job every 15 minutes from Prometheus data to rebuild Redis state after recovery. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Pricing table outdated | Cost tracking drifts from actual provider invoices; teams appear under budget but are actually over | Monthly reconciliation of metered cost vs. provider invoice. Alert if drift exceeds 10%. | Update MODEL_PRICING in the cost metering service. Backfill corrected costs from provider usage API. Deploy pricing table as a ConfigMap for fast updates without redeployment. |
| Redis state lost | All teams show zero spend; previously exhausted budgets allow requests again | Redis monitoring detects restart. Budget utilization drops to zero unexpectedly. | Reconciliation job rebuilds spend totals from Prometheus counters (llm_cost_usd_total). Recovery time depends on Prometheus query speed, typically under 5 minutes. |
| Budget controller crash | New LLMBudget CRDs are not picked up; budget changes do not propagate | Controller health check fails. Pod restart count increases. | Controller runs with 2 replicas and leader election. If both fail, the gateway continues enforcing the last-known budget configuration cached in Redis. |
| Cost routing sends complex query to cheap model | Lower-quality response for a query that needed a capable model | User complaints. Application-level quality metrics degrade. | Tune the complexity threshold. Allow applications to override routing with a header (X-Require-Model: gpt-4o) that bypasses cost routing for critical requests, subject to budget limits. |
| Team bypasses gateway for direct provider calls | Spend not tracked; budget enforcement circumvented | Provider invoice shows usage not reflected in internal metrics. Network policy audit shows direct egress to AI provider IPs. | Enforce NetworkPolicy that blocks direct egress to provider API endpoints (`api.openai.com`, `api.anthropic.com`). All traffic must route through the gateway. |

## When to Consider a Managed Alternative

[Portkey](https://portkey.ai) provides a managed AI gateway with built-in cost tracking, budget enforcement, and chargeback reporting across multiple providers. [Helicone](https://helicone.ai) offers request logging and cost analytics as a proxy layer with minimal integration effort. [Kong](https://konghq.com) Konnect with the AI Gateway plugin supports token metering and per-consumer cost limits as managed infrastructure.

**Premium content pack:** LLM cost control templates. Kubernetes CRDs for budget definitions, cost metering service with multi-provider pricing, Prometheus alert rules for spend thresholds, Grafana dashboard JSON for chargeback reporting, and model routing configuration.

## Related Articles

- [AI API Key Management: Rotation, Scoping, and Abuse Detection](/articles/kubernetes/ai-api-key-management/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [GPU Cost and Security Monitoring: Prometheus, Grafana, and Alerting](/articles/kubernetes/gpu-cost-security-monitoring/)
- [AI Guardrails Implementation: Content Filtering, Output Validation, and Safety Layers](/articles/kubernetes/ai-guardrails-implementation/)
- [Prometheus Security Metrics: What to Measure and How to Alert](/articles/observability/prometheus-security-metrics/)
