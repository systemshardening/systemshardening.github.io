---
title: "A/B Model Deployment Safety: Canary Rollouts, Traffic Splitting, and Automated Rollback for ML Models"
description: "Deploying a new ML model version is not the same as deploying a new application version."
slug: "ab-deployment-safety"
date: 2026-02-16
lastmod: 2026-02-16
category: "kubernetes"
tags: ["canary", "rollback", "istio", "ml-deployment", "traffic-splitting", "ai-security"]
personas: ["ai-ml-engineer", "platform-engineer", "sre"]
article_number: 119
difficulty: "intermediate"
estimated_reading_time: 17
provider_bridges:
  - name: "Cloudflare"
    id: 29
    category: "cdn-edge"
  - name: "Kong"
    id: 86
    category: "api-gateways"
premium_pack: "ml-canary-deployment-configs"
published: true
layout: article.njk
permalink: "/articles/kubernetes/ab-deployment-safety/index.html"
---

# A/B Model Deployment Safety: Canary Rollouts, Traffic Splitting, and Automated Rollback for ML Models

## Problem

Deploying a new ML model version is not the same as deploying a new application version. A container image that passes health checks can still serve a model that produces subtly wrong, toxic, or degraded outputs. Standard [Kubernetes](https://kubernetes.io) rolling updates check liveness and readiness, not output quality. A model that returns HTTP 200 with confidently wrong answers passes every infrastructure health check.

Teams that deploy models with `kubectl apply` and a rolling update strategy risk sending 100% of production traffic to a model that has regressed on accuracy, increased latency due to a larger architecture, or developed new failure modes on specific input categories. By the time someone notices, thousands of bad predictions have been served.

Model deployments need canary rollouts that evaluate model-specific metrics (accuracy, latency percentiles, toxicity scores) before increasing traffic, and automated rollback when those metrics degrade.

**Target systems:** Kubernetes model serving deployments with [Istio](https://istio.io) service mesh or [Envoy](https://www.envoyproxy.io)-based gateways. Works with any model serving framework (TorchServe, Triton, vLLM) behind an HTTP/gRPC endpoint.

## Threat Model

- **Adversary:** Not primarily an external attacker. The threat is an untested or degraded model version reaching production traffic. However, an attacker who can trigger a model deployment (compromised CI/CD) can use this as a vector.
- **Objective:** Deploy a model that produces harmful, biased, or incorrect outputs at scale. Exhaust GPU resources with a model that has higher latency characteristics. Cause a denial-of-service by deploying a model that crashes on certain inputs.
- **Blast radius:** Degraded user experience (quality). Financial loss from incorrect predictions (integrity). Reputational damage from toxic or biased outputs (safety).

## Configuration

### Istio Traffic Splitting for Model Versions

Deploy the new model version alongside the existing one. Use Istio VirtualService to control what percentage of traffic reaches each version.

```yaml
# model-v1-deployment.yaml - current production model
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-inference-v1
  namespace: ai-inference
  labels:
    app: llm-inference
    version: v1
    model-version: "1.0.42"
spec:
  replicas: 3
  selector:
    matchLabels:
      app: llm-inference
      version: v1
  template:
    metadata:
      labels:
        app: llm-inference
        version: v1
        model-version: "1.0.42"
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: inference
          image: registry.internal/ml-serving:v2.1.0
          args: ["--model=/models/llm-v1.0.42"]
          ports:
            - containerPort: 8080
              name: http
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              nvidia.com/gpu: 1
            limits:
              nvidia.com/gpu: 1
          volumeMounts:
            - name: models
              mountPath: /models
              readOnly: true
      volumes:
        - name: models
          persistentVolumeClaim:
            claimName: model-storage-v1
            readOnly: true
---
# model-v2-deployment.yaml - canary model (new version)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-inference-v2
  namespace: ai-inference
  labels:
    app: llm-inference
    version: v2
    model-version: "1.0.43"
spec:
  replicas: 1  # Start with minimal replicas for canary
  selector:
    matchLabels:
      app: llm-inference
      version: v2
  template:
    metadata:
      labels:
        app: llm-inference
        version: v2
        model-version: "1.0.43"
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: inference
          image: registry.internal/ml-serving:v2.1.0
          args: ["--model=/models/llm-v1.0.43"]
          ports:
            - containerPort: 8080
              name: http
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          resources:
            requests:
              nvidia.com/gpu: 1
            limits:
              nvidia.com/gpu: 1
          volumeMounts:
            - name: models
              mountPath: /models
              readOnly: true
      volumes:
        - name: models
          persistentVolumeClaim:
            claimName: model-storage-v2
            readOnly: true
```

```yaml
# istio-traffic-split.yaml - start with 5% canary traffic
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: llm-inference
  namespace: ai-inference
spec:
  hosts:
    - llm-inference.ai-inference.svc.cluster.local
  http:
    - route:
        - destination:
            host: llm-inference.ai-inference.svc.cluster.local
            subset: v1
          weight: 95
        - destination:
            host: llm-inference.ai-inference.svc.cluster.local
            subset: v2
          weight: 5
      timeout: 30s
      retries:
        attempts: 2
        perTryTimeout: 15s
        retryOn: 5xx,reset,connect-failure
---
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: llm-inference
  namespace: ai-inference
spec:
  host: llm-inference.ai-inference.svc.cluster.local
  subsets:
    - name: v1
      labels:
        version: v1
    - name: v2
      labels:
        version: v2
  trafficPolicy:
    connectionPool:
      http:
        h2UpgradePolicy: UPGRADE
        maxRequestsPerConnection: 100
    outlierDetection:
      consecutive5xxErrors: 3
      interval: 30s
      baseEjectionTime: 60s
      maxEjectionPercent: 100
```

### [Flagger](https://flagger.app) Canary with ML-Specific Metrics

Use Flagger to automate the canary progression based on model-specific metrics, not just HTTP success rates.

```yaml
# flagger-canary.yaml - automated canary with ML metrics
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: llm-inference
  namespace: ai-inference
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: llm-inference
  service:
    port: 8080
    targetPort: 8080
    gateways:
      - mesh
    hosts:
      - llm-inference.ai-inference.svc.cluster.local
  analysis:
    # Canary progression schedule
    interval: 2m          # Check metrics every 2 minutes
    threshold: 3          # Max failed checks before rollback
    maxWeight: 50         # Max canary traffic percentage
    stepWeight: 10        # Increase by 10% each step
    # ML-specific metrics for canary analysis
    metrics:
      # Standard: request success rate must stay above 99%
      - name: request-success-rate
        thresholdRange:
          min: 99
        interval: 1m
      # Standard: p99 latency must stay under 2 seconds
      - name: request-duration
        thresholdRange:
          max: 2000
        interval: 1m
      # Custom: model-specific quality metric from Prometheus
      - name: model-accuracy-score
        templateRef:
          name: model-accuracy
          namespace: ai-inference
        thresholdRange:
          min: 0.85
        interval: 2m
      # Custom: toxicity score must stay below threshold
      - name: model-toxicity-score
        templateRef:
          name: model-toxicity
          namespace: ai-inference
        thresholdRange:
          max: 0.02
        interval: 2m
---
# Prometheus metric template for model accuracy
apiVersion: flagger.app/v1beta1
kind: MetricTemplate
metadata:
  name: model-accuracy
  namespace: ai-inference
spec:
  provider:
    type: prometheus
    address: http://prometheus.monitoring:9090
  query: |
    sum(rate(model_correct_predictions_total{
      deployment=~"{{ target }}",
      namespace="{{ namespace }}"
    }[2m]))
    /
    sum(rate(model_total_predictions_total{
      deployment=~"{{ target }}",
      namespace="{{ namespace }}"
    }[2m]))
---
# Prometheus metric template for toxicity
apiVersion: flagger.app/v1beta1
kind: MetricTemplate
metadata:
  name: model-toxicity
  namespace: ai-inference
spec:
  provider:
    type: prometheus
    address: http://prometheus.monitoring:9090
  query: |
    avg(model_toxicity_score{
      deployment=~"{{ target }}",
      namespace="{{ namespace }}"
    })
```

### Model Metrics Instrumentation

Instrument your inference endpoint to emit the custom metrics that Flagger uses for canary analysis.

```python
# metrics_middleware.py - Prometheus metrics for model quality
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time

# Counters for accuracy tracking
PREDICTIONS_TOTAL = Counter(
    "model_total_predictions_total",
    "Total number of predictions",
    ["deployment", "model_version"],
)
CORRECT_PREDICTIONS = Counter(
    "model_correct_predictions_total",
    "Predictions matching quality threshold",
    ["deployment", "model_version"],
)

# Histogram for inference latency
INFERENCE_LATENCY = Histogram(
    "model_inference_duration_seconds",
    "Time spent on model inference",
    ["deployment", "model_version"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0],
)

# Gauge for toxicity score
TOXICITY_SCORE = Gauge(
    "model_toxicity_score",
    "Rolling average toxicity score of model outputs",
    ["deployment", "model_version"],
)

# Gauge for confidence score
CONFIDENCE_SCORE = Histogram(
    "model_confidence_score",
    "Distribution of model confidence scores",
    ["deployment", "model_version"],
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99],
)


class ModelMetricsMiddleware:
    """Wrap inference calls with Prometheus metrics."""

    def __init__(self, deployment_name: str, model_version: str):
        self.deployment = deployment_name
        self.version = model_version
        self.labels = {
            "deployment": deployment_name,
            "model_version": model_version,
        }

    def record_prediction(
        self,
        latency_seconds: float,
        confidence: float,
        toxicity: float,
        quality_pass: bool,
    ):
        PREDICTIONS_TOTAL.labels(**self.labels).inc()
        if quality_pass:
            CORRECT_PREDICTIONS.labels(**self.labels).inc()
        INFERENCE_LATENCY.labels(**self.labels).observe(latency_seconds)
        TOXICITY_SCORE.labels(**self.labels).set(toxicity)
        CONFIDENCE_SCORE.labels(**self.labels).observe(confidence)
```

### Automated Rollback Script

For environments without Flagger, use a script that monitors metrics and triggers rollback.

```bash
#!/bin/bash
# model_rollback_monitor.sh - monitor canary and rollback if degraded
set -euo pipefail

NAMESPACE="ai-inference"
CANARY_DEPLOYMENT="llm-inference-v2"
STABLE_DEPLOYMENT="llm-inference-v1"
PROMETHEUS_URL="http://prometheus.monitoring:9090"
CHECK_INTERVAL=120  # seconds
MAX_FAILURES=3
FAILURE_COUNT=0

check_metric() {
    local query="$1"
    local threshold="$2"
    local operator="$3"  # "gt" or "lt"

    value=$(curl -s "${PROMETHEUS_URL}/api/v1/query" \
        --data-urlencode "query=${query}" \
        | jq -r '.data.result[0].value[1] // "0"')

    if [ "$operator" = "lt" ] && [ "$(echo "$value < $threshold" | bc -l)" -eq 1 ]; then
        return 1  # Below minimum threshold
    fi
    if [ "$operator" = "gt" ] && [ "$(echo "$value > $threshold" | bc -l)" -eq 1 ]; then
        return 1  # Above maximum threshold
    fi
    return 0
}

rollback() {
    echo "ROLLBACK: Shifting all traffic to stable version"

    # Set canary weight to 0
    kubectl -n "$NAMESPACE" patch virtualservice llm-inference --type=json \
        -p='[
            {"op": "replace", "path": "/spec/http/0/route/0/weight", "value": 100},
            {"op": "replace", "path": "/spec/http/0/route/1/weight", "value": 0}
        ]'

    # Scale down canary
    kubectl -n "$NAMESPACE" scale deployment "$CANARY_DEPLOYMENT" --replicas=0

    echo "Rollback complete. Canary traffic set to 0%."
    exit 1
}

echo "Monitoring canary deployment: ${CANARY_DEPLOYMENT}"

while true; do
    echo "$(date): Checking canary metrics..."

    # Check accuracy (must be above 0.85)
    if ! check_metric \
        "sum(rate(model_correct_predictions_total{deployment=\"${CANARY_DEPLOYMENT}\"}[5m])) / sum(rate(model_total_predictions_total{deployment=\"${CANARY_DEPLOYMENT}\"}[5m]))" \
        "0.85" "lt"; then
        echo "WARNING: Accuracy below threshold"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi

    # Check toxicity (must be below 0.02)
    if ! check_metric \
        "avg(model_toxicity_score{deployment=\"${CANARY_DEPLOYMENT}\"})" \
        "0.02" "gt"; then
        echo "WARNING: Toxicity above threshold"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi

    # Check p99 latency (must be below 2s)
    if ! check_metric \
        "histogram_quantile(0.99, rate(model_inference_duration_seconds_bucket{deployment=\"${CANARY_DEPLOYMENT}\"}[5m]))" \
        "2.0" "gt"; then
        echo "WARNING: P99 latency above threshold"
        FAILURE_COUNT=$((FAILURE_COUNT + 1))
    fi

    if [ "$FAILURE_COUNT" -ge "$MAX_FAILURES" ]; then
        rollback
    fi

    # Reset failure count on successful check
    if [ "$FAILURE_COUNT" -eq 0 ]; then
        echo "$(date): All metrics healthy"
    fi
    FAILURE_COUNT=0

    sleep "$CHECK_INTERVAL"
done
```

### Traffic Shifting Schedule

```yaml
# progressive-traffic-shift.yaml - CronJob to gradually increase canary traffic
apiVersion: batch/v1
kind: CronJob
metadata:
  name: canary-traffic-increase
  namespace: ai-inference
spec:
  schedule: "*/30 * * * *"  # Every 30 minutes
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: canary-manager
          containers:
            - name: traffic-shift
              image: bitnami/kubectl:1.30
              command: ["sh", "-c"]
              args:
                - |
                  # Get current canary weight
                  CURRENT=$(kubectl -n ai-inference get virtualservice llm-inference \
                    -o jsonpath='{.spec.http[0].route[1].weight}')

                  if [ "$CURRENT" -ge 50 ]; then
                    echo "Canary at max weight (${CURRENT}%). No further increase."
                    exit 0
                  fi

                  NEW_WEIGHT=$((CURRENT + 10))
                  STABLE_WEIGHT=$((100 - NEW_WEIGHT))

                  echo "Increasing canary from ${CURRENT}% to ${NEW_WEIGHT}%"

                  kubectl -n ai-inference patch virtualservice llm-inference --type=json \
                    -p="[
                      {\"op\": \"replace\", \"path\": \"/spec/http/0/route/0/weight\", \"value\": ${STABLE_WEIGHT}},
                      {\"op\": \"replace\", \"path\": \"/spec/http/0/route/1/weight\", \"value\": ${NEW_WEIGHT}}
                    ]"
          restartPolicy: OnFailure
```

## Expected Behaviour

- New model versions start receiving 5% of traffic, increasing by 10% every step
- Canary progression halts and rolls back if accuracy drops below 85%, toxicity exceeds 2%, or p99 latency exceeds 2 seconds
- Istio outlier detection ejects unhealthy canary pods after 3 consecutive 5xx errors
- All model versions emit Prometheus metrics for accuracy, latency, toxicity, and confidence
- Rollback shifts 100% of traffic to the stable version and scales the canary to zero
- Traffic splitting is transparent to clients; all requests go through the same service endpoint

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| 5% initial canary traffic | New model is tested on real traffic but on a small percentage | 5% of users may see degraded results during testing | Use synthetic traffic for initial validation before real traffic exposure |
| Automated rollback on accuracy drop | Fast recovery from bad models | Flaky metrics cause unnecessary rollbacks | Set thresholds with appropriate margins. Require 3 consecutive failures before rollback. |
| Istio sidecar on GPU pods | Adds ~50MB memory and slight latency overhead | Resource overhead on expensive GPU nodes | Sidecar resource usage is negligible compared to GPU workload. Latency overhead is typically under 1ms. |
| Progressive traffic increase every 30 minutes | Full rollout takes 2-3 hours | Slower time to full deployment | Acceptable trade-off for production safety. Use faster schedules (10 min) for low-risk updates. |
| Separate PVCs per model version | Doubles storage during canary | Storage cost increase | Clean up old model PVCs after successful full rollout. Use shared storage with version-specific paths. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Canary model crashes on specific inputs | Istio reports 5xx errors from canary subset | Outlier detection ejects canary pods; Flagger detects success rate drop | Automatic rollback via Flagger or manual VirtualService patch. Investigate crash-inducing inputs. |
| Model produces subtly wrong outputs (no errors) | Users report incorrect answers; downstream systems produce bad results | Custom accuracy metric drops below threshold; Flagger triggers rollback | Roll back. Add the failing cases to the evaluation benchmark for future gate checks. |
| Metrics pipeline delay | Flagger sees stale metrics during canary analysis | Flagger reports "no data" for custom metrics | Configure Flagger to treat missing metrics as failure. Fix Prometheus scrape interval. |
| VirtualService misconfiguration | All traffic goes to canary or stable, ignoring weights | Traffic monitoring shows unexpected distribution | Validate VirtualService with `istioctl analyze`. Use admission webhook to validate traffic split configs. |
| Rollback fails (stable version also broken) | Both model versions serve bad results | Monitoring shows degradation across all subsets | Scale down both deployments. Deploy a known-good model version from the model registry. |

## When to Consider a Managed Alternative

Managed ML deployment platforms handle canary rollouts, traffic splitting, and automated rollback.

- **[Modal](https://modal.com):** Serverless model deployment with built-in rollback.
- **[Baseten](https://www.baseten.co):** Model deployment with traffic splitting and monitoring.
- **[Replicate](https://replicate.com):** Managed model hosting with versioning.
- **[Cloudflare](https://www.cloudflare.com):** Edge-level traffic management and load balancing in front of model endpoints.
- **[Kong](https://konghq.com):** API gateway with built-in canary release plugins.

**Premium content pack:** Complete Istio and Flagger configurations for ML canary deployments, Prometheus metric templates for model quality monitoring, and automated rollback scripts.


## Related Articles

- [Prompt Injection Defence in Production: Input Validation, Output Filtering, and Monitoring](/articles/kubernetes/prompt-injection/)
- [Hardening Model Serving Frameworks: TorchServe, Triton, and vLLM Security Configuration](/articles/kubernetes/model-serving-hardening/)
- [RLHF Data Protection: Securing Human Feedback Loops, Preference Data, and Reward Models](/articles/kubernetes/rlhf-data-protection/)
- [Vector Database Security: Access Control, Embedding Protection, and Query Isolation](/articles/kubernetes/vector-database-security/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
