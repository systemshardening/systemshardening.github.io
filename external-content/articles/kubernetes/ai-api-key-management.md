---
title: "AI API Key Management: Rotation, Scoping, and Abuse Detection"
description: "AI services have turned API keys into direct spending controls. A leaked OpenAI or Anthropic key can generate thousands of dollars in charges within..."
slug: "ai-api-key-management"
date: 2026-01-11
lastmod: 2026-01-11
category: "kubernetes"
tags: ["ai", "api-keys", "vault", "secrets", "rotation", "abuse-detection"]
personas: ["ai-ml-engineer", "platform-engineer", "devops-engineer"]
article_number: 82
difficulty: "intermediate"
estimated_reading_time: 13
provider_bridges:
  - name: "HCP Vault"
    id: 65
    category: "secrets-management"
  - name: "Doppler"
    id: 68
    category: "secrets-management"
  - name: "Kong"
    id: 86
    category: "api-gateway"
premium_pack: "api-key-rotation-automation-templates"
published: true
layout: article.njk
permalink: "/articles/kubernetes/ai-api-key-management/index.html"
---

# AI API Key Management: Rotation, Scoping, and Abuse Detection

## Problem

AI services have turned API keys into direct spending controls. A leaked OpenAI or Anthropic key can generate thousands of dollars in charges within hours. Unlike traditional API keys where abuse means data loss, AI API key abuse means immediate financial loss at compute prices of $0.01-$0.10 per request for large models.

Teams manage keys across multiple AI providers (OpenAI, Anthropic, Cohere, internal inference endpoints), multiple environments (development, staging, production), and multiple teams. The result is key sprawl: keys hardcoded in notebooks, shared in Slack, stored in environment variables on developer laptops, and duplicated across CI/CD pipelines. No single system tracks which keys exist, who has access, what they are scoped to, or when they were last rotated.

A compromised key is rarely detected through the provider's built-in monitoring. Most AI API providers offer basic usage dashboards but no real-time anomaly detection. By the time a team notices an unexpected bill, the damage is done.

**Target systems:** Applications consuming AI provider APIs. Internal inference endpoints with API key authentication. Vault or equivalent secrets management. API gateways proxying AI requests.

## Threat Model

- **Adversary:** External attacker who obtains an API key through source code exposure (public Git repository), compromised CI/CD pipeline, insider threat, or phishing. Also: automated scanners that trawl GitHub for API key patterns.
- **Objective:** Use the key for unauthorized inference (generating content, running models at the victim's expense) or extract data through prompt injection and data exfiltration via model context.
- **Blast radius:** A single compromised key with no rate limits or scope restrictions can generate unlimited API calls. At $0.06 per 1K tokens for GPT-4 class models, a script running overnight can produce $10,000+ in charges. If the key also has access to fine-tuning endpoints, the attacker can download or corrupt fine-tuned models.

## Configuration

### Centralised Key Storage with Vault

Store all AI API keys in Vault with dynamic secret generation where providers support it.

```hcl
# vault-ai-secrets-engine.hcl
# Mount a KV secrets engine for AI provider keys
path "secret/data/ai-providers/*" {
  capabilities = ["read"]
}

# Per-environment, per-team access policies
path "secret/data/ai-providers/openai/production" {
  capabilities = ["read"]
  allowed_parameters = {
    "version" = []
  }
}

path "secret/data/ai-providers/anthropic/staging" {
  capabilities = ["read"]
}
```

```bash
# Store keys with metadata
vault kv put secret/ai-providers/openai/production \
  api_key="sk-proj-..." \
  org_id="org-..." \
  created_at="2026-04-22" \
  rotated_at="2026-04-22" \
  owner="ml-platform-team" \
  scope="chat-completions-only" \
  max_monthly_spend="5000"
```

### Per-Key Scoping and Rate Limits

Use an API gateway to enforce per-key rate limits and scope restrictions, regardless of what the upstream provider allows.

```yaml
# kong-ai-gateway-config.yaml
# Kong gateway configuration for AI API proxying
_format_version: "3.0"

services:
  - name: openai-proxy
    url: https://api.openai.com
    routes:
      - name: openai-route
        paths:
          - /ai/openai
        strip_path: true

plugins:
  # Rate limiting per consumer (team/service)
  - name: rate-limiting
    service: openai-proxy
    config:
      minute: 60
      hour: 1000
      day: 10000
      policy: redis
      redis_host: redis.kong-system.svc.cluster.local

  # Request size limiting (prevent abuse via large prompts)
  - name: request-size-limiting
    service: openai-proxy
    config:
      allowed_payload_size: 64  # KB

  # Request transformer: inject the real API key
  # Consumers send a scoped internal key; Kong swaps it for the provider key
  - name: request-transformer
    service: openai-proxy
    config:
      remove:
        headers:
          - Authorization
      add:
        headers:
          - "Authorization: Bearer $(vault read -field=api_key secret/ai-providers/openai/production)"

consumers:
  - username: ml-team-prod
    keyauth_credentials:
      - key: internal-ml-prod-key-001
  - username: data-science-staging
    keyauth_credentials:
      - key: internal-ds-staging-key-001
```

### Automated Key Rotation

```bash
#!/bin/bash
# rotate-ai-keys.sh
# Run monthly via cron or CI pipeline

set -euo pipefail

PROVIDER="openai"
ENV="production"
VAULT_PATH="secret/ai-providers/${PROVIDER}/${ENV}"

# Step 1: Generate new key via provider API
# OpenAI example (API key creation endpoint)
NEW_KEY=$(curl -s -X POST "https://api.openai.com/v1/organization/api_keys" \
  -H "Authorization: Bearer $(vault kv get -field=admin_key secret/ai-providers/${PROVIDER}/admin)" \
  -H "Content-Type: application/json" \
  -d '{"name": "production-'"$(date +%Y%m%d)"'", "scope": {"type": "project", "project_id": "proj_abc123"}}' \
  | jq -r '.api_key')

# Step 2: Store new key in Vault
vault kv put "${VAULT_PATH}" \
  api_key="${NEW_KEY}" \
  rotated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  previous_key="$(vault kv get -field=api_key ${VAULT_PATH})"

# Step 3: Restart consuming pods to pick up new key
kubectl rollout restart deployment/ai-gateway -n ml-platform

# Step 4: Verify new key works
sleep 30
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${NEW_KEY}" \
  "https://api.openai.com/v1/models")

if [ "${HEALTH}" != "200" ]; then
  echo "ERROR: New key health check failed. Rolling back."
  vault kv put "${VAULT_PATH}" \
    api_key="$(vault kv get -field=previous_key ${VAULT_PATH})" \
    rotated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    rollback="true"
  kubectl rollout restart deployment/ai-gateway -n ml-platform
  exit 1
fi

# Step 5: Revoke old key (after grace period for in-flight requests)
echo "New key verified. Old key will be revoked in 24 hours."
echo "Schedule: revoke-old-key.sh ${PROVIDER} ${ENV}"
```

### Abuse Detection

```yaml
# prometheus-ai-key-abuse-alerts.yaml
groups:
  - name: ai-key-abuse
    rules:
      # Sudden spike in request volume (3x normal for time of day)
      - alert: AIKeyUsageSpike
        expr: >
          sum by (consumer) (
            rate(kong_http_requests_total{service="openai-proxy"}[15m])
          ) > 3 * avg_over_time(
            sum by (consumer) (
              rate(kong_http_requests_total{service="openai-proxy"}[15m])
            )[7d:1h]
          )
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "AI API usage spike for {{ $labels.consumer }}: 3x normal volume"
          runbook: "Check if a new batch job was deployed. If not, rotate the key immediately."

      # Requests from unexpected source IPs
      - alert: AIKeyNewSourceIP
        expr: >
          count by (consumer) (
            count by (consumer, client_ip) (
              kong_http_requests_total{service="openai-proxy"}
            )
          ) > 1.5 * avg_over_time(
            count by (consumer) (
              count by (consumer, client_ip) (
                kong_http_requests_total{service="openai-proxy"}
              )
            )[7d:1h]
          )
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "AI API key {{ $labels.consumer }} used from new source IPs"

      # Cost threshold alert
      - alert: AIMonthlySpendThreshold
        expr: >
          sum by (consumer) (
            increase(kong_http_requests_total{service=~".*-proxy"}[30d])
          ) * 0.03 > 5000
        labels:
          severity: critical
        annotations:
          summary: "Estimated monthly AI API spend for {{ $labels.consumer }} exceeds $5,000"
```

### Emergency Revocation

```bash
#!/bin/bash
# emergency-revoke.sh - run when compromise is detected
set -euo pipefail

PROVIDER=$1
ENV=$2

echo "EMERGENCY: Revoking ${PROVIDER} ${ENV} API key"

# Immediately update Vault to empty value (blocks new requests)
vault kv put "secret/ai-providers/${PROVIDER}/${ENV}" \
  api_key="REVOKED-$(date +%s)" \
  revoked_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  revoked_by="${USER}"

# Restart gateway to pick up revocation
kubectl rollout restart deployment/ai-gateway -n ml-platform

# Notify team
curl -X POST "${SLACK_WEBHOOK}" \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"SECURITY: ${PROVIDER} ${ENV} API key revoked by ${USER}. Generate new key and update Vault.\"}"

echo "Key revoked. Generate new key via provider dashboard and run rotate-ai-keys.sh"
```

## Expected Behaviour

- No AI API keys exist outside Vault. Applications retrieve keys through Vault sidecar or API gateway injection.
- Each team and environment has a separate key with explicit rate limits
- Key rotation runs monthly with automated verification
- Usage spikes trigger alerts within 5 minutes
- Emergency revocation completes within 2 minutes (Vault update + gateway restart)
- Monthly spend per key is tracked and alerted on threshold breach

## Trade-offs

| Decision | Impact | Risk | Mitigation |
|----------|--------|------|------------|
| API gateway proxy (Kong) | Adds 5-15ms latency per request | Gateway becomes a single point of failure | Run gateway in HA (3+ replicas). Circuit breaker falls back to direct API call with cached key. |
| Monthly key rotation | Limits exposure window of compromised keys | Rotation failure leaves stale key | Automated health check after rotation. Alert on rotation script failure. Keep previous key in Vault for rollback. |
| Per-consumer rate limits | Prevents runaway spend from any single consumer | Legitimate batch jobs may hit limits | Configurable per-consumer limits. Batch jobs use dedicated consumer with higher limits and tighter monitoring. |
| Internal proxy keys (not provider keys) | Teams never see the real provider key | More infrastructure to manage (gateway + Vault) | Justified for any team spending over $500/month on AI APIs. Below that, direct provider keys with Vault storage may suffice. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Vault unavailable | Applications cannot retrieve API keys; AI features fail | Vault health check fails; application error logs show Vault connection timeout | Vault HA cluster. If total outage, fall back to cached key in gateway (time-limited cache, 1 hour max). |
| Key rotation fails mid-process | New key invalid, old key may be revoked | Rotation script exits with error; health check fails | Automatic rollback to previous key (stored in Vault). Alert on rotation failure. |
| Rate limit too aggressive | Legitimate requests rejected (HTTP 429) | Application error rate increases; Kong logs show rate limit rejections | Increase rate limit for the affected consumer. Review usage patterns to set appropriate limits. |
| Compromised key detected late | Unexpected charges on provider bill | Monthly bill review; provider usage dashboard | Revoke key immediately. File dispute with provider (most providers credit unauthorized usage if reported promptly). Rotate all keys on same provider. |

## When to Consider a Managed Alternative

HCP [Vault](https://www.vaultproject.io) for managed secrets lifecycle, eliminating Vault cluster operations. [Doppler](https://www.doppler.com) for universal secrets sync across environments when Vault is too complex. [Kong](https://konghq.com) Konnect for managed API gateway with built-in analytics per consumer.

**Premium content pack:** API key rotation automation templates. Vault policies, Kong gateway configuration, rotation scripts for major AI providers, and [Prometheus](https://prometheus.io) alert rules for usage monitoring.


## Related Articles

- [Kubernetes Secrets Management: External Secrets Operator, Vault, and Sealed Secrets](/articles/kubernetes/secrets-management/)
- [etcd Encryption at Rest: Configuration, Key Rotation, and Performance Impact](/articles/kubernetes/etcd-encryption/)
- [Hardening Model Inference Endpoints: Authentication, Rate Limiting, and Input Validation](/articles/kubernetes/inference-endpoint-hardening/)
- [GPU Workload Isolation: MIG, MPS, and vGPU Security Boundaries](/articles/kubernetes/gpu-isolation/)
- [Securing Model Artifact Pipelines: From Training to Serving](/articles/kubernetes/model-artifact-pipelines/)
