---
title: "Prompt Cache Security: Side-Channels, Poisoning, and Tenant Isolation in LLM Provider Caches"
description: "Provider-side prompt caching speeds up applications by 30-90% — and introduces a new attack surface with timing side-channels and poisoning vectors."
slug: "prompt-cache-security"
date: 2026-04-27
lastmod: 2026-04-27
category: "ai-landscape"
tags: ["prompt-cache", "llm", "side-channel", "ai-security", "anthropic", "openai"]
personas: ["security-engineer", "ml-engineer", "platform-engineer"]
article_number: 201
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/ai-landscape/prompt-cache-security/index.html"
---

# Prompt Cache Security: Side-Channels, Poisoning, and Tenant Isolation in LLM Provider Caches

## Problem

Major LLM providers introduced prompt caching in 2024-2025. Anthropic's prompt caching (GA in 2024), OpenAI's prompt caching (released 2024), Google Gemini context caching (2024) — all share the same model: long, repeated prefixes (system prompts, retrieval-augmented context, large code files) get cached server-side. Subsequent requests with the same prefix skip recomputation, paying ~10% of the original cost and returning 30-90% faster.

The security story is barely documented. The mechanism is a server-side cache keyed on a hash of the prefix tokens, scoped to the customer account. The cache is shared across all requests from that account; cache hits and misses produce measurable timing differences. This creates several attack surfaces that almost no application security review accounts for:

- **Cross-request timing side-channel.** An attacker who can submit prompts and observe response timing can probe the cache. If a specific text is in the cache (because another user submitted it), the attacker's request hits and returns faster. This leaks information about other users on the same account.
- **Cache-key collision poisoning (theoretical).** If the cache key isn't cryptographically strong against colliders, an attacker could craft a prompt whose hash collides with a victim prompt's, returning attacker-controlled cached output.
- **Tenant boundary unclear.** When a SaaS application runs on a single API key on behalf of many end-users, the cache is shared across users. User A's cached prefix may be exposed to User B's queries via timing.
- **System-prompt leak via cache eviction.** If your system prompt is cached and an attacker can probe enough prefixes to reverse the cached content, they may reconstruct portions of confidential prompts.
- **Billing-side leakage.** Cache hits are often invoiced separately from cache misses. The invoice itself exposes which prompts your application caches and how often.

The provider documentation typically says the cache is "isolated per organization" and "doesn't impact other organizations." This is true; it does not address per-user isolation within an organization. Building a multi-user product on a single API key means accepting cross-user cache exposure unless mitigated at the application layer.

This article covers the threat model for prompt caching, application-level mitigations (cache-key salting, request shaping, deterministic latency), and the configuration choices that bound the side-channel surface.

**Target systems:** Anthropic API with prompt caching (`cache_control` parameter), OpenAI prompt caching (automatic on supported models), Google Gemini context caching (`CachedContent` API), Azure OpenAI prompt caching.

## Threat Model

- **Adversary 1 — Cross-user observer in shared application:** an end-user of a multi-tenant SaaS app that uses one provider API key for all users. Wants to determine what other users have queried.
- **Adversary 2 — External timing-side-channel attacker:** anyone with the ability to submit prompts, observing response latency to infer cache state.
- **Adversary 3 — System-prompt extractor:** an attacker who wants to reconstruct the application's confidential system prompt by observing which prefixes hit cache.
- **Adversary 4 — Cache-key collider (theoretical):** crafts inputs whose internal cache key matches a victim's, hoping to influence the victim's response.
- **Access level:** Adversary 1 has user-level access to the application. Adversaries 2-3 have only API submission capability. Adversary 4 has API submission + knowledge of the cache-key derivation.
- **Objective:** Read or infer cache contents from other users / sessions; reconstruct confidential prompts; influence other users' outputs.
- **Blast radius:** With shared cache and no application-level isolation, every cached prompt's content is observable via timing to anyone who can submit prompts on the same API key. With proper salting and per-tenant scoping, observation is bounded to the requester's own cached content.

## Configuration

### Pattern 1: Per-Tenant Cache-Key Salting

The simplest mitigation: include a per-tenant secret in the cached prefix. Different tenants produce different cache keys for what would otherwise be identical content.

```python
import hashlib

def per_tenant_system_prompt(tenant_id: str, base_prompt: str) -> str:
    # Per-tenant salt — secret, not derived from tenant_id alone.
    salt = TENANT_SALTS[tenant_id]
    # Salt is deliberately invisible to the model (whitespace + hash).
    salt_marker = f"<!--cache-salt-{salt}-->"
    return f"{salt_marker}\n{base_prompt}"

# Anthropic API call.
import anthropic
client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-opus-4-7",
    max_tokens=1024,
    system=[
        {
            "type": "text",
            "text": per_tenant_system_prompt(tenant_id, BASE_SYSTEM_PROMPT),
            "cache_control": {"type": "ephemeral"},
        }
    ],
    messages=[{"role": "user", "content": user_query}],
)
```

Now tenant A's cache and tenant B's cache are entirely separate inside the provider's cache namespace. A timing side-channel between them is impossible.

The salt format must be invisible to the model — an HTML comment, a zero-width-space pattern, or a token sequence the model treats as no-op. Don't put the salt in a position where it changes model behavior.

### Pattern 2: Per-User Salting Within a Tenant

For multi-user applications, take the per-tenant pattern down one level:

```python
def per_user_cache_prefix(user_id: str, system_prompt: str) -> str:
    # User-specific salt; rotate periodically.
    salt = derive_user_salt(user_id)
    return f"<!-- u:{salt} -->\n{system_prompt}"
```

The trade-off: cache hit rate drops. Each user's cache is independent; first request per user always misses. Calculate whether the privacy benefit outweighs the cost — for sensitive content, almost always yes.

### Pattern 3: Constant-Time Response Normalization

For applications that genuinely need a shared cache (cost matters more than per-user privacy), eliminate the timing channel by normalizing latency.

```python
import time

async def constant_time_response(prompt, target_latency_ms=2000):
    start = time.monotonic()
    result = await llm.generate(prompt)
    elapsed_ms = (time.monotonic() - start) * 1000
    if elapsed_ms < target_latency_ms:
        await asyncio.sleep((target_latency_ms - elapsed_ms) / 1000)
    return result
```

Pad every response to a fixed latency. The minimum should be the cache-miss latency; cache hits are artificially slowed.

The cost: cache-hit responses no longer deliver their performance benefit to end-users. The benefit is purely cost (you still pay 10% of tokens for cache hits). Use this for endpoints where the application is highly latency-tolerant — back-office, batch, async — and never for interactive chat.

### Pattern 4: Cache-Key Hardening

For providers that expose cache-key configuration, configure it to require explicit invocation rather than implicit hashing of the prefix:

```python
# Anthropic API: cache_control points are explicit. Place them only at
# stable, public-knowledge boundaries (system prompt, public document).
# Never cache user-specific or sensitive content.

system = [
    {
        "type": "text",
        "text": PUBLIC_SYSTEM_PROMPT,
        "cache_control": {"type": "ephemeral"},   # cache this
    },
]
messages = [
    {
        "role": "user",
        "content": [
            {
                "type": "text",
                "text": LARGE_PUBLIC_DOCUMENT,
                "cache_control": {"type": "ephemeral"},   # cache this
            },
            {
                "type": "text",
                "text": user_specific_query,            # do NOT cache this
            },
        ],
    },
]
```

User-specific content lands after the cache point, so it isn't included in the cached prefix. The cache covers only the public preamble.

### Pattern 5: Probing Detection

For applications with a constrained input surface, detect cache-probing attempts:

```python
class CacheProbeDetector:
    def __init__(self, window_seconds=60, max_unique_prefixes=10):
        self.requests_per_user = defaultdict(list)
        self.window = window_seconds
        self.max_unique = max_unique_prefixes

    def check(self, user_id: str, prefix_hash: bytes) -> bool:
        now = time.time()
        self.requests_per_user[user_id] = [
            (h, t) for (h, t) in self.requests_per_user[user_id]
            if now - t < self.window
        ]
        unique = {h for (h, t) in self.requests_per_user[user_id]}
        if len(unique) > self.max_unique:
            return False  # too many distinct prefixes; block
        self.requests_per_user[user_id].append((prefix_hash, now))
        return True
```

A legitimate user generally submits a small number of distinct prefix shapes per minute. An attacker probing the cache submits many distinct, deliberately-different prefixes. Rate-limit on prefix-cardinality, not request count.

### Pattern 6: Cache-Hit Telemetry Hygiene

Cache hits are billed differently from cache misses; many providers expose `cache_creation_input_tokens` and `cache_read_input_tokens` separately in the response. Logs and metrics that include these values can leak cache state.

```python
# Bad: per-request metric exposes cache state.
metrics.observe("llm_cache_read_tokens", response.usage.cache_read_input_tokens,
                tags=["user_id:" + user_id])

# Good: aggregate across users; keep cardinality coarse.
metrics.observe("llm_cache_read_tokens_total", response.usage.cache_read_input_tokens)
```

Don't expose per-user cache statistics in operational dashboards visible across teams. The aggregate is fine; per-user is a side-channel into another internal surface.

### Pattern 7: Choose Cache Lifetime Carefully

Anthropic's prompt caching defaults to a 5-minute TTL with optional 1-hour extension. OpenAI caches for 5-10 minutes typically. Longer TTLs increase hit rates and cost savings but extend the window during which side-channel observation is possible.

For sensitive content, use the shortest TTL the provider offers. A cache that lives 30 seconds bounds attack windows much tighter than one living an hour.

## Expected Behaviour

| Signal | No mitigation | With per-tenant salting + telemetry hygiene |
|--------|----------------|-----------------------------------------------|
| Cross-tenant timing observable | Yes (probing detects other tenants' prefixes) | No (each tenant has independent cache namespace) |
| Cross-user (within tenant) timing observable | Yes | Depends on per-user salting (Pattern 2) |
| System-prompt content reconstructable | Possible via cumulative probing | Salt makes hash-collision-finding effectively impossible |
| Cache hit rate | High (no salting) | Lower per user; near-zero across tenants |
| Cost saving from caching | Maximum | Reduced; trade-off vs. privacy |
| Probe detection | None | Block on prefix-cardinality threshold |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Per-tenant salt | Hard tenant isolation in shared API key | Cache hit rate per-tenant | Tenants with high-volume queries still benefit from cache; per-user salt for multi-user-per-tenant. |
| Per-user salt within tenant | Strong cross-user isolation | First-request latency penalty per user | Acceptable for sensitive applications (healthcare, finance, legal). |
| Constant-time response padding | Eliminates timing channel completely | Loses interactive latency benefit | Use for non-interactive workloads only. |
| Selective cache_control placement | Cache only public-knowledge content | Cache hit rate lower than caching everything | The right default; treat user-specific content as never-cache. |
| Probe-rate detection | Catches active attacks | False positives on legitimate variability | Tune threshold per application; alert before block. |
| Telemetry hygiene | Eliminates internal-side-channel | Less granular observability | Aggregate is sufficient for operational purposes. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Salt accidentally visible to model | Cache-control marker influences output | Output contains salt-related artifacts | Use truly invisible markers (zero-width-space, HTML comments stripped by markdown). Test that model output is unchanged with vs. without salt. |
| Salt rotation breaks cache | Sudden cost spike on rotation event | Provider invoice shows cache-miss-only billing | Rotate salts during low-traffic windows; warm cache deliberately afterwards. |
| Provider changes cache-key derivation | Mitigation degrades silently | Cache hit rate changes shape | Subscribe to provider changelog; periodically validate isolation experimentally. |
| User submits salt as part of input | Cache key leaks via user input | Salt visible in logs | Sanitize user input — strip cache-control markers, comments, etc., before incorporation into prompts. |
| Constant-time padding too short | Some real responses exceed pad time | Padding ineffective for those requests | Set pad to slightly above worst-case observed latency; monitor and adjust. |
| Probe detector false positive | Legitimate user blocked | Support tickets | Lower threshold sensitivity; add appeal mechanism; alert before automatic block. |
| Logging accidentally captures cache-hit fields | Internal telemetry leak | Audit of dashboards reveals per-user cache stats | Strip `cache_*_tokens` fields at the logging layer; aggregate only. |

## Related Articles

- [LLM Deployment Security](/articles/ai-landscape/llm-deployment-security/)
- [LLM Prompt Security Patterns](/articles/ai-landscape/llm-prompt-security-patterns/)
- [Agent Memory Poisoning Defence](/articles/ai-landscape/agent-memory-poisoning/)
- [MCP Authentication Patterns](/articles/ai-landscape/mcp-authentication/)
- [LLM Jailbreak Defence](/articles/ai-landscape/llm-jailbreak-defence/)
