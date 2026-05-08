---
title: "Frontend RUM Security: Grafana Faro, Session Replay, and Browser Telemetry"
description: "Hardening browser-side RUM and session-replay pipelines: PII scrubbing, supply-chain integrity, sampling controls, and detection for hostile telemetry."
slug: "frontend-rum-security-grafana-faro"
date: 2026-05-08
lastmod: 2026-05-08
category: "observability"
tags: ["rum", "grafana-faro", "session-replay", "browser", "pii", "observability"]
personas: ["security-engineer", "sre", "platform-engineer"]
article_number: 653
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/observability/frontend-rum-security-grafana-faro/index.html"
---

# Frontend RUM Security: Grafana Faro, Session Replay, and Browser Telemetry

## Problem

Real User Monitoring (RUM) collects telemetry from end-user browsers: page loads, route changes, exceptions, web vitals, fetch/XHR latency, and increasingly *session replay* — DOM mutation streams that reconstruct the user's view in playback. Grafana Faro is the open-source entrant that joined Datadog RUM, Sentry Replay, FullStory, and LogRocket as production options. RUM is now table-stakes for any user-facing app where SLOs matter.

It is also a hostile threat surface that observability teams routinely under-secure. Three properties make RUM uniquely dangerous compared to backend telemetry:

1. **Untrusted execution context.** RUM SDKs run inside the user's browser. Any XSS, malicious extension, or compromised npm dependency in the page can read or modify telemetry — and can use the RUM endpoint as an exfiltration channel back to the operator's own ingest, where the data lands looking trustworthy.
2. **PII by default.** DOM session replay captures input fields, page text, query parameters, headers, and stack traces unless explicitly scrubbed. The default Faro/Sentry/Datadog configurations capture more PII than most teams realise; under GDPR, CCPA, and HIPAA this is a substantive compliance risk.
3. **Supply-chain exposure.** RUM SDKs are typically loaded from a CDN or bundled into the JavaScript build. Either path lets a single SDK compromise affect every user. The 2024 Polyfill.io incident and several 2025 npm SDK takeovers used exactly this pattern.

Beyond the SDK-side risks, the ingest endpoint itself is rarely authenticated — by design, since browsers cannot hold secrets. The result is a write-only logging API that anyone on the internet can spam, often without rate limits, often parsed into a SIEM, often retaining stack traces with internal hostnames and module paths.

This article covers Faro specifically because it is the OSS choice teams have most flexibility to harden, but the patterns apply to every RUM tool. Target systems: Grafana Faro Web SDK ≥ 1.10, Faro Collector / Grafana Cloud Faro ingest, modern browsers (CSP Level 3, Trusted Types support), Node 20+ build pipelines.

## Threat Model

1. **XSS or compromised dependency exfiltrating data via the RUM endpoint.** Goal: covert exfil that looks like normal observability traffic. Surface: RUM endpoint accepts arbitrary attributes, no payload schema validation.
2. **Malicious browser extension reading session-replay buffers.** Goal: harvest PII for resale. Surface: replay buffers in `window` scope; SDK does not isolate context.
3. **Hostile traffic generator spamming the ingest.** Goal: inflate observability costs, drown out real signal. Surface: unauthenticated, ungated public ingest endpoint.
4. **Insider with read access to RUM index.** Goal: enumerate user sessions for sensitive content. Surface: replay retention; coarse RBAC on observability tooling.

Without hardening, RUM becomes both an exfil channel and a privacy liability. A single XSS in a checkout page can leak card numbers via session replay; the operator's own observability pipeline ingests, indexes, and retains the data.

## Configuration / Implementation

### Step 1 — Pin and SRI-protect the SDK

Bundle the SDK from npm; do not load from a third-party CDN. If a CDN is unavoidable, pin a version and use Subresource Integrity:

```html
<script
  src="https://cdn.example.net/faro-web-sdk-1.10.3.min.js"
  integrity="sha384-V0a+pBxqSvY+PfVmpJ8hMIJI2J3ePc8mKoYc8mJ9wkKEH2u0YxK0w9kZ4kQpT+E"
  crossorigin="anonymous"
  defer></script>
```

Bundled is preferred:

```bash
npm install --save-exact @grafana/faro-web-sdk@1.10.3 @grafana/faro-web-tracing@1.10.3
```

Verify the SBOM and lockfile in CI; flag any update on a separate review path.

### Step 2 — Initialise with strict scrubbing

```typescript
import { initializeFaro, getWebInstrumentations } from '@grafana/faro-web-sdk';
import { TracingInstrumentation } from '@grafana/faro-web-tracing';

const PII_REGEX = /\b(?:\d{13,19}|\d{3}-\d{2}-\d{4}|[\w.+-]+@[\w-]+\.[\w.-]+)\b/g;

initializeFaro({
  url: 'https://rum.example.net/collect',
  app: { name: 'checkout', version: import.meta.env.VITE_APP_VERSION },

  beforeSend: (event) => {
    const json = JSON.stringify(event);
    const scrubbed = json.replace(PII_REGEX, '[REDACTED]');
    return JSON.parse(scrubbed);
  },

  sessionTracking: { enabled: true, samplingRate: 0.1 },

  instrumentations: [
    ...getWebInstrumentations({
      captureConsole: true,
      captureConsoleDisabledLevels: ['debug', 'log', 'trace'],
    }),
    new TracingInstrumentation({
      instrumentationOptions: {
        propagateTraceHeaderCorsUrls: [/^https:\/\/api\.example\.net/],
      },
    }),
  ],

  // Replay configuration
  experimental: {
    replay: {
      enabled: true,
      mask: {
        textSelectors: ['input', 'textarea', '[data-pii]', 'label'],
        ignoreSelectors: ['[data-no-replay]'],
        maskAllText: false,
        maskAllInputs: true,
      },
      block: {
        selectors: ['#card-number', '#cvv', '#ssn', '[data-block-replay]'],
      },
    },
  },
});
```

Key choices:
- `maskAllInputs: true` — all input values masked by default; selectively unmask non-sensitive fields.
- `block.selectors` — fields completely excluded from the DOM stream.
- `beforeSend` — last-line PII scrubber; pattern-based catch-net for what selector-based masking missed.
- `samplingRate: 0.1` — record 10% of sessions; full replay is rarely needed and storage adds up.

### Step 3 — Content Security Policy that constrains the SDK

```
Content-Security-Policy: default-src 'self';
  script-src 'self' 'wasm-unsafe-eval' 'sha256-<your-inline-hash>';
  connect-src 'self' https://rum.example.net https://api.example.net;
  worker-src 'self' blob:;
  trusted-types faro default;
  require-trusted-types-for 'script';
  report-uri /csp-report
```

Two specifics that matter for RUM:
- `connect-src` enumerates the RUM endpoint explicitly. An XSS-injected exfil to `https://attacker.example` is blocked.
- `trusted-types` plus a Faro-named policy means the SDK must use a sanctioned policy to inject any HTML — required by Faro 1.10+.

### Step 4 — Authenticate and rate-limit the ingest

Browser ingest cannot hold a long-lived secret, but it can hold a short-lived token issued by your origin:

```typescript
// On page render:
const rumToken = await fetch('/auth/rum-token').then(r => r.text());

initializeFaro({
  url: 'https://rum.example.net/collect',
  apiKey: rumToken, // sent as header by Faro 1.10+
});
```

Server-side, `/auth/rum-token` mints a 15-minute JWT bound to the user's session and the page origin. The ingest validates:

```yaml
# Faro Collector / Grafana Agent config
receivers:
  faro:
    endpoint: 0.0.0.0:8027
    auth:
      jwt:
        jwks_url: https://idp.example.net/.well-known/jwks.json
        audiences: ["rum"]
        clock_skew: 60s

processors:
  attributes/strip:
    actions:
    - key: session.id
      action: hash
    - pattern: "^http\\.url$"
      action: redact

  filter/anomaly:
    error_rate_per_session: 100
    events_per_minute_per_ip: 600

exporters:
  loki:
    endpoint: https://logs.example.net/loki/api/v1/push
    tenant_id: rum
```

Rate limits on `events_per_minute_per_ip` and `error_rate_per_session` cut the cost-amplification surface dramatically.

### Step 5 — Schema validation at ingest

A surprising amount of exfil works because the ingest will accept an event with a 50KB `customAttributes` payload. Reject anything outside the Faro schema:

```yaml
processors:
  filter/schema:
    metrics:
      include:
        match_type: regexp
        metric_names: ["^faro\\..*"]
    logs:
      include:
        match_type: regexp
        attributes:
        - key: "log.level"
          value: "^(error|warn|info)$"
    spans:
      include:
        match_type: regexp
        attributes:
        - key: "span.kind"
          value: "^(client|internal)$"
```

Cap individual attribute lengths at 1KB; reject events whose total size exceeds 16KB.

### Step 6 — Scope the replay retention

Session replay storage ≠ log storage. Treat it as PII-bearing:

- Retention: 7 days default, 30 days for incidents, never indefinite.
- Access: dedicated RBAC role separate from general logs/metrics. Audit every read.
- Encryption: customer-managed keys if your provider supports them (Grafana Cloud, Datadog do).

```yaml
# Grafana Cloud Faro retention override
session_replay:
  retention_days: 7
  cmk_kms_key: projects/example/locations/global/keyRings/rum/cryptoKeys/replay
  audit_access: true
```

### Step 7 — Detection rules

Stream the ingest collector logs to your SIEM. Alert on:

- Spike in events from a single IP over 10× p95 baseline (DoS or exfil).
- Event payloads that fail schema validation > 1%/min from a deployed app version (likely a bad release; possibly hostile).
- Attribute values matching credit-card / SSN / JWT regexes after scrubbing — indicates scrubbing gap.
- New origin in `Origin` header (CSRF-style ingest write).
- JWT validation failures over 5%/min.

## Expected Behaviour

| Signal | Before hardening | After hardening |
|--------|------------------|-----------------|
| Card number reaches Loki | Visible in error replay | Masked / blocked at SDK; scrubbed at ingest |
| XSS exfil to attacker domain | Succeeds | CSP blocks `connect-src` |
| Replay retention | 90+ days, mixed RBAC | 7 days, dedicated RBAC + audit |
| Ingest from unauthenticated IP | Accepted | 401 |
| 50KB custom attribute payload | Stored | Rejected at processor |
| Polyfill-style SDK swap | Silent compromise | SRI mismatch fails load; CSP report fires |

```bash
# Spot-check: try to post unsigned event.
curl -X POST https://rum.example.net/collect \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"name":"test"}]}'
# expect: 401 Unauthorized
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `maskAllInputs: true` | Default-deny on PII | Lost signal on legitimate fields (search box, etc.) | Selectively unmask `[data-replay-ok]` after legal review |
| 10% session sampling | Storage and replay-cost reduction | Lower probability of capturing rare bug repro | Boost sampling for error sessions via `sessionTracking.errorSampleRate: 1.0` |
| JWT-bound ingest | Authenticated writes | Token mint adds page latency | Mint at session start, embed in initial HTML |
| Schema validation | Closes exfil channel | Rejects custom attributes you might want | Allowlist specific attribute keys per app |
| CSP `connect-src` allowlist | Blocks exfil | Breaks third-party scripts that didn't declare their endpoints | Inventory all third-party calls; add to CSP or remove |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| `beforeSend` regex regresses | PII leaks to logs | SIEM rule on credit-card pattern post-ingest | Tighten regex; replay last 24h logs through scrubber |
| JWT mint endpoint flaky | RUM ingest drops | Hit rate at collector vs page-view rate | Cache token in `sessionStorage` with 14-min TTL |
| SRI mismatch on legitimate SDK update | All sessions stop reporting | Alert on collector ingest = 0 | Tooling to update integrity hash atomically with SDK version bump |
| CSP overblocks with strict policy | Page errors, broken third-party widgets | CSP `report-uri` floods | Iterate CSP in `Content-Security-Policy-Report-Only` first for 1 week |
| Trusted Types break framework | App fails to render | CSP violations in console | Use a named policy; framework usually has TT support since 2024 |

## When to Consider a Managed Alternative

- Datadog RUM, Sentry, and FullStory ship strict defaults and PII detectors that are typically better than a self-hosted Faro install on day one.
- For HIPAA / payment workloads, BAAs and CMK support from established vendors are usually more practical than DIY.
- Self-host Faro when sovereignty, cost at scale, or extreme schema customisation matter — and when you have a team to maintain CSP, schema validation, and rotation.

## Related Articles

- [OpenTelemetry Collector Hardening](/articles/observability/otel-collector-hardening/)
- [OpenTelemetry SDK Security](/articles/observability/otel-sdk-security/)
- [OpenTelemetry PII Leakage Prevention](/articles/observability/otel-pii-leakage/)
- [HTTP Security Headers](/articles/network/http-security-headers/)
- [Centralized Logging](/articles/observability/centralized-logging/)
