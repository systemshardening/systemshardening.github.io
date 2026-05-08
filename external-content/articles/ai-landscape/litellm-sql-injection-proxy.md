---
title: "LiteLLM Proxy Pre-Auth SQL Injection: CVE-2026-42208"
description: "CVE-2026-42208 (CVSS 9.3) is a pre-authentication SQL injection in LiteLLM's API key verification — exploited within 36 hours of disclosure. Patch to v1.83.7+, rotate all LLM provider keys, and harden LiteLLM database access."
slug: litellm-sql-injection-proxy
date: 2026-05-07
lastmod: 2026-05-07
category: ai-landscape
tags:
  - litellm
  - sql-injection
  - llm-proxy
  - cve
  - credential-theft
personas:
  - platform-engineer
  - security-engineer
article_number: 452
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/ai-landscape/litellm-sql-injection-proxy/
---

# LiteLLM Proxy Pre-Auth SQL Injection: CVE-2026-42208

## The Problem

CVE-2026-42208 is a pre-authentication SQL injection vulnerability in LiteLLM's API key verification logic. CVSS 9.3 Critical. Disclosed April 17, 2026. Fixed in LiteLLM v1.83.7, released April 19, 2026. Active exploitation in the wild was documented within 36 hours of disclosure. Affected versions are all LiteLLM releases prior to v1.83.7 that use a database-backed virtual key store — the default configuration for any production LiteLLM deployment.

LiteLLM is an open-source proxy that presents a unified OpenAI-compatible API surface and routes requests to 100+ LLM providers: OpenAI, Anthropic Claude, Google Gemini, AWS Bedrock, Azure OpenAI, Cohere, Mistral, and self-hosted inference servers. Organisations deploy it to centralise LLM provider API key management behind a single gateway, enforce spend controls, and insulate application code from provider-specific SDKs. That architecture creates a concentrated target: a single LiteLLM instance may hold credentials for every LLM service the organisation uses.

The vulnerability lives in the `verify_key` function inside LiteLLM's authentication middleware. When the proxy receives a request, it reads the value from the `Authorization` header and constructs a SQL query to look up the virtual key record in the `litellm_verificationtoken` table. The query is built by string concatenation, not parameterisation. The raw header value is interpolated directly into the SQL string before execution. An unauthenticated attacker controls the entire `Authorization` header.

A minimal exploitation payload:

```bash
curl -X POST http://litellm-host:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ' OR '1'='1" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "test"}]}'
```

Because `'1'='1'` is always true, the query returns all rows from the `litellm_verificationtoken` table rather than matching a specific key. The authentication check passes. The attacker is now operating as an authenticated LiteLLM user with no valid key.

More destructive payloads use a `UNION SELECT` to extract rows from other tables alongside the authentication result. The `litellm_proxyconfig` table stores the raw values of all configured LLM provider credentials — OpenAI API keys, Anthropic API keys, AWS access key IDs and secrets for Bedrock, Azure OpenAI endpoints and keys, and any other provider credentials added to the LiteLLM configuration. A single request with a crafted payload can return all of these values to the attacker through LiteLLM's response body or through a timing-based side channel. The attacker does not need to interact with the database directly; the vulnerable SQL query does the extraction for them.

Database write access is also available through the same vector. An attacker can `INSERT` rows into `litellm_verificationtoken` to create new admin virtual keys, `UPDATE` existing records to remove spend limits or extend key expiry, or inject poisoned logging configurations that exfiltrate future request data to attacker-controlled infrastructure.

The 36-hour exploitation window follows the same pattern observed in the LMDeploy SSRF (CVE-2026-33626). LLM infrastructure is specifically targeted because a single compromised proxy holds credentials for multiple expensive LLM services simultaneously. Stolen API keys are immediately usable for compute-intensive tasks — large-scale inference, model fine-tuning on the victim's quota — that generate large API bills charged to the victim organisation while the attacker pays nothing. The operational window between disclosure and exploitation is consistently shorter for AI infrastructure than for traditional web application vulnerabilities because the monetisation path for stolen LLM API keys is direct and frictionless.

## Threat Model

**Unauthenticated attacker reaching port 4000.** LiteLLM's proxy listens on port 4000 by default. The exploitation requires one HTTP request with a crafted `Authorization` header. No credentials, no prior knowledge of the deployment, and no existing session are needed. Any attacker who can reach that port — from the internet if the service is publicly exposed, from the internal network if it is not — can execute the SQL injection.

**Extraction of all LLM provider credentials.** The `litellm_proxyconfig` table and the provider API key values stored in `litellm_verificationtoken` records can be extracted via `UNION SELECT` payloads. The attacker obtains:

- OpenAI API keys (`sk-...`) — usable for GPT-4o and embeddings at the victim's expense
- Anthropic API keys — usable for Claude models at the victim's expense
- AWS Bedrock access key IDs and secrets — usable for Bedrock inference and, depending on IAM scope, other AWS services
- Azure OpenAI endpoint URLs, API keys, and deployment names
- Google Gemini API keys or Vertex AI service account credentials
- Any other provider credentials configured in LiteLLM

**Unauthorised LLM usage and bill generation.** Extracted provider keys are immediately usable from off-proxy infrastructure. Attackers use them for large-scale inference (scraping, content generation at volume), fine-tuning runs on victim quota, or resale in underground markets. All costs are charged to the victim organisation's provider accounts.

**Data exfiltration of historical LLM traffic.** The `litellm_spendlogs` table stores request metadata and, in some configurations, full prompt and completion content for every request that passed through the proxy. An attacker can extract the organisation's complete LLM usage history — including any sensitive data passed to LLM providers through the proxy.

**Database write: admin key injection and configuration tampering.** Write access allows the attacker to create persistent admin virtual keys that survive a proxy restart, modify rate limits and spend controls on existing keys, or inject logging webhook URLs that forward all future LiteLLM traffic to attacker-controlled endpoints.

**Multi-tenant blast radius.** LiteLLM is frequently deployed as shared infrastructure serving multiple internal teams or, for SaaS products, multiple external customers. In these deployments, a single SQL injection extracts every customer's virtual key records, all provider credentials shared across the tenancy, and usage logs for all customers simultaneously.

## Hardening Configuration

### 1. Patch to LiteLLM v1.83.7+

The fix in v1.83.7 replaces the string-concatenated SQL query in `verify_key` with a parameterised query. The injection payload is passed as a bound parameter, never interpolated into the SQL string. The database driver treats it as a literal value, not as SQL syntax. `' OR '1'='1` is compared against key values in the table as a string and matches nothing.

Upgrade the package:

```bash
pip install --upgrade "litellm>=1.83.7"
```

Verify the installed version:

```bash
litellm --version
```

For Docker deployments, update the image tag in the deployment manifest and pull the new image:

```bash
docker pull ghcr.io/berriai/litellm:main-v1.83.7
docker run --rm ghcr.io/berriai/litellm:main-v1.83.7 litellm --version
```

For Kubernetes deployments using a pinned image tag, update the tag in the Deployment spec and apply:

```yaml
spec:
  containers:
    - name: litellm
      image: ghcr.io/berriai/litellm:main-v1.83.7
```

```bash
kubectl rollout status deployment/litellm-proxy -n litellm
```

### 2. Rotate All LLM Provider API Keys

If the LiteLLM instance was reachable during the vulnerable period — any time before upgrading to v1.83.7 — treat all stored provider credentials as compromised. The extraction payload is a single HTTP request; there is no reliable way to determine from LiteLLM logs whether it was used. The safe assumption is that all keys were exfiltrated.

Rotate credentials at each provider's console and revoke the old values:

- **OpenAI**: [platform.openai.com/api-keys](https://platform.openai.com/api-keys) — create a new key, update LiteLLM config, then delete the old key
- **Anthropic**: [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys) — create replacement, revoke old
- **Google Gemini / Vertex AI**: Google Cloud Console > APIs & Services > Credentials — generate new API key or rotate the service account key; disable or delete the old one
- **AWS Bedrock**: IAM Console — create a new IAM user or role with Bedrock permissions, generate new access keys, update LiteLLM config, then deactivate and delete the old IAM access keys
- **Azure OpenAI**: Azure Portal > your Azure OpenAI resource > Keys and Endpoint — regenerate Key 1 or Key 2, update LiteLLM config

After rotating each provider key, update the LiteLLM configuration to use the new values and restart the proxy. Verify connectivity to each provider:

```bash
litellm --test
```

Check each provider's usage dashboard for API activity during the window between initial LiteLLM deployment (or last key rotation) and the patch date of April 19, 2026. Unexplained usage spikes during that window indicate the old keys were used after extraction.

### 3. Restrict LiteLLM Network Access

The LiteLLM proxy port should not be reachable from the internet. In most deployments it should only be reachable from the specific pods or services that use it.

For Kubernetes deployments, apply a NetworkPolicy that restricts ingress to port 4000 to only the application namespaces that legitimately call LiteLLM:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: litellm-ingress-restrict
  namespace: litellm
spec:
  podSelector:
    matchLabels:
      app: litellm-proxy
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              litellm-access: allowed
      ports:
        - protocol: TCP
          port: 4000
```

Apply the `litellm-access: allowed` label only to namespaces that contain application pods authorised to call the proxy. Verify that the LiteLLM Service is of type `ClusterIP`, not `LoadBalancer` or `NodePort`:

```bash
kubectl get svc -n litellm litellm-proxy -o jsonpath='{.spec.type}'
```

For non-Kubernetes deployments, apply a firewall rule allowing port 4000 only from application server IP ranges:

```bash
ufw allow from 10.0.1.0/24 to any port 4000 proto tcp
ufw deny 4000
```

### 4. Enable LiteLLM Database Encryption at Rest

LiteLLM supports encrypting the values of stored virtual keys and provider credentials in the database using an additional master key. With encryption enabled, the values in `litellm_verificationtoken` and `litellm_proxyconfig` are stored as ciphertext. A SQL injection that reads the raw database rows obtains encrypted blobs rather than plaintext API key strings. The encryption key itself is never stored in the database.

Enable encryption by setting the `LITELLM_MASTER_KEY` environment variable and enabling the `encrypt_keys_in_db` setting in `config.yaml`:

```yaml
general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
  encrypt_keys_in_db: true
```

Store the master key in a secrets manager rather than as an environment variable in the deployment manifest. For Kubernetes, use an External Secrets Operator integration with your secrets manager of choice, or at minimum a Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: litellm-master-key
  namespace: litellm
type: Opaque
stringData:
  LITELLM_MASTER_KEY: "sk-master-replace-with-generated-value"
```

Reference it in the Deployment spec:

```yaml
env:
  - name: LITELLM_MASTER_KEY
    valueFrom:
      secretKeyRef:
        name: litellm-master-key
        key: LITELLM_MASTER_KEY
```

Generate the master key value with sufficient entropy:

```bash
python3 -c "import secrets; print('sk-master-' + secrets.token_hex(32))"
```

### 5. Audit Access Logs for Exploitation Attempts

Scan LiteLLM access logs and any upstream reverse proxy logs for `Authorization` header values containing SQL metacharacters. The most common injection patterns use single quotes, double dashes (comment syntax), semicolons, and `UNION SELECT` keywords.

If LiteLLM access logging is enabled, scan the log file:

```bash
grep -iE "(Authorization|Bearer).*(\'|%27|--|;|UNION|SELECT|OR\s+['\"]?1['\"]?\s*=)" /var/log/litellm/access.log
```

If traffic passes through nginx before reaching LiteLLM, scan the nginx access log for anomalous `Authorization` header content:

```bash
grep -iE "Bearer.*(%27|%22|--|\bUNION\b|\bSELECT\b|\bOR\b.*=)" /var/log/nginx/access.log
```

The regex covers URL-encoded variants (`%27` for single quote, `%22` for double quote) in addition to literal characters. Extend it to cover hex-encoded payloads if your application URL-decodes headers before logging:

```bash
grep -iE "Bearer.*(0x27|0x22|char\(|concat\(|substring\()" /var/log/nginx/access.log
```

Any match in these log scans indicates the injection payload was received by the proxy during the vulnerable period. The presence of a log entry does not confirm successful data extraction, but the absence of log entries does not rule it out — a sophisticated attacker may have sent requests that were not logged, or logging may not have been enabled. If in doubt, rotate all provider keys regardless.

Also check LLM provider usage dashboards for activity spikes during the vulnerable window. An attacker who extracted keys would typically begin using them within hours of extraction. Unexpected token consumption on any provider account during the vulnerable period is a strong indicator of key compromise.

## Expected Behaviour After Hardening

After patching to v1.83.7: a request with `Authorization: Bearer ' OR '1'='1` returns a `401 Unauthorized` response. The `verify_key` function executes a parameterised query that treats the entire string `' OR '1'='1` as a literal lookup value. The query returns zero rows. Authentication fails. The response contains no data from the database.

After key rotation: any provider API keys extracted during the vulnerable window are invalid. An attacker who extracted an OpenAI key before the patch and attempts to use it after rotation receives an `invalid_api_key` error from OpenAI. The extracted credentials have no value.

After network restriction: the LiteLLM port is unreachable from outside the internal cluster. An attacker who can reach the internet-facing address of the cluster cannot send any request to port 4000. The injection payload never reaches the LiteLLM process.

After database encryption: a SQL injection that successfully reads rows from `litellm_verificationtoken` or `litellm_proxyconfig` retrieves ciphertext values. Without the `LITELLM_MASTER_KEY` — which is never stored in the database — the attacker cannot recover the plaintext provider API keys from the extracted rows.

## Trade-offs and Operational Considerations

Rotating all LLM provider keys requires coordinating with every team and application that accesses provider APIs — both through LiteLLM and directly. Applications that bypass LiteLLM and use provider keys directly also need to be updated with the new key values before the old keys are revoked. Establish the rotation sequence: create new key, update LiteLLM config, update all direct consumers, verify connectivity end-to-end, then revoke the old key. Revoking before updating consumers causes outages.

Database encryption at rest means the stored keys cannot be recovered from a database backup if the `LITELLM_MASTER_KEY` is lost. A backup without the master key is useless for recovery — the encrypted blobs cannot be decrypted. Store the master key in a secrets manager with its own backup and recovery procedure. Do not store the master key as a plain environment variable in the deployment manifest or in version-controlled configuration files. A master key committed to a Git repository provides no protection against the backup recovery scenario.

The network restriction NetworkPolicy must account for all namespaces that legitimately call LiteLLM. In organisations with many application teams, maintaining the `litellm-access: allowed` label on the correct set of namespaces requires a process — add it as part of the onboarding checklist for new application teams, and audit label presence periodically. A namespace missing the label cannot reach LiteLLM and will experience authentication failures that appear as network timeouts rather than 401 responses, which can be confusing to debug.

## Failure Modes

**LiteLLM upgraded to v1.83.7 but provider keys not rotated.** The patched proxy no longer allows SQL injection, but an attacker who extracted keys during the vulnerable window still holds valid credentials. They continue using the extracted keys from off-proxy infrastructure, generating bills against the victim's provider accounts. The patch eliminates the injection vector but does not invalidate already-exfiltrated credentials. Key rotation is not optional if the proxy was reachable before the patch.

**Network restriction applied to the production LiteLLM instance but a staging or development instance with the same provider keys is still publicly accessible.** Development instances frequently share provider API keys with production, or use keys from the same OpenAI or Anthropic account with the same billing scope. An attacker who cannot reach production directly scans for the development instance, exploits it, and extracts keys that work in production. Verify that all LiteLLM instances — production, staging, development — are patched and network-restricted, and that development instances do not share live provider keys with production.

**Log audit searches for literal single quote `'` but the attacker used URL-encoded `%27` or hex-encoded `CHAR(39)` injection payloads.** A `grep` for `'` in the access log misses payloads that encode the metacharacter. Use a regex covering multiple encodings as shown in the audit commands above. Additionally, examine logs for any `Authorization` header longer than approximately 200 characters — legitimate virtual keys are fixed-length and do not contain SQL keywords; anomalously long header values warrant manual inspection regardless of encoding.

**LiteLLM database encryption enabled but the `LITELLM_MASTER_KEY` stored as a plain environment variable in the Kubernetes Deployment manifest.** The manifest is typically committed to a GitOps repository. Anyone with read access to that repository — including CI/CD systems, developers onboarded after the secret was committed, and any system with access to the repository's history — can read the master key. A master key committed in plaintext defeats the purpose of database encryption. Move it to a Kubernetes Secret backed by a secrets manager before enabling encryption.

## Related Articles

- [LLM Deployment Security](/articles/ai-landscape/llm-deployment-security/)
- [LiteLLM Proxy Security](/articles/ai-landscape/litellm-proxy-security/)
- [LMDeploy SSRF IMDS Exfiltration](/articles/ai-landscape/lmdeploy-ssrf-imds-exfiltration/)
- [AI Credential Delegation](/articles/ai-landscape/ai-credential-delegation/)
- [MCP Server Security](/articles/ai-landscape/mcp-server-security/)
