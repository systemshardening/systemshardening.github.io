---
title: "CI/CD Webhook Security Hardening: GitHub, GitLab, and Generic Receivers"
description: "Unsecured webhook receivers are a reliable path to triggering arbitrary pipeline executions, bypassing branch protections, and exfiltrating infrastructure secrets. This article covers HMAC signature verification for GitHub and GitLab webhooks, replay attack prevention, receiver hardening, IP allowlisting, secret rotation, and Jenkins CSRF protection."
slug: webhook-security-hardening
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - webhooks
  - hmac
  - github-webhooks
  - replay-prevention
  - pipeline-security
personas:
  - security-engineer
  - platform-engineer
article_number: 522
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cicd/webhook-security-hardening/
---

# CI/CD Webhook Security Hardening: GitHub, GitLab, and Generic Receivers

## Problem

Webhooks are HTTP callbacks that source control platforms, registries, and monitoring tools fire to notify downstream systems of events — a push to main, a pull request merge, a container image push. In CI/CD pipelines, these callbacks trigger builds, deployments, and infrastructure changes. A webhook receiver that does not validate the caller's identity is an unauthenticated remote code execution endpoint.

Common failures:

- **No signature verification.** The receiver accepts any POST to its URL and immediately starts a pipeline. An attacker who discovers the endpoint URL — through DNS enumeration, accidental exposure in a job log, or Shodan — can forge arbitrary events.
- **Signature verified incorrectly.** Many implementations compare the HMAC digest with a standard string equality check. This is vulnerable to timing side-channel attacks that allow an attacker to brute-force valid signatures byte by byte.
- **No replay prevention.** A correctly signed request captured on the wire (or in a log) can be replayed minutes or hours later to re-trigger a deployment. Combined with a race condition in the deploy logic, replayed webhooks have caused production incidents.
- **Receiver runs with deployment credentials.** The webhook handler has write access to production infrastructure. A forged or replayed trigger call is a direct path to unauthorized deployment.
- **SSRF via webhook target URLs.** Some platforms allow users to configure the webhook destination URL. Without validation, an attacker can point this at internal services — AWS EC2 metadata endpoint, Kubernetes API server, internal admin dashboards — and use the webhook firing mechanism as a proxy.
- **Secrets in webhook payloads logged verbatim.** Webhook bodies often contain repository names, branch names, commit SHAs, and occasionally token values. Logging the raw request body without scrubbing creates a persistent record of sensitive data.

**Target systems:** GitHub and GitHub Enterprise (2022+); GitLab 15.x+; Jenkins 2.440 LTS with Generic Webhook Trigger Plugin; generic Python/Go/Node.js webhook receivers; nginx/Caddy as TLS termination proxy.

## Threat Model

- **Adversary 1 — Forged payload triggering deployment:** An attacker sends a POST to the receiver with a crafted JSON body claiming a push to the main branch. Without signature verification, the receiver starts a deployment pipeline using production credentials.
- **Adversary 2 — Timing attack on signature comparison:** The receiver compares HMAC digests character by character. An attacker measures response times across many requests with single-character variations to reconstruct a valid signature without knowing the secret.
- **Adversary 3 — Replay attack:** An attacker captures a valid signed webhook (from a compromised log aggregation system or a man-in-the-middle position on unencrypted infrastructure). They replay the identical request hours later to re-trigger a deployment.
- **Adversary 4 — SSRF via webhook URL:** A platform allows project members to set webhook destination URLs. An attacker with developer access sets the URL to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to retrieve the instance's IAM credentials via the platform's outbound webhook firing.
- **Adversary 5 — Jenkins unauthenticated trigger:** An attacker discovers a Jenkins job URL with the Remote Build Trigger token visible in a pipeline config file committed to the repository. They call the trigger endpoint directly, bypassing branch protection rules.
- **Access level:** Adversaries 1, 3, and 5 require network access to the receiver. Adversary 2 requires repeated network access. Adversary 4 requires developer-level SCM access.
- **Objective:** Trigger unauthorized deployments; execute arbitrary code via pipeline; exfiltrate infrastructure credentials.
- **Blast radius:** A compromised webhook receiver with deployment permissions has equivalent blast radius to the pipeline's service account — which typically includes production write access.

## Configuration

### Step 1: GitHub Webhook HMAC-SHA256 Signature Verification

GitHub signs every webhook delivery with an HMAC-SHA256 digest of the raw request body, using the webhook secret as the key. The digest is sent in the `X-Hub-Signature-256` header as `sha256=<hex_digest>`.

The critical requirement is **constant-time comparison**. Standard string equality (`==`) short-circuits on the first mismatched byte, leaking timing information. Use `hmac.compare_digest` (Python), `subtle.ConstantTimeCompare` (Go), or `crypto.timingSafeEqual` (Node.js).

```python
# Python — Flask webhook receiver with constant-time HMAC verification.
import hashlib
import hmac
import os
from flask import Flask, request, abort

app = Flask(__name__)

WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"].encode()

def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify GitHub X-Hub-Signature-256 header using constant-time comparison."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected_sig = signature_header.removeprefix("sha256=")
    computed_sig = hmac.new(WEBHOOK_SECRET, payload_body, hashlib.sha256).hexdigest()
    # hmac.compare_digest is constant-time — safe against timing attacks.
    return hmac.compare_digest(computed_sig, expected_sig)

@app.route("/webhook/github", methods=["POST"])
def github_webhook():
    payload = request.get_data()  # Raw bytes — do NOT use request.json here.
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not verify_github_signature(payload, signature):
        abort(403)  # Return 403, not 401 — don't reveal that auth exists.

    event_type = request.headers.get("X-GitHub-Event", "")
    delivery_id = request.headers.get("X-GitHub-Delivery", "")
    # Process event_type, delivery_id, and json.loads(payload) safely.
    return "", 204
```

```go
// Go — net/http webhook receiver with constant-time HMAC verification.
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "net/http"
    "os"
    "strings"
)

var webhookSecret = []byte(os.Getenv("GITHUB_WEBHOOK_SECRET"))

func verifyGitHubSignature(body []byte, sigHeader string) bool {
    if !strings.HasPrefix(sigHeader, "sha256=") {
        return false
    }
    receivedSig, err := hex.DecodeString(strings.TrimPrefix(sigHeader, "sha256="))
    if err != nil {
        return false
    }
    mac := hmac.New(sha256.New, webhookSecret)
    mac.Write(body)
    expectedSig := mac.Sum(nil)
    // subtle.ConstantTimeCompare via hmac.Equal — timing-safe.
    return hmac.Equal(expectedSig, receivedSig)
}

func githubWebhookHandler(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit.
    if err != nil {
        http.Error(w, "", http.StatusBadRequest)
        return
    }
    if !verifyGitHubSignature(body, r.Header.Get("X-Hub-Signature-256")) {
        http.Error(w, "", http.StatusForbidden)
        return
    }
    // Safe to process body here.
    w.WriteHeader(http.StatusNoContent)
}
```

```typescript
// Node.js / TypeScript — Express webhook receiver.
import crypto from "crypto";
import express, { Request, Response } from "express";

const app = express();
const WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET!;

// express.raw() preserves the raw body buffer needed for HMAC computation.
app.use("/webhook/github", express.raw({ type: "application/json" }));

function verifyGitHubSignature(body: Buffer, sigHeader: string): boolean {
  if (!sigHeader?.startsWith("sha256=")) return false;
  const received = Buffer.from(sigHeader.slice(7), "hex");
  const computed = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(body)
    .digest();
  // crypto.timingSafeEqual throws if buffers differ in length.
  if (received.length !== computed.length) return false;
  return crypto.timingSafeEqual(computed, received);
}

app.post("/webhook/github", (req: Request, res: Response) => {
  const body = req.body as Buffer;
  const sig = req.headers["x-hub-signature-256"] as string;
  if (!verifyGitHubSignature(body, sig)) {
    res.status(403).send();
    return;
  }
  res.status(204).send();
});
```

### Step 2: GitLab Webhook Secret Token Verification

GitLab uses a simpler mechanism: a static secret token sent in the `X-Gitlab-Token` header. The receiver compares this header value against the stored secret. Use constant-time comparison here as well.

```python
# Python — GitLab webhook verification.
import hmac
import os
from flask import Flask, request, abort

app = Flask(__name__)
GITLAB_WEBHOOK_TOKEN = os.environ["GITLAB_WEBHOOK_TOKEN"].encode()

@app.route("/webhook/gitlab", methods=["POST"])
def gitlab_webhook():
    received_token = request.headers.get("X-Gitlab-Token", "").encode()
    # Constant-time comparison prevents timing attacks on the token value.
    if not hmac.compare_digest(received_token, GITLAB_WEBHOOK_TOKEN):
        abort(403)
    # Process request.get_json() safely.
    return "", 204
```

Note that GitLab's token mechanism does not sign the payload body — only the token header is verified. This means a valid token header combined with a modified body will pass verification. For GitLab webhooks triggering deployment actions, consider adding a secondary payload integrity check or using GitLab's [push rules](https://docs.gitlab.com/ee/push_rules/push_rules.html) to restrict what branches can trigger the webhook.

### Step 3: Replay Attack Prevention

Replay prevention requires two controls: a **timestamp check** to reject old requests, and a **nonce/delivery-ID store** to reject duplicate requests within the validity window.

GitHub includes an `X-GitHub-Delivery` header with a UUID for every delivery. Store processed delivery IDs in a cache (Redis with TTL, or an in-memory LRU cache for low-volume receivers) and reject duplicates.

```python
# Python — replay prevention with Redis nonce store and timestamp window.
import json
import time
import redis

REPLAY_WINDOW_SECONDS = 300  # Reject requests older than 5 minutes.
nonce_store = redis.Redis(host="localhost", port=6379, db=0)

def check_replay(delivery_id: str, timestamp: float) -> bool:
    """Return True if the request is fresh and not a replay."""
    now = time.time()
    if abs(now - timestamp) > REPLAY_WINDOW_SECONDS:
        return False  # Request is too old (or too far in the future).
    # nx=True: SET only if key does not exist. Returns None if key already set.
    key = f"webhook:delivery:{delivery_id}"
    set_result = nonce_store.set(key, "1", ex=REPLAY_WINDOW_SECONDS * 2, nx=True)
    return set_result is not None  # None means key already existed — replay.
```

For GitHub, combine `X-GitHub-Delivery` (nonce) with the `created_at` or `pushed_at` field in the payload body (timestamp). For GitLab, use the `X-Gitlab-Event-UUID` header (GitLab 15.6+) as the nonce, and the `object_attributes.created_at` field as the timestamp.

### Step 4: Receiver Service Hardening

The webhook receiver process itself must be hardened independently of the signature verification logic.

```yaml
# Kubernetes Deployment — webhook receiver with minimal privileges.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webhook-receiver
  namespace: cicd
spec:
  replicas: 2
  template:
    spec:
      serviceAccountName: webhook-receiver  # Bound to minimal RBAC role.
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534  # nobody
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: receiver
          image: your-registry/webhook-receiver:v1.2.3@sha256:<digest>
          ports:
            - containerPort: 8080
          env:
            - name: GITHUB_WEBHOOK_SECRET
              valueFrom:
                secretKeyRef:
                  name: webhook-secrets
                  key: github-webhook-secret
          resources:
            limits:
              cpu: "200m"
              memory: "128Mi"
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

```yaml
# Kubernetes RBAC — webhook receiver service account.
# The receiver only needs to create PipelineRun objects, nothing else.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: webhook-receiver
  namespace: cicd
rules:
  - apiGroups: ["tekton.dev"]
    resources: ["pipelineruns"]
    verbs: ["create"]
  # NOT: secrets, configmaps, deployments, cluster-wide resources, or ServiceAccounts.
```

**Idempotent handlers** prevent duplicate pipeline runs if the receiver is accidentally called twice. Use the delivery ID as the pipeline run name or an idempotency key in the pipeline metadata — a second call with the same delivery ID returns 200 without creating a second run.

### Step 5: Exposing Receivers Safely — IP Allowlisting and WAF Rules

GitHub and GitLab publish their outbound IP ranges for webhook delivery. Allowlist these ranges at the firewall or WAF level so that only legitimate platform traffic can reach the receiver.

```bash
# Fetch GitHub's current webhook IP ranges.
curl -s https://api.github.com/meta | jq -r '.hooks[]'
# Example output (ranges change — automate this):
# 192.30.252.0/22
# 185.199.108.0/22
# 140.82.112.0/20
# 143.55.64.0/20

# nginx — restrict webhook endpoint to GitHub IP ranges.
# /etc/nginx/conf.d/webhook.conf
geo $allowed_webhook_source {
    default         0;
    192.30.252.0/22 1;
    185.199.108.0/22 1;
    140.82.112.0/20  1;
    143.55.64.0/20   1;
}

server {
    listen 443 ssl;
    server_name webhooks.example.com;

    location /webhook/github {
        if ($allowed_webhook_source = 0) {
            return 403;
        }
        proxy_pass http://webhook-receiver:8080;
        proxy_set_header X-Forwarded-For $remote_addr;
        # Do NOT log the request body — it may contain sensitive branch names or tokens.
        access_log /var/log/nginx/webhook_access.log combined;
    }
}
```

```bash
# Fetch GitLab.com's webhook outbound IPs (GitLab.com only — self-managed uses your own IPs).
# GitLab.com does not publish a machine-readable IP list.
# Allowlist by hostname resolution or use GitLab's IP range documentation:
# https://docs.gitlab.com/ee/user/gitlab_com/index.html#ip-range

# AWS Security Group — allow GitHub webhook IPs on port 443.
for cidr in $(curl -s https://api.github.com/meta | jq -r '.hooks[]'); do
    aws ec2 authorize-security-group-ingress \
        --group-id sg-XXXXXXXXX \
        --protocol tcp \
        --port 443 \
        --cidr "$cidr"
done
```

**Automate IP range updates.** GitHub's IP ranges change without notice. Subscribe to the [GitHub status page](https://www.githubstatus.com/) and implement a daily job that reconciles the current `/meta` endpoint output against your firewall rules.

### Step 6: Webhook Secret Rotation Procedure

Rotating a webhook secret without dropping deliveries requires a brief dual-secret acceptance window.

```python
# Python — accept both old and new secrets during rotation window.
import os
import hmac
import hashlib

OLD_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET_OLD", "").encode()
NEW_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"].encode()

def verify_with_rotation(payload: bytes, sig_header: str) -> bool:
    """Accept signatures from both old and new secrets during rotation."""
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    received = sig_header.removeprefix("sha256=")
    for secret in filter(None, [NEW_SECRET, OLD_SECRET]):
        computed = hmac.new(secret, payload, hashlib.sha256).hexdigest()
        if hmac.compare_digest(computed, received):
            return True
    return False
```

**Rotation procedure:**

1. Generate a new secret: `openssl rand -hex 32`.
2. Deploy receiver with `GITHUB_WEBHOOK_SECRET_OLD` (current) and `GITHUB_WEBHOOK_SECRET` (new) — accept both.
3. Update the webhook secret in GitHub/GitLab settings.
4. Wait for 10 minutes to ensure no in-flight deliveries use the old secret.
5. Remove `GITHUB_WEBHOOK_SECRET_OLD` from the receiver's environment.
6. Redeploy.

Store webhook secrets in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets with encryption at rest) — never in version control or `.env` files committed to the repository.

### Step 7: Jenkins Webhook Security — CSRF Protection and Token-Based Auth

Jenkins exposes remote build triggers via URLs of the form `/job/<name>/build?token=<token>`. Without additional protection, these endpoints are unauthenticated once the token is known.

```groovy
// Jenkinsfile — using the Generic Webhook Trigger Plugin with HMAC verification.
// Requires Generic Webhook Trigger Plugin 1.86+.

pipeline {
  triggers {
    GenericTrigger(
      // Extract the HMAC signature from the request header.
      genericHeaderVariables: [
        [key: 'X-Hub-Signature-256', regexpFilter: 'sha256=']
      ],
      // Extract branch name from the payload body.
      genericVariables: [
        [key: 'REF', value: '$.ref']
      ],
      // The token in the URL path — separate from the HMAC secret.
      token: env.JENKINS_WEBHOOK_TOKEN,
      // Prevent builds from unrecognised branch patterns.
      regexpFilterExpression: '^refs/heads/main$',
      regexpFilterText: '$REF',
      causeString: 'Triggered by GitHub push to main',
      printContributedVariables: false,  // Do not log variables — may contain secrets.
      printPostContent: false            // Do not log the raw payload body.
    )
  }
  stages {
    stage('Deploy') {
      steps {
        // Verify HMAC inside the pipeline before executing deployment steps.
        script {
          def receivedSig = X_Hub_Signature_256  // Extracted by GenericTrigger.
          def payloadHmac = sh(
            script: "echo -n \"\${payload}\" | openssl dgst -sha256 -hmac \"\${WEBHOOK_HMAC_SECRET}\" | cut -d' ' -f2",
            returnStdout: true
          ).trim()
          if (receivedSig != payloadHmac) {
            error("HMAC verification failed — aborting deployment.")
          }
        }
      }
    }
  }
}
```

Enable Jenkins CSRF protection (enabled by default in Jenkins 2.x — do not disable it):

```groovy
// JCasC — verify CSRF protection is enforced.
// /var/jenkins_home/casc_configs/security.yaml
jenkins:
  crumbIssuer:
    standard:
      excludeClientIPFromCrumb: false  # Include IP in crumb for stricter binding.
```

Remote build tokens should be treated as secrets: store them in the Jenkins credential store, never in the Jenkinsfile or repository. Use the Jenkins Credentials Binding Plugin to inject the token as an environment variable only when configuring the trigger.

### Step 8: Testing Webhook Signatures Locally

Use [smee.io](https://smee.io) as a webhook relay during development. smee.io forwards GitHub webhook deliveries to a local port via a persistent EventSource connection — you do not need a publicly reachable server or an open port.

```bash
# Install the smee client.
npm install --global smee-client

# Start forwarding from your smee.io channel to localhost.
smee --url https://smee.io/<your-channel-id> --path /webhook/github --port 8080
```

**Avoid ngrok for production webhook testing.** ngrok exposes a stable subdomain that, if leaked, becomes a permanent attack surface. ngrok sessions persist beyond the development session in paid tiers, and ngrok's subdomain is predictable in free tiers. If you must use ngrok, use ephemeral (random) subdomains, restrict access with ngrok's IP allowlist feature, and shut down the tunnel immediately after testing.

For integration tests, verify signatures programmatically by generating a test payload and computing the HMAC against a test secret, rather than disabling verification in the test environment.

### Step 9: Logging and Alerting on Signature Failures

Signature verification failures are high-signal security events. A single failure may be a misconfiguration. Repeated failures from a consistent source IP indicate active probing.

```python
# Python — structured logging for webhook verification outcomes.
import logging
import json

logger = logging.getLogger("webhook.security")

@app.route("/webhook/github", methods=["POST"])
def github_webhook():
    payload = request.get_data()
    signature = request.headers.get("X-Hub-Signature-256", "")
    source_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    delivery_id = request.headers.get("X-GitHub-Delivery", "unknown")
    event_type = request.headers.get("X-GitHub-Event", "unknown")

    if not verify_github_signature(payload, signature):
        logger.warning(json.dumps({
            "event": "webhook.signature_failure",
            "source_ip": source_ip,
            "delivery_id": delivery_id,
            "event_type": event_type,
            "signature_present": bool(signature),
            # Do NOT log the raw signature value — it contains partial key material.
        }))
        abort(403)

    logger.info(json.dumps({
        "event": "webhook.accepted",
        "source_ip": source_ip,
        "delivery_id": delivery_id,
        "event_type": event_type,
    }))
    return "", 204
```

**Alert thresholds:**

- More than 5 signature failures from any single IP in 10 minutes — alert (active probing).
- Any signature failure from an IP outside the GitHub/GitLab allowlisted ranges — alert immediately (forged request bypassed IP filter).
- More than 2 replay attempts (duplicate delivery IDs) in any 1-hour window — alert (captured-and-replay attack in progress).

Feed webhook security events into your SIEM as a separate stream from general application logs so they are not lost in volume.

## Verification

```bash
# Test GitHub signature verification with curl — compute the correct HMAC.
SECRET="your-webhook-secret"
PAYLOAD='{"ref":"refs/heads/main","repository":{"full_name":"org/repo"}}'
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)

# Send a correctly signed request — expect 204.
curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://webhooks.example.com/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=${SIG}" \
  -H "X-GitHub-Event: push" \
  -H "X-GitHub-Delivery: $(uuidgen)" \
  -d "$PAYLOAD"
# Expected: 204

# Send a request with an invalid signature — expect 403.
curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://webhooks.example.com/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=0000000000000000000000000000000000000000000000000000000000000000" \
  -H "X-GitHub-Event: push" \
  -H "X-GitHub-Delivery: $(uuidgen)" \
  -d "$PAYLOAD"
# Expected: 403

# Confirm IP allowlisting is working — send from an IP outside the allowlist.
# (Run from a non-GitHub IP, or use curl with --interface on a different NIC.)
curl -s -o /dev/null -w "%{http_code}" \
  -X POST https://webhooks.example.com/webhook/github \
  -H "X-Hub-Signature-256: sha256=${SIG}" \
  -d "$PAYLOAD"
# Expected: 403 (blocked at nginx/WAF before reaching the receiver)

# Check that the nonce store is rejecting replays.
DELIVERY=$(uuidgen)
for i in 1 2; do
  echo -n "Request $i: "
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST https://webhooks.example.com/webhook/github \
    -H "Content-Type: application/json" \
    -H "X-Hub-Signature-256: sha256=${SIG}" \
    -H "X-GitHub-Event: push" \
    -H "X-GitHub-Delivery: ${DELIVERY}" \
    -d "$PAYLOAD"
done
# Expected: 204 (first), 409 or 403 (second — replay rejected)
```

## Summary

| Control | GitHub | GitLab | Jenkins |
|---|---|---|---|
| Request signing | HMAC-SHA256 (`X-Hub-Signature-256`) | Static token (`X-Gitlab-Token`) | Token in URL + optional HMAC via plugin |
| Constant-time comparison | Required (`hmac.compare_digest`) | Required | Required |
| Replay prevention | `X-GitHub-Delivery` nonce + timestamp | `X-Gitlab-Event-UUID` nonce (15.6+) | Pipeline run idempotency key |
| IP allowlisting | GitHub meta API (`/meta` hooks ranges) | GitLab documentation IP ranges | Restrict trigger endpoint at firewall |
| CSRF protection | N/A — stateless POST | N/A — stateless POST | Enable crumb issuer (default on) |
| Secret storage | Secrets manager, injected at runtime | Secrets manager, injected at runtime | Jenkins credential store or Vault |

Webhook endpoints are unauthenticated by design — they must accept calls from external systems without session cookies or OAuth flows. This makes correct HMAC verification, constant-time comparison, replay prevention, and IP allowlisting essential controls rather than optional hardening. The investment is small: fewer than 30 lines of code per language for the verification logic, and a straightforward operational procedure for IP range automation and secret rotation.
