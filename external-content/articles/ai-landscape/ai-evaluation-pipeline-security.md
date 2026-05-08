---
title: "AI Model Evaluation Pipeline Security"
description: "Hardening LLM eval pipelines (Inspect, lm-eval-harness, custom): untrusted dataset isolation, sandboxed model execution, attestation of eval results, leakage controls."
slug: "ai-evaluation-pipeline-security"
date: 2026-05-08
lastmod: 2026-05-08
category: "ai-landscape"
tags: ["ai-eval", "inspect", "lm-eval-harness", "model-evaluation", "sandbox", "attestation"]
personas: ["ml-engineer", "security-engineer", "platform-engineer"]
article_number: 654
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/ai-landscape/ai-evaluation-pipeline-security/index.html"
---

# AI Model Evaluation Pipeline Security

## Problem

Evaluation pipelines are how teams decide whether a model is safe enough to deploy. Inspect AI (UK AISI), lm-evaluation-harness (EleutherAI), HELM (Stanford), MT-Bench, the OpenAI evals framework, and a long tail of internal harnesses run candidate models against benchmark datasets, agentic tasks, and red-team prompts. Their output drives release decisions, regulatory filings (EU AI Act conformity), and capability claims in model cards.

Three properties make eval pipelines a non-obvious threat surface that security teams routinely overlook:

1. **They run untrusted code by design.** Agentic evals (SWE-bench, Cybench, GAIA, AISI's autonomy suite) require the model to execute shell commands, write to disk, browse the web, and call APIs. The eval harness is *expected* to give the model a sandbox in which to run arbitrary code. If that sandbox is the host machine, every eval run is a code-execution opportunity for whoever supplies the dataset or the candidate model.
2. **They ingest untrusted datasets.** Benchmark datasets are pulled from HuggingFace, GitHub, S3 buckets, or model providers. A poisoned dataset can include adversarial examples that target the harness itself (parser bugs in the JSONL loader, deserialization in pickle-encoded prompts) or that manipulate the eval scorer into producing favourable scores.
3. **Their outputs feed regulatory and commercial decisions.** A pipeline that mis-reports a 75% safety score as 95% has compliance and reputational consequences far beyond a normal CI test failure. Tampering with eval results — by either an insider or an attacker who has gained pipeline access — is a high-value target.

Several specific incidents in 2024–2025 showed the pattern: HuggingFace datasets weaponised with pickle deserialization that ran during `datasets.load_dataset()`, a Cybench-style harness used as a launchpad to attack the host because the agent's `bash` tool was a thin wrapper over `subprocess.run`, and an internal eval pipeline at one frontier lab where a contractor manipulated scoring scripts to inflate a model's harmlessness numbers prior to release sign-off.

This article focuses on the three pillars of a hardened eval pipeline: dataset trust, sandboxed model execution, and attestation of results. Target systems: Inspect AI ≥ 0.3, lm-evaluation-harness ≥ 0.5, HuggingFace datasets ≥ 3.0, Docker / Firecracker / gVisor / WASI sandboxes for agent execution, and SLSA-style provenance for eval artifacts.

## Threat Model

1. **Poisoned benchmark dataset.** Goal: trigger code execution during dataset load, or craft examples that exploit the scorer's grading logic. Surface: HuggingFace `trust_remote_code=True`, pickle/jsonl parsing, regex-based scorers.
2. **Hostile candidate model in agentic eval.** Goal: escape the agent sandbox during a permitted code-execution task. Surface: `subprocess` wrappers, host-network access, mounted credentials.
3. **Insider tampering with eval outputs.** Goal: alter pass/fail rates, flip safety verdicts before sign-off. Surface: writeable result store, no signing, no audit log.
4. **Compromised eval-runner credential.** Goal: pivot from eval pipeline to model registry, training data, or deployment systems. Surface: broad IAM scopes on the runner, persistent secrets.

Blast radius without hardening: a poisoned eval can give an attacker code execution on infrastructure that holds model weights and training data. With hardening, eval execution is contained to a single ephemeral sandbox with attested results.

## Configuration / Implementation

### Step 1 — Pin and verify datasets

Use HuggingFace dataset revisions and forbid `trust_remote_code`:

```python
from datasets import load_dataset, DownloadConfig

ds = load_dataset(
    "lmsys/mt_bench_human_judgments",
    revision="d8f4a4b7a3c5e6f8a9b0c1d2e3f4g5h6",   # commit-pinned
    trust_remote_code=False,                          # never True in production
    download_config=DownloadConfig(
        num_proc=1,
        max_retries=3,
        force_download=False,
        token=None,                                   # public datasets only on this path
    ),
)
```

Maintain a vetted-dataset registry — a YAML file with `name`, `revision`, `sha256`, `license`, `vetted_by`, `vetted_at`. Pre-flight check before any eval run:

```python
def verify_dataset(name: str, revision: str) -> None:
    expected = REGISTRY[name]
    if revision != expected["revision"]:
        raise SecurityError(f"unpinned dataset {name}@{revision}")
    actual_sha = compute_dataset_sha256(name, revision)
    if actual_sha != expected["sha256"]:
        raise SecurityError(f"dataset hash mismatch: {actual_sha}")
```

For datasets that legitimately ship loader scripts (which require `trust_remote_code=True`), fork them, audit the script, vendor the reviewed copy, and load from the local path only.

### Step 2 — Sandbox the candidate model's tool calls

Inspect AI ships a sandbox abstraction; use it strictly:

```python
from inspect_ai import Task, eval
from inspect_ai.solver import use_tools, generate
from inspect_ai.tool import bash, python
from inspect_ai.dataset import json_dataset

@task
def cybench_subset() -> Task:
    return Task(
        dataset=json_dataset("vetted/cybench-2025-Q2.jsonl"),
        solver=[
            use_tools([bash(timeout=30), python(timeout=30)]),
            generate(),
        ],
        sandbox=("docker", "infra/cybench-sandbox.yaml"),
        message_limit=20,
        time_limit=300,
    )
```

Sandbox config (`infra/cybench-sandbox.yaml`):

```yaml
services:
  default:
    image: cybench-sandbox:1.4.0@sha256:abc...
    cap_drop: [ALL]
    cap_add: []
    security_opt:
      - no-new-privileges:true
      - seccomp=infra/seccomp-strict.json
      - apparmor=cybench-sandbox
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
      - /workspace:size=128m
    networks:
      - sandbox-isolated
    user: "65534:65534"
    pids_limit: 100
    mem_limit: 512m
    cpu_quota: 50000
networks:
  sandbox-isolated:
    driver: bridge
    internal: true   # no external network
```

Key elements:
- `internal: true` — the sandbox cannot reach the internet at all by default. Tasks that legitimately need web access run on a separate proxied network with an FQDN allowlist.
- No mounted host paths beyond a fresh tmpfs.
- `user: 65534` — non-root.
- `mem_limit`, `pids_limit`, `cpu_quota` — resource bounds prevent agent CPU/RAM exhaustion of the runner.

For higher-isolation needs, swap Docker for Firecracker / gVisor / Kata. lm-evaluation-harness's `--sandbox` flag accepts the same backends since 0.5.

### Step 3 — Network-allowlist tasks that need it

Web-browsing tasks (GAIA, BrowseComp) need network. Constrain it:

```yaml
networks:
  sandbox-web-allowlist:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.enable_ip_masquerade: "true"
    ipam:
      config:
      - subnet: 10.42.0.0/16
```

Plus an egress proxy:

```nginx
# eval-egress.example.net
server {
  listen 443 ssl;
  server_name eval-egress.example.net;
  location / {
    if ($http_host !~ ^(en\.wikipedia\.org|www\.google\.com|arxiv\.org)$) {
      return 403;
    }
    proxy_pass https://$http_host$request_uri;
  }
  access_log /var/log/nginx/eval-egress.log json_combined;
}
```

Sandbox uses HTTP_PROXY pointing at this proxy; routes to anything else are dropped at the network-namespace iptables.

### Step 4 — Sign and attest eval results

Every eval run produces a JSON or `.eval` log. Sign it at completion with a runner-bound key:

```python
import json
from sigstore.sign import SigningContext

ctx = SigningContext.production()
with ctx.signer(identity_token=runner_oidc_token) as signer:
    result = signer.sign_artifact(eval_log_bytes)
    open("results/eval.sig", "wb").write(result.to_bundle().to_json().encode())
```

Provenance via SLSA-style attestation:

```yaml
# eval-provenance.json
predicateType: https://slsa.dev/provenance/v1
predicate:
  buildDefinition:
    buildType: https://example.net/eval/v1
    externalParameters:
      task: cybench_subset
      model: claude-opus-4-7@2026-04-15
      dataset: cybench-2025-Q2@sha256:abc...
      harness: inspect-ai@0.3.42
    internalParameters:
      sandbox_image: cybench-sandbox:1.4.0@sha256:def...
      runner: gh-actions/ubuntu-22.04
  runDetails:
    builder:
      id: https://example.net/runners/eval-runner-7
    metadata:
      invocationId: eval-2026-05-08-001
      startedOn: 2026-05-08T10:00:00Z
      finishedOn: 2026-05-08T10:42:13Z
```

Store the signed log + provenance in a write-once bucket (`s3://example-eval-results` with object lock = governance, retention = 7 years for AI Act conformity).

### Step 5 — Scope eval-runner IAM

The runner needs to: pull the candidate model, write results, post status. It should not be able to: read arbitrary models, write to deployment paths, or read training data.

```hcl
resource "aws_iam_role_policy" "eval_runner" {
  name = "eval-runner"
  role = aws_iam_role.eval_runner.id
  policy = jsonencode({
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = "arn:aws:s3:::eval-models/${var.candidate_model}/*"
      },
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:PutObjectRetention"]
        Resource = "arn:aws:s3:::eval-results/${var.run_id}/*"
      },
      {
        Effect = "Deny"
        Action = ["s3:*"]
        Resource = ["arn:aws:s3:::training-data/*", "arn:aws:s3:::prod-models/*"]
      },
    ]
  })
}
```

Use OIDC federation, not long-lived keys. Token lifetime ≤ run duration + 5 minutes.

### Step 6 — Lock down the scorer

For LLM-as-judge scoring, the judge model itself is part of the trusted base. Pin it explicitly and run it in its own isolated path:

```python
@scorer
def judge_with_pinned_model(question, answer):
    response = judge_client.complete(
        model="claude-opus-4-7@2026-04-15",
        system=read_signed_file("scorer-prompts/v3-signed.txt"),
        messages=[{"role": "user", "content": format_q_a(question, answer)}],
        max_tokens=512,
    )
    return parse_grade(response)
```

Sign the scorer prompt files; verify on load. A subtle insider attack is to tweak the scorer prompt to be more lenient — signing forces the change to leave a git trail.

### Step 7 — Audit and detection

```yaml
audit_signals:
  - sandbox_egress_policy_violations  # alert on >0
  - eval_runs_without_signed_log      # alert on >0
  - dataset_loaded_without_revision_pin
  - candidate_model_attempting_subprocess_outside_sandbox
  - judge_prompt_unsigned
  - eval_result_modified_post_signing
```

The last two are the insider-tampering tripwires; the first four catch external compromise.

## Expected Behaviour

| Signal | Before hardening | After hardening |
|--------|------------------|-----------------|
| `trust_remote_code=True` in eval | Allowed; arbitrary loader code runs | Refused at preflight |
| Agent task escapes via `os.system` | Runs on host | Contained to ephemeral sandbox |
| Eval log altered post-run | Silent | Signature verification fails |
| Runner credentials usable post-run | Yes | OIDC token expired ≤5min after |
| Web access from non-allowlisted FQDN | Allowed | 403 at proxy |
| Score-prompt edit for leniency | No trace | Git diff + signature failure |

```bash
# Verify a signed eval log:
sigstore verify identity \
  --bundle results/eval.sig \
  --cert-identity 'https://github.com/example/eval-runner/.github/workflows/eval.yml@refs/heads/main' \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  results/eval.json
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Strict sandbox network policy | Eliminates exfil | Some web-using tasks need explicit allowlist | Per-task allowlist registry; review quarterly |
| Pinned dataset revisions | Reproducibility + integrity | Dataset updates need re-vet | Monthly review cadence; auto-PR on upstream changes |
| Signed scorer prompts | Tamper-evident | More cumbersome iteration | Use ephemeral signing keys for dev branch |
| OIDC short-lived runner creds | No long-lived secrets to leak | Slight runner setup complexity | Reuse standard CI federation patterns |
| Sandbox CPU/mem limits | Predictable runner cost | Some genuinely heavy tasks need overrides | Per-task budget profile; on-call review for new asks |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Sandbox image bitrot | Container start fails after upstream tag move | Daily preflight `docker run --rm sandbox:tag /bin/true` | Pin by digest; auto-PR on rebuild |
| Egress proxy blocks legit task | Task fails partway, partial scores | Eval log shows 403 on URL | Add to allowlist; rerun; mark previous result invalidated |
| Signing key compromise | Trust boundary collapsed | Cosign rekor log shows signatures from unexpected identity | Revoke key, re-sign all in-flight results, audit Rekor |
| Insider tampering with raw `.eval` | Detected on signature verify | CI post-run verify step | Replay run; investigate writer; rotate runner |
| Judge prompt drift | Subtle metric shifts | Diff alert against signed baseline | Roll back to prior prompt; investigate change author |

## When to Consider a Managed Alternative

- AISI-supported managed Inspect runs and HuggingFace's evaluation services bake in many sandboxing defaults.
- Internal red-team / capability evals at frontier scale (GAIA, METR uplift suites) typically require self-hosted custom infra; the patterns here apply directly.

## Related Articles

- [Model Artifact Pipelines](/articles/kubernetes/model-artifact-pipelines/)
- [Fine-tuning Pipeline Security](/articles/kubernetes/fine-tuning-pipeline-security/)
- [LLM Deployment Security](/articles/ai-landscape/llm-deployment-security/)
- [AI Red Teaming](/articles/kubernetes/ai-red-teaming/)
- [Continuous Red Teaming](/articles/ai-landscape/continuous-red-teaming/)
