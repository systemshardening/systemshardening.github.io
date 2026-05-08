---
title: "HuggingFace Hub Supply Chain Security"
description: "Protect ML pipelines from malicious model weights, pickle deserialization attacks, and rogue Hub repositories—with guidance on safetensors adoption and tracking silent fixes in the transformers library."
slug: huggingface-model-hub-security
date: 2026-05-02
lastmod: 2026-05-02
category: ai-landscape
tags: ["huggingface", "model-hub", "pickle", "safetensors", "supply-chain", "ml-security", "transformers"]
personas: ["ml-engineer", "security-engineer", "platform-engineer"]
article_number: 348
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/ai-landscape/huggingface-model-hub-security/index.html"
---

# HuggingFace Hub Supply Chain Security

## Problem

HuggingFace Hub is the dominant public repository for ML model weights, datasets, and Spaces. As of 2025 it hosts more than 900,000 models, spanning everything from 80-million-parameter BERT variants to 70-billion-parameter Llama derivatives. The `huggingface_hub` Python library and the `transformers` library are used by virtually every production ML pipeline that loads a pre-trained model — they handle authentication, caching, file integrity, and the mechanics of downloading weights from Hub. When these two libraries are compromised, or when an adversary publishes a malicious model to Hub, the impact reaches every downstream pipeline that calls `from_pretrained()`.

The most acute danger is the pickle serialisation format. PyTorch models have historically been serialised using Python's built-in `pickle` module, producing `.pt`, `.pth`, and `.bin` files. Pickle is not a data format — it is a code execution format. A valid pickle stream can embed arbitrary Python opcodes, and `torch.load()` will faithfully execute them with the full privileges of the loading process. An attacker who publishes a model to Hub with a malicious `.bin` file can achieve remote code execution on every GPU host that loads that model. This is not theoretical: HuggingFace Hub has had malicious models uploaded — the "baller3000" series in 2023 being a documented example — that contained pickle payloads designed to open reverse shells when loaded. Community-flagged models with similar payloads appeared through 2024.

The `transformers` library compounds the pickle surface with a second mechanism: `trust_remote_code=True`. When this flag is set, `AutoModel.from_pretrained("org/model")` does not merely download weight files — it also imports `modeling_*.py` Python files from the model repository and executes them locally. The model repository becomes an arbitrary code delivery channel. A typosquatted model (`bert-base-uncaseed` instead of `bert-base-uncased`) that includes a plausible-looking `modeling_bert.py` with a single exfiltration call at import time can steal secrets from the loading environment without triggering any pickle-specific scanner.

The `transformers` library (`github.com/huggingface/transformers`) has had multiple security-relevant fixes committed without accompanying CVEs. A path traversal vulnerability in the model download cache allowed model archive files with `../` components in their filenames to write outside the designated cache directory — potentially overwriting arbitrary files reachable by the loading process. This was fixed in a commit titled "fix path handling in model download," but no CVE was filed against the `transformers` package at the time. A GitHub Security Advisory (GHSA) was eventually added to the database months after the fix shipped, long after many pipelines had run against the vulnerable version.

The `trust_remote_code=True` warning behaviour itself was patched. In early versions of `transformers`, the warning that remote code would be executed appeared only once per session and could be suppressed entirely by setting an environment variable. A later fix made the warning persistent on each call and added a commit-hash pinning mechanism so that the exact version of `modeling_*.py` executed could be recorded and re-verified. This was merged as a feature PR with no CVE designation, meaning pipelines tracking only CVE feeds missed the security relevance entirely. The `huggingface_hub` package had a separate SSRF vulnerability in its HTTP proxy configuration: a crafted `HF_ENDPOINT` or proxy setting could redirect model download requests to internal endpoints such as the cloud instance metadata service. This was fixed silently in a patch release with no CVE.

The `safetensors` library — the secure alternative to pickle — has not been immune either. Its Rust implementation had a memory-safety bug that could cause out-of-bounds reads on malformed tensor files. The bug was found by a fuzzer and fixed in the `safetensors` 0.4.x line without a CVE. Because `safetensors` is positioned as the safe path away from pickle, teams that migrated to it and then stopped scanning were exposed during the patch gap. The lesson is that no dependency in the ML stack is exempt from security-relevant changes, and the HuggingFace ecosystem has a documented pattern of fixing vulnerabilities without filing CVEs — making passive CVE-feed monitoring insufficient.

Tracking these fixes requires active measures: running `pip-audit` against `transformers` and `huggingface_hub` in CI; subscribing to GitHub Security Advisories for `huggingface/transformers`, `huggingface/huggingface_hub`, and `huggingface/safetensors`; monitoring `https://huggingface.co/security` for Hub-level advisories; and running `picklescan` on every model file before it is promoted into a production pipeline. Target systems: `transformers` >= 4.40, `huggingface_hub` >= 0.23, `safetensors` >= 0.4, Python 3.10+.

## Threat Model

1. **Pickle payload in a Hub model**: A supply chain attacker publishes a model to HuggingFace Hub. The model's `.bin` or `.pth` weight files contain embedded pickle opcodes that spawn a reverse shell when `torch.load()` or `AutoModel.from_pretrained()` executes them. The attacker requires only a free HuggingFace account and the ability to upload files. Detection by Hub's automated scanning is not guaranteed — malicious models have remained on Hub for days before removal.

2. **Typosquatting with `trust_remote_code` exfiltration**: An attacker registers `bert-base-uncaseed` (one extra 'e') on Hub and uploads a model that visually resembles the legitimate `bert-base-uncased` checkpoint. The model's `modeling_bert.py` file contains a top-level import that reads environment variables (`AWS_ACCESS_KEY_ID`, `HUGGING_FACE_HUB_TOKEN`, etc.) and POSTs them to an attacker-controlled endpoint. Any pipeline that calls `AutoModel.from_pretrained("bert-base-uncaseed", trust_remote_code=True)` exfiltrates credentials immediately on import, before any model inference occurs.

3. **Patch-gap attack on path traversal**: An attacker identifies the commit that fixed the `../` path traversal in `huggingface_hub` via its public GitHub history. They craft a malicious model archive in which one of the shard files has a filename such as `../../../.ssh/authorized_keys` or `../../../etc/cron.d/backdoor`. Pipelines running versions of `huggingface_hub` prior to the fix will write the attacker's payload outside the cache directory when the model is downloaded. The attacker's window is the patch-gap period — often weeks or months in ML infrastructure where dependency updates are infrequent and the original fix had no CVE to trigger automated alerts.

4. **Insider `trust_remote_code` pivot**: A developer within the organisation loads a research model with `trust_remote_code=True` without reviewing the model repository's `modeling_*.py` files. The model is legitimate but was uploaded by a researcher who included a debug logging call that hits the cloud metadata service at `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and logs the response. The insider action is unintentional; the model author may not have considered the execution environment. The resulting cloud credential exfiltration is indistinguishable from an external attack.

The blast radius across all four scenarios is determined by the privileges of the process that calls `from_pretrained()`. In a typical ML training pipeline, the loading process has access to training data (often terabytes in S3), model checkpoints from previous runs, database credentials stored in environment variables, and cloud IAM instance roles that may have broad write access to production storage. A single malicious model load can pivot from the GPU host to the entire data platform.

## Configuration / Implementation

### Mandatory Safetensors Adoption

The most impactful single change is requiring safetensors format for all model loads. Safetensors is a header-validated format that stores only raw tensor data — it cannot encode executable Python opcodes.

```python
# BEFORE: loads pickle by default if safetensors not present
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-2-7b-hf")

# AFTER: fails explicitly if no safetensors format is available
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained(
    "meta-llama/Llama-2-7b-hf",
    use_safetensors=True,   # raises ValueError if safetensors not available
)
```

For direct tensor loading outside the `transformers` abstraction:

```python
import safetensors.torch

# Safe: parses only tensor metadata and raw data, no code execution
tensors = safetensors.torch.load_file("/path/to/model/model.safetensors")

# Never do this with untrusted model files:
# import torch
# tensors = torch.load("/path/to/model/pytorch_model.bin")  # executes pickle
```

Set `HF_HUB_DISABLE_IMPLICIT_TOKEN=1` to prevent the Hub client from silently using cached authentication tokens when downloading models, which reduces the attack surface for credential-scoped SSRF:

```bash
export HF_HUB_DISABLE_IMPLICIT_TOKEN=1
```

Verify that a model repository actually provides safetensors before downloading it:

```bash
# List cached models and check for safetensors presence
huggingface-cli scan-cache | grep safetensors

# Check a specific model's available files before downloading
python3 -c "
from huggingface_hub import list_repo_files
files = list(list_repo_files('org/model-name'))
has_safetensors = any(f.endswith('.safetensors') for f in files)
print('safetensors available:', has_safetensors)
print('files:', [f for f in files if f.endswith(('.safetensors', '.bin', '.pt'))])
"
```

### Scanning Model Files Before Loading

`picklescan` statically analyses pickle streams without executing them and will identify embedded opcodes that indicate malicious payloads.

```bash
pip install picklescan

# Scan a downloaded model directory
picklescan -p ./model-dir/

# Exit with non-zero status on any finding (for CI integration)
picklescan --exit-on-error -p /path/to/downloaded/model
```

Integrate picklescan into the model promotion pipeline. Models should be downloaded into a quarantine directory, scanned, and only moved to production storage if the scan is clean:

```bash
#!/usr/bin/env bash
set -euo pipefail

MODEL_ID="$1"
QUARANTINE_DIR="/tmp/model-quarantine/$(echo "$MODEL_ID" | tr '/' '-')"
PROD_CACHE="/mnt/model-store"

# Download to quarantine (isolated from production paths)
huggingface-cli download "$MODEL_ID" --local-dir "$QUARANTINE_DIR"

# Scan for pickle payloads
if ! picklescan --exit-on-error -p "$QUARANTINE_DIR"; then
    echo "SECURITY: picklescan detected malicious payload in $MODEL_ID"
    rm -rf "$QUARANTINE_DIR"
    exit 1
fi

# Promote to production cache only after passing scan
mv "$QUARANTINE_DIR" "$PROD_CACHE/$(echo "$MODEL_ID" | tr '/' '-')"
echo "Model $MODEL_ID promoted to production cache"
```

Run scans inside an isolated Docker container to contain any exfiltration if a model somehow executes during scanning:

```dockerfile
FROM python:3.11-slim
RUN pip install picklescan huggingface_hub
# No credentials mounted, no network after download
ENTRYPOINT ["picklescan", "--exit-on-error", "-p"]
```

```bash
docker run --rm --network none \
  -v /tmp/model-quarantine:/models:ro \
  picklescan-scanner /models
```

### `trust_remote_code` Policy

The `trust_remote_code=True` parameter must be treated as a code deployment mechanism, not a model loading flag. Enforce its absence in production code through linting:

```bash
# Fail CI if trust_remote_code=True appears anywhere in source
grep -r "trust_remote_code=True" src/ && {
    echo "ERROR: trust_remote_code=True detected. See security policy."
    exit 1
}
```

Add this as a pre-commit hook or CI step:

```yaml
# .github/workflows/security.yml
- name: Check for trust_remote_code=True
  run: |
    if grep -r "trust_remote_code=True" src/ --include="*.py"; then
      echo "::error::trust_remote_code=True is banned in production code"
      exit 1
    fi
```

When `trust_remote_code` is genuinely required (e.g., for a model architecture not yet merged into `transformers`), pin to a specific commit hash and document the review:

```python
from transformers import AutoModel

# REQUIRED: pin to exact commit SHA, not a mutable tag or branch
# The commit abc123def was reviewed by @security-reviewer on 2026-04-15
# PR link: https://github.com/org/repo/pull/42
model = AutoModel.from_pretrained(
    "org/custom-architecture-model",
    revision="abc123def456789abc123def456789abc123def4",
    trust_remote_code=True,
)
```

The reviewer must inspect the `modeling_*.py` files at that exact revision for any network calls, file writes, subprocess invocations, or environment variable reads.

### Model Hash Pinning and Verification

Pin model downloads to a specific commit SHA rather than a mutable tag or `main` branch. HuggingFace Hub allows mutable tags — a tag like `v1.0` can be moved to a different commit, changing the model weights silently.

```python
from huggingface_hub import snapshot_download

# Pin to an immutable commit SHA
local_dir = snapshot_download(
    repo_id="meta-llama/Llama-2-7b-hf",
    revision="c1b0db933684edbfe29a06fa47eb19cc48025e93",  # immutable SHA
    local_dir="/mnt/model-store/llama-2-7b",
)
```

Verify the downloaded files against Hub's file-level SHA256 metadata:

```bash
# Download with pinned revision
huggingface-cli download org/model-name \
  --revision c1b0db933684edbfe29a06fa47eb19cc48025e93 \
  --local-dir /tmp/model-download

# Verify safetensors file integrity
sha256sum /tmp/model-download/model.safetensors

# Cross-check against Hub metadata
python3 -c "
from huggingface_hub import get_paths_info
info = list(get_paths_info(
    'org/model-name',
    paths=['model.safetensors'],
    revision='c1b0db933684edbfe29a06fa47eb19cc48025e93',
))
for entry in info:
    print(f'{entry.path}: {entry.lfs.sha256 if entry.lfs else \"no-lfs\"}')
"
```

Store pinned SHAs in a manifest file committed to version control:

```yaml
# model-manifest.yaml
models:
  - id: meta-llama/Llama-2-7b-hf
    revision: c1b0db933684edbfe29a06fa47eb19cc48025e93
    sha256_model_safetensors: "a1b2c3d4e5f6..."
    approved_by: security-team
    approved_date: 2026-04-15
  - id: bert-base-uncased
    revision: 86b5e0934494bd15c9632b12f734a8a67f723594
    sha256_model_safetensors: "f6e5d4c3b2a1..."
    approved_by: security-team
    approved_date: 2026-03-20
```

### Private Model Registry

Route all model loads through an internal registry to prevent direct access to public Hub:

```bash
# Set the HuggingFace Hub endpoint to an internal proxy
export HF_ENDPOINT=https://internal-hub.company.com

# All subsequent from_pretrained() calls use the internal endpoint
python3 -c "
from transformers import AutoTokenizer
# This hits internal-hub.company.com, not huggingface.co
tok = AutoTokenizer.from_pretrained('approved/bert-base-uncased')
"
```

A minimal allowlist proxy using nginx:

```nginx
# nginx.conf for internal HuggingFace proxy
server {
    listen 443 ssl;
    server_name internal-hub.company.com;

    # Only proxy requests for approved model IDs
    location ~ ^/api/models/(approved-org)/(.+)$ {
        proxy_pass https://huggingface.co;
        proxy_set_header Host huggingface.co;
    }

    location ~ ^/(approved-org)/(.+)/resolve/(.+)$ {
        proxy_pass https://huggingface.co;
        proxy_set_header Host huggingface.co;
    }

    # Block all other model paths
    location / {
        return 403 "Model not in approved registry";
    }
}
```

For fully air-gapped environments, host approved models in MinIO with the same directory structure Hub uses:

```bash
# Mirror an approved model to internal MinIO
huggingface-cli download org/model-name \
  --revision <pinned-sha> \
  --local-dir /tmp/model-staging

# Verify with picklescan before mirroring
picklescan --exit-on-error -p /tmp/model-staging

# Upload to internal MinIO
mc cp --recursive /tmp/model-staging/ \
  minio/model-registry/org/model-name/
```

### Monitoring for Silent Fixes

Because the HuggingFace ecosystem has a documented pattern of security-relevant fixes without CVEs, passive monitoring is insufficient. Use all of the following:

```bash
# In CI: audit all ML dependencies for known vulnerabilities
pip-audit --requirement requirements.txt --output json | \
  jq '.dependencies[] | select(.vulns | length > 0)'

# Also run safety for its separate advisory database
safety check -r requirements.txt
```

Subscribe to GitHub Security Advisories programmatically:

```bash
# Check for new advisories on key HuggingFace repos
gh api graphql -f query='
{
  securityAdvisories(first: 10, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
    nodes {
      summary
      publishedAt
      vulnerabilities(first: 5) {
        nodes {
          package { name ecosystem }
          severity
        }
      }
    }
  }
}' | jq '.data.securityAdvisories.nodes[] |
  select(.vulnerabilities.nodes[].package.name |
    test("transformers|huggingface|safetensors"))'
```

Monitor release notes for patch versions of key packages:

```bash
# Check current and latest versions
pip index versions transformers 2>/dev/null | head -5
pip index versions huggingface-hub 2>/dev/null | head -5
pip index versions safetensors 2>/dev/null | head -5

# Pin in requirements.txt with minimum patch versions
# transformers>=4.40.0  # last audited: 4.40.2 (2026-03-01)
# huggingface-hub>=0.23.0
# safetensors>=0.4.3
```

Manual monitoring checklist (run weekly or on any patch release):

- `https://github.com/huggingface/transformers/security/advisories`
- `https://github.com/huggingface/huggingface_hub/releases` — read patch release notes
- `https://github.com/huggingface/safetensors/releases`
- `https://huggingface.co/security`

## Expected Behaviour

| Signal | Default `from_pretrained` | Hardened Pipeline |
|---|---|---|
| Pickle payload in `.bin` weight file | Arbitrary code executes at load time; no warning or error | `picklescan` fails in quarantine; model never reaches production; alert fired |
| Path traversal (`../`) in model archive filename | File written outside cache directory at download time | `huggingface_hub` >= patched version rejects path; model blocked in quarantine regardless |
| `trust_remote_code=True` in calling code | Arbitrary Python from model repo executes silently | CI lint check fails; `trust_remote_code=True` never reaches runtime |
| Safetensors format not available for model | Falls back to pickle `.bin` download silently | `use_safetensors=True` raises `ValueError`; pipeline fails loudly; on-call notified |
| Patch-gap window (unfixed `huggingface_hub` version) | Vulnerable to path traversal during window | `pip-audit` in CI flags version; deployment blocked until updated |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Safetensors-only (`use_safetensors=True`) | Eliminates pickle code-execution surface entirely | Some models — particularly older or research checkpoints — exist only in pickle format and cannot be loaded | Maintain a conversion pipeline: download in isolated environment, convert with `safetensors.torch.save_file()`, re-host on internal registry; or explicitly accept the risk for specific models with documented approvals |
| Private model registry (internal proxy or MinIO mirror) | Prevents direct Hub access; enforces allowlist; survives Hub outages for approved models | Significant operational overhead: storage costs for large models (70B+ models are 100–140 GB), proxy maintenance, mirroring latency when approving new models | Tier the policy: require internal registry only for production inference; allow direct Hub access in sandboxed development environments with egress monitoring |
| Revision pinning (commit SHA instead of tag/branch) | Prevents silent model weight substitution via mutable tags | Blocks automatic updates; teams must manually review and re-pin to pick up fine-tuned improvements or bug fixes in model weights | Automate a weekly PR that proposes updated revision SHAs with a diff of changed files; require security review before merging |
| `picklescan` in CI before model promotion | Detects known malicious pickle opcodes before any execution | Slow for large multi-shard models (scanning 140 GB of `.bin` files can take 10–20 minutes); potential false positives on legitimate models with unusual serialisation | Run picklescan on a content-addressed cache: compute SHA256 of each file and skip re-scanning files with a known-clean SHA; parallelise across shards |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Safetensors not available for required model | Pipeline raises `ValueError: Could not load model ... with any of the following ...` and exits at startup | Immediately visible in application logs; no silent degradation | Check `list_repo_files()` for available formats; if only `.bin` exists, initiate conversion request with model owner or convert internally using the safetensors conversion script; document exception with security team approval if pickle load is unavoidable |
| `picklescan` false positive on legitimate model | CI pipeline blocks a model that has passed other reviews; team pressure to disable scanner | Picklescan output identifies the specific file and opcode that triggered; compare against known-false-positive list | Report false positive upstream to `picklescan` maintainers with the specific file; add the content-addressed SHA to an approved-exception list with written justification; do not disable the scanner globally |
| Revision SHA changed on Hub (mutable tag moved) | SHA stored in `model-manifest.yaml` no longer resolves on Hub; download fails with "revision not found" | `huggingface_hub` raises `RepositoryNotFoundError` or `RevisionNotFoundError` at download time; caught in deployment pipeline | Investigate why the tag moved — this may indicate a compromise of the upstream repository; do not blindly update the SHA; review the new commit's changed files before updating the manifest; consider this a security event if the change was unexplained |
| Private registry unavailable (MinIO/proxy down) | All model loads fail in production; inference services cannot restart; new deployments blocked | Health checks on model-loading services fail; all-zero model response rates; infra alerts on MinIO/proxy availability | Maintain a read-only local disk cache of the last successfully loaded model on each inference host so that restarts do not require a network model fetch; implement circuit-breaker with cached model path fallback; registry availability SLA should be higher than inference service SLA |

## Related Articles

- [AI Model Weight Security](/articles/ai-landscape/ai-model-weight-security/)
- [AI Supply Chain Attack Surface](/articles/ai-landscape/ai-supply-chain-attack-surface/)
- [Model Extraction Prevention](/articles/ai-landscape/model-extraction-prevention/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
