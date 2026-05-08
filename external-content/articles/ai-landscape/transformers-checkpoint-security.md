---
title: "HuggingFace Transformers Checkpoint Security"
description: "Harden ML training pipelines against CVE-2026-1839—unsafe torch.load() in Transformers Trainer._load_rng_state() enabling checkpoint RCE—and the broader unsafe deserialization pattern in ML frameworks."
slug: transformers-checkpoint-security
date: 2026-05-03
lastmod: 2026-05-03
category: ai-landscape
tags: ["transformers", "pytorch", "checkpoint", "cve-2026-1839", "pickle", "rce", "ml-security", "torch-load"]
personas: ["ml-engineer", "security-engineer", "platform-engineer"]
article_number: 380
difficulty: advanced
estimated_reading_time: 16
published: true
layout: article.njk
permalink: "/articles/ai-landscape/transformers-checkpoint-security/index.html"
---

# HuggingFace Transformers Checkpoint Security

## Problem

Training a large neural network is an expensive, long-running process that can span days or weeks on clusters of GPU machines. To protect against hardware failures, preemption, and other interruptions, training frameworks periodically save the complete state of the training run to disk. These **training checkpoints** capture everything needed to resume exactly where training left off: the model's weight tensors, the optimizer's internal state (momentum buffers, adaptive learning rate accumulators), the random number generator state that governs data shuffling and dropout, and metadata such as the current step count and learning rate schedule position. Without checkpoints, a multi-day training run interrupted at hour 47 would have to restart from scratch, wasting significant GPU compute time and cloud spending.

The HuggingFace `transformers` library's `Trainer` class handles checkpoint saving and loading for the majority of transformer model fine-tuning workflows in industry and research. `Trainer` is the entry point that many ML engineers reach for when fine-tuning a GPT, BERT, T5, or Llama model on a custom dataset. Because `Trainer` abstracts away the complexity of distributed training, gradient accumulation, and mixed-precision training, it also abstracts away many implementation details — including how checkpoint files are read from disk.

**CVE-2026-1839 (disclosed April 7, 2026)** is an unsafe deserialization vulnerability in the HuggingFace `Trainer` class, specifically in the `_load_rng_state()` method at line 3059 of `src/transformers/trainer.py`. This method loads the random number generator state from a checkpoint directory using `torch.load(rng_file)` — without the `weights_only=True` parameter. `torch.load()` without `weights_only=True` delegates deserialization to Python's pickle module. Pickle can execute arbitrary Python code during deserialization: any Python object's `__reduce__` method is called as part of the unpickling process, and a crafted pickle payload can embed operating system commands, network calls, or file operations. An attacker who can place a malicious `.pkl` file at the path that `_load_rng_state()` reads achieves remote code execution in the context of the training process. Training processes typically run with GPU access, cloud credentials in environment variables (`AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`), and broad read access to the filesystem containing datasets and model weights. CVE-2026-1839 affects all Transformers versions supporting `torch>=2.2` with `PyTorch<2.6`. The fix was committed to the Transformers repository before the CVE was publicly published, and the patched version is Transformers v5.0.0rc3.

The `weights_only=True` migration is a multi-year effort across the PyTorch ecosystem. PyTorch 2.0 introduced `weights_only=True` as a safe deserialization mode that restricts `torch.load()` to loading only tensors, primitive scalars, and a small allowlist of safe types — completely rejecting arbitrary Python objects that could contain malicious `__reduce__` implementations. PyTorch 2.6 deprecated `weights_only=False` as the default, emitting a `FutureWarning` on every unsafe `torch.load()` call. The Transformers library has been progressively migrating its `torch.load()` calls to use `weights_only=True`, but the migration has been incremental and inconsistent. CVE-2026-1839 is the most recently patched instance, but auditing the Transformers codebase with `grep -r "torch.load(" src/transformers/ | grep -v "weights_only=True"` reveals additional call sites that may not yet have been updated. Third-party training libraries built on top of Transformers frequently import and re-use patterns from the Transformers source code, spreading the same unsafe pattern further.

Checkpoint files are distributed through several channels, each with its own attack surface. On-premises training infrastructure commonly uses shared NFS volumes or distributed filesystems where checkpoint files accumulate from many training runs. A user with write access to the NFS mount can replace a legitimate RNG state file with a malicious pickle payload. On cloud infrastructure, checkpoints are frequently stored in S3 buckets or GCS buckets that are shared across the ML team. Misconfigured bucket policies or overly permissive IAM roles — common in organizations that prioritize iteration speed over security — allow any authenticated team member to overwrite checkpoint files. A third vector is the HuggingFace Hub itself: Hub model repositories store model weights, configuration files, and training checkpoints (including `trainer_state.json` and RNG state files) in the same repository. An attacker who compromises a Hub account that has write access to a popular fine-tuned model repository can inject a malicious checkpoint file alongside legitimate weights. Finally, checkpoint downloads over HTTP (rather than HTTPS) or from URLs that are not pinned to a specific content hash are susceptible to man-in-the-middle substitution of the checkpoint payload.

**The open source transparency angle of CVE-2026-1839 is particularly instructive.** The vulnerability was discovered by an external security researcher and disclosed via the GitLab Advisory Database at `advisories.gitlab.com/pkg/pypi/transformers/CVE-2026-1839/`. The fix — changing `torch.load(rng_file)` to `torch.load(rng_file, weights_only=True)` in `trainer.py` — is a single-line change in the public HuggingFace Transformers repository. The commit appeared in the repository before the CVE was formally published. Any developer following the `src/transformers/trainer.py` diff on GitHub could identify the exact vulnerable pattern from the commit message or the unified diff. The Transformers codebase has had multiple similar fixes over 2024–2026 as the library systematically migrated toward `weights_only=True`; this migration history is fully visible in the commit log and serves as a roadmap for finding any remaining unsafe call sites. The pattern repeats in the broader ecosystem: `weights_only` was available since PyTorch 1.13 but was not consistently adopted, and every library that copied `torch.load()` patterns from pre-migration source code carries the same risk.

Monitoring for this class of vulnerability requires three parallel approaches: running `pip-audit` against your requirements to detect known CVEs including CVE-2026-1839; performing a local audit of the installed Transformers library for unsafe `torch.load()` calls; and subscribing to `https://github.com/huggingface/transformers/security/advisories` for direct notification of new security advisories. The combination catches both known CVEs and novel instances of the same underlying pattern before they are formally assigned a CVE number.

**Target systems:** `transformers` < v5.0.0rc3, `torch` < 2.6 (with default unsafe `torch.load()`), ML training infrastructure using HuggingFace Trainer.

## Threat Model

1. **CVE-2026-1839 — shared checkpoint volume**: A distributed training job saves periodic checkpoints to a shared NFS volume accessible to multiple users. An attacker with write access to the volume directory monitors for new checkpoint directories and replaces the RNG state file (e.g., `rng_state_0.pth`) with a crafted pickle payload that, on execution, exfiltrates `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from the environment, copies model weight files to an external server, and then restores the legitimate RNG state so training continues without visible disruption. When the training job resumes from checkpoint and `Trainer._load_rng_state()` calls `torch.load(rng_file)`, the payload executes with the GPU machine's full credentials. On modern multi-GPU training nodes, this means the attacker gains access to high-memory GPU instances that may be processing proprietary datasets.

2. **Model repository checkpoint poisoning**: An attacker who has obtained write access to a popular HuggingFace Hub model repository — through a phishing attack on the repository owner, a compromised API token left in a public CI configuration, or a compromised organization member account — uploads a malicious RNG state file (`rng_state.pth`) alongside legitimate model weights in a `checkpoint-1000/` subdirectory. The malicious file is indistinguishable from a legitimate checkpoint file without content inspection. When an ML engineer runs `trainer.train(resume_from_checkpoint="./checkpoint-1000")` after downloading the repository, the pickle payload executes during `_load_rng_state()`, exfiltrating the engineer's local `~/.huggingface/token`, `~/.aws/credentials`, and any API keys present in the shell environment.

3. **Remaining unsafe `torch.load()` calls in the Transformers codebase**: CVE-2026-1839 patches the specific instance in `_load_rng_state()`, but the same underlying pattern — `torch.load()` without `weights_only=True` — may exist elsewhere in the codebase. A security researcher systematically audits the installed Transformers package using `grep -r "torch.load(" | grep -v "weights_only"` and identifies an additional unsafe call in a callback class or dataset caching function. This becomes a new CVE, and the cycle repeats. Downstream training libraries that have copied or wrapped Transformers' checkpoint-loading logic may also contain the same pattern without applying the upstream fix.

4. **Distributed training checkpoint poisoning**: In multi-node training using `torchrun` or DeepSpeed, each worker node independently loads its own shard of the checkpoint. RNG state files are written and read per-rank (e.g., `rng_state_0.pth`, `rng_state_1.pth`, ..., `rng_state_N.pth`). A malicious checkpoint targeting any single rank's RNG state file executes code on that GPU node. Because all nodes share the same training environment — the same mounted volumes, the same injected cloud credentials via Kubernetes secrets or EC2 instance metadata, and the same network access — compromising a single rank provides equivalent access to compromising the head node. In a 64-GPU training job, there are 64 independent RNG state files, any of which is an entry point.

The blast radius of a checkpoint RCE is substantially larger than most application-level code execution vulnerabilities. Training processes run on nodes with high-memory GPUs, direct access to the full training dataset, cloud credential access via IAM roles or injected secrets, network access to the organization's model registry and artifact store, and often elevated privileges on the host node to support GPU drivers. Exfiltration of a proprietary fine-tuned model, the training dataset, and cloud credentials represents both immediate financial loss and long-term competitive harm. In regulated industries — healthcare AI, financial services — the exfiltrated training data may itself be the primary liability.

## Configuration / Implementation

### Upgrading Transformers and PyTorch

The first and most important remediation is upgrading to a version of Transformers that contains the CVE-2026-1839 fix:

```bash
pip install "transformers>=5.0.0rc3" "torch>=2.6"
```

Verify the installed versions and confirm CVE-2026-1839 is resolved:

```bash
python -c "import transformers; print('transformers:', transformers.__version__)"
python -c "import torch; print('torch:', torch.__version__)"

# Audit installed packages for known CVEs
pip install pip-audit
pip-audit --requirement requirements.txt

# Or audit the current environment directly
pip-audit
```

`pip-audit` queries the OSV database and will flag CVE-2026-1839 if the unpatched Transformers version is installed. Incorporate `pip-audit` as a mandatory step in your CI pipeline, running on every pull request that modifies `requirements.txt` or `pyproject.toml`.

If you cannot upgrade immediately (due to downstream compatibility constraints), apply a targeted monkey-patch as a temporary measure:

```python
# apply_torch_load_patch.py — temporary CVE-2026-1839 mitigation
# Apply before importing transformers in your training script
import torch
import functools

_original_load = torch.load

@functools.wraps(_original_load)
def safe_torch_load(f, map_location=None, pickle_module=None, *,
                    weights_only=True, **kwargs):
    # Force weights_only=True unless the caller explicitly opts out
    return _original_load(f, map_location=map_location,
                          pickle_module=pickle_module,
                          weights_only=weights_only, **kwargs)

torch.load = safe_torch_load
```

Apply this patch with caution: it will break any legitimate code that relies on loading non-tensor Python objects via `torch.load()`, and it is not a substitute for upgrading.

### Auditing Remaining Unsafe `torch.load()` Calls

After upgrading, audit the installed Transformers library for any `torch.load()` calls that do not pass `weights_only=True`:

```bash
# Find the transformers package directory
TRANSFORMERS_DIR=$(python -c "import transformers, os; print(os.path.dirname(transformers.__file__))")

# Scan for unsafe torch.load calls (excluding comments and already-safe calls)
grep -rn "torch\.load(" "$TRANSFORMERS_DIR" \
  | grep -v "weights_only=True" \
  | grep -v "^\s*#" \
  | grep -v "\.pyc:"
```

Add this as a CI lint step for your own training code:

```bash
# In .github/workflows/security-lint.yml or similar
grep -rn "torch\.load(" src/ \
  | grep -v "weights_only=True" \
  | grep -v "^\s*#" \
  && echo "FAIL: unsafe torch.load() calls found" && exit 1 \
  || echo "OK: all torch.load() calls use weights_only=True"
```

Use `semgrep` for a more robust static analysis check that understands Python syntax rather than simple grep patterns:

```yaml
# semgrep-rules/torch-unsafe-load.yaml
rules:
  - id: torch-load-missing-weights-only
    patterns:
      - pattern: torch.load(...)
      - pattern-not: torch.load(..., weights_only=True, ...)
      - pattern-not: torch.load(..., weights_only=$VAR, ...)
    message: |
      torch.load() called without weights_only=True. This uses pickle
      deserialization and can execute arbitrary code when loading untrusted
      checkpoint files. Pass weights_only=True or use safetensors instead.
      See CVE-2026-1839.
    languages: [python]
    severity: ERROR
    metadata:
      cve: CVE-2026-1839
      category: security
```

Run with:

```bash
semgrep --config semgrep-rules/torch-unsafe-load.yaml src/
```

### Checkpoint File Access Control

Restrict write access to checkpoint directories to only the specific training job's identity:

**S3 bucket policy (restrict checkpoint writes to a specific IAM role):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowTrainingJobCheckpointWrite",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/training-job-role"
      },
      "Action": ["s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::ml-checkpoints/jobs/${aws:PrincipalTag/JobId}/*"
    },
    {
      "Sid": "DenyCheckpointWriteFromOtherPrincipals",
      "Effect": "Deny",
      "NotPrincipal": {
        "AWS": [
          "arn:aws:iam::123456789012:role/training-job-role",
          "arn:aws:iam::123456789012:role/admin-role"
        ]
      },
      "Action": ["s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::ml-checkpoints/*"
    }
  ]
}
```

Verify checkpoint integrity before loading by maintaining a signed manifest:

```python
import hashlib
import json
import pathlib

def verify_checkpoint_integrity(checkpoint_dir: str, manifest_path: str) -> bool:
    """
    Verify checkpoint files against a SHA-256 manifest before loading.
    The manifest should be written by the training job and stored separately
    from the checkpoint directory (e.g., in a different S3 prefix with
    write access only for the training pipeline, not the resuming job).
    """
    checkpoint_dir = pathlib.Path(checkpoint_dir)
    with open(manifest_path) as f:
        manifest = json.load(f)

    for filename, expected_hash in manifest["files"].items():
        file_path = checkpoint_dir / filename
        if not file_path.exists():
            print(f"MISSING: {filename}")
            return False
        actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            print(f"HASH MISMATCH: {filename}")
            print(f"  expected: {expected_hash}")
            print(f"  actual:   {actual_hash}")
            return False

    print("Checkpoint integrity verified.")
    return True


def generate_checkpoint_manifest(checkpoint_dir: str, manifest_path: str) -> None:
    """Call this immediately after saving a checkpoint to record expected hashes."""
    checkpoint_dir = pathlib.Path(checkpoint_dir)
    manifest = {"files": {}}
    for file_path in sorted(checkpoint_dir.rglob("*.pth")):
        relative = file_path.relative_to(checkpoint_dir)
        manifest["files"][str(relative)] = hashlib.sha256(
            file_path.read_bytes()
        ).hexdigest()
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
```

### Checkpoint Source Allowlisting

Validate the checkpoint path before passing it to `Trainer`:

```python
import os
import pathlib
from typing import Optional

APPROVED_CHECKPOINT_PREFIXES = [
    "/mnt/ml-storage/checkpoints/",
    "/home/training/checkpoints/",
    "s3://my-org-ml-checkpoints/",
]

def validate_checkpoint_path(path: Optional[str]) -> Optional[str]:
    """
    Validate that a checkpoint path is within an approved prefix.
    Raises ValueError if the path is not approved.
    """
    if path is None:
        return None

    # Resolve symlinks and relative components for local paths
    if not path.startswith("s3://") and not path.startswith("gs://"):
        resolved = str(pathlib.Path(path).resolve())
    else:
        resolved = path

    for approved_prefix in APPROVED_CHECKPOINT_PREFIXES:
        if resolved.startswith(approved_prefix):
            return path

    raise ValueError(
        f"Checkpoint path '{path}' is not in an approved prefix. "
        f"Approved prefixes: {APPROVED_CHECKPOINT_PREFIXES}"
    )


# Usage:
from transformers import Trainer, TrainingArguments

checkpoint_path = os.environ.get("RESUME_FROM_CHECKPOINT")
validated_path = validate_checkpoint_path(checkpoint_path)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
)
trainer.train(resume_from_checkpoint=validated_path)
```

### Replacing `torch.load()` with safetensors for Model State

The `safetensors` library provides a safe serialization format for tensor data that does not use pickle. It should be the default format for all model weight serialization:

```python
from transformers import TrainingArguments

# Enable safetensors for model weight saving
training_args = TrainingArguments(
    output_dir="./checkpoints",
    save_safetensors=True,        # Save model weights as .safetensors instead of .bin
    # ... other training args
)
```

For RNG state, which `safetensors` cannot represent (it is a Python dict of framework-specific objects, not a tensor), the only safe option after upgrading Transformers is the patched `torch.load(rng_file, weights_only=True)`. Confirm the patched behavior is in effect:

```python
import torch
import inspect
import transformers.trainer as trainer_module

# Verify the patched _load_rng_state uses weights_only=True
source = inspect.getsource(trainer_module.Trainer._load_rng_state)
if "weights_only=True" not in source:
    raise RuntimeError(
        "Trainer._load_rng_state() does not use weights_only=True. "
        "Check that transformers>=5.0.0rc3 is installed."
    )
print("Checkpoint: _load_rng_state uses weights_only=True")
```

### Isolated Training Environment

Run training jobs in containers with restricted network egress and read-only checkpoint mounts:

```yaml
# kubernetes/training-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: training-job
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        readOnlyRootFilesystem: true
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: trainer
          image: my-registry/trainer:5.0.0rc3
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            - name: HF_HUB_OFFLINE
              value: "1"          # Prevent checkpoint downloads from Hub during training
          volumeMounts:
            - name: checkpoint-input
              mountPath: /mnt/checkpoints/input
              readOnly: true      # Read-only mount for source checkpoints
            - name: checkpoint-output
              mountPath: /mnt/checkpoints/output
              readOnly: false     # Separate write mount for new checkpoints
            - name: tmp-dir
              mountPath: /tmp
      volumes:
        - name: checkpoint-input
          persistentVolumeClaim:
            claimName: checkpoint-input-pvc
        - name: checkpoint-output
          persistentVolumeClaim:
            claimName: checkpoint-output-pvc
        - name: tmp-dir
          emptyDir: {}
      restartPolicy: Never
```

Set `HF_HUB_OFFLINE=1` to prevent the training job from reaching out to the HuggingFace Hub during training, eliminating the hub-based checkpoint injection vector.

### Monitoring Transformers for Unsafe `torch.load()` Fixes

Subscribe to security advisories and monitor for commits that fix torch.load patterns:

```bash
# Monitor Transformers commits for torch.load-related changes
gh api repos/huggingface/transformers/commits \
  --jq '.[] | select(.commit.message | test("torch\\.load|weights_only|pickle|security|checkpoint|CVE"; "i")) | {sha: .sha[0:8], msg: .commit.message, date: .commit.author.date}' \
  | head -20

# Check pip-audit in CI (add to .github/workflows/security.yml)
# - name: Audit Python dependencies
#   run: pip-audit --requirement requirements.txt --format json | tee pip-audit.json
#   continue-on-error: false
```

Subscribe to the HuggingFace Transformers GitHub security advisories page at `https://github.com/huggingface/transformers/security/advisories` using the "Watch" -> "Security alerts" option. Create a Dependabot configuration to receive automated PRs when a new patched version is released:

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    allow:
      - dependency-name: "transformers"
      - dependency-name: "torch"
    ignore: []
```

## Expected Behaviour

| Signal | Unpatched Transformers + unsafe load | Patched + access controls |
|--------|--------------------------------------|--------------------------|
| Malicious RNG checkpoint placed in checkpoint directory | `torch.load(rng_file)` deserializes pickle payload; attacker code executes silently during training resume; training continues after payload execution | `torch.load(rng_file, weights_only=True)` raises `pickle.UnpicklingError`; training job fails fast; no attacker code runs; error is logged and alerted |
| NFS checkpoint directory written to by untrusted process | Write succeeds silently; malicious file is indistinguishable from legitimate checkpoint | NFS ACL or S3 bucket policy denies write; `PermissionError` recorded in storage audit log; security team alerted via CloudTrail event |
| `torch.load()` without `weights_only` detected by audit | `grep` or `semgrep` scan finds the call site; PR with fix can be raised | CI lint step (`grep -v "weights_only=True"`) fails pipeline; developer receives immediate feedback before merge |
| Checkpoint loaded from unapproved path (e.g., user-supplied URL) | `Trainer(resume_from_checkpoint=untrusted_path)` loads without validation | `validate_checkpoint_path()` raises `ValueError` before `Trainer` is constructed; path is logged; no deserialization occurs |
| `pip-audit` run against requirements | CVE-2026-1839 flagged as HIGH severity against `transformers<5.0.0rc3` | `pip-audit` exits clean; no CVEs matching installed versions |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `weights_only=True` in `torch.load()` | Eliminates pickle RCE attack surface for checkpoint loading; CVE-2026-1839 and similar CVEs are fully mitigated | Breaks loading of legacy checkpoint files that contain non-tensor Python objects (custom callback state, non-standard optimizer state); raises `TypeError` or `UnpicklingError` on load | Audit existing checkpoints before upgrading; convert legacy checkpoints to safe formats; for unavoidable non-tensor state, use explicit `pickle.loads()` with strict allowlisting in a sandboxed subprocess |
| Checkpoint access control (S3 bucket policies, NFS ACLs) | Prevents unauthorized writes to checkpoint directories; eliminates the shared-volume poisoning vector | Adds friction to multi-team workflows where teams share pre-trained checkpoints; each team needs its own checkpoint storage or explicit cross-account access grants | Implement a checkpoint registry service that handles cross-team sharing with access logging; use S3 presigned URLs with short TTLs for cross-team checkpoint access |
| Isolated training containers (`HF_HUB_OFFLINE=1`, no egress) | Eliminates Hub-based checkpoint injection and MITM checkpoint substitution during training | Breaks workflows that fetch datasets, tokenizer configs, or model configs from the Hub at training time; requires pre-staging all dependencies | Pre-download all required files to the container image or a mounted volume before training starts; use `huggingface-cli download` in a separate preparation step with network access |
| safetensors for checkpoint model weights | Safe serialization for model weight tensors; no pickle involved; much faster load times for large models | Not yet fully supported for all training state (optimizer state in some configurations, RNG state inherently requires pickle); `save_safetensors=True` only covers model weights, not the full checkpoint | Use safetensors for model weights (the highest-value target); accept the residual pickle risk for RNG state after upgrading to patched Transformers where `weights_only=True` is enforced |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|---------|
| `weights_only=True` rejects valid optimizer state from a legacy checkpoint format | `trainer.train(resume_from_checkpoint=...)` raises `TypeError: Unsupported global: GLOBAL torch.optim...` or `UnpicklingError`; training cannot resume | Error message references the checkpoint file path and the offending class name; appears immediately on resume attempt | Convert the legacy checkpoint: load it in an isolated environment with `weights_only=False` on the unpatched version, extract the state dict, re-save using a compatible format; or restart training from a more recent checkpoint |
| Checkpoint access control blocks legitimate resume from a previous run | Training job fails with `PermissionError` or S3 `AccessDenied` when attempting to read an existing checkpoint saved by a different IAM role or under a different job identity | S3 access logs show `403 AccessDenied`; training log shows checkpoint directory enumeration failure | Update the S3 bucket policy or NFS ACL to grant read access to the new job's identity; use a consistent IAM role for all training jobs in the same project; document the required permissions in the training job runbook |
| semgrep rule produces false positives on already-patched torch.load calls | CI fails on code that correctly uses `weights_only=True` because the pattern matcher hits a comment, a docstring example, or a dynamically constructed call | Review the semgrep output: if flagged lines contain `weights_only=True` or are in comments, it is a false positive | Refine the semgrep rule to use `pattern-not` for the specific false positive pattern; add `# nosemgrep: torch-load-missing-weights-only` to suppress individual confirmed-safe lines |
| safetensors does not support RNG state; fallback to pickle still needed | Training cannot save or restore RNG state for deterministic resumption; shuffle order is non-deterministic after resume; model training is not fully reproducible | Explicit error or warning from `safetensors` when attempting to serialize non-tensor types; or silent failure to restore RNG state causing training divergence after resume | Accept pickle for RNG state only, but ensure the Transformers version is patched (>=5.0.0rc3) so that `torch.load(..., weights_only=True)` is used; restrict RNG state file write access strictly to the training job; monitor for Transformers releases that provide a non-pickle RNG state serialization path |

## Related Articles

- [HuggingFace Model Hub Security](/articles/ai-landscape/huggingface-model-hub-security/)
- [AI Model Weight Security](/articles/ai-landscape/ai-model-weight-security/)
- [LangChain Serialization Security](/articles/ai-landscape/langchain-serialization-security/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [Vulnerability Management Program](/articles/cross-cutting/vulnerability-management-program/)
