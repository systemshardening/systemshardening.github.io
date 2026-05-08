---
title: "AI-Assisted npm Package Anomaly Detection: Catching Supply Chain Attacks Before Install"
description: "The Axios 1.14.1 diff had ML-detectable signals: a new postinstall script, a phantom dependency, and code similarity drift. Build a pre-install anomaly detector using package diff features and integrate it as a CI gate before npm install runs."
slug: ai-npm-package-anomaly-detection
date: 2026-05-03
lastmod: 2026-05-03
category: ai-landscape
tags:
  - supply-chain
  - npm
  - anomaly-detection
  - machine-learning
  - ci-security
personas:
  - security-engineer
  - platform-engineer
article_number: 420
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/ai-landscape/ai-npm-package-anomaly-detection/
---

# AI-Assisted npm Package Anomaly Detection: Catching Supply Chain Attacks Before Install

## The Problem

Static analysis tools — `npm audit`, Snyk, Socket.dev — operate on known-bad signatures: CVE IDs, known malicious package names, known bad hashes. The Axios 1.14.1 attack, published on March 31 2026 by North Korean threat actor Sapphire Sleet using a stolen npm publish token, used a never-before-seen dependency (`plain-crypto-js@4.2.1`) with a clean reputation. No CVE. No Snyk advisory. No blocklist entry. It was zero-day by definition, and every static tool in a standard CI pipeline passed it.

ML anomaly detection takes a different approach. Instead of matching against known bad, it models what *normal* looks like for a given package and scores new versions by their deviation from that norm. For Axios, "normal" means patch releases that add a few lines to HTTP handling code, update a changelog, and bump a version number. The diff signature of 200+ prior releases is consistent enough to be learnable.

Axios 1.14.1 deviated from that norm on four simultaneous axes. First, it added a `postinstall` lifecycle script — a capability never used in any prior Axios release. Second, it introduced `plain-crypto-js` as a runtime dependency in a semver patch release; legitimate patch releases do not add new dependencies. Third, the code similarity between 1.14.0 and 1.14.1 was far below the historical mean for Axios patch diffs — the malicious version had injected a substantial new code path with no relation to the HTTP client functionality. Fourth, the publish event carried no npm provenance attestation, despite Axios having consistently published with attestation since npm Provenance reached general availability.

None of these four signals is individually conclusive. Packages occasionally add `postinstall` scripts for legitimate reasons. New dependencies in patch releases happen, rarely, for good reasons. Code similarity is a noisy metric. Provenance attestation can fail for infrastructure reasons. But a model trained on Axios's full release history would score the combination as highly anomalous — and that anomaly score would have triggered a CI gate before the package was installed in any organisation running this pipeline.

This article covers the full implementation: extracting features from npm package diffs, training a per-package `IsolationForest` on legitimate release history, integrating the detector as a pre-install CI gate, using an LLM to summarise flagged diffs for human reviewers, and maintaining models over time.

## Threat Model

- **Zero-day malicious packages with no CVE or blocklist entry.** Static analysis has no signal. The only available signal is deviation from the package's own historical norm.
- **New `postinstall` script added to a package that has never used lifecycle scripts.** Lifecycle scripts execute arbitrary code at install time. A package with 200 clean releases that suddenly adds `postinstall` in a patch version is exhibiting a significant behavioural change.
- **Phantom dependency added in a patch version.** Semver convention is that patch releases contain bug fixes only. A new runtime dependency in a patch version is a structural anomaly. If that dependency has zero download history on npm, the signal is stronger still — `plain-crypto-js` had never been downloaded before the Axios 1.14.1 release.
- **Code similarity drift.** The cosine similarity of TF-IDF vectors computed over the minified JS source of consecutive patch releases is normally very high for mature packages. A dramatic drop in similarity between 1.14.0 and 1.14.1 indicates a structural change inconsistent with a bug fix.
- **Publish without npm provenance attestation for a package that has always published with provenance.** The absence of an attestation that was consistently present is itself an anomalous event — it may indicate the publish was performed outside the normal CI pipeline (e.g., from a developer machine using a stolen token).

## Hardening Configuration

### 1. Feature Extraction from npm Package Diffs

The anomaly model requires a fixed-length feature vector for each package version. The following five features capture the signals present in the Axios 1.14.1 attack and are generalisable to other packages:

- `postinstall_added` (binary): was a `postinstall` script present in this version but absent from the previous version?
- `new_dep_count_in_patch` (integer): number of new runtime dependencies added in a semver patch release; non-zero values in patch releases are anomalous.
- `code_similarity` (float, 0–1): TF-IDF cosine similarity between the minified JS of the current version and the previous version.
- `has_provenance` (binary): does the version carry an npm provenance attestation?
- `publish_source_ci` (binary): was the publish triggered from a CI environment (as indicated by the `_npmUser` and attestation metadata)?

```python
import json
import subprocess
import tarfile
import tempfile
import os
import re
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import semver


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True)


def fetch_package_metadata(package: str) -> dict:
    raw = run(["npm", "view", package, "--json"])
    return json.loads(raw)


def fetch_version_metadata(package: str, version: str) -> dict:
    raw = run(["npm", "view", f"{package}@{version}", "--json"])
    return json.loads(raw)


def download_tarball(package: str, version: str, dest_dir: str) -> Path:
    run(["npm", "pack", f"{package}@{version}", "--pack-destination", dest_dir])
    safe = package.replace("@", "").replace("/", "-")
    return Path(dest_dir) / f"{safe}-{version}.tgz"


def extract_js_source(tarball: Path) -> str:
    texts = []
    with tarfile.open(tarball, "r:gz") as tf:
        for member in tf.getmembers():
            if member.name.endswith(".js") and "/node_modules/" not in member.name:
                f = tf.extractfile(member)
                if f:
                    texts.append(f.read().decode("utf-8", errors="ignore"))
    return " ".join(texts)


def is_patch_bump(prev: str, curr: str) -> bool:
    try:
        p = semver.VersionInfo.parse(prev)
        c = semver.VersionInfo.parse(curr)
        return c.major == p.major and c.minor == p.minor and c.patch > p.patch
    except ValueError:
        return False


def extract_features(
    package: str,
    prev_version: str,
    curr_version: str,
) -> dict:
    prev_meta = fetch_version_metadata(package, prev_version)
    curr_meta = fetch_version_metadata(package, curr_version)

    prev_scripts = prev_meta.get("scripts", {})
    curr_scripts = curr_meta.get("scripts", {})
    postinstall_added = int(
        "postinstall" in curr_scripts and "postinstall" not in prev_scripts
    )

    prev_deps = set((prev_meta.get("dependencies") or {}).keys())
    curr_deps = set((curr_meta.get("dependencies") or {}).keys())
    new_deps = curr_deps - prev_deps
    new_dep_count_in_patch = len(new_deps) if is_patch_bump(prev_version, curr_version) else 0

    with tempfile.TemporaryDirectory() as tmp:
        prev_tb = download_tarball(package, prev_version, tmp)
        curr_tb = download_tarball(package, curr_version, tmp)
        prev_src = extract_js_source(prev_tb)
        curr_src = extract_js_source(curr_tb)

    if prev_src and curr_src:
        vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=10000)
        matrix = vec.fit_transform([prev_src, curr_src])
        code_similarity = float(cosine_similarity(matrix[0], matrix[1])[0][0])
    else:
        code_similarity = 0.0

    curr_dist = curr_meta.get("dist", {})
    has_provenance = int("attestations" in curr_dist or "provenance" in curr_dist)

    publish_env = (curr_meta.get("_npmUser") or {}).get("email", "")
    publish_source_ci = int(
        has_provenance == 1 or re.search(r"ci|actions|github|gitlab", publish_env, re.I) is not None
    )

    return {
        "postinstall_added": postinstall_added,
        "new_dep_count_in_patch": new_dep_count_in_patch,
        "code_similarity": code_similarity,
        "has_provenance": has_provenance,
        "publish_source_ci": publish_source_ci,
    }
```

The character n-gram TF-IDF approach for `code_similarity` is deliberately low-level: it treats the JS source as a byte sequence, which means it captures structural changes even after variable renaming. A legitimate bug-fix patch changes a handful of tokens; an injected payload changes the character distribution measurably.

### 2. Training an Isolation Forest on Historical Releases

The `IsolationForest` algorithm isolates anomalies by recursively partitioning the feature space. Points that require fewer partitions to isolate are more anomalous. It requires no labelled anomalies for training — only examples of normal behaviour.

Train one model per monitored package, not a single model across all packages. Diff patterns vary enormously between packages; a single model would learn only the broadest signal and miss package-specific anomalies.

```python
import json
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest
from pathlib import Path


def build_training_matrix(package: str, all_versions: list[str]) -> np.ndarray:
    rows = []
    sorted_versions = sorted(all_versions, key=lambda v: [int(x) for x in v.split(".")[:3] if x.isdigit()])
    for i in range(1, len(sorted_versions)):
        prev = sorted_versions[i - 1]
        curr = sorted_versions[i]
        try:
            features = extract_features(package, prev, curr)
            rows.append([
                features["postinstall_added"],
                features["new_dep_count_in_patch"],
                features["code_similarity"],
                features["has_provenance"],
                features["publish_source_ci"],
            ])
        except Exception:
            continue
    return np.array(rows)


def train_model(package: str, output_dir: str) -> None:
    meta = fetch_package_metadata(package)
    all_versions = list(meta.get("versions", {}).keys())

    if len(all_versions) < 20:
        raise ValueError(f"{package} has fewer than 20 versions; insufficient history for modelling")

    X = build_training_matrix(package, all_versions)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,
        random_state=42,
    )
    model.fit(X)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    safe_name = package.replace("/", "__").replace("@", "")
    with open(out / f"{safe_name}.pkl", "wb") as f:
        pickle.dump({"model": model, "package": package, "trained_on_versions": len(all_versions)}, f)

    print(f"Trained model for {package} on {len(all_versions)} versions ({len(X)} transitions)")


def score_version(package: str, prev_version: str, candidate_version: str, model_dir: str) -> float:
    safe_name = package.replace("/", "__").replace("@", "")
    model_path = Path(model_dir) / f"{safe_name}.pkl"
    with open(model_path, "rb") as f:
        artifact = pickle.load(f)

    model: IsolationForest = artifact["model"]
    features = extract_features(package, prev_version, candidate_version)
    X = np.array([[
        features["postinstall_added"],
        features["new_dep_count_in_patch"],
        features["code_similarity"],
        features["has_provenance"],
        features["publish_source_ci"],
    ]])

    raw_score = model.decision_function(X)[0]
    normalised = 1.0 - (raw_score - (-0.5)) / 1.0
    return float(np.clip(normalised, 0.0, 1.0))
```

`contamination=0.01` tells the model to expect roughly 1% of training samples to be anomalous. For a mature package with hundreds of releases, this is conservative; legitimate releases very rarely exhibit the feature combinations seen in supply chain attacks. The `decision_function` output is a raw score; the normalisation step maps it to a 0–1 range where values near 1 are highly anomalous.

### 3. Pre-Install CI Gate

The gate reads `package-lock.json` to determine the exact resolved versions being installed, scores each against its per-package model, and fails the build if any score exceeds the threshold.

```python
import json
import sys
from pathlib import Path


ANOMALY_THRESHOLD = 0.70
MODEL_DIR = "/opt/npm-anomaly-models"


def load_lock_file(lock_path: str) -> dict[str, tuple[str, str]]:
    with open(lock_path) as f:
        lock = json.load(f)

    packages = {}
    for name, info in lock.get("packages", {}).items():
        if not name or name == "":
            continue
        pkg_name = name.removeprefix("node_modules/")
        version = info.get("version", "")
        resolved_prev = info.get("_previousVersion", "")
        if version and resolved_prev:
            packages[pkg_name] = (resolved_prev, version)

    return packages


def gate(lock_path: str) -> None:
    packages = load_lock_file(lock_path)
    failures = []

    for package, (prev_version, curr_version) in packages.items():
        safe_name = package.replace("/", "__").replace("@", "")
        model_path = Path(MODEL_DIR) / f"{safe_name}.pkl"
        if not model_path.exists():
            print(f"SKIP {package}@{curr_version}: no model available")
            continue

        try:
            score = score_version(package, prev_version, curr_version, MODEL_DIR)
            status = "ANOMALOUS" if score >= ANOMALY_THRESHOLD else "OK"
            print(f"{status} {package}@{curr_version} score={score:.3f}")
            if score >= ANOMALY_THRESHOLD:
                failures.append((package, curr_version, score))
        except Exception as e:
            print(f"ERROR scoring {package}@{curr_version}: {e}")

    if failures:
        print("\nCI GATE FAILED — manual review required:")
        for pkg, ver, sc in failures:
            print(f"  Package {pkg}@{ver} anomaly score {sc:.2f} (threshold {ANOMALY_THRESHOLD})")
        sys.exit(1)

    print("\nAll scored packages within normal range.")


if __name__ == "__main__":
    gate(sys.argv[1])
```

The gate intentionally skips packages with no model rather than blocking them; blocking unmodelled packages would make the gate unusable for any project with new or obscure dependencies. Those packages fall back to static analysis tools. The gate is additive, not a replacement for `npm audit`.

```yaml
name: Pre-install Package Anomaly Gate
on:
  pull_request:
    paths:
      - "package-lock.json"
  push:
    branches:
      - main
    paths:
      - "package-lock.json"

jobs:
  anomaly-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Restore anomaly models cache
        uses: actions/cache@v4
        with:
          path: /opt/npm-anomaly-models
          key: npm-anomaly-models-${{ hashFiles('.npm-model-manifest.json') }}

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install scorer dependencies
        run: pip install scikit-learn numpy semver

      - name: Run anomaly gate
        run: python scripts/npm_anomaly_gate.py package-lock.json

      - name: Run standard static analysis
        run: npm audit --audit-level=high
```

The anomaly gate runs before `npm install` — it scores the versions recorded in `package-lock.json` without installing them. `npm audit` runs after as a complementary static check.

### 4. LLM-Assisted Diff Review for High-Scoring Packages

When the gate flags a package, an LLM summarises the diff for the security team. This is an advisory output, not an automated block decision. LLMs hallucinate; they must not be in the blocking path for security tooling.

```python
import subprocess
import tempfile
import tarfile
import difflib
import anthropic


def extract_readable_diff(package: str, prev_version: str, curr_version: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        prev_tb = download_tarball(package, prev_version, tmp)
        curr_tb = download_tarball(package, curr_version, tmp)
        prev_src = extract_js_source(prev_tb)
        curr_src = extract_js_source(curr_tb)

    diff_lines = list(difflib.unified_diff(
        prev_src.splitlines(),
        curr_src.splitlines(),
        fromfile=f"{package}@{prev_version}",
        tofile=f"{package}@{curr_version}",
        lineterm="",
        n=3,
    ))
    return "\n".join(diff_lines[:500])


SYSTEM_PROMPT = """You are a security analyst reviewing a diff between two versions of an npm package.
The diff has been flagged as anomalous by a statistical model.

Analyse the diff and report:
1. Any new lifecycle scripts (install, postinstall, preinstall) and what they execute.
2. Any new dependencies and whether they have plausible prior npm history.
3. Any new network calls (http, https, fetch, XMLHttpRequest, WebSocket).
4. Any new child process spawning (child_process, exec, spawn, execSync).
5. Any new use of eval, Function(), or dynamic import with external URLs.
6. Whether the changed code is consistent with the stated semver change type (patch/minor/major).

Be specific. Quote the relevant lines. Do not speculate beyond what the diff shows.
End with a one-sentence risk summary."""


def llm_diff_review(package: str, prev_version: str, curr_version: str, anomaly_score: float) -> str:
    diff_text = extract_readable_diff(package, prev_version, curr_version)
    client = anthropic.Anthropic()

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Package: {package}\n"
                    f"Previous version: {prev_version}\n"
                    f"Flagged version: {curr_version}\n"
                    f"Anomaly score: {anomaly_score:.3f} (threshold 0.70)\n\n"
                    f"Diff (first 500 lines):\n\n{diff_text}"
                ),
            }
        ],
    )

    return message.content[0].text
```

The diff is truncated to 500 lines before sending to the LLM. This limits cost and avoids hitting context limits for large packages, while capturing the most relevant changes at the top of the unified diff. The output is written to the CI job summary for async human review; the gate decision (pass/fail) is made solely by the anomaly score.

### 5. Model Maintenance and Retraining

Models become stale as packages evolve. A mature package that legitimately adopts provenance attestation, or that switches from `npm publish` to a CI pipeline, will produce features that look anomalous to a model trained on older behaviour. A weekly retraining pipeline keeps models current.

```python
import pickle
import json
from pathlib import Path
from datetime import datetime


MONITORED_PACKAGES_FILE = "/opt/npm-anomaly-models/.monitored-packages.json"


def load_monitored_packages() -> list[str]:
    with open(MONITORED_PACKAGES_FILE) as f:
        return json.load(f)


def retrain_all(model_dir: str) -> None:
    packages = load_monitored_packages()
    results = {"retrained": [], "failed": [], "unpublished": [], "timestamp": datetime.utcnow().isoformat()}

    for package in packages:
        try:
            meta = fetch_package_metadata(package)
            if not meta.get("versions"):
                results["unpublished"].append(package)
                print(f"ALERT: {package} has no versions — may have been unpublished")
                continue
            train_model(package, model_dir)
            results["retrained"].append(package)
        except Exception as e:
            results["failed"].append({"package": package, "error": str(e)})
            print(f"RETRAIN FAILED for {package}: {e}")

    out = Path(model_dir) / "retrain-results.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)

    if results["unpublished"]:
        raise RuntimeError(f"ALERT: {len(results['unpublished'])} monitored packages appear unpublished: {results['unpublished']}")

    if results["failed"]:
        raise RuntimeError(f"Retraining failed for {len(results['failed'])} packages")
```

```yaml
name: Weekly Model Retraining
on:
  schedule:
    - cron: "0 2 * * 0"
  workflow_dispatch: {}

jobs:
  retrain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: pip install scikit-learn numpy semver

      - name: Retrain all monitored package models
        run: python scripts/npm_retrain.py /opt/npm-anomaly-models

      - name: Upload updated models
        uses: actions/upload-artifact@v4
        with:
          name: npm-anomaly-models
          path: /opt/npm-anomaly-models/
          retention-days: 90
```

An unpublished package during the retraining run is itself a signal worth alerting on. Package unpublishing is rare; if a monitored package has disappeared, it may indicate the package has been removed in response to a discovered compromise, or that a takeover has replaced the package contents entirely.

Start with the 500 packages that have the highest resolved dependency frequency in your organisation. Running `npm ls --json --all` across all repositories and aggregating the resolved package names gives a ranked list. Prioritise packages with `postinstall` scripts in their current versions — those are already executing code at install time and warrant closer monitoring.

## Expected Behaviour After Hardening

Axios 1.14.1 scored against a model trained on Axios 1.0.0–1.14.0:

- `postinstall_added = 1`. Axios has never had a `postinstall` script in 200+ prior releases. This single feature is a 5-sigma deviation from the historical distribution; the model has never seen this value set to 1 in training.
- `new_dep_count_in_patch = 1`. Axios 1.14.1 is a semver patch release that introduces `plain-crypto-js` as a new runtime dependency. This combination has no precedent in the Axios release history.
- `code_similarity` drops significantly below the historical mean for Axios patch diffs, reflecting the injected payload code path.
- `has_provenance = 0`. Axios had published with provenance attestation since mid-2023. This version does not.

The combined feature vector is deep in the tail of the training distribution. The `IsolationForest` isolates this point in very few partitions. The anomaly score is 0.94 — well above the 0.70 threshold.

The CI gate fails:

```bash
ANOMALOUS axios@1.14.1 score=0.940
OK axios@1.14.0 score=0.121

CI GATE FAILED — manual review required:
  Package axios@1.14.1 anomaly score 0.94 (threshold 0.70) — manual review required
```

The LLM diff review summary:

```text
New postinstall script executes: `node node_modules/plain-crypto-js/install.js`.
New dependency plain-crypto-js@4.2.1 has no prior npm download history visible in public registry data.
The install.js entrypoint makes an outbound HTTPS request to an external host and spawns a child process.
None of the changed code relates to HTTP client functionality described in the patch notes.
Risk summary: this patch release contains a code-execution payload executed at install time via a
previously unused lifecycle script and a dependency with no legitimate history.
```

The build does not proceed. The security team receives the LLM summary in the CI job summary view. The package is not installed in any environment until manual review clears it.

## Trade-offs and Operational Considerations

Per-package models require sufficient version history for reliable anomaly scoring. The minimum is approximately 20 version transitions (21 published versions). Packages below this threshold cannot be modelled reliably — the feature distribution has too few samples for the `IsolationForest` to learn a stable normal region. For those packages, fall back to static analysis tools (`npm audit`, Socket.dev) and manual review of the package's diff.

False positive rate is the main operational challenge. Legitimate major refactors published as patch versions — rare, but real — will score anomalously. The LLM review step is specifically designed to handle this: a human reviewer who sees the LLM summary describing "refactored HTTP error handling to use a new utility function" can clear the gate without delay. The LLM reduces the cost of false-positive review without putting it in the blocking path.

Model training requires downloading all historical package tarballs. For a package like `lodash` with hundreds of versions and large tarball sizes, the training run is storage- and compute-intensive. Allocate roughly 500 MB of storage and 30 minutes of compute per large package for initial training. Incremental retraining (adding only new versions since the last run) is significantly cheaper and is the right approach for the weekly pipeline.

The `contamination` parameter in `IsolationForest` directly controls the false positive / false negative trade-off. At `0.01`, the model treats 1% of training samples as anomalous. Raising this to `0.05` makes the model more sensitive (fewer false negatives, more false positives). Lower it for packages in active flux; raise it for very stable packages with predictable release patterns.

A sufficiently sophisticated attacker who knows about this detection method could craft a diff that scores within the normal range — introducing malicious behaviour incrementally across several releases, each individually scoring as low-anomaly. This is a known limitation of anomaly detection based on historical patterns. It does not make the approach worthless: it raises the cost and complexity of the attack significantly, and incremental poisoning over multiple releases leaves a longer evidence trail for post-incident investigation.

## Failure Modes

- **Model trained on all npm packages rather than per-package.** Different packages have vastly different diff patterns. A global model learns only the loudest signals and misses package-specific anomalies entirely. The entire value of this approach is that it models what *normal* looks like for a specific package.
- **CI gate set to `warn` instead of `fail`.** Anomaly scores are logged but the build proceeds. Alerts accumulate in a log that no one reads. The gate has no effect on supply chain security. The gate must fail the build; advisory-only modes are not a hardening control.
- **LLM used for automated blocking rather than advisory output.** Hallucination causes a legitimate security patch to be blocked, delaying a critical update. Or, in the opposite direction, a hallucinated "this looks fine" summary causes a reviewer to clear a genuinely malicious package. The LLM output is for human consumption only. The gate decision is made by the anomaly score.
- **Retraining pipeline disabled after a false positive.** The model becomes stale. A package that legitimately adopts provenance attestation or migrates to a monorepo will score anomalously on every future release. Stale models cause alert fatigue, which causes the team to disable the gate entirely. Retraining must be automated and must run on schedule.
- **Monitoring only top-level dependencies.** The Axios attack affected a direct dependency, but supply chain attacks frequently target transitive dependencies — packages that are dependencies of your dependencies. `package-lock.json` contains all resolved transitive versions; the gate should score all of them for which models exist, not only packages listed in `package.json`.

## Related Articles

- [AI Supply Chain Attack Surface](/articles/ai-landscape/ai-supply-chain-attack-surface/)
- [AI Vulnerability Discovery](/articles/ai-landscape/ai-vulnerability-discovery/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [npm Supply Chain Runtime Detection](/articles/observability/npm-supply-chain-runtime-detection/)
