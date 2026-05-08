---
title: "CI/CD Cache Poisoning Defence Across Actions, Bazel, Nx, and Turbo"
description: "Hardening shared CI build caches against poisoning: scope keys, signed cache entries, branch-isolated namespaces, and detection for replay and tampering."
slug: "cicd-cache-poisoning-defence"
date: 2026-05-08
lastmod: 2026-05-08
category: "cicd"
tags: ["cache-poisoning", "github-actions", "bazel", "nx", "turbo", "ci"]
personas: ["security-engineer", "platform-engineer", "devops-engineer"]
article_number: 652
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/cicd/cicd-cache-poisoning-defence/index.html"
---

# CI/CD Cache Poisoning Defence Across Actions, Bazel, Nx, and Turbo

## Problem

Modern CI pipelines depend on shared build caches: GitHub Actions Cache, Bazel remote cache, Nx Cloud, Turborepo Remote Cache, sccache, ccache, BuildKit cache mounts, and the Gradle build cache. They turn 30-minute builds into 30-second ones. They also share a structural weakness: a malicious cache write from a low-trust branch becomes a trusted read on the default branch.

The classic exploit is straightforward. An attacker (a fork-PR contributor, a compromised dev with write to a feature branch, or a third-party action with cache-write privileges) computes the cache key that `main`'s next build will compute — usually deterministic from `package-lock.json`, `Cargo.lock`, or source hashes — and writes a poisoned artefact at that key from their feature branch. When `main` runs next, it reads the cache, executes the artefact, and the attacker has code execution in the trusted-branch context where deploy credentials live.

GitHub published the canonical pattern in 2023 (`actions/cache`'s scope-by-branch fix), but in 2025 the industry has not generalised the lesson. Bazel remote caches frequently allow any builder to write any object as long as the action hash matches — there is no signer identity. Turbo's Remote Cache uses a team-scoped token by default; any branch with the token can poison the cache for all branches. Nx Cloud has improved with read-only access tokens, but most installs still use a single read/write token. sccache + S3 backends often have no per-branch separation at all.

Several real incidents in 2024–2025 followed the pattern: poisoning Bazel `@bazel_tools` artefacts via a compromised contributor branch, resulting in `main`-build code-exec; tampering with Nx Cloud-cached test outputs to make `npm test` falsely pass on a malicious dependency PR; corrupting BuildKit cache-from layers to inject a curl-pipe command into a Dockerfile RUN step that was deemed unchanged. None required a 0-day; all exploited the trust model of "the cache key matched, so the artefact is fine".

The defence has four parts that compose: (1) namespace caches by trust level, (2) authenticate cache writes per-identity not per-team, (3) sign cache entries cryptographically, (4) detect anomalous reads/writes. Most teams do (1) partially, ignore (2) and (3), and have no detection for (4).

Target systems: GitHub Actions cache v4+, Bazel remote-cache (REAPI v2 / BuildBuddy / Buildbarn), Nx Cloud, Turborepo Remote Cache, sccache ≥ 0.7 with S3/GCS backends, BuildKit ≥ v0.13 with registry/inline cache.

## Threat Model

1. **Fork-PR or feature-branch contributor poisoning the default-branch cache.** Goal: trigger code execution during `main`'s next build. Surface: shared cache namespace; predictable keys.
2. **Compromised CI runner with cache-write token.** Goal: inject malicious artefact, persist across pipeline runs. Surface: token is broad (read+write, all branches); single-use.
3. **Malicious dependency masquerading as cache hit.** Goal: avoid build-from-source step that would otherwise trip security scanners. Surface: cache lookup precedes verification.
4. **Insider modifying cache directly via cloud console.** Goal: introduce backdoor without leaving git trail. Surface: cache backend (S3, GCS, NFS) lacks audit logging or per-object integrity check.

Without defence, any of these turns into one or more `main`-branch RCEs that are extremely hard to trace because the malicious code never appears in source control. With namespacing + signing + detection, the attacker either needs valid signing identity (escalation, not poisoning) or leaves a clear audit trail.

## Configuration / Implementation

### Step 1 — Scope by branch trust on GitHub Actions cache

GitHub Actions cache v4 already isolates cache access between branches by default — *except* that any branch can read from `main`. The risk vector is actually feature branches *writing* to the same key namespace and `main` reading. Mitigation:

```yaml
- name: Restore cache (read-only on default branch)
  uses: actions/cache/restore@v4
  with:
    path: ~/.cache/build
    key: build-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}

- name: Build
  run: cargo build --release

- name: Save cache (only on default branch)
  if: github.ref == 'refs/heads/main' && github.event_name == 'push'
  uses: actions/cache/save@v4
  with:
    path: ~/.cache/build
    key: build-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}
```

Feature branches read but never write the production-shared key. They can still benefit from cache via their own scoped keys (`build-${{ runner.os }}-${{ github.ref_name }}-${{ hashFiles(...) }}`) which are isolated by GitHub's branch scope.

### Step 2 — Bazel: authenticated per-identity remote cache

BuildBuddy and Buildbarn both support OIDC authentication. Configure per-build identity:

```bash
# .bazelrc
build --remote_cache=grpcs://cache.example.net
build --remote_upload_local_results=true
build --remote_header=x-buildbuddy-api-key=
build --google_default_credentials                # OIDC from CI runner identity

# Trust-tier separation
build:trusted    --remote_instance_name=trusted
build:untrusted  --remote_instance_name=untrusted
build:untrusted  --remote_upload_local_results=false   # never write
```

In CI, select the tier from branch context:

```yaml
- name: Set Bazel tier
  run: |
    if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
      echo "BAZEL_CONFIG=--config=trusted" >> $GITHUB_ENV
    else
      echo "BAZEL_CONFIG=--config=untrusted" >> $GITHUB_ENV
    fi
- run: bazel ${{ env.BAZEL_CONFIG }} build //...
```

The `untrusted` instance shares no objects with `trusted`; PR builds get cache speedup from prior PR builds but cannot poison `main`.

### Step 3 — Sign cache entries

For caches that support custom metadata, attach an HMAC over the action hash + content hash. With `sccache`:

```toml
# ~/.config/sccache/config
[cache.s3]
bucket = "ci-sccache"
endpoint = "s3.amazonaws.com"
key_prefix = "v1/"
server_side_encryption = true

[cache.s3.no_credentials]
no_credentials = false
```

Then wrap puts/gets with a small proxy that signs:

```python
# cache-proxy.py — runs inside the runner
import hashlib, hmac, json, os, sys
KEY = os.environ["CACHE_SIGNING_KEY"].encode()

def sign(content_hash: str, action_hash: str) -> str:
    return hmac.new(KEY, f"{action_hash}:{content_hash}".encode(),
                    hashlib.sha256).hexdigest()
```

Store the signature in object metadata; verify on read. For Bazel REAPI, the BuildBuddy `--remote_signed_url_expiration` and a sidecar verifier achieve the same end.

### Step 4 — Turborepo: read-only tokens for untrusted contexts

Turbo supports `TURBO_TEAM` + `TURBO_TOKEN` plus a separate `TURBO_REMOTE_CACHE_SIGNATURE_KEY`. Use signature mode and split tokens:

```yaml
env:
  TURBO_TOKEN: ${{ secrets.TURBO_READ_TOKEN }}      # read-only on PRs
  TURBO_REMOTE_CACHE_SIGNATURE_KEY: ${{ secrets.TURBO_SIG }}

# On main only:
- if: github.ref == 'refs/heads/main'
  env:
    TURBO_TOKEN: ${{ secrets.TURBO_WRITE_TOKEN }}
  run: pnpm turbo build
```

The signature key forces Turbo to verify that a cache hit was produced by a build that knew the key. PRs validate but do not write, blocking poisoning.

### Step 5 — Nx Cloud: scoped access tokens

Nx Cloud (≥ 18) supports access tokens with `read` and `read-write` scopes. Issue a `read-only` token for PR builds and the `read-write` token only for trusted branches:

```yaml
- name: Set Nx token
  run: |
    if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
      echo "NX_CLOUD_ACCESS_TOKEN=${{ secrets.NX_RW }}" >> $GITHUB_ENV
    else
      echo "NX_CLOUD_ACCESS_TOKEN=${{ secrets.NX_RO }}" >> $GITHUB_ENV
    fi
```

### Step 6 — BuildKit: ban inline cache from untrusted sources

BuildKit's `--cache-from` accepts an OCI image reference. Restrict it:

```dockerfile
# Build job uses --cache-from from a write-restricted registry path:
docker buildx build \
  --cache-from type=registry,ref=registry.example.net/cache/main:latest \
  --cache-to   type=registry,ref=registry.example.net/cache/main:latest,mode=max \
  --output type=image,name=app:${SHA},push=true .
```

Configure the registry so only `main`-branch builds (identified by OIDC `sub` claim) can push to `cache/main:*`. PRs read from `cache/main` but write only to `cache/pr-${PR}` paths.

### Step 7 — Detection signals

Stream cache backend access logs (S3 access logs, GCS audit logs, BuildBuddy event log, Nx Cloud audit log) to your SIEM. Alert on:

- Cache write from an unexpected identity (any branch other than allowlisted producers).
- Cache key collision: two different builders writing the same key with different content hashes.
- Cache hit rate anomaly on `main`: a sudden 0% → 100% jump in a previously stable key indicates either a wholesale poisoning or a legitimate dep upgrade — both worth a human eye.
- `Last-Modified` of a cache object newer than the corresponding source commit on `main`.

Bazel BEP example detector:

```bash
# Pull last 24h of cache writes
buildbuddy_cli history --since=24h --output=json \
  | jq '.[] | select(.action.cache_writes[]?.identity != "main-bot")' \
  | tee /tmp/suspicious-cache-writes.json
```

### Step 8 — Periodic cache reset

Even with all the above, schedule a quarterly cache flush of the trusted tier. Long-lived caches accumulate orphaned objects whose origin no one remembers; the attacker's dwell-time advantage on a poisoned object grows linearly with cache age. A scheduled flush forces a rebuild from clean source and verifies the build is reproducible — itself a useful invariant.

## Expected Behaviour

| Signal | Before hardening | After hardening |
|--------|------------------|-----------------|
| PR branch writes shared cache key | Allowed; trusted-branch read poisoned | Rejected; PR has its own namespace |
| Cache hit with mismatched signature | Used as if valid | Treated as miss; logged |
| `main` build using cache from PR branch | Possible | Impossible by namespace |
| Cache backend audit log | Sparse, generic | Per-write identity, per-read verifier |
| Hit-rate anomaly on `main` | Unmonitored | Alerted within 15 min |

```bash
# Validate scoping by trying to write to the trusted Bazel namespace from a feature branch.
git checkout -b test-poison
bazel --config=trusted build //... 2>&1 | tail -3
# expect: PERMISSION_DENIED or rejection by remote_instance_name policy
```

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Trust-tier namespace | Eliminates fork-poisoning class | Lower hit rate on PR builds initially | Warm PR namespace from trusted on first build (verified copy) |
| Signed cache entries | Detects tampering | Build-time CPU + signing-key management | Use HMAC (cheap); rotate key quarterly with grace period |
| Read-only tokens for PRs | Prevents poisoning | Slight UX regression for engineers used to rebuilding cache via PR | Document; tooling to manually invalidate via PR comment |
| Audit log streaming | Early detection of anomaly | Cost of log volume + SIEM rules | Sample reads; full fidelity for writes only |
| Quarterly cache flush | Eliminates dwell-time advantage | First post-flush build is slow | Schedule for off-peak; pre-warm common paths |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Signature key rotated without grace | All cache misses for one build cycle | Sudden drop in hit rate | Add overlap period: accept N-1 and N keys for 24h |
| Per-identity cache splits hit rate badly | CI duration regression | Build-duration p95 alert | Tune namespacing — split by language/branch class, not per-PR |
| Detection rule false-positive on legit dep upgrade | On-call paged for `main` cache flip | Correlate with merge commit | Suppress when commit touches lockfile; trust the diff |
| Read-only PR token leak | Attacker reads cache contents | Token usage from non-CI IP | Token-scoped IP allowlist; bind to OIDC sub of runner |
| Cache backend outage | Build slowdown but not failure | Backend health metric | Builds fall back to no-cache; pipeline still completes |

## When to Consider a Managed Alternative

- BuildBuddy and Nx Cloud offer managed cache with per-identity attribution and signed entries built in.
- GitHub-hosted Actions cache with v4 scoping is already aligned to many defences here; resist the temptation to install third-party cache actions that re-introduce shared-key risk.
- For Bazel-heavy monorepos, EngFlow and BuildBarn-as-a-service provide enforced trust tiers out of the box.

## Related Articles

- [BuildKit Cache Security](/articles/cicd/buildkit-cache-security/)
- [Bazel Build Security](/articles/cicd/bazel-build-security/)
- [Securing GitHub Actions](/articles/cicd/securing-github-actions/)
- [Container Image Attestations](/articles/cicd/container-image-attestations/)
- [Reproducible Builds](/articles/cicd/reproducible-builds/)
