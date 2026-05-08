---
title: "Bazel Build System Security: Remote Execution, bzlmod, and Hermetic Hardening"
description: "Bazel's hermetic build model provides strong security properties by default, but remote execution, bzlmod registry trust, external repository rules, and remote cache poisoning introduce distinct attack surfaces. This guide covers hardening each layer end-to-end."
slug: bazel-build-security
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - bazel
  - remote-execution
  - build-security
  - hermetic-builds
  - bzlmod
personas:
  - security-engineer
  - platform-engineer
article_number: 538
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/cicd/bazel-build-security/
---

# Bazel Build System Security: Remote Execution, bzlmod, and Hermetic Hardening

## Problem

Bazel is designed for correctness and scale, not just speed. Its hermetic build model — where each action sees only explicitly declared inputs, has no ambient filesystem access, and produces outputs that are content-addressed — is a security property as much as an engineering one. Yet the same features that make Bazel powerful in large organisations (remote execution clusters, shared remote caches, external repository fetching) introduce attack surfaces that a naive deployment leaves open.

A compromised remote cache can serve malicious binaries to every developer who builds a target. A remote execution worker with insufficient isolation can read artefacts from other tenants' builds. An `http_archive` rule without a `sha256` attribute fetches whatever the server returns at build time, converting your build definition into a live network dependency. And the transition from legacy `WORKSPACE` to `MODULE.bazel` (bzlmod) changes the trust model for dependency resolution in ways that most teams have not fully audited.

This article covers the full stack: Bazel's hermetic build model as a foundational security property, bzlmod dependency management and registry trust, remote execution security with BuildBuddy and EngFlow, remote cache poisoning and output verification, sandbox escape mitigations, and toolchain hardening.

## Threat Model

- **Adversary 1 — Compromised remote cache:** An attacker with write access to the shared remote action cache stores a malicious build output keyed to the expected cache key. All subsequent builds that hit the cache receive the malicious binary without rebuilding.
- **Adversary 2 — Malicious bzlmod registry:** A team using a third-party module registry (or a compromised Bazel Central Registry module) pulls a `MODULE.bazel` extension that runs arbitrary Starlark at fetch time, exfiltrating source code or secrets.
- **Adversary 3 — Unauthenticated remote execution:** Remote execution workers that do not require mutual TLS or token authentication allow any caller to submit actions, potentially exfiltrating source files submitted as action inputs.
- **Adversary 4 — `http_archive` without integrity:** A build rule fetches an external archive over HTTPS but omits the `sha256` attribute. The upstream server is compromised and begins serving a backdoored archive. Bazel downloads and executes it.
- **Adversary 5 — Sandbox escape:** A build action exploits a vulnerability in Bazel's Linux namespace sandbox or macOS sandbox to read files outside its declared sandbox root, including credentials in the build environment.
- **Adversary 6 — Host toolchain leakage:** A build that uses the host `cc_toolchain` rather than a hermetic registered toolchain inadvertently depends on the host compiler version, linker flags, and system headers — which vary between machines and CI runners — introducing non-determinism and a vector for supply-chain substitution.
- **Blast radius:** A compromised remote cache output affects every developer and CI pipeline that consumes that cache. A compromised `http_archive` runs at repository fetch time with full access to the fetching user's environment. A compromised remote execution worker can read all source files submitted as action inputs.

## Configuration

### Hermetic Builds: Deterministic Inputs, Reproducible Outputs

Bazel's core security property is hermeticity: an action's output is a pure function of its declared inputs. Bazel achieves this through the sandbox (Linux namespaces or macOS sandbox profiles) that wraps every action.

Hermeticity must be enforced, not assumed. Several build patterns break it silently:

```python
# BUILD — DO NOT DO THIS: depending on an undeclared file leaks host state
cc_binary(
    name = "my_service",
    srcs = ["main.cc"],
    # Missing: copts that reference a host include path like /usr/local/include
    # Missing: data that reads from the source tree at runtime
)
```

```python
# BUILD — hardened version: all inputs declared explicitly
cc_binary(
    name = "my_service",
    srcs = ["main.cc"],
    deps = [":my_lib"],
    # toolchain is resolved via registered hermetic toolchain (see Toolchain section)
    # no copts referencing host paths
)
```

Run `bazel build --sandbox_debug //...` on a clean checkout to surface any actions that read undeclared files. The `--incompatible_strict_action_env` flag prevents actions from inheriting the caller's environment variables — critical on developer workstations where `PATH`, `HOME`, and cloud credential variables would otherwise bleed into the sandbox:

```bash
# .bazelrc — applied to all builds in the workspace
build --incompatible_strict_action_env
# Explicitly allowlist only the environment variables actions may read:
build --action_env=PATH=/usr/bin:/bin
build --action_env=HOME=/nonexistent

# Fail if any action reads a file not listed in its declared inputs:
build --experimental_use_hermetic_linux_sandbox

# Content-address all outputs; invalidate cache on any input change:
build --remote_upload_local_results=true
```

The combination of `--incompatible_strict_action_env` and a hermetic sandbox means that two builds of the same target from the same source tree produce bit-for-bit identical outputs — any deviation is evidence of either a non-hermetic input or a tampered cache entry.

### bzlmod: MODULE.bazel and Registry Security

Bzlmod replaces the legacy `WORKSPACE` file with a structured dependency graph declared in `MODULE.bazel`. The security implications differ significantly from `WORKSPACE`.

**Registry trust.** By default, bzlmod resolves modules from the Bazel Central Registry (`https://bcr.bazel.build`). The BCR is a Git repository; each module version is an immutable entry with a content hash. You can override the default registry to an internal mirror, but the mirror must itself be integrity-checked.

```python
# MODULE.bazel — pin the registry and declare all direct dependencies
module(
    name = "my_project",
    version = "0.1.0",
    compatibility_level = 1,
)

# Declare the registry explicitly rather than relying on the default.
# Use an internal mirror for air-gapped or controlled environments:
# (set via .bazelrc: --registry=https://registry.internal.example.com/bazel/)

bazel_dep(name = "rules_go", version = "0.48.0")
bazel_dep(name = "gazelle", version = "0.36.0")
bazel_dep(name = "rules_oci", version = "2.0.0")

# For development-only tools, declare them in dev_dependency blocks
# so they are not transitively pulled into downstream consumers:
bazel_dep(name = "buildifier_prebuilt", version = "7.3.1", dev_dependency = True)
```

**The MODULE.bazel.lock file.** Bzlmod generates a lockfile at `MODULE.bazel.lock` that records the exact resolved version of every transitive dependency, including the content hash of each module's `MODULE.bazel` file as fetched from the registry. Commit this file and enforce that it is up to date in CI:

```bash
# CI check: fail if the lockfile is out of sync with MODULE.bazel
bazel mod deps --lockfile_mode=error
# --lockfile_mode=error causes Bazel to fail rather than update the lockfile.
# Use --lockfile_mode=update locally when intentionally changing dependencies.
```

A diff in `MODULE.bazel.lock` on a pull request should be reviewed with the same care as a `go.sum` or `package-lock.json` change. Unexplained additions or hash changes indicate a dependency was modified at the registry without a version bump.

**Extension integrity.** Bzlmod module extensions (defined with `module_extension()`) run Starlark code at repository fetch time with access to the network and the ability to create repository rules. They are equivalent in power to `WORKSPACE` repository rules. Audit any extension you depend on:

```python
# MODULE.bazel — inspect what extensions you are running
go_sdk = use_extension("@rules_go//go:extensions.bzl", "go_sdk")
go_sdk.download(version = "1.22.3")
use_repo(go_sdk, "go_sdk", "go_toolchains")

# The go_sdk extension downloads the Go SDK from dl.google.com.
# Verify that rules_go pins the SDK download with an integrity hash:
# grep -r "integrity" $(bazel info output_base)/external/rules_go~/go/extensions.bzl
```

To verify extension-fetched artefacts, check that the extension records a `sha256` or `integrity` attribute for every downloaded file. If it does not, file an issue with the ruleset maintainer and consider vendoring the SDK.

### Remote Execution Security

Remote execution (RE) distributes build actions across a cluster of workers. BuildBuddy, EngFlow, and self-hosted `bazel-remote` all implement the Remote Execution API (REAPI). The security surface covers transport security, worker authentication, and action isolation.

**Transport: gRPC over TLS.** All communication between the Bazel client and the RE service must use TLS. Do not use `grpc://` (plaintext) in any environment where source code is confidential:

```ini
# .bazelrc — remote execution configuration
build:remote --remote_executor=grpcs://remote.buildbuddy.io
build:remote --remote_instance_name=my-org/my-project
# TLS client certificate for mutual TLS (mTLS) — authenticates the Bazel client to the RE service:
build:remote --tls_client_certificate=/run/secrets/bazel-client.crt
build:remote --tls_client_key=/run/secrets/bazel-client.key
# Server certificate authority — verifies the RE service's identity:
build:remote --remote_default_exec_properties=container-image=docker://gcr.io/my-org/build-image@sha256:abc123

# Authentication token (API key or OIDC token from Workload Identity):
build:remote --remote_header=x-buildbuddy-api-key=${BUILDBUDDY_API_KEY}
```

**Worker authentication.** Each RE worker must authenticate to the scheduler before accepting work. In BuildBuddy Enterprise and EngFlow, workers authenticate with a service account credential. For self-hosted clusters using `buildfarm` or `bazel-remote`, configure worker-to-scheduler mTLS:

```yaml
# buildfarm worker config (worker.config.yml)
worker:
  tls:
    # Workers present this cert to the scheduler
    certFile: /etc/buildfarm/worker.crt
    keyFile:  /etc/buildfarm/worker.key
    # Scheduler's CA — only workers signed by this CA are accepted
    caFile:   /etc/buildfarm/scheduler-ca.crt
  # Each action executes in a fresh ephemeral container, not the worker's filesystem
  sandboxing:
    enabled: true
    containerImage: "gcr.io/my-org/build-sandbox@sha256:def456"
```

**Action isolation on workers.** Each Bazel action submitted to remote execution should execute in a fresh, ephemeral environment. On Linux workers this means a new mount namespace, network namespace, and PID namespace per action — identical to local sandbox mode. Verify your RE service enforces this:

```bash
# Test that actions cannot see each other's outputs:
# Submit two concurrent actions that attempt to read /tmp from a sibling action.
# A correctly sandboxed worker returns ENOENT for any path outside the action root.

# For BuildBuddy: confirm "Execution Isolation" is set to "docker" or "firecracker"
# in the executor configuration, not "none".

# For self-hosted bazel-remote: use the --max_size flag to cap cache size
# and configure OCI container isolation per action:
bazel-remote \
  --dir=/var/cache/bazel-remote \
  --max_size=50 \
  --tls_cert_file=/etc/bazel-remote/server.crt \
  --tls_key_file=/etc/bazel-remote/server.key \
  --htpasswd_file=/etc/bazel-remote/htpasswd
```

### Remote Cache Poisoning and Output Verification

The remote action cache is keyed by the action's input hash (all input file hashes, the command, and the environment). An attacker who can write to the cache can store a malicious output under a legitimate key, and every subsequent client that builds the same target will receive the poisoned output without rebuilding.

**Defence 1: Authenticated cache writes.** The cache should require authenticated writes and unauthenticated (or separately authenticated) reads. Separate the write credential used by CI from the read credential used by developers:

```ini
# .bazelrc — developers read from cache but cannot write poisoned entries
build --remote_cache=grpcs://cache.buildbuddy.io
build --remote_header=x-buildbuddy-api-key=${BUILDBUDDY_READ_API_KEY}
build --noremote_upload_local_results   # developers do not upload to shared cache

# CI runners write to the cache using a separate elevated credential:
# build:ci --remote_upload_local_results=true
# build:ci --remote_header=x-buildbuddy-api-key=${BUILDBUDDY_WRITE_API_KEY}
```

**Defence 2: Cache-as-hint, not cache-as-truth.** For release and security-sensitive builds, rebuild from source regardless of cache state and compare the output hash against any cached entry. If they differ, the cache entry is suspect:

```bash
#!/bin/bash
# scripts/verify-build-output.sh — run this for release builds

set -euo pipefail

TARGET="${1:?Usage: $0 //path/to:target}"

# Build without using the remote cache to get the ground-truth output hash:
bazel build --noremote_cache --nouse_action_cache "${TARGET}"
FRESH_HASH=$(sha256sum "$(bazel cquery --output=files "${TARGET}")" | awk '{print $1}')

# Build using the remote cache to get the cached output:
bazel build --remote_cache=grpcs://cache.buildbuddy.io "${TARGET}"
CACHED_HASH=$(sha256sum "$(bazel cquery --output=files "${TARGET}")" | awk '{print $1}')

if [ "${FRESH_HASH}" != "${CACHED_HASH}" ]; then
  echo "SECURITY ALERT: cached output does not match freshly built output"
  echo "  Fresh:  ${FRESH_HASH}"
  echo "  Cached: ${CACHED_HASH}"
  echo "  Target: ${TARGET}"
  exit 1
fi

echo "OK: cache output verified (${FRESH_HASH})"
```

Run this verification script as a post-build step in your release pipeline. A mismatch is an incident requiring cache eviction and investigation.

**Defence 3: Remote cache TLS and content addressing.** All connections to the remote cache must use TLS. The cache key is the SHA-256 of the action's input tree; the stored content is referenced by its own SHA-256. A man-in-the-middle attack that substitutes a different blob would require producing a SHA-256 collision — computationally infeasible — but only if the connection is TLS-protected. Plaintext `http://` connections to the cache remove this property entirely.

### Sandbox Escape Mitigations

Bazel's Linux sandbox uses Linux user namespaces, mount namespaces, and network namespaces to restrict what an action can see. The macOS sandbox uses sandbox profiles. Neither is equivalent to a VM boundary; a kernel privilege-escalation vulnerability can break out of both.

```bash
# .bazelrc — enforce the strictest available sandbox mode

# Linux: use the namespace-based sandbox for all local actions
build --spawn_strategy=sandboxed
# Prevent actions from making network calls (no outbound connections from build actions):
build --sandbox_default_allow_network=false
# Allowlist specific targets that legitimately need network (e.g., integration tests):
# build --//tools/integration_test:requires_network=true

# Fail if the sandbox cannot be initialised (do not silently fall back to no sandbox):
build --experimental_use_hermetic_linux_sandbox
build --experimental_sandbox_async_tree_deletion

# macOS: use the macOS sandbox profile
build --strategy=Sandboxed
```

For CI runners executing untrusted code (e.g., builds triggered by external pull requests), run Bazel inside a VM or use Firecracker/gVisor as the action execution layer on remote execution workers. This contains a sandbox escape within the microVM boundary:

```yaml
# GitHub Actions — run builds inside a dedicated VM to contain sandbox escapes
jobs:
  build:
    runs-on: ubuntu-24.04
    container:
      image: gcr.io/my-org/bazel-runner@sha256:abc123
      options: --security-opt=no-new-privileges --cap-drop=ALL
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Build
        run: bazel build --config=remote //...
```

Mount the Bazel output directory on a separate volume so that a compromised action cannot read source files outside the declared sandbox root by exploiting filesystem mount propagation:

```yaml
      volumes:
        - name: bazel-cache
          emptyDir: {}
      volumeMounts:
        - name: bazel-cache
          mountPath: /root/.cache/bazel
```

### External Repository Rules: `http_archive` and Integrity

Every `http_archive`, `http_file`, or similar repository rule that fetches external content must include an integrity attribute. Without it, Bazel fetches whatever the server returns — a silently corrupted or compromised archive is accepted without error.

```python
# MODULE.bazel or legacy WORKSPACE — always include sha256 or integrity

# WRONG: no integrity check
http_archive(
    name = "my_dep",
    url = "https://github.com/example/my_dep/archive/v1.2.3.tar.gz",
)

# CORRECT: sha256 pinned, Bazel refuses to use a non-matching archive
http_archive(
    name = "my_dep",
    urls = [
        # Prefer multiple mirrors for resilience, but verify the hash:
        "https://github.com/example/my_dep/archive/v1.2.3.tar.gz",
        "https://mirror.bazel.build/github.com/example/my_dep/archive/v1.2.3.tar.gz",
    ],
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    strip_prefix = "my_dep-1.2.3",
)
```

To generate the correct `sha256` when adding a new dependency:

```bash
# Download the archive to a temp location and compute its hash:
curl -L -o /tmp/my_dep.tar.gz \
  https://github.com/example/my_dep/archive/v1.2.3.tar.gz
sha256sum /tmp/my_dep.tar.gz
# Paste the output hash into the sha256 attribute before committing.
```

**Avoid `git_repository` without integrity.** The `git_repository` rule (from `rules_git`) checks out a Git remote at a given commit or tag. Without a content hash, it trusts the remote server's response. A tag can be force-pushed to a different commit. Use `http_archive` with a tarball and `sha256` instead, or pin the Git repository to a commit hash (which is content-addressed) rather than a tag:

```python
# RISKY: tag can be force-pushed; no integrity check on fetched content
git_repository(
    name = "my_dep",
    remote = "https://github.com/example/my_dep.git",
    tag = "v1.2.3",
)

# SAFER: pinned to a specific commit SHA (immutable), but still no content hash
git_repository(
    name = "my_dep",
    remote = "https://github.com/example/my_dep.git",
    commit = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
)

# BEST: use http_archive with the GitHub archive URL and sha256
http_archive(
    name = "my_dep",
    url = "https://github.com/example/my_dep/archive/a1b2c3d4e5f6.tar.gz",
    sha256 = "...",
    strip_prefix = "my_dep-a1b2c3d4e5f6",
)
```

### Toolchain Security: Hermetic vs Host Toolchains

Bazel resolves toolchains (compilers, linkers, SDK tools) through the toolchain resolution mechanism. A build that falls back to the host toolchain is non-hermetic and potentially insecure: it depends on whatever `gcc`, `clang`, or `javac` happens to be installed on the build machine.

Register hermetic toolchains that download a pinned, content-addressed version of the compiler from a known source:

```python
# MODULE.bazel — register a hermetic C++ toolchain via llvm_toolchain
bazel_dep(name = "toolchains_llvm", version = "1.1.2")

llvm = use_extension("@toolchains_llvm//toolchain/extensions:llvm.bzl", "llvm")
llvm.toolchain(
    name = "llvm_toolchain",
    llvm_versions = {
        "": "17.0.6",  # default for all platforms
        "linux-x86_64": "17.0.6",
        "linux-aarch64": "17.0.6",
        "darwin-x86_64": "17.0.6",
        "darwin-aarch64": "17.0.6",
    },
)
use_repo(llvm, "llvm_toolchain", "llvm_toolchain_llvm")

register_toolchains("@llvm_toolchain//:all")
```

```python
# MODULE.bazel — hermetic Go toolchain via rules_go
go_sdk.download(
    version = "1.22.3",
    # rules_go verifies the Go SDK download against a pinned hash
)
```

```bash
# .bazelrc — refuse to use any host tool not provided by a registered toolchain
build --incompatible_enable_cc_toolchain_resolution
# This flag disables the legacy CC_FLAGS-based toolchain lookup and requires
# a properly registered cc_toolchain. Builds that cannot resolve a registered
# toolchain fail rather than falling back to the host compiler.
```

Verify that no target in your build graph depends on the `@local_config_cc` toolchain (the auto-detected host toolchain) except where explicitly intended:

```bash
# Find all targets that resolve to the host toolchain:
bazel cquery \
  "deps(//...) intersect @local_config_cc//:all" \
  --output=label 2>/dev/null | sort -u
# Any output here is a hermetic build violation — investigate and replace
# with a registered hermetic toolchain.
```

## Expected Behaviour

- Builds run with `--incompatible_strict_action_env` and `--experimental_use_hermetic_linux_sandbox` produce identical output hashes on two consecutive runs from the same source tree.
- `bazel mod deps --lockfile_mode=error` exits zero when `MODULE.bazel.lock` is in sync; any pull request that modifies `MODULE.bazel` without updating the lockfile fails CI.
- Every `http_archive` in `MODULE.bazel` and `WORKSPACE` has a `sha256` or `integrity` attribute; a grep-based CI check fails any pull request that adds a fetch rule without one.
- Release builds run the output verification script; a hash mismatch between a fresh build and the cached output triggers an incident response workflow.
- Remote execution and remote cache connections use `grpcs://`; a `.bazelrc` linter rejects any configuration using `grpc://` without TLS.
- `bazel cquery` for `@local_config_cc` dependencies returns no results for production targets.

## Trade-offs

| Control | Security Gain | Operational Cost | Mitigation |
|---|---|---|---|
| `--incompatible_strict_action_env` | Prevents credential and PATH leakage into build actions | Actions that previously worked by accident on host tools now fail | Enumerate required `--action_env` entries; document them in `.bazelrc` with comments explaining each one. |
| `MODULE.bazel.lock` enforcement | Detects supply-chain changes in transitive dependencies without a version bump | Lockfile must be regenerated on every `bazel_dep` version change | Add a CI job that runs `bazel mod deps --lockfile_mode=update` and fails if the lockfile changes unexpectedly. |
| Authenticated cache writes (CI only) | Prevents developers from polluting or poisoning the shared cache | Developer builds are slower (no write to shared cache) | Configure a developer-local disk cache; developers still benefit from cache reads. |
| Remote cache output verification | Detects cache poisoning before artefacts reach production | Adds a full rebuild to the release pipeline critical path | Run the verification step only for release builds, not for every PR build. |
| Hermetic toolchains | Eliminates host compiler dependency; identical output across all machines | Toolchain download adds cold-start time to the first build | Cache the toolchain download in the remote cache; subsequent builds pay zero cost. |
| `--sandbox_default_allow_network=false` | Prevents build actions from making outbound network calls | Build rules that fetch at build time (not fetch time) break | Migrate any network-fetching build rules to `http_archive` at the `WORKSPACE`/`MODULE.bazel` level. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Remote cache poisoning | Release binary behaviour differs from source; output hash mismatch in verification script | Post-build output verification step exits non-zero | Evict the poisoned cache key (`bazel remote cache delete`); revoke the write credential; audit cache write logs for the injection window. |
| `MODULE.bazel.lock` drift | `bazel mod deps --lockfile_mode=error` fails in CI | CI failure on `bazel mod deps` check | Run `bazel mod deps --lockfile_mode=update` locally; review the diff for unexpected version changes or new transitive dependencies before committing. |
| `http_archive` without `sha256` | A compromised upstream archive is silently accepted; the build succeeds with malicious content | Grep-based pre-commit hook or CI lint check | Add `sha256` to the offending rule; verify the hash against the upstream release page. |
| Sandbox network access | A build action exfiltrates source files or secrets via HTTP during the build | Network egress monitoring on CI runners; unexpected outbound connections | Enable `--sandbox_default_allow_network=false`; investigate which rule was making the connection; replace with a declared `http_archive` fetch. |
| Worker authentication failure | Remote execution returns `UNAUTHENTICATED` errors; builds fall back to local execution silently | Build logs show `WARNING: Remote execution disabled`; build time spikes | Rotate the API key or mTLS certificate; check expiry dates; set up a credential rotation calendar reminder. |
| Host toolchain regression | Build output changes between CI and developer machines; `diff` on binaries shows non-determinism | Reproducibility check fails; `bazel cquery` for `@local_config_cc` shows production targets | Register a hermetic toolchain; add `--incompatible_enable_cc_toolchain_resolution` to `.bazelrc`. |

## Related Articles

- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
- [SLSA Provenance: Generating and Verifying Build Attestations](/articles/cicd/slsa-provenance/)
- [Artifact Integrity Verification: Checksums, Signatures, and Transparency Logs](/articles/cicd/artifact-integrity/)
- [Securing CI/CD Runners: Isolation, Ephemeral Environments, and Privilege Reduction](/articles/cicd/securing-cicd-runners/)
- [Software Supply Chain Third-Party Risk: Dependency Vetting and Continuous Monitoring](/articles/cicd/software-supply-chain-third-party-risk/)
