---
title: "Rust and Cargo Supply Chain Security: cargo-audit, cargo-deny, and Build Script Risks"
description: "Rust's memory safety guarantees end at the crate boundary. Build scripts execute arbitrary code at compile time, proc macros run inside the compiler, and crates.io has no mandatory code review. This article covers cargo-audit, cargo-deny, Cargo.lock strategy, cargo-vet, private registry pinning, and reproducible builds to harden the Rust supply chain."
slug: rust-cargo-supply-chain-security
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - rust
  - cargo
  - supply-chain
  - cargo-audit
  - crates-io
personas:
  - security-engineer
  - platform-engineer
article_number: 526
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/rust-cargo-supply-chain-security/
---

# Rust and Cargo Supply Chain Security: cargo-audit, cargo-deny, and Build Script Risks

## Problem

Rust is widely adopted for its compile-time memory safety guarantees. That reputation creates a dangerous blind spot: teams assume "it's Rust, so it's safe" and apply less scrutiny to their dependency tree than they would for a Node or Python project. The supply chain attack surface in a Rust project is substantial.

- **Build scripts (`build.rs`) execute arbitrary code** during every `cargo build`. A build script has full filesystem and network access with the permissions of the developer or CI runner running the build.
- **Procedural macros run inside the Rust compiler** during compilation. A proc macro crate can exfiltrate secrets from environment variables, write files to the filesystem, or reach out to external hosts — all under the cover of "code generation."
- **crates.io has no mandatory code review.** Anyone can publish any crate. There is no review process equivalent to npm's audit system or Go's module proxy. Typosquatting and name-squatting attacks are possible.
- **`Cargo.lock` is often absent or misunderstood.** Many library authors follow advice to not commit `Cargo.lock`, which means CI resolves dependency versions at build time and can silently pull in a newer, compromised crate version.
- **SemVer ranges are common in `Cargo.toml`.** `tokio = "1"` will resolve to any `1.x` release, including a future compromised `1.99.0`.

Rust's memory safety guarantees apply to the code you write. They do not apply to the code that runs as part of your build process or that you pull in from crates.io.

**Target systems:** Rust projects using Cargo on any OS; CI pipelines on GitHub Actions, GitLab CI, Jenkins; teams building CLI tools, web services, embedded firmware, or WebAssembly modules with Rust.

## Threat Model

- **Adversary 1 — Compromised crate with malicious build script:** A popular utility crate receives a malicious release. Its `build.rs` reads environment variables (including `CARGO_ENCODED_RUSTFLAGS`, `HOME`, `AWS_SECRET_ACCESS_KEY`) and exfiltrates them to an attacker-controlled host. Every developer who runs `cargo build` and every CI pipeline that builds the project executes this code.
- **Adversary 2 — Typosquat on crates.io:** A developer mistypes `serde_json` as `serde-json` in `Cargo.toml`. The attacker-registered package with that name is downloaded, compiled, and linked into the binary.
- **Adversary 3 — Dep chain confusion via semver float:** A project pins `reqwest = "0.11"` but does not commit `Cargo.lock`. CI resolves this to `0.11.27` one day and, after a compromised publish, to `0.11.28` the next. The binary changes without any source code change.
- **Adversary 4 — Proc macro data exfiltration:** A proc macro crate dependency reads `std::env::vars()` at macro expansion time and sends the contents to an external endpoint. Because this happens inside the compiler, standard runtime security controls (seccomp, network policies on containers) may not block it unless build environments are network-isolated.
- **Adversary 5 — Known CVE in transitive dependency:** A transitive dependency has a published advisory in the RustSec database. No one on the team knows because there is no automated check. The vulnerability is exploited in production months after the advisory was published.
- **Access level:** Adversaries 1 and 4 require only that the target runs a build. Adversary 2 requires a typo in `Cargo.toml`. Adversary 3 requires a compromised crates.io publish. Adversary 5 requires a known vulnerability and no advisory monitoring.
- **Objective:** Credential theft during build, malicious code in the compiled binary, or exploitation of a known vulnerability in a running service.
- **Blast radius:** Every binary built from the affected project, every developer machine, every CI runner, and every production service running the output.

## Configuration

### Step 1: cargo-audit — Advisory Scanning

`cargo-audit` queries the [RustSec Advisory Database](https://rustsec.org/) against your `Cargo.lock` and reports known vulnerabilities, unmaintained crates, and security notices.

```bash
# Install cargo-audit.
cargo install cargo-audit --locked

# Run a basic audit against Cargo.lock.
cargo audit

# Fail the build if any advisory is found (use in CI).
cargo audit --deny warnings

# Audit and output JSON for downstream processing (SIEM, dashboards).
cargo audit --json | tee audit-report.json
```

```yaml
# .github/workflows/security.yml
name: Security Audit
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    # Run daily — new advisories are published continuously.
    - cron: "0 7 * * *"

jobs:
  audit:
    name: cargo-audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cargo-audit
        run: cargo install cargo-audit --locked

      - name: Run cargo audit
        # --deny warnings: treat unmaintained crates as failures too.
        # --ignore RUSTSEC-0000-0000: add known false positives with justification.
        run: cargo audit --deny warnings

      - name: Upload audit report
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: audit-report
          path: audit-report.json
```

The `--deny warnings` flag is critical for CI enforcement. Without it, `cargo audit` reports findings but exits with code 0, so CI passes. Advisories are suppressed per-crate using `--ignore RUSTSEC-XXXX-XXXX` — document each suppression with a justification comment in a `deny.toml` (see Step 2) so the decision is visible to reviewers.

### Step 2: cargo-deny — Comprehensive Policy Enforcement

`cargo-audit` checks known vulnerabilities. `cargo-deny` goes further: it enforces policies on licenses, permitted crate sources, banned crates, and duplicate dependencies — all in a single `deny.toml` configuration file.

```bash
# Install cargo-deny.
cargo install cargo-deny --locked

# Initialise a deny.toml with sensible defaults.
cargo deny init

# Run all checks.
cargo deny check

# Run only specific checks.
cargo deny check advisories
cargo deny check licenses
cargo deny check bans
cargo deny check sources
```

```toml
# deny.toml — checked into the repository root.

[advisories]
# Reject any crate with a published vulnerability or a security notice.
vulnerability = "deny"
unmaintained = "warn"
unsound = "deny"
yanked = "deny"
notice = "warn"

# Suppress specific advisories with documented justification.
# [advisories.ignore]
# id = "RUSTSEC-2020-0071"   # time 0.1 — only used in test code, not in production path.

[licenses]
# Require explicitly listed licences. Deny anything else.
allow = [
  "MIT",
  "Apache-2.0",
  "Apache-2.0 WITH LLVM-exception",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Unicode-DFS-2016",
]
# Deny copyleft licences in a commercial project.
deny = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.0", "LGPL-3.0"]
# Treat unlicensed crates as a hard failure.
unlicensed = "deny"
# Require confidence above this threshold when cargo-deny detects a licence.
confidence-threshold = 0.8

[bans]
# Deny specific crates by name (known-bad or internally prohibited).
deny = [
  # Example: ban an older, unsound version of a crate.
  { name = "openssl", wrappers = ["openssl-sys"] },
]

# Warn on multiple versions of the same crate in the dep tree.
# Duplicates increase binary size and may mean two crates with different
# vulnerability profiles are both present.
multiple-versions = "warn"

# Highlight crates with wildcard version requirements.
wildcards = "deny"

[sources]
# Only allow crates from crates.io and your internal registry.
# Deny git dependencies in production builds (unpinned, no audit trail).
unknown-registry = "deny"
unknown-git = "deny"

allow-registry = ["https://github.com/rust-lang/crates.io-index"]
# Add your private registry:
# allow-registry = ["https://github.com/rust-lang/crates.io-index", "https://crates.internal.example.com/index"]

# If you must use git sources, allow only specific repositories.
# allow-git = ["https://github.com/your-org/internal-crate"]
```

```yaml
# Add to security.yml workflow.
  deny:
    name: cargo-deny
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v1
        with:
          command: check
          arguments: --all-features
```

### Step 3: Cargo.lock — Commit Strategy

`Cargo.lock` records the exact resolved versions and checksums of every dependency in the tree. The Cargo documentation advises library authors not to commit `Cargo.lock`, but this advice is misapplied to binary crates and services.

**Always commit `Cargo.lock` for:**
- Binary crates (CLI tools, services, daemons)
- Applications deployed to production
- WebAssembly modules
- Anything where reproducible builds matter

**The argument for not committing `Cargo.lock` in libraries** is that library consumers should resolve the dep tree themselves, so they get compatible versions. This is correct for library authors publishing to crates.io. It does not apply to your service or application.

```bash
# Verify that Cargo.lock is committed and up to date in CI.
# --locked: fail if Cargo.lock needs to be updated (i.e., it is out of sync with Cargo.toml).
cargo build --locked
cargo test --locked

# This will fail if:
# - Cargo.lock is not committed.
# - Cargo.lock is out of date relative to Cargo.toml.
# - A dependency was added to Cargo.toml without regenerating Cargo.lock.
```

**What `Cargo.lock` does not protect against:**

`Cargo.lock` records exact versions and hashes for packages fetched from crates.io. It does not:

- Prevent a build script from those pinned crates from making network calls.
- Guarantee the crate source has not been silently replaced (though crates.io content-addresses tarballs; a SHA mismatch causes a build failure).
- Prevent a future `cargo update` from bringing in a new version if someone updates the lock file without review.
- Protect against malicious code that was in the crate at the time it was published — if the crate was already compromised when you first pinned it, the lock file preserves the compromise.

Treat `Cargo.lock` updates as code changes. Review them in pull requests the same way you review source changes.

### Step 4: cargo-vet — Third-Party Auditing

`cargo-vet` is Mozilla's tool for requiring human-reviewed audits of third-party crates before they enter a build. It integrates with the supply chain Levels for Artifacts (SLSA) concept: each crate either has an audit entry in `supply-chain/audits.toml` or is covered by a trusted organisation's published audit set.

```bash
# Install cargo-vet.
cargo install cargo-vet --locked

# Initialise cargo-vet in the project.
cargo vet init

# Check which crates still need audits.
cargo vet

# Add an audit after reviewing a crate manually.
cargo vet certify serde 1.0.197

# Import audits from a trusted organisation (e.g., Mozilla, Google).
cargo vet import mozilla https://raw.githubusercontent.com/mozilla/cargo-vet/main/supply-chain/audits.toml
```

```toml
# supply-chain/config.toml — generated by cargo vet init.
[imports.mozilla]
url = "https://raw.githubusercontent.com/mozilla/cargo-vet/main/supply-chain/audits.toml"

[imports.google]
url = "https://raw.githubusercontent.com/google/supply-chain/main/audits.toml"

# Require audits for all crates; not just new additions.
[policy]
audit-as-crates-io = true
```

`cargo-vet` is a high-friction control best suited to security-critical projects (cryptography libraries, firmware, financial systems). For most production services, `cargo-deny` with advisory enforcement and a reviewed `Cargo.lock` is the right baseline.

### Step 5: Private Registry and Source Restriction

For organisations that need tighter control over which crates are used, `.cargo/config.toml` can redirect all crate resolution through a private registry and block direct crates.io access.

```toml
# .cargo/config.toml (project-level) or ~/.cargo/config.toml (user-level).

[source.crates-io]
# Replace crates.io with your private registry for all dependencies.
replace-with = "internal-registry"

[source.internal-registry]
registry = "https://crates.internal.example.com/index"

# Result: `cargo build` will only fetch from the internal registry.
# Crates not mirrored there will fail to resolve, preventing accidental
# use of unapproved upstream crates.
```

For organisations using Cloudsmith, Artifactory, or a self-hosted Kellnr registry, this pattern forces all resolution through the registry where crates can be scanned, approved, and mirrored.

To enforce this without relying on developer workstation configuration, set the registry source substitution in CI explicitly:

```yaml
- name: Configure private registry
  run: |
    mkdir -p ~/.cargo
    cat >> ~/.cargo/config.toml <<'EOF'
    [source.crates-io]
    replace-with = "internal-registry"

    [source.internal-registry]
    registry = "${{ secrets.CARGO_REGISTRY_URL }}"
    token = "${{ secrets.CARGO_REGISTRY_TOKEN }}"
    EOF
```

### Step 6: Build Script Security

`build.rs` files are compiled and executed as native binaries during `cargo build`. This is necessary for FFI bindings, generated code, and platform-specific configuration — but it is a significant trust boundary.

```toml
# Cargo.toml — disable the build script if your crate does not need one.
# Do not include a build = "build.rs" line unless you need it.

# For dependencies you control, audit build.rs files explicitly.
# For third-party crates, check whether the build script:
# - Makes network calls (reqwest in build.rs is a red flag)
# - Reads environment variables beyond CARGO_* and OUT_DIR
# - Writes files outside OUT_DIR
# - Executes external binaries without a clear need
```

```bash
# Inspect build scripts before adding a dependency.
# After adding a crate to Cargo.toml, before committing:

# 1. Check if the crate has a build.rs.
find ~/.cargo/registry/src/*/serde-1.0.197/ -name "build.rs"

# 2. Read the build script and verify it only reads CARGO_* env vars
#    and writes to OUT_DIR.

# 3. For CI runners: use network egress restrictions.
#    A build.rs that makes outbound HTTP calls is anomalous.
#    Use iptables rules, security groups, or a network policy (in k8s)
#    to drop outbound connections from CI runners during the build phase.
```

In Kubernetes-based CI (Tekton, Argo Workflows), apply a `NetworkPolicy` that blocks egress from the build pod except to the package registry:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ci-build-egress
  namespace: ci-builds
spec:
  podSelector:
    matchLabels:
      role: cargo-build
  policyTypes:
    - Egress
  egress:
    # Allow only the internal crate registry and DNS.
    - to:
        - ipBlock:
            cidr: 10.0.0.5/32   # Internal registry IP.
      ports:
        - port: 443
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - port: 53
          protocol: UDP
```

### Step 7: Proc Macro Security

Procedural macros are compiled as dynamic libraries and loaded into the Rust compiler during the compilation phase. They receive the token stream of the code being compiled and produce new token stream output. The security concern is that they run **before** the final binary is linked — so network egress restrictions that apply to the running binary do not apply during the compilation phase on a typical developer workstation.

Treat proc macro crates with the same scrutiny as build scripts:

```bash
# Identify proc macro crates in your dependency tree.
cargo metadata --format-version 1 | \
  python3 -c "
import json, sys
meta = json.load(sys.stdin)
for pkg in meta['packages']:
    for target in pkg.get('targets', []):
        if 'proc-macro' in target.get('kind', []):
            print(pkg['name'], pkg['version'], pkg['source'])
"

# Review proc macro crates before accepting them as dependencies.
# Key questions:
# - Is the crate widely used and maintained by a reputable author?
# - Does the crate's functionality justify a proc macro (vs. a regular macro)?
# - Have any security researchers reviewed it?
# - Does cargo-audit report any advisories for it?
```

Minimise proc macro exposure: prefer derive macros from established crates (`serde`, `thiserror`, `tokio::main`) over novel proc macro crates from unknown authors.

### Step 8: Reproducible Builds

A reproducible build produces a bit-for-bit identical binary given the same source, toolchain, and inputs. Reproducibility lets you verify that the binary you ship matches the source you reviewed.

```bash
# Pin the Rust toolchain version exactly via rust-toolchain.toml.
# Without this, `rustup` uses whatever is current, and builds vary over time.
cat rust-toolchain.toml
```

```toml
# rust-toolchain.toml — commit this to the repository.
[toolchain]
channel = "1.78.0"       # Exact version; not "stable" or "1.78".
components = ["rustfmt", "clippy"]
targets = ["x86_64-unknown-linux-musl"]   # Pin the target too.
```

```bash
# Build with locked dependencies and the pinned toolchain.
cargo build --release --locked --target x86_64-unknown-linux-musl

# Enable source-based code coverage flags for reproducibility checks.
# RUSTFLAGS affects the binary; pin it in CI.
export RUSTFLAGS="-C target-feature=+crt-static"
export CARGO_BUILD_TARGET=x86_64-unknown-linux-musl

# Verify reproducibility by building twice and comparing.
cargo build --release --locked
cp target/release/myapp /tmp/myapp-build1
cargo build --release --locked
diff /tmp/myapp-build1 target/release/myapp
# Should produce no output if the build is reproducible.
```

Common sources of non-reproducibility in Rust builds:

- Timestamps embedded by `std::time::SystemTime::now()` at build time — avoid in build scripts.
- Non-deterministic hash maps in code generation — use `BTreeMap` in proc macros and build scripts.
- `file!()` and `env!()` macros embed absolute paths — use `CARGO_MANIFEST_DIR` carefully.
- Differing `CARGO_PKG_VERSION_*` env vars if they are not set consistently.

The Reproducible Builds project maintains a Rust-specific guide at [reproducible-builds.org](https://reproducible-builds.org/docs/rust/).

## Expected Behaviour

| Signal | Without Controls | With Controls |
|--------|-----------------|---------------|
| Known CVE in transitive dep | Silently present; discovered in pentest | `cargo audit --deny warnings` fails CI at PR time |
| Unlicensed or GPL crate added | Merged without review | `cargo deny check licenses` fails PR |
| Build script makes outbound HTTP | Executes silently; credentials exfiltrated | Network policy blocks egress; CI fails |
| `Cargo.lock` out of date | CI resolves new version silently | `cargo build --locked` fails; engineer must update and review lockfile diff |
| Typosquat crate added | Compiled and linked into binary | `cargo deny check sources` blocks unknown registries; `cargo-vet` requires audit before build |
| New proc macro dep added | Compiled into build; no review | Team audit process flags it; `cargo deny` policy enforced |

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| `cargo audit --deny warnings` | Blocks builds with known CVEs | May block builds on unmaintained-but-safe crates | Use `--ignore` with documented justification in `deny.toml` |
| `cargo deny` license enforcement | Prevents GPL crate integration | Requires licence review when adding deps | Use `cargo deny check licenses` locally as a pre-commit check |
| Commit `Cargo.lock` for binaries | Reproducible, auditable builds | Lockfile update PRs require explicit review | Treat lockfile diffs as meaningful security-relevant changes |
| Network egress restriction in CI | Prevents build-time exfiltration | Blocks legitimate network access in some build scripts (e.g., downloading system headers for FFI) | Mirror required build assets into the internal registry or CI cache |
| `cargo-vet` | Strongest supply chain guarantee | High operational overhead; requires manual crate reviews | Suitable for security-critical projects; too heavy for general applications |
| `rust-toolchain.toml` pin | Reproducible, auditable toolchain | Requires periodic toolchain update PRs | Automate via Dependabot or a weekly workflow that proposes the toolchain update |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| New advisory published for pinned dep | `cargo audit` fails in daily scheduled CI run | Scheduled audit workflow produces failure notification | Assess the advisory; update the dep or add a justified `--ignore` entry |
| Lockfile update pulls in compromised version | Binary behaviour changes without source changes | Review lockfile diff in PR; compare binary hashes | Revert `Cargo.lock` to last known good; investigate the crate version |
| Build script fails with network restriction | CI build fails at compile step with network error | CI log shows connection refused in build.rs | Determine if the network call is legitimate; if so, mirror the resource into CI |
| `deny.toml` too strict for a new dep | Dependency blocked by licence or source policy | `cargo deny` fails with policy violation | Review the policy entry; update `deny.toml` with justification if the dep is acceptable |
| Proc macro crate compromised | Malicious code compiled into binary | No automatic detection without `cargo-vet`; audit diff | Rotate all credentials that were in env vars during the affected build; rebuild from known-good lockfile |
| `rust-toolchain.toml` pin falls behind security-relevant compiler fix | Builds use a compiler with a known miscompilation or unsoundness | Track Rust security advisories; subscribe to the Rust security mailing list | Update `channel` in `rust-toolchain.toml`; rebuild and re-test |

## Related Articles

- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Artifact Integrity: SLSA Provenance and Sigstore for Build Outputs](/articles/cicd/artifact-integrity/)
- [Container Build Hardening: Rootless BuildKit and Minimal Base Images](/articles/cicd/container-build-hardening/)
- [GitHub Actions Security: Permissions, Pinning, and Workflow Injection](/articles/cicd/securing-github-actions/)
- [WebAssembly Linear Memory Safety](/articles/wasm/wasm-linear-memory-safety/)
