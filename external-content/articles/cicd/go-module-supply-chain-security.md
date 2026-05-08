---
title: "Go Module Supply Chain Security: Proxy, Checksums, govulncheck, and Private Modules"
description: "Go's module proxy and checksum database provide a strong foundation for supply chain security, but only when teams understand what they protect against — and what they don't. This article covers the full Go module security model: go.sum verification, govulncheck in CI, GONOSUMCHECK pitfalls, private module proxies with Athens, replace directive risks, and vanity import path hardening."
slug: go-module-supply-chain-security
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - golang
  - go-modules
  - supply-chain
  - govulncheck
  - module-proxy
personas:
  - security-engineer
  - platform-engineer
article_number: 536
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/go-module-supply-chain-security/
---

# Go Module Supply Chain Security: Proxy, Checksums, govulncheck, and Private Modules

## Problem

Go's module system ships with two infrastructure components that most other language ecosystems lack: a transparent module proxy and a checksum database. Together they make supply chain attacks meaningfully harder. But "harder" is not "impossible," and a surface-level understanding of these controls leads teams to trust them beyond their actual scope.

- **The module proxy and checksum database protect against tampering after publication.** They do not protect against malicious code that was in the module before it was published, a typosquatted module name, or a vanity import path that redirects to attacker-controlled source.
- **`go.sum` is only useful if it is committed and verified in CI.** A missing or outdated `go.sum` file, or a CI pipeline that allows updates without review, undermines the entire checksum chain.
- **`govulncheck` is not run by default.** Known vulnerabilities in dependencies are invisible unless you explicitly scan for them. Unlike `npm audit`, which runs automatically, `govulncheck` must be installed and invoked as a separate step.
- **`GONOSUMCHECK` and `GONOSUMDB` bypass checksum verification entirely.** They exist for legitimate use cases — private modules that cannot be published to sum.golang.org — but are routinely misconfigured in ways that create silent verification gaps for public modules.
- **`replace` directives in `go.mod` can silently redirect module resolution.** A `replace` that points to a local path or an attacker-controlled repository will override the checksum database lookup for the replaced module. This is a vector for build-time compromise in projects that accept external contributions.
- **`go install` without a version pin fetches the latest version.** `go install golang.org/x/tools/gopls@latest` silently resolves to whatever version is current at build time, bypassing reproducibility guarantees.

Go is widely used for security-critical infrastructure: container runtimes, admission webhooks, certificate managers, Kubernetes operators, and service meshes. Supply chain compromise in a Go module can have blast radius far beyond a typical application dependency.

**Target systems:** Go applications and services using Go modules (Go 1.11+); CI pipelines on GitHub Actions, GitLab CI, Tekton, or Jenkins; teams maintaining internal Go tooling or open-source Go projects.

## Threat Model

- **Adversary 1 — Typosquatted module name:** A developer adds `github.com/acme/utlis` instead of `github.com/acme/utils`. An attacker who registered the typo module before the legitimate one exists provides a malicious package. The proxy serves it; the checksum database records the checksum of the malicious module — the checksum database only proves the module has not changed since it was first indexed, not that it is safe.

- **Adversary 2 — Vanity import path hijack:** A module uses a vanity import path like `go.company.com/sdk`. The vanity redirect is controlled by a DNS record or a web server serving `<meta>` tags. If that server is compromised or the DNS record is hijacked, future `go get` commands for that module will resolve to attacker-controlled source. The checksum database protects against the resolved content changing after first fetch, but not against the initial resolution pointing to malicious source.

- **Adversary 3 — `replace` directive injection:** An attacker submits a pull request to an open-source project that includes a seemingly innocuous `replace` directive in `go.mod`: `replace golang.org/x/crypto => github.com/attacker/crypto v0.0.1`. Code reviewers who do not read `go.mod` diffs carefully merge the PR. CI builds now resolve `golang.org/x/crypto` to the attacker's fork, which is excluded from checksum database verification if the attacker controls the `GONOSUMDB` configuration, or is silently trusted if the `replace` is accepted at face value.

- **Adversary 4 — Known CVE in transitive dependency:** A transitive Go module dependency has a published advisory in the Go vulnerability database. The project never runs `govulncheck`. The vulnerability is exploited in production months after the advisory is published. Because Go statically links dependencies into binaries, the vulnerable code is present in every deployed binary compiled after the dependency was added.

- **Adversary 5 — Private module leaked through public proxy:** A developer imports an internal module (`go.internal.company.com/payments/v2`) without configuring `GOPRIVATE`. The `go` command attempts to look up the module through `proxy.golang.org` and record the path in `sum.golang.org`. The lookup fails (the module is not public), but the module path has now been disclosed to Google's infrastructure. In extreme cases, a misconfigured module with a publicly routable path could be served by the proxy from an earlier poisoned fetch.

- **Access level:** Adversaries 1–3 require write access to a public package registry or DNS control. Adversary 4 requires only that the vulnerable dependency exists and is invoked. Adversary 5 is an information disclosure risk inherent to misconfigured `GOPRIVATE`.

- **Objective:** Code execution during build or at runtime; credential theft through malicious module code; disclosure of internal module paths to external infrastructure.

## Configuration

### Step 1: Understand the Module Proxy and Checksum Database

The Go module system routes all dependency resolution through two infrastructure components by default.

**`proxy.golang.org`** is a transparent caching proxy. When you run `go get github.com/some/module@v1.2.3`, the `go` command fetches the module from the proxy rather than directly from GitHub. The proxy:
- Caches module content so it remains available even if the upstream repository is deleted or goes private.
- Provides a consistent, immutable source for a given module version once it has been fetched.
- Does **not** audit module content for malicious code.

**`sum.golang.org`** is the checksum database (also called a transparency log). It records the hash of every module version it has seen, in an append-only Merkle tree. When you download a module, the `go` command verifies the module's hash against the entry in this log. This means:
- If a module version was tampered with after being indexed, the checksum mismatch causes a build failure.
- If a module version has never been indexed and is being fetched for the first time, the hash is recorded. A subsequent fetch of the same version must match.
- It does **not** prevent a malicious module from being indexed with its malicious content intact.

The `go.sum` file in your repository records the hashes of every module (and each module's `go.mod` file) that your project depends on. This file is the local record of what your project has verified — it must be committed to version control and treated as a security artifact.

```bash
# View the current GOPROXY and GONOSUMDB settings.
go env GOPROXY
go env GONOSUMDB
go env GONOSUMCHECK
go env GOFLAGS

# Default values on a standard Go installation:
# GOPROXY=https://proxy.golang.org,direct
# GONOSUMDB=  (empty — all modules go through sum.golang.org)
# GONOSUMCHECK=  (empty)
# GOFLAGS=  (empty)
```

The `direct` fallback in `GOPROXY=https://proxy.golang.org,direct` means that if the proxy does not have a module, Go falls back to fetching it directly from the VCS. This fallback bypasses the proxy's caching guarantees. Consider whether you need it:

```bash
# Remove the direct fallback — require all modules to be available in the proxy.
# Appropriate for production CI where all dependencies should already be cached.
export GOPROXY=https://proxy.golang.org

# For airgapped or private-proxy environments, disable the public proxy entirely.
export GOPROXY=https://goproxy.internal.company.com
```

### Step 2: go.sum — Commit, Verify, and Enforce

The `go.sum` file must be committed to the repository. Without it, the `go` command cannot verify that module content has not changed between fetches. This is not optional for production services or security-critical code.

```bash
# Verify that all modules in go.mod match their go.sum entries.
# This reads go.sum and re-fetches module checksums from the module cache
# or the checksum database, comparing against recorded hashes.
go mod verify

# Expected output when go.sum is intact and all modules are unmodified:
# all modules verified

# If a module's content has been tampered with locally (in the module cache):
# github.com/some/module v1.2.3: zip has been modified (...)
```

In CI, run `go mod verify` as an early step before any compilation. Add it alongside `go mod tidy` checks to ensure the `go.sum` file is complete and consistent:

```yaml
# .github/workflows/security.yml — module integrity checks.
name: Module Integrity
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * *"

jobs:
  module-integrity:
    name: go mod verify
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Verify module checksums
        run: go mod verify

      - name: Check go.sum is up to date
        # go mod tidy updates go.sum; if there are diffs after running it,
        # the committed go.sum was not generated from the current go.mod.
        run: |
          go mod tidy
          git diff --exit-code go.sum go.mod
```

The `git diff --exit-code` step catches the common case where a developer updated `go.mod` manually without running `go mod tidy`, leaving `go.sum` inconsistent with the actual dependency tree.

### Step 3: GOFLAGS=-mod=readonly in CI

By default, the `go` command will update `go.mod` and `go.sum` during a build if they are missing entries. In CI, this behaviour is dangerous: it means a build can silently pull in new module versions and update the lockfiles without any review.

```bash
# Set -mod=readonly to prevent the go command from modifying go.mod or go.sum.
# With this flag, the build fails if go.mod or go.sum are out of date.
export GOFLAGS=-mod=readonly

# Or set it per-command without modifying the environment:
go build -mod=readonly ./...
go test -mod=readonly ./...
```

In CI, set `GOFLAGS` in the job environment rather than per-command to ensure it applies to all `go` invocations in the job, including indirect calls from build tools or Makefiles:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      GOFLAGS: "-mod=readonly"
      GONOSUMCHECK: ""        # Explicitly empty — never bypass checksum verification.
      GOPROXY: "https://proxy.golang.org,direct"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true
      - run: go build ./...
      - run: go test ./...
```

The explicit `GONOSUMCHECK: ""` line in the CI environment definition documents the intent — no modules bypass checksum verification — and prevents an accidentally set shell variable from propagating into the build.

### Step 4: govulncheck — Vulnerability Scanning

`govulncheck` is the official Go vulnerability scanner, maintained by the Go security team. It queries the Go vulnerability database (`https://vuln.go.dev/`) and uses a call-graph analysis to determine whether a vulnerable function is actually reachable in your code. This call-graph analysis reduces false positives compared to SCA tools that flag any dependency that contains a CVE regardless of whether the vulnerable code path is invoked.

```bash
# Install govulncheck.
go install golang.org/x/vuln/cmd/govulncheck@latest

# Scan the entire module for vulnerabilities.
# --scan=package (default): report only vulnerabilities in packages your code imports.
# --scan=module: report all vulnerabilities in modules you depend on,
#                even if you don't import the affected package.
govulncheck ./...

# Use --scan=module for a conservative policy that flags all known-vulnerable
# module versions, regardless of call reachability.
govulncheck --scan=module ./...

# Output JSON for downstream processing (SIEM, dashboards, policy engines).
govulncheck -json ./... | tee govulncheck-report.json

# Scan a compiled binary directly — useful for auditing pre-built tools
# without access to source.
govulncheck -mode=binary /usr/local/bin/some-go-tool
```

The difference between `--scan=package` and `--scan=module` matters for policy decisions:

| Flag | Reports | Use When |
|------|---------|----------|
| `--scan=package` (default) | Only vulnerabilities in packages your code directly imports and where the vulnerable call is reachable | General application development; minimising noise |
| `--scan=module` | All vulnerabilities in any version of any module in your dependency graph, whether or not the affected package is imported | Security-critical services; compliance requirements; conservative vulnerability management policy |

Integrate `govulncheck` into CI with a scheduled run to catch newly published advisories for existing dependencies:

```yaml
jobs:
  govulncheck:
    name: govulncheck
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
          cache: true

      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest

      - name: Run govulncheck (package scan)
        run: govulncheck ./...
        # govulncheck exits with code 3 when vulnerabilities are found,
        # which fails this CI step and blocks the PR.

      - name: Run govulncheck (module scan for policy enforcement)
        # This step reports vulnerabilities even in packages you don't import.
        # Use 'continue-on-error: true' here and handle the report downstream
        # if you want to distinguish "reachable CVE" from "module-level CVE".
        run: govulncheck --scan=module -json ./... | tee govulncheck-module.json

      - name: Upload vulnerability report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: govulncheck-report
          path: govulncheck-module.json
```

For GitLab CI, the equivalent configuration:

```yaml
govulncheck:
  stage: security
  image: golang:1.24-alpine
  script:
    - go install golang.org/x/vuln/cmd/govulncheck@latest
    - govulncheck ./...
  rules:
    - if: $CI_PIPELINE_SOURCE == "push"
    - if: $CI_PIPELINE_SOURCE == "schedule"
  artifacts:
    when: always
    paths:
      - govulncheck-report.json
    expire_in: 30 days
```

### Step 5: GONOSUMCHECK and GONOSUMDB — When to Use Them and the Security Risk

`GONOSUMDB` is a comma-separated list of module path prefixes for which the `go` command will not consult the checksum database. `GONOSUMCHECK` is similar but also suppresses checksum verification entirely (not just the database lookup). Both exist for a legitimate reason: modules that are not publicly accessible cannot be registered in `sum.golang.org`, so the checksum database lookup would always fail.

```bash
# GONOSUMDB: skip the checksum database for these module paths,
# but still verify against the local go.sum file.
export GONOSUMDB=go.internal.company.com,github.com/your-org

# GONOSUMCHECK: skip checksum verification entirely for these paths.
# WARNING: this means no tamper detection for matched modules.
# Use only for modules that are genuinely unreachable from sum.golang.org.
export GONOSUMCHECK=go.internal.company.com

# GOPRIVATE sets both GONOSUMDB and GONOPROXY for the listed prefixes.
# This is the recommended way to configure private module support.
export GOPRIVATE=go.internal.company.com,github.com/your-org/*
```

The security risk of misconfiguring these variables is that public modules can accidentally be excluded from checksum verification:

```bash
# DANGEROUS: this bypasses checksum verification for ALL modules under github.com.
# A typosquat or tampered module would be silently accepted.
export GONOSUMCHECK=github.com   # Never do this.

# DANGEROUS: using a wildcard that accidentally covers public modules.
export GOPRIVATE=github.com/your-org  # Intended: only your-org modules.
# But if an attacker registers github.com/your-org-fake, it is also excluded
# from checksum verification if the prefix matches.
```

The correct approach for private modules is to set `GOPRIVATE` to the most specific prefix that covers only your internal modules:

```bash
# Correct: specific internal domain only.
export GOPRIVATE=go.internal.company.com

# Correct: specific GitHub org, using the full prefix.
export GOPRIVATE=github.com/acme-internal-org

# Correct for multiple private prefixes.
export GOPRIVATE=go.internal.company.com,github.com/acme-internal-org
```

In CI, document every `GONOSUMDB` and `GONOSUMCHECK` setting and the justification for it. Review these settings in security audits. An undocumented bypass is a gap that will be discovered during an incident, not before.

### Step 6: Private Module Security — Athens and Self-Hosted Proxies

For organisations with private Go modules, the recommended architecture is a self-hosted module proxy that:
1. Authenticates requests from internal clients.
2. Caches approved public modules (preventing dependency on `proxy.golang.org` availability).
3. Hosts private modules without exposing them to public infrastructure.

[Athens](https://docs.gomods.io/) is the standard open-source self-hosted Go module proxy. It supports multiple storage backends (GCS, S3, Azure Blob, local disk) and integrates with private Git hosting.

```yaml
# athens-config.toml — base Athens configuration.
# Deployed as a Kubernetes Deployment or Docker container.

GoEnv = "production"
GoBinaryEnv = ["GONOSUMDB=go.internal.company.com", "GOPRIVATE=go.internal.company.com"]

# StorageType controls where Athens stores cached modules.
StorageType = "gcs"

[Storage]
  [Storage.GCS]
    ProjectID = "your-gcp-project"
    Bucket    = "your-athens-bucket"

# NetworkMode controls how Athens fetches upstream modules.
# "strict" means Athens only serves modules it has already cached;
# "offline" means it never fetches from upstream.
# For production CI with a known dependency set, "strict" prevents
# new modules from being pulled without explicit caching.
NetworkMode = "strict"

# FilterFile controls which modules Athens will proxy.
# Modules not in the filter are rejected.
FilterFile = "/conf/filter.conf"

# Credentials for fetching from private Git hosting.
[GitConfig]
  # Use SSH deploy keys or a service account token.
```

```
# filter.conf — allowlist of modules Athens will proxy.
# Prefix with + to allow, - to deny, D for direct (no proxy).
+ go.internal.company.com
+ github.com/acme-internal-org
+ github.com/google/
+ golang.org/x/
+ google.golang.org/
- *   # Deny all other modules — require explicit allowlisting.
```

Configure your CI runners and developer workstations to use Athens:

```bash
# In CI environment or developer shell profile.
export GOPROXY=https://athens.internal.company.com,direct
export GONOSUMDB=go.internal.company.com
export GOPRIVATE=go.internal.company.com
```

The `direct` fallback in `GOPROXY` allows Athens to fetch from upstream on cache miss. Remove `direct` in a fully airgapped environment where only pre-approved modules should be accessible.

For private modules stored in a private Git host, Athens authenticates using `.netrc` or SSH keys configured in the proxy's deployment environment. This means CI runners do not need individual credentials for every private module — they authenticate to Athens, which handles upstream authentication.

### Step 7: replace Directive Security

`replace` directives in `go.mod` are a common source of security misconfiguration. They override module resolution for a named module, pointing to a different path or version. This is legitimately used for local development (replacing a module with a local fork) and for patching a transitive dependency that has a vulnerability before an upstream fix is available.

The security risk is that a `replace` directive can silently redirect module resolution away from the checksum-verified version to an unverified alternative:

```
# go.mod — DANGEROUS: replaces a standard library module with an untrusted fork.
module github.com/acme/myapp

go 1.24

require (
    golang.org/x/crypto v0.22.0
)

// This replaces golang.org/x/crypto with an unverified fork.
// The checksum for the fork is recorded in go.sum, but no one has reviewed the fork.
replace golang.org/x/crypto => github.com/untrusted-author/crypto v0.0.1
```

Controls for `replace` directives:

```bash
# Audit all replace directives in your go.mod.
grep -A 100 "^replace" go.mod

# Check the replace directives in all modules in your build graph,
# including transitive dependencies.
go mod edit -json | python3 -c "
import json, sys
data = json.load(sys.stdin)
replaces = data.get('Replace', []) or []
if replaces:
    for r in replaces:
        print(f\"REPLACE: {r['Old']['Path']} => {r['New']['Path']}\")
else:
    print('No replace directives found.')
"
```

In code review policies, require explicit approval from a security reviewer for any PR that adds or modifies a `replace` directive. Add a CI check that fails if `replace` directives point to non-canonical paths:

```bash
#!/usr/bin/env bash
# check-replace-directives.sh — fail if replace directives use non-org paths.
# Run as a CI step before go build.

ALLOWED_REPLACE_TARGETS="^(go\.internal\.company\.com|github\.com/acme-internal-org)"

if grep -qE "^replace" go.mod; then
    replacements=$(grep -A 100 "^replace" go.mod | grep "=>" | awk '{print $NF}')
    while IFS= read -r target; do
        module_path=$(echo "$target" | sed 's/ v[0-9].*//')
        if ! echo "$module_path" | grep -qE "$ALLOWED_REPLACE_TARGETS"; then
            echo "ERROR: Unapproved replace target: $module_path"
            echo "Replace directives to non-internal modules require security review."
            exit 1
        fi
    done <<< "$replacements"
fi
echo "Replace directive check passed."
```

### Step 8: Vanity Import Path Security

Vanity import paths (`go.company.com/sdk` rather than `github.com/company/sdk`) are resolved by the `go` command fetching the URL and reading a `<meta name="go-import">` HTML tag. This resolution is a trust boundary: whoever controls the web server at `go.company.com` controls where `go get go.company.com/sdk` resolves.

Threat vectors for vanity import paths:
- **DNS hijack:** An attacker takes over the DNS record for `go.company.com`.
- **TLS certificate compromise:** An attacker obtains a fraudulent certificate for `go.company.com` and performs a MITM attack on the metadata fetch.
- **Web server compromise:** The server hosting the `<meta>` tag redirect is compromised and the redirect is changed.
- **Domain expiry:** The domain lapses and is re-registered by an attacker.

Hardening measures:

```bash
# Audit your vanity import paths and their current redirect targets.
# For each vanity path, fetch the meta redirect and verify it points to the expected VCS.
curl -s "https://go.company.com/sdk?go-get=1" | grep 'go-import'
# Expected: <meta name="go-import" content="go.company.com/sdk git https://github.com/acme/sdk">

# Monitor vanity path redirects in CI — alert if the resolved VCS URL changes.
```

For internal vanity paths hosted on infrastructure you control:
- Use infrastructure-as-code to manage the web server configuration, so redirect changes go through code review.
- Enable DNSSEC for the domain.
- Set a short TTL on the DNS records and monitor for unexpected changes.
- Consider replacing vanity paths with direct module paths for new modules — the indirection adds attack surface without much usability benefit for private projects.

### Step 9: Go Toolchain Supply Chain — go install and Version Pinning

`go install` without a specific version installs the latest version of a tool:

```bash
# DANGEROUS: resolves to whatever is latest at the time of installation.
# The installed version can change silently between CI runs if the cache is cold.
go install golang.org/x/tools/gopls@latest

# CORRECT: pin to an exact version.
go install golang.org/x/tools/gopls@v0.16.1
```

For tools used in CI, pin the version explicitly and verify the expected binary hash after installation. In GitHub Actions, use a dedicated tools file to track tool versions:

```go
//go:build tools
// +build tools

// tools.go — track tool dependencies with explicit versions.
// Run: go generate ./tools/... to install at pinned versions.
package tools

import (
    _ "golang.org/x/tools/gopls"
    _ "golang.org/x/vuln/cmd/govulncheck"
    _ "mvdan.cc/gofumpt"
    _ "github.com/golangci/golangci-lint/cmd/golangci-lint"
)
```

```bash
# go.mod includes the tool dependencies at pinned versions.
# Install all tools at their pinned versions from go.mod.
go install golang.org/x/tools/gopls@$(go list -m -f '{{.Version}}' golang.org/x/tools)
go install golang.org/x/vuln/cmd/govulncheck@$(go list -m -f '{{.Version}}' golang.org/x/vuln)
```

This pattern ensures that tool versions are tracked in `go.sum` alongside application dependencies, providing the same checksum guarantees for tooling as for production code.

## Expected Behaviour

| Signal | Without Controls | With Controls |
|--------|-----------------|---------------|
| Known CVE in transitive dep | Silently present; discovered in incident or pentest | `govulncheck ./...` fails CI at PR time; advisory blocks merge |
| go.sum tampered with | Undetected; build succeeds with wrong dependency content | `go mod verify` fails CI; tampered module cache entry rejected |
| `replace` directive added pointing to fork | Merged without review; build silently uses unverified fork | CI check fails; PR requires explicit security reviewer approval |
| GONOSUMCHECK misconfigured to cover public modules | Public module checksums not verified; tampered module silently accepted | CI environment definition explicitly sets `GONOSUMCHECK=`; no bypass |
| go.sum missing from commit | Developer forgets to commit; CI regenerates it on each run | `GOFLAGS=-mod=readonly` fails CI; `git diff --exit-code go.sum` check fails |
| Private module path leaked to proxy.golang.org | Internal module path recorded in public transparency log | `GOPRIVATE` set correctly; no lookup sent to public infrastructure |
| `go install @latest` in CI | Tool version changes silently between runs; compromised release pulled | Tools pinned to exact versions in `go.mod`; versions tracked in `go.sum` |

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| `GOFLAGS=-mod=readonly` in CI | Prevents silent go.sum updates; enforces reviewed lockfile | Breaks CI if go.sum is legitimately out of date | Add a separate `go mod tidy && git diff --exit-code` check to catch this condition explicitly |
| `govulncheck --scan=module` | Reports all module-level CVEs, not just reachable ones | Higher volume of findings; may block builds on CVEs in unused packages | Use `--scan=package` for PR gates; `--scan=module` for nightly policy reporting |
| Athens self-hosted proxy | Full control over which modules are allowed; no dependency on proxy.golang.org | Operational overhead of running and maintaining Athens | Use a managed proxy service (Artifactory GoProxy, GCP Artifact Registry) if Athens maintenance is not feasible |
| `replace` directive check in CI | Prevents unreviewed module substitution | May block legitimate emergency patches | Allow specific approved replacements via CI configuration; require documented justification |
| Vanity path elimination | Removes DNS/web server as an attack vector in module resolution | Breaks existing import paths; requires go.mod updates across all consumers | Apply only to new modules; maintain existing vanity paths with infrastructure hardening |
| Exact version pins for `go install` | Reproducible tool installation; no silent version drift | Requires manual version updates for tool upgrades | Use Renovate or Dependabot to open PRs for tool version bumps automatically |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| New advisory published for pinned dep | `govulncheck` fails in daily scheduled CI run | Scheduled security job produces failure; alert to security channel | Assess the advisory; update the dep in `go.mod` and `go.sum`; regenerate binaries |
| Athens proxy unavailable | CI builds fail with module fetch errors | Build step fails with connection error to proxy URL | Fall back to `GOPROXY=https://proxy.golang.org,direct` temporarily; restore Athens from backup; ensure modules are cached |
| `GONOSUMCHECK` set incorrectly in CI environment | Public module checksums not verified; silent security gap | Manual audit of CI environment variables during security review | Audit all `GONOSUMCHECK` and `GONOSUMDB` values; document exceptions; set `GONOSUMCHECK=""` explicitly in CI |
| `go.sum` conflict in merge | Two PRs update different dependencies; merge conflict in `go.sum` | Git merge conflict; CI fails | Run `go mod tidy` on the merge result; verify with `go mod verify`; commit the resolved `go.sum` |
| `replace` directive to local path committed accidentally | Build works in CI but only because of absolute path on CI runner; fails on other machines | `go build` fails on machines without the local path | Remove the `replace` directive; use a published version or a properly referenced module |
| Vanity import path redirect changed | `go get` resolves to different repository than before; checksum mismatch if go.sum exists | `go mod verify` or `go build -mod=readonly` fails with checksum error | Investigate the meta redirect; if the redirect was legitimately changed, update `go.sum` after verifying the new source; if hijacked, rotate any credentials accessible from the compromised module |

## Related Articles

- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [Go Crypto and x509 Security in CI/CD Pipelines](/articles/cicd/go-crypto-cicd-security/)
- [Software Supply Chain and Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [Rust and Cargo Supply Chain Security](/articles/cicd/rust-cargo-supply-chain-security/)
- [Artifact Integrity: SLSA Provenance and Sigstore for Build Outputs](/articles/cicd/artifact-integrity/)
