---
title: "Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI"
description: "Dependency confusion and typosquatting attacks exploit the gap between \"I declared a dependency\" and \"I verified the dependency I got.\" Version pinning..."
slug: "dependency-pinning"
date: 2026-01-28
lastmod: 2026-01-28
category: "cicd"
tags: ["dependencies", "lockfile", "supply-chain", "npm", "pip", "go"]
personas: ["devops-engineer", "security-engineer"]
article_number: 51
difficulty: "intermediate"
estimated_reading_time: 14
provider_bridges:
  - name: "Snyk"
    id: 48
    category: "container-security"
  - name: "Socket"
    id: 102
    category: "supply-chain"
premium_pack: "dependency-security-configs"
published: true
layout: article.njk
permalink: "/articles/cicd/dependency-pinning/index.html"
---

# Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI

## Problem

Dependency confusion and typosquatting attacks exploit the gap between "I declared a dependency" and "I verified the dependency I got." Version pinning alone is insufficient, a compromised registry can serve different code for the same version number. Lockfiles with integrity hashes are the first line of defence: they pin the exact content hash of every dependency, not just its version string.

## Threat Model

- **Adversary:** Supply chain attacker who compromises a package registry, publishes a malicious package with the same name as your internal package (dependency confusion), or publishes a typosquat package similar to a popular dependency.
- **Blast radius:** Every build that installs the compromised dependency. The malicious code runs during install (npm postinstall scripts, `setup.py` execution) with full pipeline permissions.

## Configuration

### npm: Hash-Pinned Lockfile

```bash
# ALWAYS use npm ci (not npm install) in CI.
# npm ci installs from package-lock.json exactly - fails if lockfile is out of sync.
npm ci

# Verify lockfile integrity:
# package-lock.json contains SHA-512 integrity hashes for every package.
# Example entry:
# "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
# "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="

# npm ci verifies these hashes. If the content doesn't match: the install fails.

# Configure private registry for scoped packages (prevent dependency confusion):
# .npmrc
@your-org:registry=https://npm.your-company.com/
//npm.your-company.com/:_authToken=${NPM_TOKEN}

# CRITICAL: claim your org scope on npmjs.com even if you use a private registry.
# This prevents attackers from publishing @your-org/package-name on the public registry.
```

### Python: Hash-Pinned Requirements

```bash
# Generate requirements with hashes:
pip-compile --generate-hashes requirements.in > requirements.txt

# Example output in requirements.txt:
# flask==3.0.3 \
#     --hash=sha256:34e815e5029... \
#     --hash=sha256:5f1c7b...

# Install with hash verification:
pip install --require-hashes -r requirements.txt

# If any package content doesn't match its hash: install fails.
```

```yaml
# CI workflow:
- name: Install dependencies
  run: pip install --require-hashes -r requirements.txt
  # Fails if: lockfile modified, hash mismatch, or package content changed on PyPI
```

### Go: Module Verification

```bash
# Go modules use go.sum for hash verification.
# go.sum contains cryptographic hashes for all module contents.

# Verify all modules:
go mod verify
# Expected: all modules verified

# In CI, set GONOSUMCHECK only for private modules:
GONOSUMCHECK=github.com/your-org/*

# Enable the checksum database for all other modules:
GONOSUMDB=github.com/your-org/*
GOPROXY=https://proxy.golang.org,direct
# The Go checksum database (sum.golang.org) provides a tamper-proof
# record of expected module hashes.
```

### CI Lockfile Verification

```yaml
# .github/workflows/lockfile-check.yml
# Verify lockfile is committed and matches package declarations.
name: Lockfile Integrity
on: [pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Verify npm lockfile
        run: |
          npm ci
          git diff --exit-code package-lock.json
          # Fails if npm ci modified the lockfile (meaning it was out of sync)

      - name: Check for new dependencies
        run: |
          # Alert on new dependencies added in this PR
          ADDED=$(git diff origin/main -- package-lock.json | grep '^\+.*"resolved"' | wc -l)
          if [ "$ADDED" -gt 0 ]; then
            echo "::warning::$ADDED new dependencies added in this PR, review required"
          fi
```

### Preventing Dependency Confusion

```bash
# Claim your organisation's namespace on public registries
# even if you only use private packages.

# npm: create the scope on npmjs.com
npm init --scope=@your-org
# Publish a placeholder: npm publish --access public

# PyPI: register your package name
# Create a minimal setup.py and publish a placeholder to pypi.org

# This prevents attackers from registering @your-org/secret-package
# or your-org-secret-package on the public registry.
```

## Expected Behaviour

- `npm ci` / `pip install --require-hashes` / `go mod verify` all pass in CI
- Any hash mismatch fails the build immediately
- New dependencies in PRs are flagged for review
- Private package scopes claimed on public registries
- Lockfiles committed to Git and reviewed in PRs

## Trade-offs

| Control | Impact | Risk | Mitigation |
|---------|--------|------|------------|
| `npm ci` (not `npm install`) | Fails if lockfile is out of sync | Developers must update lockfile locally before pushing | Add pre-commit hook that runs `npm install` and checks for lockfile changes. |
| Hash verification | Catches content tampering | Build fails if registry serves different content (even for legitimate re-publishes) | Rare in practice. If it happens: verify with the package maintainer. |
| Private registry scope | Prevents dependency confusion | Must maintain the private registry | Use a cloud-hosted private registry (GitHub Packages, npm Enterprise, Artifactory). |
| Claiming public namespace | Prevents namespace squatting | Must maintain the placeholder package | Publish a "this is a placeholder" README. No code needed. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Lockfile out of sync | `npm ci` fails with lockfile mismatch | CI build failure at install step | Developer runs `npm install` locally, commits updated lockfile. |
| Hash mismatch (registry compromise) | `pip install --require-hashes` fails with hash error | CI build failure; hash verification error in log | Investigate: is this a registry issue or legitimate package update? Verify with the package maintainer. Pin to known-good version. |
| Dependency confusion attack | Malicious package installed instead of internal package | Unexpected behaviour in builds; new package name in lockfile diff | Configure private registry for all internal scopes. Claim namespaces on public registries. |

## When to Consider a Managed Alternative

Manual lockfile review does not scale past 10 repositories.

- **[Snyk](https://snyk.io):** Dependency vulnerability scanning and monitoring across all repositories. Automatic PR for vulnerable dependency updates.
- **[Socket](https://socket.dev):** Behavioural analysis of dependencies (detects malicious behaviour, not just known CVEs). Catches supply chain attacks that Snyk/[Trivy](https://trivy.dev) miss.
- **[Phylum](https://www.phylum.io):** Automated malicious package detection using static and dynamic analysis.

**Premium content pack:** Dependency security configurations. `.npmrc` templates for private registry, `pip-compile` CI workflow, Go module verification scripts, lockfile CI check workflows, and namespace claiming guides for npm/PyPI/Go.


## Related Articles

- [SLSA Provenance for Container Images: From Build to Admission Control](/articles/cicd/slsa-provenance/)
- [Secret Management in CI/CD Pipelines: Vault, SOPS, and OIDC Federation](/articles/cicd/cicd-secret-management/)
- [Reproducible Builds for Container Images: Achieving Deterministic Output](/articles/cicd/reproducible-builds/)
- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
- [Terraform Security: State File Protection, Provider Pinning, and Plan Review Automation](/articles/cicd/terraform-security/)
