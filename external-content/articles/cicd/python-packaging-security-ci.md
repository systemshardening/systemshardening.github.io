---
title: "Python Packaging Security in CI/CD Pipelines"
description: "PyPI supply chain attacks, typosquatting, and malicious install-time code are live threats to every Python CI pipeline. This guide covers pip-audit, hash-pinned requirements, Poetry lock file verification, private PyPI mirrors, OIDC trusted publishing, and Dependabot configuration to close the gaps."
slug: python-packaging-security-ci
date: 2026-05-07
lastmod: 2026-05-07
category: cicd
tags:
  - python
  - pypi
  - pip-audit
  - trusted-publishing
  - supply-chain
personas:
  - security-engineer
  - platform-engineer
article_number: 525
difficulty: Intermediate
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cicd/python-packaging-security-ci/
---

# Python Packaging Security in CI/CD Pipelines

## Problem

Python's packaging ecosystem makes supply chain compromise unusually easy for attackers. PyPI has no mandatory review for new packages, any uploaded package can declare arbitrary `install_requires` chains, and the default `pip install` invocation executes arbitrary Python during installation via `setup.py`. When your CI pipeline runs `pip install -r requirements.txt`, it potentially runs code contributed by dozens of transitive maintainers you have never audited, under the same permissions as the rest of your build — including access to `GITHUB_TOKEN`, cloud credentials, SSH keys, and every secret in the environment.

The threat is not theoretical. The `colourama` typosquatting package targeted developers who mistyped `colorama`. The `ctx` and `phpass` packages on PyPI were hijacked in 2022 and modified to exfiltrate environment variables to an attacker-controlled server. Dependency confusion attacks against Python have succeeded in corporate environments where internal package names were discovered from public repositories or job postings, then registered on public PyPI at a higher version number. The `--extra-index-url` flag, commonly used to add private registries, causes pip to consult both registries and install whichever version is higher, making dependency confusion trivially exploitable.

Securing Python packaging in CI requires several independent controls that work together: vulnerability scanning on the resolved dependency set, hash-pinned lockfiles that detect content tampering, a private mirror that proxies PyPI through your own registry, and OIDC-based trusted publishing that eliminates long-lived upload tokens.

## Threat Model

- **Adversary 1 — Typosquatting / namespace confusion:** An attacker publishes a package named `reqeusts`, `pillow-pil`, or `setup-tools` on PyPI. A developer misreads the package name in a dependency, or the attacker picks a name that is plausibly the canonical package. Malicious code runs at install time via `setup.py` or a custom `setup()` call.
- **Adversary 2 — Dependency confusion against a private package index:** An attacker discovers your internal package name (e.g. `mycompany-utils`) from a public commit or artifact. They register it on PyPI at version `99.0.0`. Any build using `--extra-index-url` or `--index-url` without a strict scoping policy resolves the public version.
- **Adversary 3 — Malicious `setup.py` execution during install:** Even a legitimate package can have its distribution archive tampered with on the registry or in transit. The `setup.py` in the distribution runs arbitrary code. Install-time execution happens before your application code runs any validation.
- **Adversary 4 — Compromised package maintainer account publishes a backdoored release:** A PyPI maintainer account without MFA is compromised. The attacker pushes a patched release that adds a credential harvester to a widely-used utility library. Builds that resolve versions by a floating `>=` constraint or that run `pip install --upgrade` automatically install the backdoored version.
- **Adversary 5 — Known-CVE dependency in production:** A package you depend on has a published CVE. Your CI does not run a vulnerability scanner. The vulnerable version ships to production.
- **Adversary 6 — Long-lived PyPI upload token leaked from CI secrets:** A developer generated a `PYPI_TOKEN` and stored it in GitHub Actions secrets. A compromised workflow step reads the environment and exfiltrates it. The attacker publishes a backdoored version of your package.

**Blast radius across adversaries:** Install-time code executes with full build environment access — all CI secrets, cloud credentials, and repository tokens are exposed. A compromised published package version reaches every downstream consumer.

## Configuration

### Vulnerability Scanning with pip-audit

`pip-audit` queries the Python Packaging Advisory Database (PyPA) and the OSV database for CVEs against the resolved dependency set. It operates on an installed environment or directly against a requirements file, making it suitable as both a local developer tool and a CI gate.

```bash
# Install pip-audit
pip install pip-audit

# Audit a requirements file directly (does not require an active install)
pip-audit -r requirements.txt

# Audit the current virtual environment
pip-audit

# Output as JSON for downstream processing
pip-audit -r requirements.txt --format json -o pip-audit-report.json

# Fail the command if any vulnerability is found (default behaviour)
# Exit code 1 on findings — use this as a CI gate
pip-audit -r requirements.txt
```

```yaml
# .github/workflows/pip-audit.yml
name: Dependency Vulnerability Scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * 1"  # Weekly scan catches new CVEs against pinned deps

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
        with:
          python-version: "3.12"

      - name: Install pip-audit
        run: pip install pip-audit==2.7.3

      - name: Run pip-audit
        run: pip-audit -r requirements.txt --format json -o pip-audit-report.json

      - name: Upload audit report
        if: always()
        uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08  # v4.6.0
        with:
          name: pip-audit-report
          path: pip-audit-report.json
```

**Policy enforcement:** Add `--ignore-vuln` only with a documented exception and a fixed-by date. Any unignored finding exits non-zero and fails the CI job. Never use `pip-audit --skip-editable` in production pipelines without understanding which local packages are being excluded from the scan.

### Safety as an Alternative Scanner

`safety` (from pyup.io) maintains its own vulnerability database and offers a complementary signal to pip-audit. The two tools sometimes catch different issues due to database source differences.

```bash
pip install safety

# Scan a requirements file
safety check -r requirements.txt

# Output JSON for SIEM ingestion
safety check -r requirements.txt --json > safety-report.json

# Exit non-zero on vulnerabilities (default)
safety check -r requirements.txt
```

Run both pip-audit and safety in parallel in your CI pipeline. When the two tools disagree, investigate before dismissing either finding.

### Hash-Pinned Requirements with pip-compile

Version pinning alone (`requests==2.32.3`) is insufficient. PyPI allows package maintainers to upload new distribution files for an existing version, or a compromised registry proxy can serve different content under the same version number. Hash-pinned requirements tie each installed package to the exact bytes you tested.

```bash
# Install pip-tools
pip install pip-tools

# requirements.in — your high-level declared dependencies
# requests>=2.28
# flask>=3.0
# boto3>=1.34

# Generate requirements.txt with SHA-256 hashes for every package
# and all transitive dependencies
pip-compile --generate-hashes requirements.in

# requirements.txt output example:
# flask==3.1.0 \
#     --hash=sha256:5f873b... \
#     --hash=sha256:a1d8b9...
# werkzeug==3.1.3 \
#     --hash=sha256:c4f3a2...

# Install with mandatory hash verification — fails if any hash does not match
pip install --require-hashes -r requirements.txt
```

```yaml
# CI: enforce hash-pinned install
- name: Install dependencies
  run: pip install --require-hashes -r requirements.txt
  # If any package's content does not match the pinned hash:
  # ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE
  # The build fails. Investigate before proceeding.
```

**Updating dependencies:** Run `pip-compile --generate-hashes requirements.in` locally, review the diff in `requirements.txt`, and commit. Never regenerate hashes in CI without a review gate. The hash update commit is the review artifact — treat it the same way you treat a source code change.

### Poetry Lock File Security

Poetry generates `poetry.lock` containing content hashes for every resolved package. The lock file pins both version and hash.

```bash
# Install with locked dependencies — fails if poetry.lock is out of sync
poetry install --no-root

# Verify that poetry.lock matches pyproject.toml without installing
poetry lock --check

# Export to requirements.txt format for tools that need it
poetry export --format requirements.txt --output requirements.txt --with-hashes
```

```yaml
# CI: enforce Poetry lock file
- name: Validate poetry.lock
  run: poetry lock --check
  # Fails if pyproject.toml has changed without updating poetry.lock

- name: Install dependencies
  run: poetry install --no-root
  # Installs exactly what is in poetry.lock, verifying all hashes
```

**Lock file drift detection:** Add a CI step on pull requests that runs `poetry lock --check` before the install step. If the lock file is out of sync with `pyproject.toml`, the PR cannot merge until a developer updates and commits the lock file. This prevents undeclared transitive dependency changes from shipping silently.

### Private PyPI Mirror

A private PyPI mirror (Nexus Repository, Artifactory, or devpi) gives you control over which packages your builds can install, enforces that all packages are proxied through a server you control, and provides an audit log of every package download.

**Nexus PyPI proxy configuration:**

```bash
# pip.conf — configure pip to use private mirror exclusively
# Place in: $VIRTUAL_ENV/pip.conf or $HOME/.config/pip/pip.conf
# Or set via environment variable in CI

[global]
index-url = https://nexus.example.com/repository/pypi-proxy/simple/
# Do NOT add --extra-index-url alongside a private mirror.
# Adding --extra-index-url means pip consults both registries — this
# reintroduces dependency confusion. Use index-url only.
trusted-host = nexus.example.com
```

```yaml
# CI: set private index via environment variable
- name: Configure private PyPI mirror
  env:
    PIP_INDEX_URL: https://nexus.example.com/repository/pypi-proxy/simple/
    PIP_TRUSTED_HOST: nexus.example.com
  run: pip install --require-hashes -r requirements.txt
```

**Dependency confusion prevention with a private mirror:** In Nexus or Artifactory, configure the PyPI proxy repository to block packages that match your internal package names unless they come from your internal hosted repository. In Artifactory this is "Exclude Patterns" on the remote repository configuration. In Nexus, use the "Negative Cache" and repository routing rules. The goal is that `mycompany-utils` can only ever resolve from your internal hosted repo, never from public PyPI through the proxy.

**devpi for smaller teams:**

```bash
# devpi-server setup
pip install devpi-server devpi-client
devpi-server --init --serverdir /opt/devpi
devpi-server --serverdir /opt/devpi &

devpi use http://localhost:3141
devpi login root --password=""
devpi index -c dev bases=root/pypi  # Creates a dev index that proxies PyPI
```

### PyPI Trusted Publishing (OIDC)

Trusted publishing eliminates `PYPI_TOKEN` from your CI secrets entirely. GitHub Actions requests a short-lived OIDC identity token from GitHub, presents it to PyPI, and PyPI issues a temporary upload credential scoped to a single publish run. The credential expires within minutes and cannot be reused.

**Step 1: Configure PyPI project settings**

In your PyPI project under **Manage > Publishing**, add a new trusted publisher:

- **Publisher:** GitHub Actions
- **Owner:** your GitHub organisation or username (exact case)
- **Repository name:** the repository name
- **Workflow filename:** `publish.yml` (the exact filename you will create)
- **Environment name:** `pypi` (recommended — link to a GitHub Actions environment with required reviewers)

**Step 2: Create the GitHub Actions environment**

In the repository settings under **Environments**, create a `pypi` environment. Add required reviewers (at least one maintainer) and restrict it to the `main` branch. This means every publish requires a human approval and can only run from the protected branch.

**Step 3: Publish workflow**

```yaml
# .github/workflows/publish.yml
name: Publish to PyPI
on:
  push:
    tags:
      - "v*"

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b  # v5.3.0
        with:
          python-version: "3.12"

      - name: Build distribution
        run: |
          pip install build==1.2.2
          python -m build

      - name: Upload build artifacts
        uses: actions/upload-artifact@65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08  # v4.6.0
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: pypi          # Links to the GitHub environment with approval gates
    permissions:
      id-token: write          # Required for OIDC token exchange
      contents: read

    steps:
      - name: Download build artifacts
        uses: actions/download-artifact@fa0a91b85d4f404e444fe0e9db940a93e84c8d81  # v4.1.8
        with:
          name: dist
          path: dist/

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc  # v1.12.4
        # No password or token required — OIDC exchange happens automatically
        # Pin to digest, not tag, to prevent tag-hijacking attacks
```

**What you gain:** No `PYPI_TOKEN` in GitHub secrets. No human-generated credential to rotate, leak, or forget to revoke when a maintainer leaves the team. The publish window is five to ten minutes. If a runner is compromised mid-publish, the stolen OIDC token cannot be replayed after expiry.

**Pin the Action by digest:** The `pypa/gh-action-pypi-publish` repository has shipped security fixes as tag updates. Pinning by tag (`@release/v1`) means you receive fixes automatically but also receive any malicious update to the tag. Pin by commit digest and use Dependabot to propose digest updates through a reviewed pull request.

### Dependabot for Python Dependency Updates

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
      day: monday
      time: "06:00"
    open-pull-requests-limit: 10
    groups:
      non-breaking:
        update-types:
          - "minor"
          - "patch"
    ignore:
      # Example: ignore major version bumps that require migration work
      - dependency-name: "django"
        update-types: ["version-update:semver-major"]

  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
    # Dependabot updates Action pins by commit digest, not just tag
```

Dependabot opens a pull request for each dependency update, regenerates `requirements.txt` via pip-compile if you configure it with a custom command, and runs your full CI suite against the update before you merge. This moves dependency updates out of the "I'll do it manually eventually" category and into a reviewable, auditable flow.

### Protecting Against Malicious setup.py and pyproject.toml

Install-time code execution is the most dangerous attack vector in Python packaging. `setup.py` runs arbitrary Python during `pip install`. Even packages that migrate to `pyproject.toml` with a PEP 517 build backend can still run arbitrary code through build hooks.

```bash
# --no-build-isolation is dangerous: do not use it unless you understand the implications.
# It disables the isolated build environment that separates your host tools from the
# package's build system. With --no-build-isolation, the package's setup.py runs with
# access to everything in your current environment.
# NEVER use in CI for untrusted packages.

# Prefer binary wheels over source distributions to avoid setup.py execution:
pip install --only-binary :all: -r requirements.txt

# If source builds are required for specific packages, audit them:
pip download requests --no-deps --dest ./downloads/
# Inspect the downloaded .tar.gz before installing

# For packages that must be built from source, use --no-deps to prevent
# the build system from pulling transitive build dependencies:
# (Review what you're installing before installing it.)
```

**Auditing transitive dependencies:** The packages you list in `requirements.in` are a fraction of what actually installs. `pip-audit` scans the full resolved set. Additionally, tools like `pip-licenses` enumerate every transitive package and its licence — a useful secondary check that tells you exactly what code is in your build.

```bash
pip install pip-licenses
pip-licenses --format=table --with-urls
# Review the full list for unexpected packages or packages you don't recognise.
# An unrecognised package in your transitive graph is worth investigating.
```

## Expected Behaviour

- `pip install --require-hashes -r requirements.txt` passes in CI with no hash mismatches. Any content change to any package — legitimate or malicious — fails the build.
- `pip-audit -r requirements.txt` exits zero (no known CVEs) on every PR merge and weekly schedule.
- `poetry lock --check` passes before every install step, confirming the lock file matches declared dependencies.
- Dependabot opens weekly PRs for dependency updates. Each PR passes pip-audit before merge.
- Publish workflows use OIDC trusted publishing with no `PYPI_TOKEN` in repository secrets.
- All pip installs in CI resolve exclusively through the private PyPI mirror, not directly against pypi.org.
- The GitHub Actions environment for publish requires reviewer approval before the publish job runs.

## Trade-offs

| Control | Benefit | Cost | Mitigation |
|---------|---------|------|------------|
| `--require-hashes` | Detects content tampering in any dependency | Developers must regenerate `requirements.txt` on every dependency change | Use `pip-compile` as a documented workflow. Add a CI check that verifies the generated file matches the committed one. |
| Private PyPI mirror | Controls what packages can install; audit log | Operational overhead of running Nexus/Artifactory | Use a managed service (AWS CodeArtifact, Cloudsmith) to reduce ops burden. |
| OIDC trusted publishing | Eliminates long-lived upload tokens | PyPI project and GitHub environment must be configured correctly, initial setup takes 20–30 minutes | Document the setup procedure. Use the GitHub environment with required reviewers as a second safeguard. |
| `--only-binary :all:` | Prevents setup.py execution | Some packages do not publish wheels; builds fail for those packages | Identify which packages require source builds, audit them individually, add explicit exceptions. |
| Dependabot | Automated dependency updates through a reviewable PR | PR volume can be high on projects with many dependencies | Use Dependabot groups to batch minor/patch updates into one PR per week. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Hash mismatch on install | `pip install --require-hashes` fails with `THESE PACKAGES DO NOT MATCH THE HASHES` | CI build failure at install step | Verify whether the package was legitimately re-released. If yes, regenerate hashes. If no explanation exists for the hash change, treat it as a potential supply chain incident. |
| pip-audit finds a CVE | CI audit job exits non-zero | Audit step failure with CVE details | Upgrade the vulnerable package. If no fix is available, assess exploitability and add a documented `--ignore-vuln` exception with an expiry review date. |
| Trusted publishing OIDC exchange fails | `pypa/gh-action-pypi-publish` fails with a 403 from PyPI | Publish job failure with authentication error in logs | Verify the workflow filename, owner, repository name, and environment name in PyPI project settings exactly match the workflow configuration. Check that the job has `id-token: write` permission. |
| Dependency confusion via `--extra-index-url` | Unexpected package installed from public PyPI | Package appears in pip-audit output from pypi.org rather than your internal registry; unexpected version number | Remove `--extra-index-url`. Use `--index-url` exclusively with your private mirror. Configure the private mirror to block public resolution of internal package names. |
| `poetry lock --check` fails on PR | CI pre-install check fails | Lock file drift check step fails | Developer runs `poetry lock` locally and commits the updated `poetry.lock`. |

## Related Articles

- [Trusted Publishing to npm and PyPI with OIDC](/articles/cicd/trusted-publishing-oidc/)
- [Private Package Registry Security: Dependency Confusion and Namespace Protection](/articles/cicd/private-package-registry-security/)
- [Dependency Pinning and Lockfile Integrity: Preventing Supply Chain Attacks in CI](/articles/cicd/dependency-pinning/)
- [SBOM Generation and Verification in CI Pipelines](/articles/cicd/sbom/)
- [Securing GitHub Actions: Permissions, Pinning, and Workflow Injection Prevention](/articles/cicd/securing-github-actions/)
