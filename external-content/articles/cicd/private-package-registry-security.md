---
title: "Private Package Registry Security: Dependency Confusion and Namespace Protection"
description: "Dependency confusion attacks exploit the gap between private package names and public registries. Private registries with scope enforcement, upstream proxying, and integrity verification close the gap."
slug: "private-package-registry-security"
date: 2026-04-30
lastmod: 2026-04-30
category: "cicd"
tags: ["supply-chain", "npm", "pypi", "registry", "dependency-confusion"]
personas: ["platform-engineer", "security-engineer", "sre"]
article_number: 258
difficulty: "intermediate"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/cicd/private-package-registry-security/index.html"
---

# Private Package Registry Security: Dependency Confusion and Namespace Protection

## Problem

In 2021, Alex Birsan demonstrated that publishing a public package with the same name as a private internal package causes many build tools to prefer the public version — even when developers intend to install the internal one. This dependency confusion attack doesn't require compromising anyone; it exploits a design assumption in npm, pip, and Maven that the highest version number wins, regardless of registry source.

The attack surface is straightforward:

1. An attacker discovers the name of your internal npm package (from a `package.json` committed to a public repo, a job posting, or a leaked artifact).
2. The attacker publishes a package with that name to `registry.npmjs.org` at a high version number (e.g., `99.0.0`).
3. A CI build runs `npm install`. The build tool checks both your private registry and npmjs.org. It finds version `99.0.0` on npmjs.org and installs it.
4. The malicious package runs its `postinstall` script, exfiltrating environment variables, reading files, or establishing a reverse shell.

Beyond dependency confusion, private registries face:

- **Typosquatting:** Public packages with names one character off from legitimate dependencies (`express` → `expres`, `lodash` → `1odash`).
- **Stale upstream proxying:** A private registry caches a version of a public package. The public package is later found to contain malware; the cached version persists.
- **Unauthenticated package downloads:** An internal registry without auth exposes proprietary code to anyone on the network.
- **No integrity verification:** Packages downloaded from upstream are not hash-verified; a MITM can substitute content.

**Target systems:** Artifactory 7.x, Nexus Repository 3.x, AWS CodeArtifact, GitHub Packages, npm/pip/Maven clients in CI; Verdaccio 5.x (lightweight npm registry).

## Threat Model

- **Adversary 1 — Dependency confusion via public registry:** An attacker publishes a high-version package matching an internal package name to the public registry. Build tools resolve it over the internal version.
- **Adversary 2 — Typosquatting attack:** A developer mistypes a package name in `package.json`. The mistyped name exists on the public registry with a malicious `postinstall` script.
- **Adversary 3 — MITM on upstream proxy:** An attacker intercepts the request from the private registry to the public registry and substitutes a malicious tarball. Without integrity verification, the substitution is undetected.
- **Adversary 4 — Stale cached malicious package:** A legitimate public package is updated to include malicious code. The private registry cached the clean version; when cache expires, it fetches the malicious version.
- **Adversary 5 — Unauthenticated internal package read:** A developer's internal package (containing proprietary code) is hosted on an unauthenticated private registry. Any internal network user can download it.
- **Access level:** Adversaries 1 and 2 have public internet access to publish packages. Adversary 3 has network MITM capability between the registry and upstream. Adversary 4 has compromised the upstream public registry. Adversary 5 has internal network access.
- **Objective:** Execute code in CI environments, exfiltrate secrets, steal proprietary source code.
- **Blast radius:** A dependency confusion attack with `postinstall` execution runs arbitrary code in CI with full environment access — all secrets, tokens, and source code in the build environment are at risk.

## Configuration

### Step 1: Namespace All Internal Packages

The single most impactful defence: every internal package must use a scoped name that cannot be claimed on the public registry.

**npm:**

```json
// package.json — internal packages always use an org scope.
{
  "name": "@myorg/payments-client",   // @myorg is reserved by your org on npmjs.
  "version": "1.2.3"
}
```

Register your scope on npmjs.org (even if you never publish there):

```bash
# Reserve the @myorg scope on npmjs.org. This prevents anyone else from publishing
# packages under your scope — even if you never use it publicly.
npm login
npm org create myorg
# Set scope to private: no packages in @myorg can be published publicly.
```

**Python:**

```
# Prefix internal packages with your org namespace.
myorg-payments-client==1.2.3    # Not just "payments-client"
myorg-core==2.0.1
```

**Maven:**

```xml
<!-- Use your organisation's registered GroupId -->
<groupId>com.myorg.payments</groupId>
<artifactId>payments-client</artifactId>
```

Audit existing internal packages for unscoped names:

```bash
# Find all unscoped npm packages in your private registry.
curl -s https://registry.internal/api/packages | jq '.[] | select(.name | startswith("@") | not) | .name'
```

### Step 2: Configure Registry Priority and Blocking

Prevent build tools from falling back to public registries for internal package names.

**npm — always-auth and registry locking:**

```
# .npmrc (committed to the repo)
@myorg:registry=https://registry.internal
//registry.internal/:always-auth=true

# For projects with ONLY internal deps, use registry lockdown:
registry=https://registry.internal
# No fallback to npmjs.org for anything.
```

**Artifactory — virtual repository with priority:**

```bash
# In Artifactory: create a virtual npm repository that resolves in order:
# 1. Internal local repository (highest priority — always check here first).
# 2. Remote repository (proxied npmjs.org) — only if not found internally.

# Critical: enable "Exclude Patterns" for internal package names on the remote repo.
# Pattern: @myorg/* → never fetch from public registry, regardless of version.
```

Configure this via the Artifactory API:

```bash
curl -X PUT \
  -u admin:<password> \
  -H "Content-Type: application/json" \
  -d '{
    "key": "npm-virtual",
    "rclass": "virtual",
    "packageType": "npm",
    "repositories": ["npm-local", "npm-remote"],
    "defaultDeploymentRepo": "npm-local",
    "externalDependenciesEnabled": true,
    "externalDependenciesPatterns": ["**"],
    "externalDependenciesRemoteRepo": "npm-remote",
    "artifactoryRequestsCanRetrieveRemoteArtifacts": true,
    "keyPair": "npm-signing-key"
  }' \
  https://artifactory.internal/artifactory/api/repositories/npm-virtual
```

**AWS CodeArtifact — upstream block for internal namespaces:**

```bash
# Create a domain and repository.
aws codeartifact create-domain --domain myorg
aws codeartifact create-repository \
  --domain myorg \
  --repository internal \
  --description "Internal packages only"

# Add upstream to npmjs (public proxy).
aws codeartifact create-repository \
  --domain myorg \
  --repository npmjs-proxy \
  --upstreams '[{"repositoryName": "npmjs"}]'

# Associate public as upstream of internal.
aws codeartifact update-repository \
  --domain myorg \
  --repository internal \
  --upstreams '[{"repositoryName": "npmjs-proxy"}]'

# Block: any @myorg-scoped package must come from internal, not npmjs.
aws codeartifact put-package-origin-configuration \
  --domain myorg \
  --repository internal \
  --format npm \
  --namespace myorg \
  --package '*' \
  --restrictions '{"publish": "ALLOW", "upstream": "BLOCK"}'
```

With `upstream: BLOCK` for the `@myorg` namespace, CodeArtifact will never fetch `@myorg/*` packages from the public npmjs upstream — only from your internal repository.

### Step 3: pip — Private Index and --no-index Pinning

```ini
# pip.conf or pyproject.toml [tool.pip]
[global]
index-url = https://pypi.internal/simple/
extra-index-url = https://pypi.org/simple/

# DANGEROUS: extra-index-url means pip checks both; the highest version wins.
# Use with caution; prefer --no-index for purely internal packages.
```

The safe pattern for internal packages:

```bash
# Internal packages: --no-index means don't check PyPI at all.
pip install --no-index --find-links https://pypi.internal/packages/ myorg-payments-client

# Or: use a private index that proxies PyPI but blocks internal names from PyPI.
# Configure the private registry (Artifactory/Nexus) to block specific packages from upstream.
```

```toml
# pyproject.toml — specify exact source for each package.
[[tool.uv.index]]
name = "internal"
url = "https://pypi.internal/simple/"
priority = primary

[[tool.uv.index]]
name = "pypi"
url = "https://pypi.org/simple/"
priority = supplemental   # Only if not found internally.
```

### Step 4: Integrity Verification

Verify packages against known-good hashes, not just version numbers:

**npm:**

```bash
# package-lock.json contains SHA-512 integrity hashes for every package.
# npm verifies these at install time automatically if package-lock.json exists.
# NEVER run npm install --legacy-peer-deps or with --ignore-scripts in production builds.

# Verify the lockfile integrity explicitly.
npm ci   # Uses package-lock.json exactly; fails if it's inconsistent.
# NOT: npm install  # Allows lockfile updates.
```

**pip:**

```
# requirements.txt with hashes.
myorg-payments-client==1.2.3 \
    --hash=sha256:abc123...def456 \
    --hash=sha256:789abc...012def
```

Generate hash-pinned requirements:

```bash
pip-compile requirements.in --generate-hashes -o requirements.txt
```

**Maven:**

```xml
<!-- maven-dependency-plugin: verify artifact checksums. -->
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-dependency-plugin</artifactId>
  <executions>
    <execution>
      <goals>
        <goal>verify</goal>
      </goals>
      <configuration>
        <requireChecksum>true</requireChecksum>
        <checksumAlgorithm>SHA-256</checksumAlgorithm>
      </configuration>
    </execution>
  </executions>
</plugin>
```

### Step 5: Postinstall Script Controls

`postinstall` scripts in npm packages execute arbitrary code during `npm install`. Disable or sandbox them in CI:

```bash
# Disable all lifecycle scripts in CI (prevents postinstall execution).
npm ci --ignore-scripts

# Then run only known-safe build steps explicitly.
npm run build
```

For packages that legitimately need postinstall (native modules):

```bash
# Use an allowlist: only permit postinstall from specific trusted packages.
# Verify via lockfile that the package version hasn't changed unexpectedly.
npm ci --ignore-scripts
# Run only the specific packages' postinstall scripts if needed:
npm rebuild <native-package-name>
```

### Step 6: Registry Authentication

Every registry access (download and upload) must require authentication:

```bash
# AWS CodeArtifact: token-based auth (tokens expire after 12h).
export CODEARTIFACT_TOKEN=$(aws codeartifact get-authorization-token \
  --domain myorg \
  --query authorizationToken \
  --output text)

npm config set //myorg-account.d.codeartifact.us-east-1.amazonaws.com/npm/internal/:_authToken=$CODEARTIFACT_TOKEN

# Artifactory: use API key stored in CI secrets, not username/password.
npm config set //registry.internal/:_authToken=${ARTIFACTORY_TOKEN}
```

In CI (GitHub Actions):

```yaml
- name: Configure npm registry
  run: |
    echo "@myorg:registry=https://registry.internal" >> .npmrc
    echo "//registry.internal/:_authToken=${NPM_TOKEN}" >> .npmrc
  env:
    NPM_TOKEN: ${{ secrets.INTERNAL_NPM_TOKEN }}
```

### Step 7: Scanning for Confused Dependencies

Regularly audit which packages in your builds come from public vs internal registries:

```bash
# npm: show where each package resolves from.
npm ls --all --json 2>/dev/null | jq '.dependencies | to_entries[] | {name: .key, resolved: .value.resolved}'

# Flag any @myorg package resolving to npmjs.org (should always be from internal registry).
npm ls --all --json | jq -r '
  def walk_deps:
    .dependencies? // {} | to_entries[] | .value as $v |
    if ($v.resolved // "") | contains("registry.npmjs.org") and (.key | startswith("@myorg"))
    then {name: .key, resolved: $v.resolved}
    else $v | walk_deps
    end;
  walk_deps
'
```

Add to CI:

```bash
# Fail the build if any internal package resolves from the public registry.
CONFUSED=$(npm ls --all --json | python3 -c "
import json, sys
data = json.load(sys.stdin)
# Walk deps recursively and find @myorg packages from npmjs.org
# ... (full implementation)
")
if [ -n "$CONFUSED" ]; then
  echo "Dependency confusion detected: $CONFUSED"
  exit 1
fi
```

### Step 8: Telemetry

```
registry_package_download_total{registry, package, version, source}   counter
registry_confusion_attempt_detected_total{package}                    counter
registry_auth_failure_total{registry, user}                           counter
registry_integrity_verification_failure_total{package, version}       counter
ci_postinstall_script_blocked_total{package}                          counter
```

Alert on:

- `registry_confusion_attempt_detected_total` non-zero — a build tried to pull an internal package from the public registry.
- `registry_integrity_verification_failure_total` — package hash mismatch; possible supply chain attack.
- A new package version appearing in your lockfile from an unexpected registry — review before merging.

## Expected Behaviour

| Signal | No private registry controls | Hardened registry |
|--------|------------------------------|------------------|
| Internal package name on public registry | Malicious version installed | Blocked; only internal source allowed for `@myorg` namespace |
| `postinstall` script execution in CI | Runs with full CI environment | Blocked by `--ignore-scripts` |
| Package integrity | Not verified | Hash-pinned via lockfile; fails on mismatch |
| Registry fallback for internal names | Falls back to npmjs.org | Blocked at registry and client config level |
| Unauthenticated download | Allowed | 401 on all registry endpoints |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| `--ignore-scripts` in CI | Blocks malicious postinstall | Some legitimate native modules need postinstall | Run specific `npm rebuild` for known-safe packages after install. |
| Hash-pinned requirements | Detects substitution immediately | Requires lockfile updates for every version bump | Automate via Renovate/Dependabot; hash update is a diff-visible change. |
| Namespace scoping | Blocks public registry fallback | Must rename existing unscoped internal packages | Do once; update all internal consumers; set a deprecation period. |
| Blocking upstream for internal namespace | Prevents confusion attack completely | Packages from that namespace can only come from internal | Correct behaviour; the whole point is that internal packages should never come from public. |
| CI token expiry (12h for CodeArtifact) | Short-lived credentials | Token must be refreshed at build start | Add a `pre-build` step to refresh the token. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Internal package not published | Build fails: package not found | CI build error; `npm install` 404 | Publish the package to the internal registry; check version matches requirement. |
| Registry token expired | Build fails with 401 | CI error: authentication required | Refresh the token; in CodeArtifact, add a pre-build step to call `get-authorization-token`. |
| Hash mismatch after upstream package update | `pip install` fails: hash mismatch | CI error: hash mismatch | Regenerate `requirements.txt` with `pip-compile --generate-hashes`; review the new hash. |
| Scope not reserved on public npmjs | Attacker publishes `@myorg/package` to npmjs | Confusion attack possible | Register the scope immediately; set all packages in scope to private. |
| `--ignore-scripts` breaks native module | Build fails: `.node` file missing | CI error: cannot find module; missing `.node` file | Add specific `npm rebuild <package>` after install for that package. |
| Registry proxy caches malicious version | Stale malicious version served after upstream incident | Hash mismatch or behaviour anomaly | Purge the cached version from the proxy; update lockfile; pin the known-good hash. |

## Related Articles

- [Dependency Pinning and Integrity Verification](/articles/cicd/dependency-pinning/)
- [Sigstore Keyless Signing and Cosign Verification](/articles/cicd/sigstore-keyless-signing/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [GitHub Advanced Security](/articles/cicd/github-advanced-security/)
- [Container Registry Security](/articles/cicd/container-registry-security/)
