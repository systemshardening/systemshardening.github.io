---
title: "npm Lockfile Integrity: What package-lock.json Protects Against (and What It Doesn't)"
description: "Lockfile integrity hashes would not have caught the Axios 1.14.1 attack — the malicious tarball was legitimately published, so the hash was correct. Understand what lockfiles do and don't protect against, enforce npm ci in CI, and detect lockfile tampering."
slug: npm-lockfile-integrity-security
date: 2026-05-04
lastmod: 2026-05-04
category: cicd
tags:
  - supply-chain
  - npm
  - lockfile
  - integrity
  - cicd
personas:
  - platform-engineer
  - security-engineer
article_number: 426
difficulty: Intermediate
estimated_reading_time: 10
published: true
layout: article.njk
permalink: /articles/cicd/npm-lockfile-integrity-security/
---

# npm Lockfile Integrity: What package-lock.json Protects Against (and What It Doesn't)

## The Problem

After the Axios compromise of March 31 2026, a common reaction among platform teams was: "we pin versions in our lockfile, so we're protected." This is partially true and critically incomplete. The `integrity` field in `package-lock.json` is a SHA-512 hash of the package tarball. When the North Korean threat actor Sapphire Sleet published malicious `axios@1.14.1` to the npm registry, the registry computed and published the correct SHA-512 hash for that malicious tarball. Any project that subsequently ran `npm install` and resolved `axios@1.14.1` would have recorded that hash faithfully in its lockfile. A later `npm ci` run would have fetched the tarball, computed its SHA-512, compared it to the lockfile's `integrity` field, found a match, reported a clean install, and executed the embedded remote access trojan.

The lockfile integrity system worked exactly as designed. It verified that the tarball you received from the CDN was the same tarball that was published to the registry. The problem is that the published tarball itself was malicious. The integrity check can only compare reality against the record. When the record was created from a malicious source, the check certifies the compromise.

This matters because the two controls teams most commonly reach for after supply chain incidents — version pinning and lockfile integrity — are both ineffective against the Axios attack pattern. Version pinning (`"axios": "1.14.1"` in `package.json`) and the lockfile's `integrity` hash both assume a trustworthy upstream. They protect against a different class of attack: an attacker modifying a tarball after it was published, either on the CDN, in transit, or in a private registry cache. Against those attacks they are effective. Against a malicious maintainer or a compromised maintainer account publishing a new version, they provide no protection.

The distinction matters because it changes the controls you need. Lockfile enforcement is still essential, but for different reasons than most teams assume. The `npm install` versus `npm ci` difference is more significant than it appears, and the lifecycle script detection problem is almost entirely unaddressed in most CI pipelines.

## Threat Model

**What lockfiles protect against:**

- **CDN tampering.** If an attacker modifies a tarball on the npm CDN after it was published, the SHA-512 of the modified tarball will not match the `integrity` field recorded in your lockfile. `npm ci` detects the mismatch and fails the install. This is a meaningful protection: npm's CDN is a high-value target, and integrity verification is what makes the CDN model safe for package distribution at scale.

- **Version resolution drift.** `npm install` performs dependency resolution on every invocation and can resolve a range constraint like `"^1.13.0"` to a different patch version each time, depending on what has been published since the lockfile was last generated. If you run `npm install` in CI rather than `npm ci`, a new version satisfying the range constraint can be silently pulled mid-build. The lockfile, when enforced, pins the exact version resolved at lockfile-generation time.

- **Dependency confusion.** When a lockfile records a specific resolved URL (`"resolved": "https://registry.npmjs.org/..."`) alongside the integrity hash, a private registry proxy that serves a different package at the same name and version must also serve a different tarball, which means a different hash, which means `npm ci` fails. The lockfile's resolved field and integrity hash together make dependency confusion harder against a build that enforces the lockfile strictly.

**What lockfiles do not protect against:**

- **A malicious version published legitimately by a compromised maintainer account.** This is the Axios attack pattern. The attacker publishes a new version number to the registry using a stolen credential. The tarball is assigned a correct hash by the registry. Any consumer that updates their lockfile — or that runs `npm install` without `--frozen-lockfile` before the compromised version was identified and yanked — will record and subsequently verify the malicious hash. The lockfile is accurate. The problem is upstream.

- **A package whose source was modified before publishing.** If the attack occurs in the build pipeline of the package itself — between the source repository and the `npm publish` invocation — the published tarball contains malicious code and the registry hash reflects that. Downstream lockfiles faithfully record the attack.

- **Transitive dependency compromise in a package whose lockfile you do not control.** Your lockfile records the exact version of every package in your dependency tree, including transitive dependencies. But if a transitive dependency is compromised, the attack propagates through the version you have recorded. Your lockfile pinned the compromised version, not a clean one. The lockfile does not pin the internal composition of the packages it records — only the tarball hash of the top-level resolved artifact.

**The `npm install` versus `npm ci` distinction:**

`npm install` is a development tool. It resolves version ranges, adds new packages, and updates the lockfile to reflect whatever it resolved. When run in CI, it can silently pull a newer version of any dependency whose `package.json` range constraint allows it. A project with `"axios": "^1.13.0"` that runs `npm install` in CI will automatically resolve to `axios@1.14.1` when that version is published, without any human decision or review.

`npm ci` is a CI tool. It reads the lockfile as the authoritative source of truth and installs exactly those versions. It does not update the lockfile. If the lockfile is absent or inconsistent with `package.json`, it fails immediately. If the registry serves a tarball whose hash does not match the lockfile's `integrity` field, it fails the install. A project that runs `npm ci` in CI requires an explicit lockfile update PR before any version change takes effect.

The practical consequence: a CI pipeline using `npm install` was silently exposed to `axios@1.14.1` the moment it was published, with no human review gate. A CI pipeline using `npm ci` could only have been exposed after a developer ran `npm install` locally, observed the updated lockfile, and committed it — a step that, if combined with lockfile review in PRs, creates a human decision point.

## Hardening Configuration

### 1. Always use `npm ci` in CI pipelines

Replace every occurrence of `npm install` in CI workflows with `npm ci`. `npm ci` deletes `node_modules` before installing, installs exactly the versions recorded in `package-lock.json`, fails if the lockfile is absent or inconsistent with `package.json`, and does not modify the lockfile under any circumstances. It is also faster than `npm install` because it skips the dependency resolution step.

```yaml
name: CI

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Test
        run: npm test
```

The `cache: "npm"` setting caches the npm cache directory keyed on the lockfile hash. Because `npm ci` requires the lockfile to be stable, the cache hit rate is high and the speed benefit is retained.

### 2. Commit `package-lock.json` and protect it with branch rules

The lockfile provides no protection if it is not committed to the repository. Ensure `package-lock.json` is tracked in Git and not listed in `.gitignore`. Configure branch protection to require pull request review for changes that modify the lockfile, so that a lockfile update cannot be pushed directly to the main branch.

In GitHub, this is implemented with a CODEOWNERS file:

```bash
package-lock.json @your-org/security-reviewers
```

Add this line to `.github/CODEOWNERS`. Combined with a branch protection rule requiring CODEOWNERS review, any PR that modifies `package-lock.json` will require sign-off from the security reviewers team before it can be merged. A lockfile diff in a PR is a concrete, reviewable signal: it shows exactly which package versions changed, which were added, and which were removed. Reviewers should treat a lockfile change the same way they treat a change to infrastructure code.

### 3. Detect lockfile tampering in CI

After `npm ci` completes, verify that the install process did not modify the lockfile. Under normal operation `npm ci` never modifies the lockfile, but bugs in npm itself or unexpected interactions with `.npmrc` settings have historically caused silent lockfile mutations. Detecting this in CI provides a guard against both npm bugs and any future attack that targets the `npm ci` code path:

```yaml
      - name: Install dependencies
        run: npm ci

      - name: Verify lockfile was not modified
        run: git diff --exit-code package-lock.json
```

`git diff --exit-code` returns a non-zero exit code if there are any changes to the file, which fails the CI step. If this check fails unexpectedly, investigate the npm version and `.npmrc` configuration before assuming an attack.

### 4. Verify package integrity manually for critical dependencies

For high-value direct dependencies — authentication libraries, cryptographic modules, build tools that run with elevated permissions — independently verify that the `integrity` field in your lockfile matches the value the npm registry publishes for that version. This comparison is not a substitute for the checks above, but it provides a sanity check against registry-side metadata manipulation and gives you confidence that your lockfile was not modified locally after the last `npm install`:

```bash
PKG=axios
VERSION=1.14.0
LOCKFILE_HASH=$(node -e "const l=require('./package-lock.json'); console.log(l.packages['node_modules/${PKG}'].integrity)")
REGISTRY_HASH=$(npm view ${PKG}@${VERSION} dist.integrity)
if [ "$LOCKFILE_HASH" = "$REGISTRY_HASH" ]; then
  echo "integrity match: ${PKG}@${VERSION}"
else
  echo "MISMATCH: ${PKG}@${VERSION}"
  echo "  lockfile:  $LOCKFILE_HASH"
  echo "  registry:  $REGISTRY_HASH"
  exit 1
fi
```

Run this script against your highest-value dependencies as part of a scheduled security workflow, not just on each commit. The registry-published hash is authoritative only if the npm registry itself is trustworthy — if the registry was compromised, both values will match the malicious hash. Treat this check as a belt alongside the existing suspenders, not as a replacement.

### 5. Detect new lifecycle scripts in lockfile updates

The most underaddressed vector in npm supply chain attacks is the `postinstall` script. A package update that adds a `scripts.postinstall`, `scripts.install`, or `scripts.prepare` entry to a previously script-free dependency executes arbitrary code during `npm install` and `npm ci` without any explicit user action. Detecting this in CI provides an early warning when a dependency update introduces a new lifecycle hook:

```yaml
name: Lockfile security review

on:
  pull_request:
    paths:
      - "package-lock.json"

jobs:
  check-lifecycle-scripts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          fetch-depth: 0

      - name: Check for new lifecycle scripts in lockfile diff
        run: |
          BASE_BRANCH="${{ github.base_ref }}"
          git fetch origin "$BASE_BRANCH"

          BEFORE=$(git show "origin/${BASE_BRANCH}:package-lock.json" 2>/dev/null || echo '{}')
          AFTER=$(cat package-lock.json)

          NEW_SCRIPTS=$(node -e "
            const before = JSON.parse(process.argv[1]);
            const after = JSON.parse(process.argv[2]);
            const hooks = ['postinstall', 'install', 'preinstall', 'prepare'];
            const results = [];
            for (const [pkg, meta] of Object.entries(after.packages || {})) {
              const beforeMeta = (before.packages || {})[pkg] || {};
              for (const hook of hooks) {
                const hadBefore = !!(beforeMeta.scripts || {})[hook];
                const hasAfter = !!(meta.scripts || {})[hook];
                if (hasAfter && !hadBefore) {
                  results.push(pkg + ' added ' + hook + ': ' + meta.scripts[hook]);
                }
              }
            }
            console.log(results.join('\n'));
          " "$BEFORE" "$AFTER")

          if [ -n "$NEW_SCRIPTS" ]; then
            echo "WARNING: new lifecycle scripts detected in lockfile update:"
            echo "$NEW_SCRIPTS"
            echo ""
            echo "Review these additions before merging. Lifecycle scripts execute"
            echo "during npm ci and may run arbitrary code."
            exit 1
          fi

          echo "No new lifecycle scripts detected."
```

This workflow runs only on PRs that modify `package-lock.json`. It compares the lifecycle script entries in the lockfile before and after the change and fails the check if any package gains a new `postinstall`, `install`, `preinstall`, or `prepare` script that it did not have previously. A failing check requires a human decision to override — either by removing the offending dependency or by explicitly acknowledging the new lifecycle script and merging with a documented rationale.

## Expected Behaviour After Hardening

After `npm ci` enforcement: a CI pipeline that previously ran `npm install` and would have silently resolved `axios@1.14.1` when that version was published now requires an explicit lockfile update PR. The malicious version cannot enter the build without a developer running `npm install` locally, observing the updated lockfile, committing it, and creating a PR — a sequence that, combined with the CODEOWNERS requirement, generates a mandatory review gate.

After lifecycle script detection: a lockfile update PR that includes a package newly gaining a `postinstall` script triggers a failing CI check with the script text printed in the workflow output. The PR cannot be merged until the security reviewers team approves it, and the failing check creates a clear record that the new lifecycle script was reviewed before acceptance.

After integrity verification: a scheduled job comparing lockfile hashes against registry metadata will catch any discrepancy between the `integrity` field committed to the repository and the value the registry reports for the same version. A mismatch indicates either local lockfile modification (an attack against your repository) or a registry-side metadata change (an attack against npm).

## Trade-offs and Operational Considerations

`npm ci` fails on any lockfile inconsistency, including harmless ones caused by running `npm install` on a different Node.js version or operating system. Developers who forget to run `npm install` locally after changing `package.json` will see `npm ci` fail in CI with a lockfile mismatch error. This generates support requests and CI noise. Add a pre-commit hook that detects when `package.json` has changed without a corresponding `package-lock.json` update:

```bash
#!/bin/sh
if git diff --cached --name-only | grep -q "^package\.json$"; then
  if ! git diff --cached --name-only | grep -q "^package-lock\.json$"; then
    echo "package.json changed without package-lock.json update. Run: npm install"
    exit 1
  fi
fi
```

Requiring CODEOWNERS review for every lockfile change slows down routine dependency updates. Teams that depend on Renovate Bot or Dependabot for automated dependency updates should configure auto-merge rules: patch version updates of well-established packages with no new lifecycle scripts and no new transitive dependencies can be auto-merged without human review. Minor and major version updates, updates that add transitive dependencies, and any update that triggers the lifecycle script detection workflow should require explicit human sign-off.

The lifecycle script detection script checks for new scripts in the lockfile diff but does not check the content of scripts that already existed in the previous lockfile. If a package had a `postinstall` script before the update and the update changes that script's content to something malicious, this check will not flag it. Extend the script to also compare the content of existing lifecycle scripts between versions for high-value dependencies.

## Failure Modes

- **`npm ci` used in CI but `npm install` used in Dockerfile builds.** Docker image builds that run `npm install` without a `--frozen-lockfile`-equivalent flag can silently pull new dependency versions at image build time, bypassing the lockfile enforcement in the CI workflow. Replace `npm install` with `npm ci` in every Dockerfile that installs npm dependencies.

- **Lockfile committed but not protected by CODEOWNERS rules.** Without a CODEOWNERS entry covering `package-lock.json`, developers on teams with direct push access to feature branches can update the lockfile without review. The lockfile review requirement only works if it is enforced by branch protection. Verify that the CODEOWNERS assignment and the branch protection requirement for CODEOWNERS review are both active.

- **Lifecycle script detection only checks direct packages in the lockfile.** The detection script above inspects the `packages` map in `package-lock.json`, which includes transitive dependencies. However, the script compares the entire `packages` map between the base branch and the PR branch. If a transitive dependency is entirely new to the tree — its package name does not appear in the base lockfile at all — the `beforeMeta` lookup returns an empty object and the comparison correctly identifies any lifecycle scripts as new. This case is covered. The gap is when a PR removes a package from the tree: the removed package's lifecycle scripts are not flagged because they are absent from the `after` set. This is the correct behaviour, but reviewers should separately confirm that removed packages are genuinely removed and not replaced by a similarly named package with a lifecycle script.

- **`git diff --exit-code` check run before `npm ci`.** The lockfile tampering check only catches modifications made by `npm ci` if it runs after `npm ci`. Placing it before the install step verifies the lockfile matches the committed version at checkout, which is a different and less useful check. Ensure the step ordering in the workflow matches section 3 above.

## Related Articles

- [Dependency Pinning](/articles/cicd/dependency-pinning/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
- [Private npm Registry Supply Chain](/articles/network/private-npm-registry-supply-chain/)
- [Artifact Integrity](/articles/cicd/artifact-integrity/)
- [npm Package Integrity Verification](/articles/cross-cutting/npm-package-integrity-verification/)
