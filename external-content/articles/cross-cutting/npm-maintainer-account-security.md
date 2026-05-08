---
title: "npm Maintainer Account Security and the Ecosystem Trust Model"
description: "The Axios attacker needed only one thing: a stolen npm token. The ecosystem trust model concentrates enormous risk in individual maintainer accounts. Harden yours with FIDO2, endpoint security, and token hygiene — and reduce consumer exposure with lockfiles and provenance verification."
slug: npm-maintainer-account-security
date: 2026-05-03
lastmod: 2026-05-03
category: cross-cutting
tags:
  - supply-chain
  - npm
  - account-security
  - ecosystem-trust
  - fido2
personas:
  - security-engineer
  - platform-engineer
article_number: 421
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cross-cutting/npm-maintainer-account-security/
---

# npm Maintainer Account Security and the Ecosystem Trust Model

## The Problem

The Axios package has 3 maintainers and 100 million weekly downloads. Compromising one maintainer account was sufficient to reach every JavaScript developer globally who ran `npm install axios` during a 3-hour window on March 31 2026. The attack — attributed to North Korean threat actor Sapphire Sleet (also tracked as UNC1069) — did not exploit a vulnerability in the npm registry software, a flaw in the Axios codebase, or a misconfiguration in CI infrastructure. It exploited the npm ecosystem's fundamental trust model: a maintainer's authentication token is sufficient to publish any version of any package they maintain, with no secondary approval, no code review, and — if the package did not have `--require-2fa` set — no second factor required at publish time.

The `latest` dist-tag is the attack surface that makes this dangerous at scale. When a developer runs `npm install axios` without specifying a version, npm resolves `latest` — a mutable pointer that any maintainer can advance with a single publish. Moving `latest` to a malicious version takes under a minute. Rolling it back requires detecting the attack first, which in the Axios case took approximately 3 hours. During that window, every `npm install axios` without a pinned version or a lockfile-committed exact hash pulled the compromised package.

This is a structural property of the npm ecosystem, not a one-time failure. npm's registry is a centralised, trust-on-first-use system. Maintainers publish directly without code review. The `latest` tag is the default resolution for every unversioned install. A single stolen token is a single point of failure for every downstream consumer of that package.

Compare this to two alternative models. On **crates.io** (Rust), packages have a separate `owners` list distinct from the package's source contributors, and publish tokens are scoped per-crate — a token for `serde` cannot publish to `tokio`. As of 2026, crates.io is implementing Trusted Publishing via OIDC, where the publish token is issued ephemerally to a verified CI workflow rather than stored as a long-lived secret on a developer machine. On **PyPI**, the Trusted Publishing model is already production-standard: packages linked to a GitHub Actions workflow receive a short-lived OIDC token at CI publish time, removing the stored-token vector entirely. PyPI also requires TOTP 2FA on accounts that maintain packages above a download threshold. npm has announced improvements to 2FA enforcement and expanded Trusted Publishing support in response to the Axios incident, but as of May 2026 it does not mandate hardware-key 2FA for maintainers of high-download packages, and the Trusted Publishing requirement covers only a fraction of the registry's package count.

**Target systems:** npm registry maintainers; engineering teams consuming npm packages in production CI; security engineers responsible for supply chain policy.

## Threat Model

- **Stolen npm authentication token from a compromised developer machine.** The npm CLI stores tokens in `~/.npmrc` in plaintext. Malware with read access to the home directory — including info-stealer malware of the type Sapphire Sleet deployed on the Axios maintainer's PC — can exfiltrate the token without any additional exploitation. The stolen token is then sufficient to run `npm publish` from the attacker's own machine.
- **Malware targeting `~/.npmrc` specifically.** Sapphire Sleet has a documented pattern of targeting open source maintainers with job-offer phishing that delivers infostealer payloads designed to harvest developer credentials, SSH keys, and secrets stored in dotfiles. The `~/.npmrc` token is a high-value target because it gates publish access without requiring the maintainer's account password or 2FA.
- **`latest` dist-tag hijack.** A single `npm publish` from the attacker's session moves `latest` to the malicious version. All consumers without a pinned lockfile are affected immediately. The attack surface scales with the package's weekly download count, not with the attacker's infrastructure.
- **Package maintainer with access to multiple high-value packages.** A single npm account that maintains several popular packages is a single point of failure for all of them. The Axios maintainer account held publish rights to multiple packages; a token from that account could have been used against any of them.
- **Social engineering targeting maintainers directly.** Beyond malware, Sapphire Sleet uses convincing fake recruiter approaches on LinkedIn and email to deliver malicious interview-prep documents or repositories. The initial access is low-tech; the token theft is automated once the endpoint is compromised.
- **Access level for the attacker:** authenticated npm session with full publish rights to any package the maintainer controls. No registry vulnerability required; no insider access needed; no review process to bypass.

## Hardening Configuration

### 1. FIDO2 Hardware Key for the npm Account

A FIDO2 hardware security key (YubiKey, Google Titan, or equivalent) enrolled as the 2FA method on the npm account converts the stolen-token scenario from "publish succeeds silently" to "publish blocked by a 401 that requires physical key presence." A stolen `~/.npmrc` token alone is insufficient — the registry demands a FIDO2 challenge response that only the physical key can answer.

Two distinct enforcement points exist on npm. The first is account-level 2FA, which protects login and the web console. The second — and the one that matters for publish — is the per-package `--require-2fa` flag:

```bash
# Enrol a FIDO2 key on the npm account.
# This is done via the npm website under Account Settings > Two-Factor Authentication.
# After enrolment, verify the account-level 2FA status from the CLI:
npm profile get

# List all packages you maintain:
npm access list packages <your-username>

# Enable publish-time 2FA requirement on a package.
# Without this, account-level 2FA protects login but NOT publish.
npm access set mfa=require <package-name>

# Verify the 2FA requirement is active on the package:
npm access get mfa <package-name>
```

The critical detail: account-level 2FA protects `npm login` and website access but does not automatically protect `npm publish`. The `mfa=require` setting on the package is the control that blocks a stolen token from being used to publish. Both must be in place.

For organisations maintaining multiple packages, automate the audit:

```bash
npm access list packages <your-username> \
  | jq -r 'keys[]' \
  | while read pkg; do
      status=$(npm access get mfa "$pkg" 2>/dev/null)
      echo "$pkg: $status"
    done
```

Any package reporting `mfa=none` or `mfa=false` is a gap. Set `mfa=require` on all of them before a stolen token becomes a successful publish.

### 2. Protect the npm Token on the Developer Machine

npm stores the authentication token in `~/.npmrc` in plaintext. On a compromised machine, a file read is all an attacker needs:

```bash
cat ~/.npmrc
# //registry.npmjs.org/:_authToken=npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

The first mitigation is to never use a publish-capable token for local development. Generate a read-only token for day-to-day npm usage:

```bash
# Create a read-only token for local development.
# A read-only token cannot be used to publish, even if stolen.
npm token create --read-only

# List all active tokens on the account:
npm token list

# Revoke a specific token by its ID:
npm token revoke <token-id>
```

With a read-only token in `~/.npmrc`, a stolen credential can download packages but cannot publish. The publish-capable token is reserved for the publish workflow, issued via a FIDO2-protected session, and rotated after each release.

For teams that want to avoid storing any token on disk, configure npm to use the system keychain via a credential helper. On macOS, the keychain is available natively; on Linux, configure `secret-tool` or `pass`:

```bash
# macOS: configure npm to read from Keychain instead of .npmrc.
npm config set keychain=true

# Linux with pass (password store): set a helper script as the auth provider.
npm config set _authToken "$(pass show npm/publish-token)"
```

Rotate publish tokens on a quarterly schedule. Set a calendar reminder. A compromised token that was rotated three months ago has a finite exposure window; one that is three years old does not.

### 3. Endpoint Security for Maintainer Machines

The Axios attacker gained access to the maintainer's PC first, then harvested the npm token. The token theft was a consequence of endpoint compromise. Hardening the endpoint reduces the probability that a phishing attempt or malicious repository succeeds in establishing a foothold.

**Full disk encryption.** Ensures that physical access to the device — including theft or confiscation — does not expose the `~/.npmrc` token or other credentials at rest. On Linux, enable LUKS at installation time. On macOS, verify FileVault is active:

```bash
fdesetup status
```

**Hardware-key login for the machine itself.** If the developer's workstation login is protected by a FIDO2 key, an attacker who obtains the user's password cannot log in remotely (via SSH) to harvest dotfiles. Configure SSH to require a hardware-key-backed key:

```bash
# Generate an ed25519-sk key backed by a FIDO2 hardware token.
ssh-keygen -t ed25519-sk -f ~/.ssh/id_ed25519_sk

# The resulting key requires physical key presence for every use.
# A stolen private key file without the hardware key produces an authentication failure.
```

**Application allowlisting.** Prevent unknown executables from running. On Linux, use `systemd` service hardening and eBPF-based tools to block execution of unsigned or unexpected binaries. On macOS, Gatekeeper with `--require-notarization` and an MDM profile restricting unsigned execution reduces the chance that a malicious interview-prep script runs to completion.

**Browser isolation for high-risk browsing.** Open source maintainers frequently review pull requests, dependency links, and repository invitations from unknown contributors. Browser isolation (Chromium-based profiles with no saved credentials, or a dedicated browser VM) limits the blast radius of a malicious link in a PR description.

For deeper endpoint hardening guidance, see the endpoint hardening and Linux workstation security articles in this series.

### 4. Consumer-Side Mitigations

As a consumer of npm packages, you cannot control the security posture of package maintainers. You can reduce your exposure to a maintainer account compromise that you cannot see coming.

**Pin exact versions with a committed lockfile and use `npm ci` in CI.**

```bash
# Generate or update the lockfile:
npm install

# Commit package-lock.json alongside package.json.
git add package-lock.json
git commit -m "pin dependency lockfile"

# In CI, always use npm ci, not npm install.
# npm ci installs exactly the versions in the lockfile.
# If the lockfile is out of sync with package.json, npm ci fails rather than updating.
npm ci
```

A `latest` dist-tag hijack does not affect a CI pipeline that runs `npm ci` against a committed `package-lock.json`. The lockfile pins the exact tarball URL and its SHA-512 integrity hash. A newly-published malicious version that moves `latest` is invisible to a pipeline that never resolves `latest` — it installs the version committed in the lockfile. The attack surface exists only at the moment when someone runs `npm update` or `npm install` without a lockfile, and a malicious version is present in that window.

**Verify provenance attestations with `npm audit signatures`.**

```bash
# After npm ci, verify that installed packages have valid provenance attestations.
npm audit signatures
```

Example output for packages with provenance:

```bash
audited 847 packages in 3s

847 packages have verified registry signatures

1 package has a missing provenance attestation
  axios@1.14.1
```

The malicious Axios versions published by Sapphire Sleet did not carry a provenance attestation — they were published from the attacker's machine, not from the legitimate CI workflow that normally produces the signed build. `npm audit signatures` surfaces this as "missing provenance." In an environment where you have established that critical packages should have provenance, a missing attestation is a signal warranting investigation before the build continues.

**Monitor dist-tag changes on critical dependencies.**

```bash
# Query the npm registry API for the current dist-tag state of a package.
curl -s https://registry.npmjs.org/axios | jq '."dist-tags"'

# Compare against the version you have pinned in package-lock.json.
# A change to the "latest" tag that you did not initiate is a signal.
# Automate this check with a scheduled cron job or a monitoring script.
node -e "
  const http = require('https');
  http.get('https://registry.npmjs.org/axios', res => {
    let data = '';
    res.on('data', d => data += d);
    res.on('end', () => {
      const meta = JSON.parse(data);
      console.log('latest:', meta['dist-tags']['latest']);
    });
  });
"
```

Alerting when `latest` for a critical dependency moves to a version you have not reviewed provides advance warning of a hijack within minutes rather than hours.

### 5. Ecosystem Comparison and npm's Remaining Gaps

The npm ecosystem's architecture concentrates risk in individual maintainer tokens in ways that other registries have partially addressed.

**crates.io (Rust):** Publish tokens are per-crate. A token for `serde` cannot publish to `tokio`. As of 2026, crates.io is rolling out Trusted Publishing via OIDC, where the publish credential is a short-lived token issued to a verified GitHub Actions workflow — the token never exists on a developer's filesystem. Even without Trusted Publishing, the per-crate scoping limits blast radius: a stolen token affects only the crates it was scoped to, not everything the developer maintains.

**PyPI (Python):** Trusted Publishing is production-stable and the recommended publish method for new projects. The OIDC flow works as follows: a GitHub Actions workflow presents its GitHub-issued OIDC token to PyPI; PyPI exchanges it for a short-lived upload credential; the workflow uploads the package; the credential expires within minutes. There is no persistent token on disk. PyPI additionally requires TOTP 2FA on accounts that control packages above a download threshold. The Trusted Publishing model closes the stored-token theft vector completely for packages enrolled in it.

**npm's response to the Axios incident:** npm (GitHub/Microsoft) announced a phased rollout of mandatory 2FA for maintainers of packages with high download counts and expanded Trusted Publishing support via OIDC for GitHub Actions. As of May 2026, mandatory hardware-key 2FA is not yet required for all high-download maintainers. Trusted Publishing on npm is available but opt-in. The per-package `mfa=require` setting exists but is not defaulted to `true` for existing packages with large download counts. These gaps mean the structural vulnerability that enabled the Axios attack remains present for the majority of high-download packages on the registry.

## Expected Behaviour After Hardening

After hardware-key 2FA is enabled at the account level and `mfa=require` is set on the package, an attacker who has obtained the stolen `~/.npmrc` token runs `npm publish` from their machine. The npm registry returns a 401. The response body indicates that the request requires an OTP. The attacker cannot supply the FIDO2 challenge response without the physical hardware key. The publish fails. No malicious version reaches the registry.

After a pinned lockfile and `npm ci` in CI, a `latest` dist-tag hijack to a malicious version does not affect the build. The CI pipeline installs exactly the version recorded in `package-lock.json`, including the integrity hash. The malicious version is not downloaded, not installed, and not executed. The attack is contained entirely to environments that run `npm install` or `npm update` without a committed lockfile during the exposure window.

After running `npm audit signatures`, a package published without a provenance attestation — as the malicious Axios versions were — shows "missing provenance" in the output. In a policy-enforced environment, this fails the build before any malicious code can execute.

## Trade-offs and Operational Considerations

Hardware-key 2FA for publish is incompatible with fully automated release pipelines where `npm publish` runs in a CI job with no human present to touch the FIDO2 key. The correct solution is not to disable `mfa=require` but to use npm's OIDC Trusted Publishing for CI releases. The CI workflow receives an ephemeral credential from npm via GitHub Actions' OIDC token, uses it to publish, and the credential expires. The maintainer's personal hardware-key-protected account is never involved in the automated publish. The `mfa=require` setting on the package then applies only to non-OIDC publish attempts, which is the attacker's scenario.

If Trusted Publishing is not yet available for your CI provider, npm supports automation tokens:

```bash
# Create an automation token. Automation tokens bypass 2FA by design — necessary for CI.
# Scope them narrowly and restrict by CIDR where possible.
npm token create --type=automation
```

Automation tokens must be treated as high-value secrets: stored in the CI provider's secrets store, never committed, and rotated regularly. They should be scoped to the minimum set of packages the pipeline needs to publish and, where the CI provider supports it, tied to CIDR ranges matching the runner's IP space. A leaked automation token does not require a FIDO2 key to publish, which is why their distribution must be tightly controlled.

Protecting `~/.npmrc` with a credential helper adds configuration complexity. Document the setup in the team's developer environment guide. The credential helper approach is most effective when it is the default for all developers; a single developer who bypasses it and stores a publish token in `~/.npmrc` reintroduces the risk.

Consumer-side lockfile pinning reduces agility for dependency updates. A malicious version published while `latest` is pinned away from it does not affect builds, but a legitimate security update to a dependency also does not automatically propagate. Establish a review process for `package-lock.json` updates: treat them as code changes that require a review step, confirm that `npm audit signatures` passes after the update, and merge on a regular cadence rather than leaving them unbounded.

## Failure Modes

**2FA enabled on the npm account but `mfa=require` not set on the package.** Account-level 2FA protects `npm login` and the web console. It does not protect `npm publish` unless the per-package `mfa=require` flag is explicitly set. This is the most common misconfiguration: a maintainer believes their account is protected by 2FA and is correct about login, but a stolen token can still publish to any package that lacks the `mfa=require` flag.

**Automation token in CI set to `--type=automation` without CIDR restriction and without scope limitation.** Automation tokens bypass 2FA by design — that is their purpose. A leaked automation token with no CIDR restriction and no package scoping is functionally equivalent to a stolen personal publish token. If the CI secrets store is compromised or the token is accidentally logged, an attacker can publish to all packages the token covers from any IP address.

**Consumer pinned to exact version in `package-lock.json` but CI runs `npm install` instead of `npm ci`.** The `npm install` command can update the lockfile if the exact version is not cached or if the lockfile format has changed. In the scenario where a malicious version has been published and a developer has run `npm update` locally, committing the resulting `package-lock.json` and then running `npm install` in CI can silently pull the updated (malicious) version into the build. `npm ci` refuses to proceed if the lockfile does not exactly match `package.json` and does not update the lockfile during install — it fails loudly instead.

**`npm audit signatures` run but provenance policy not enforced.** Running `npm audit signatures` and observing "missing provenance" without failing the build or triggering an alert provides no protection. The output must be acted on: either the pipeline exits on missing provenance for packages that should have it, or the result is forwarded to a monitoring system that pages on unexpected gaps. Detection without enforcement is not a control.

## Related Articles

- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
- [OpenSSF Scorecard Supply Chain](/articles/cross-cutting/openssf-scorecard-supply-chain/)
- [Dependency Pinning](/articles/cicd/dependency-pinning/)
- [Software Supply Chain Third-Party Risk](/articles/cicd/software-supply-chain-third-party-risk/)
- [Secrets Rotation Orchestration](/articles/cross-cutting/secrets-rotation-orchestration/)
