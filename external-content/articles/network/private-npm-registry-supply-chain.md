---
title: "Private npm Registry as Supply Chain Control: Blocking the Axios Attack Pattern"
description: "A private npm registry proxy with version approval workflows would have blocked Axios 1.14.1 before it reached any developer. Configure Verdaccio with version allowlists, approval gates, and integrity verification to make future attacks need to compromise your registry too."
slug: private-npm-registry-supply-chain
date: 2026-05-04
lastmod: 2026-05-04
category: network
tags:
  - supply-chain
  - npm
  - private-registry
  - verdaccio
  - network-security
personas:
  - platform-engineer
  - security-engineer
article_number: 425
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/network/private-npm-registry-supply-chain/
---

# Private npm Registry as Supply Chain Control: Blocking the Axios Attack Pattern

## The Problem

Every developer and CI runner in an organisation that pointed directly at `registry.npmjs.org` was exposed to the Axios 1.14.1 attack the moment it was published — there was no gate, no approval, no quarantine period. A private registry proxy inserted between developers and the public npm registry creates that gate. Verdaccio and JFrog Artifactory (used as an npm proxy) can be configured to: cache specific approved versions of packages, block any version not in an explicit allowlist, require a manual promotion step before new upstream versions are available internally, and scan packages for malicious content before caching them.

The Axios attack would have been stopped at the private registry: `axios@1.14.1` would have been fetched from npm but held in quarantine until a security reviewer approved it — which would not have happened given the three-hour window before npm removed the malicious versions. The attack required reaching developer machines and CI runners. With a private registry enforcing an approved-version list that still had `axios@1.14.0` as the latest permitted version, `npm install axios` resolves to `1.14.0`, the malicious version is never downloaded, and the `postinstall` RAT never executes.

This article focuses on the registry layer as the control. The companion article on egress filtering describes the network-layer detection of `postinstall` C2 callbacks — that control assumes the malicious package reached the filesystem. This control prevents it from reaching the filesystem at all.

## Threat Model

- **`latest` dist-tag hijack reaching all developers via direct npm registry access.** When a maintainer's token is stolen and used to publish a malicious version, npm immediately advances the `latest` dist-tag to point at the new version. Any install of `npm install axios` (without an explicit version pin) resolves to the malicious version within seconds of publication. Every developer running `npm install` and every CI pipeline triggered after the publish is exposed until npm removes the package.

- **Malicious patch version pulled automatically by `npm update` or unpinned installs.** In a `package.json` with `"axios": "^1.14.0"`, the caret allows any `1.x.y` where `y >= 0`. Running `npm update` or `npm install` against a fresh environment resolves `axios@1.14.1` as the best-matching version. Lockfiles protect against this in committed environments but not in CI jobs that run `npm install --ignore-scripts` after checking out only `package.json`.

- **Dependency confusion attack: an attacker publishes a public package with the same name as a private internal package.** Without a private registry configured with internal package precedence rules, npm may pull the public malicious version rather than the internal package. A private registry that is authoritative for internal scopes and proxies public packages only for packages outside those scopes closes this vector.

- **Compromised npm CDN: even if the registry metadata is correct, the tarball CDN could serve a different tarball.** The npm registry's metadata API (`registry.npmjs.org/axios`) returns the expected SHA-512 integrity hash for each version. The actual tarball is served from a separate CDN path. A private registry that caches and re-serves the tarball after verifying the hash provides integrity assurance beyond what the public registry offers to direct consumers.

## Hardening Configuration

### 1. Verdaccio Deployment with Upstream Proxy

Deploy Verdaccio as the single internal npm registry. All developer machines and CI runners are configured to use `https://npm.internal.example.com/` as their registry. Verdaccio proxies `registry.npmjs.org` for packages not in its local store — but critically, it does so under your control, not automatically on behalf of every client request.

The `config.yaml` `uplinks` and `packages` configuration establishes the proxy relationship and enforces internal package precedence:

```yaml
uplinks:
  npmjs:
    url: https://registry.npmjs.org/
    timeout: 30s
    max_fails: 3
    fail_timeout: 5m
    cache: true

packages:
  "@internal/*":
    access: $authenticated
    publish: $authenticated
    proxy: ""

  "**":
    access: $authenticated
    publish: $restricted
    proxy: npmjs
    unpublish: $restricted
```

The `@internal/*` block has an empty `proxy` value — Verdaccio will not go upstream for any package under that scope. If an attacker publishes `@internal/auth-utils` to npmjs.org, Verdaccio serves only the locally published version. The `**` wildcard block proxies all other packages through the `npmjs` uplink, but because internal scopes are matched first, dependency confusion via scope collision is prevented.

Run Verdaccio as a least-privilege system service:

```bash
useradd --system --no-create-home --shell /bin/false verdaccio
mkdir -p /opt/verdaccio/{storage,conf,plugins}
chown -R verdaccio:verdaccio /opt/verdaccio

npm install -g verdaccio

cat > /etc/systemd/system/verdaccio.service << 'EOF'
[Unit]
Description=Verdaccio private npm registry
After=network.target

[Service]
User=verdaccio
Group=verdaccio
ExecStart=/usr/bin/verdaccio --config /opt/verdaccio/conf/config.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/verdaccio/storage

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now verdaccio
```

For production deployments, run two or more Verdaccio instances behind an internal load balancer and configure them to share a storage backend (NFS mount or S3-compatible object store via the `verdaccio-aws-s3-storage` plugin). A single Verdaccio instance failing blocks all npm installs organisation-wide.

### 2. Version Allowlist Enforcement

Verdaccio's default behaviour proxies whatever version a client requests from upstream. Restricting which versions are served requires a middleware plugin that intercepts package metadata responses and filters the versions list before it reaches the client.

The `verdaccio-package-access-proxy` plugin (or a custom middleware) can be configured with a per-package version allowlist. The Verdaccio plugin API exposes middleware hooks for `getPackage` responses:

```yaml
middlewares:
  version-allowlist:
    enabled: true
    config_path: /opt/verdaccio/conf/allowlist.yaml
```

The allowlist file maps package names to their maximum permitted versions:

```yaml
allowlist:
  axios:
    allowed_versions:
      - "1.14.0"
      - "1.13.9"
      - "1.13.8"
  lodash:
    allowed_versions:
      - "4.17.21"
  semver:
    allowed_versions:
      - "7.6.3"
      - "7.6.2"
```

When a client requests `axios@1.14.1` or `npm install axios` (resolving to `latest`), the middleware strips `1.14.1` from the returned package metadata. The client sees only the permitted versions and resolves to `1.14.0` as the newest available. The malicious version does not exist as far as any developer or CI runner is concerned.

Maintain the allowlist in a version-controlled repository with a change review process. Tooling to propose allowlist additions should generate a pull request — merging the PR triggers a CI job that updates the Verdaccio allowlist file.

### 3. Quarantine Workflow for New Upstream Versions

New upstream versions of dependencies should be detected, fetched into a quarantine namespace, and reviewed before they are added to the allowlist. A scheduled GitHub Actions workflow checks for new versions of all packages in the allowlist:

```yaml
name: Dependency Version Monitor

on:
  schedule:
    - cron: "0 * * * *"

jobs:
  check-new-versions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check for new upstream versions
        run: |
          #!/bin/bash
          set -euo pipefail

          ALLOWLIST="verdaccio/allowlist.yaml"
          QUARANTINE_LOG="quarantine/pending.json"
          NEW_VERSIONS="[]"

          while IFS= read -r package; do
            CURRENT=$(yq ".allowlist.${package}.allowed_versions[0]" "$ALLOWLIST")
            UPSTREAM=$(npm view "$package" version --registry https://registry.npmjs.org)

            if [ "$UPSTREAM" != "$CURRENT" ]; then
              NEW_VERSIONS=$(echo "$NEW_VERSIONS" | jq \
                --arg pkg "$package" \
                --arg current "$CURRENT" \
                --arg upstream "$UPSTREAM" \
                '. += [{"package": $pkg, "current": $current, "upstream": $upstream}]')
            fi
          done < <(yq '.allowlist | keys[]' "$ALLOWLIST")

          echo "$NEW_VERSIONS" > "$QUARANTINE_LOG"

      - name: Fetch quarantined versions to internal staging registry
        run: |
          while IFS= read -r entry; do
            PKG=$(echo "$entry" | jq -r '.package')
            VERSION=$(echo "$entry" | jq -r '.upstream')

            npm pack "${PKG}@${VERSION}" --registry https://registry.npmjs.org
            npm publish "${PKG}-${VERSION}.tgz" \
              --registry https://npm-quarantine.internal.example.com/ \
              --tag quarantine
          done < <(jq -c '.[]' quarantine/pending.json)

      - name: Notify security team
        if: steps.check-new-versions.outputs.new_versions != '[]'
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "New upstream npm versions pending security review",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Packages requiring review before promotion:*\nReview at: https://npm-quarantine.internal.example.com/\nPR to approve: ${{ github.server_url }}/${{ github.repository }}/pulls"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SECURITY_SLACK_WEBHOOK }}
```

The quarantine registry (`npm-quarantine.internal.example.com`) is a second Verdaccio instance that is not configured in any developer or CI `.npmrc`. It is accessible only to security reviewers who know its address. A reviewer can `npm install --registry https://npm-quarantine.internal.example.com/ axios@1.14.1` to fetch and inspect the package in an isolated environment, compare `package.json` scripts against the previous approved version, and run the tarball through automated tooling before approving it.

Promoting an approved version to the main Verdaccio instance means merging a pull request that adds the new version to `allowlist.yaml`. The CI pipeline that deploys the allowlist update also publishes the quarantined tarball to the main Verdaccio storage.

### 4. Package Integrity Verification at Proxy Time

The npm registry's metadata for each package version includes a `dist.integrity` field containing the SHA-512 hash of the published tarball. When Verdaccio proxies a package from upstream, it can verify this hash before caching and serving the tarball.

A Verdaccio storage middleware plugin intercepts the tarball write and rejects it if the computed hash does not match the registry-published `integrity` value:

```yaml
middlewares:
  integrity-check:
    enabled: true
    action_on_failure: block
    alert_webhook: https://alerts.internal.example.com/npm-integrity
```

For environments without a custom plugin, implement hash verification as a wrapper around the npm fetch in the quarantine workflow:

```bash
#!/bin/bash
# verify-package-integrity.sh
# Download a package tarball and verify its SHA-512 hash
# against the value published in the npm registry metadata.

set -euo pipefail

PACKAGE="${1}"
VERSION="${2}"
REGISTRY="https://registry.npmjs.org"

METADATA=$(curl -sf "${REGISTRY}/${PACKAGE}/${VERSION}")
PUBLISHED_INTEGRITY=$(echo "$METADATA" | jq -r '.dist.integrity')
TARBALL_URL=$(echo "$METADATA" | jq -r '.dist.tarball')

TMPDIR=$(mktemp -d)
curl -sf "$TARBALL_URL" -o "${TMPDIR}/package.tgz"

COMPUTED_HASH=$(openssl dgst -sha512 -binary "${TMPDIR}/package.tgz" \
  | openssl base64 -A)
COMPUTED_INTEGRITY="sha512-${COMPUTED_HASH}"

if [ "$COMPUTED_INTEGRITY" != "$PUBLISHED_INTEGRITY" ]; then
  echo "INTEGRITY MISMATCH for ${PACKAGE}@${VERSION}"
  echo "Published: ${PUBLISHED_INTEGRITY}"
  echo "Computed:  ${COMPUTED_INTEGRITY}"
  rm -rf "$TMPDIR"
  exit 1
fi

echo "Integrity verified: ${PACKAGE}@${VERSION}"
rm -rf "$TMPDIR"
```

Run this script for every package in the quarantine workflow before publishing to the quarantine registry. If the hash does not match, the package is not published, the workflow fails, and the alert fires. A mismatch between the registry-published hash and the CDN-served tarball is an indication of CDN tampering or a supply chain compromise that occurred after the original publish — a different attack vector from the Axios case but one that this control also catches.

### 5. Point All CI and Developer Machines at the Private Registry

The private registry provides no protection if developers or CI runners can bypass it by reaching `registry.npmjs.org` directly. Two controls enforce exclusive use of the private registry: `.npmrc` configuration and network-layer blocking.

Set the organisation-wide npm registry in a checked-in `.npmrc` at the repository root:

```bash
registry=https://npm.internal.example.com/
always-auth=true
```

For CI pipelines, assert the registry configuration is correct before any `npm install` step:

```bash
#!/bin/bash
set -euo pipefail

EXPECTED_REGISTRY="https://npm.internal.example.com/"
ACTUAL_REGISTRY=$(npm config get registry)

if [ "$ACTUAL_REGISTRY" != "$EXPECTED_REGISTRY" ]; then
  echo "ERROR: npm registry is ${ACTUAL_REGISTRY}, expected ${EXPECTED_REGISTRY}"
  echo "Direct access to the public npm registry is not permitted in CI."
  exit 1
fi

echo "Registry check passed: ${ACTUAL_REGISTRY}"
```

Block direct access to `registry.npmjs.org` at the network firewall for all CI runner hosts and developer subnets. The npm registry resolves to Cloudflare CDN addresses, so an IP-based firewall rule needs to cover the Cloudflare ranges, or the block can be enforced at DNS level:

```bash
nft add table inet npm_block
nft add chain inet npm_block output { type filter hook output priority 0 \; policy accept \; }
nft add rule inet npm_block output \
  ip daddr { 104.16.0.0/12, 104.20.0.0/14 } \
  tcp dport 443 \
  tcp dport != 4873 \
  log prefix "DIRECT-NPM-BLOCK: " drop
```

For organisations where IP-level blocking is not feasible (shared network infrastructure, developer workstations on the corporate SSID with no per-device firewall policy), use a DNS override instead. Configure the internal DNS resolver to return the private Verdaccio address for `registry.npmjs.org`:

```yaml
server:
  local-zone: "registry.npmjs.org." redirect
  local-data: "registry.npmjs.org. A 10.0.1.50"
```

This redirects any request for `registry.npmjs.org` to Verdaccio's IP (`10.0.1.50`). The npm client connects to Verdaccio, which proxies requests according to its configured package rules. Developers never need to change their local `.npmrc` defaults — the DNS resolution enforces the routing transparently.

Verify that the control is in place in every CI pipeline run:

```bash
npm config get registry
nslookup registry.npmjs.org
```

Both commands should confirm that `registry.npmjs.org` resolves to the internal Verdaccio address and that the npm client is configured to use the private registry URL.

## Expected Behaviour After Hardening

After the version allowlist is deployed, `npm install axios@1.14.1` from a developer machine returns a `404 Not Found` from Verdaccio — `axios@1.14.1` is not in the approved version list, so Verdaccio does not serve it. `npm install axios` (relying on `latest`) resolves to `axios@1.14.0`, the highest version in the allowlist. The malicious version is invisible to the npm client. No `postinstall` hook from `axios@1.14.1` ever executes.

After the quarantine workflow is deployed, the hourly version monitor detects that npm has published `axios@1.14.1` upstream. The workflow fetches the tarball to the quarantine registry and sends a Slack notification to the security team channel with a link to the quarantine review interface and the proposed PR. The security team inspects the new version's `package.json` — observing that it introduces a new `postinstall` script and a phantom dependency (`plain-crypto-js`) absent from the previous version — and closes the PR without merging. The version remains in quarantine indefinitely. The production allowlist stays at `axios@1.14.0`.

After the integrity verification step is in place, any tarball whose computed SHA-512 hash does not match the `dist.integrity` value from the npm registry metadata is rejected. The quarantine workflow fails, the package is not published to the quarantine registry, and the mismatch is reported to the security team as a potential CDN tampering event.

## Trade-offs and Operational Considerations

A private registry is a single point of failure for all npm installs in the organisation. A Verdaccio process crash, a disk full condition on the storage volume, or a network partition between CI runners and the Verdaccio host stops all builds. Run at least two Verdaccio instances behind an internal load balancer. Use an S3-compatible backend (MinIO, AWS S3 with VPC endpoint) rather than local disk for the package storage so that instance failures do not cause data loss and new instances can be brought up without re-caching. For organisations that cannot operate this infrastructure, JFrog Artifactory Cloud, GitHub Packages, or AWS CodeArtifact are managed alternatives that provide equivalent proxy and access control features with SLA-backed availability.

The version allowlist is a manual maintenance process. Every legitimate dependency update — security patches, feature releases — requires a pull request to add the new version to the allowlist, a review, and a merge before developers or CI can use the new version. This adds one to two business days to the normal update cycle. Automate the non-security-sensitive parts of this process with Renovate Bot: configure Renovate to open pull requests against the `allowlist.yaml` file when new upstream versions appear, including the changelog and a link to the npm diff. Human reviewers are still required to merge, but the proposal step is automated and the reviewer has all the context needed without manual research.

Applying the quarantine workflow to every package in the organisation's dependency tree is impractical at scale. A large application may have several hundred transitive dependencies; reviewing every new version of every package would consume more security engineering time than the risk warrants. Prioritise the top 100 dependencies by install count in the organisation, the packages with elevated supply chain risk scores (high download counts, few maintainers, recent account activity changes), and any package that runs `postinstall` scripts. Packages outside the priority list can be promoted to the allowlist via an automated Renovate PR with a shorter or no review hold period.

## Failure Modes

A private registry deployed without a corresponding network block on direct access to `registry.npmjs.org` provides no protection if a developer or CI runner falls back to the public registry on a cache miss. Verdaccio, by default, will proxy missing packages from upstream — but if a developer manually sets `--registry https://registry.npmjs.org` on a single command, or if a project-level `.npmrc` overrides the organisation default, the private registry is bypassed entirely. The DNS override approach mitigates the command-line flag bypass because the resolution of `registry.npmjs.org` itself is redirected. The network firewall block mitigates all bypass methods that operate above the DNS layer. Both controls together are required for complete enforcement.

The quarantine workflow notifies the security team but does not enforce a mandatory review SLA. If the notification goes to a shared channel with no ownership assignment, packages accumulate in the quarantine registry without review. Legitimate updates — including genuine security patches — are blocked from reaching developers because no one approved them. Establish an ownership model: the security team receives the notification, but the package's owning development team is tagged and is responsible for initiating the review. Verdaccio's quarantine registry should have a retention policy that expires packages after 30 days of inactivity, prompting re-evaluation of whether the update is still needed.

A version allowlist that is not updated when a legitimate critical security patch is released leaves developers running the known-vulnerable version. If `axios@1.14.0` itself had a separate CVE, and `axios@1.14.2` is the legitimate fix, but the allowlist still specifies only `1.14.0`, the organisation is protected from the supply chain attack but exposed to the CVE. The allowlist approval process must have an expedited path for security patches — a fast-track review that can be completed in hours rather than days, with a designated reviewer on call. Without this, the security control creates a different security exposure.

## Related Articles

- [npm Lockfile Integrity Security](/articles/cicd/npm-lockfile-integrity-security/)
- [Private Package Registry Security](/articles/cicd/private-package-registry-security/)
- [npm Postinstall C2 Egress Detection](/articles/network/npm-postinstall-c2-egress-detection/)
- [Pipeline Egress Control](/articles/cicd/pipeline-egress-control/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
