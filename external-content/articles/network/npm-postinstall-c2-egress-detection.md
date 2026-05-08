---
title: "Detecting npm postinstall C2 Callbacks at the Network Layer"
description: "The Axios RAT phoned home to C2 infrastructure during npm install. Build egress filters for CI runners, DNS monitoring for phantom dependency domains, and Suricata rules that catch the network signature of postinstall supply chain attacks."
slug: npm-postinstall-c2-egress-detection
date: 2026-05-03
lastmod: 2026-05-03
category: network
tags:
  - supply-chain
  - npm
  - egress-filtering
  - suricata
  - dns-monitoring
personas:
  - security-engineer
  - platform-engineer
article_number: 417
difficulty: Intermediate
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/network/npm-postinstall-c2-egress-detection/
---

# Detecting npm postinstall C2 Callbacks at the Network Layer

## The Problem

The Axios RAT — deployed via a stolen maintainer token on March 31 2026 by the North Korean threat actor Sapphire Sleet (UNC1069) — had one immediate requirement after deployment: reach its C2 server to receive second-stage payloads and exfiltrate credentials. That outbound connection is the most detectable moment in the entire attack chain. It happens during `npm install`. It originates from the `node` or `npm` process. It goes to an IP that is not the npm registry, not GitHub, not any legitimate CDN. The attack window was approximately three hours before the malicious versions of `axios@1.14.1` were yanked from the registry, but CI pipelines and developer workstations globally had already executed the `postinstall` hook.

Most CI environments allow unrestricted internet egress from build runners "because npm needs it." This is the exact network condition the Axios attacker relied on. The infected `postinstall` script opened an outbound HTTPS connection to attacker-controlled infrastructure the moment `npm install` completed. Without egress filtering, nothing stood between the running `node` process and the C2 server.

The opportunity is narrow but decisive. If build runners restrict egress to only the npm registry and known CDN ranges, the RAT deploys to the filesystem but cannot reach C2. Second-stage payloads are never downloaded. Credentials sitting in CI environment variables — cloud provider keys, container registry tokens, deployment credentials — are never exfiltrated. The attack chain breaks at the most critical point, before any post-compromise activity occurs.

The second detection opportunity is DNS. The Axios RAT pulled in a phantom dependency, `plain-crypto-js`, as part of its obfuscation layer. That package name does not appear in any committed `package-lock.json` in any legitimate repository. npm resolves package metadata via the registry API at `registry.npmjs.org/<package-name>` — which means the DNS resolver on the CI runner issued a query containing the name of an unknown package. If you maintain a known-good inventory of every package name referenced in your organisation's lockfiles and monitor DNS queries from CI runners against that inventory, a query for `plain-crypto-js` is an unambiguous alert before a single byte of malicious code is downloaded.

Neither of these controls requires endpoint detection or runtime instrumentation. Both are network-layer observations on traffic that is already flowing through infrastructure you control.

## Threat Model

- **Postinstall RAT making outbound HTTPS to attacker C2 from a CI runner with broad internet egress.** The `postinstall` hook runs as the same user as `npm install`. On a GitHub Actions-hosted runner, that is a privileged user with access to all environment variables injected by the platform. On a self-hosted runner inside a corporate network, it may have access to internal services. The outbound HTTPS request looks like any other Node.js HTTPS call — `User-Agent: node-fetch/...` or `axios/...` — and is indistinguishable from legitimate application traffic without inspecting the destination.

- **Second-stage payload downloaded from C2 after initial beacon.** The initial `postinstall` callback is a lightweight beacon: it establishes that the infection succeeded and returns the runner's environment. The C2 server responds with a second-stage payload tailored to the environment — a more capable implant, a credential harvester, or commands to exfiltrate specific secrets. This second download is also an outbound HTTPS connection, again indistinguishable from legitimate traffic without egress filtering.

- **Credential exfiltration: environment variables sent to C2 over HTTPS.** CI tokens, cloud credentials, and API keys are present in environment variables during `npm install`. The RAT serialises the process environment and sends it to C2 over HTTPS. Without TLS inspection on the egress path, the exfiltration looks like a normal HTTPS POST and generates no alert.

- **DNS resolution of phantom dependency package names via the npm registry API.** npm resolves every package in the dependency graph by querying `registry.npmjs.org/<package-name>`. Phantom dependencies — packages that appear in the `postinstall` script's dependency chain but are not in any committed lockfile — generate DNS queries for names that have never appeared in your organisation's builds. These queries are detectable if you monitor DNS from CI runner hosts.

- **Developer workstation where outbound filtering is impractical.** On a workstation, blocking all outbound HTTPS except to npm registries is not operationally feasible. The detection-only approach applies here: DNS sinkholing of known IOC domains, Suricata alerts on the Axios RAT's specific TLS fingerprint, and endpoint telemetry correlated with `npm install` process events.

## Hardening Configuration

### 1. CI Runner Egress Allowlist

The minimal IP ranges required for `npm install` to complete are the Cloudflare CDN ranges that serve `registry.npmjs.org` and `cdn.jsdelivr.net` (`104.16.0.0/12` and `104.20.0.0/14`), GitHub (`140.82.112.0/20`), and your internal package registry if you run one. Everything else should be denied.

Apply the allowlist at the CI runner network namespace level using nftables. This example runs on the host that executes build jobs; if jobs run as containers, see the note on Docker networking below.

```bash
#!/bin/bash
# /usr/local/bin/ci-egress-filter.sh
# Apply egress allowlist for CI runner host.
# Run at system startup before any build jobs execute.

nft flush ruleset

nft add table inet ci_egress
nft add chain inet ci_egress output { type filter hook output priority 0 \; policy drop \; }

# Allow established and related connections (responses to allowed outbound).
nft add rule inet ci_egress output ct state established,related accept

# Allow DNS to internal resolver only.
nft add rule inet ci_egress output ip daddr 10.0.0.53 udp dport 53 accept
nft add rule inet ci_egress output ip daddr 10.0.0.53 tcp dport 53 accept

# Allow npm registry and CDN (Cloudflare ranges serving registry.npmjs.org).
nft add rule inet ci_egress output ip daddr 104.16.0.0/12 tcp dport 443 accept
nft add rule inet ci_egress output ip daddr 104.20.0.0/14 tcp dport 443 accept

# Allow GitHub (for npm packages sourced from GitHub).
nft add rule inet ci_egress output ip daddr 140.82.112.0/20 tcp dport 443 accept

# Allow internal Verdaccio / Artifactory registry.
nft add rule inet ci_egress output ip daddr 10.0.1.50 tcp dport 4873 accept

# Log and drop everything else.
nft add rule inet ci_egress output log prefix "CI-EGRESS-DROP: " drop
```

With this filter in place, the Axios RAT's `postinstall` HTTPS request to its C2 server hits the `drop` rule. The package installs successfully because `registry.npmjs.org` is allowlisted. The RAT runs. The C2 call fails. Second-stage payloads are never received.

Note on Docker networking: if build jobs run in Docker containers with `--network=bridge`, the host nftables `output` chain does not inspect container traffic — bridge traffic traverses the `FORWARD` chain instead. Add rules to the `DOCKER-USER` chain, which Docker does not flush on restart:

```bash
nft add table inet docker_egress
nft add chain inet docker_egress docker_user { type filter hook forward priority -1 \; policy accept \; }

# Drop forwarded traffic from Docker bridge ranges that is not destined for allowed ranges.
nft add rule inet docker_egress docker_user \
  ip saddr 172.16.0.0/12 \
  ip daddr != { 104.16.0.0/12, 104.20.0.0/14, 140.82.112.0/20, 10.0.0.0/8 } \
  tcp dport 443 \
  log prefix "DOCKER-EGRESS-DROP: " drop
```

### 2. Squid Forward Proxy for npm Traffic

IP-based allowlisting is brittle: Cloudflare's CDN serving the npm registry uses a large and occasionally-updated IP space. A forward proxy with a hostname allowlist is easier to maintain and provides an additional inspection layer.

Route all CI npm installs through a Squid proxy. Configure npm to use the proxy via environment variable in the CI pipeline definition. The proxy allowlist permits only the registries your builds require; all other `CONNECT` requests are denied.

```conf
# /etc/squid/squid.conf

# Allowed registry hostnames.
acl npm_registries dstdomain registry.npmjs.org
acl npm_registries dstdomain cdn.jsdelivr.net
acl npm_registries dstdomain verdaccio.internal

# Allowlist ports for HTTPS CONNECT.
acl ssl_port port 443 4873

# Allow npm registry traffic.
http_access allow CONNECT npm_registries ssl_port

# Deny all other CONNECT (blocks all other HTTPS destinations).
http_access deny CONNECT

# Allow plain HTTP only to internal hosts.
acl internal_net src 10.0.0.0/8
http_access allow internal_net npm_registries
http_access deny all

# Logging for SIEM ingestion.
access_log /var/log/squid/access.log squid
```

Configure npm to use the proxy in the CI pipeline environment:

```bash
# CI pipeline environment — set before npm install runs.
export HTTP_PROXY=http://squid.internal:3128
export HTTPS_PROXY=http://squid.internal:3128
export NO_PROXY=verdaccio.internal,10.0.0.0/8

npm install
```

When the Axios RAT's `postinstall` hook opens an HTTPS connection to its C2 server, Squid receives the `CONNECT` request, checks the destination hostname against `npm_registries`, finds no match, and returns a 403. The connection is blocked at the proxy layer regardless of what Cloudflare IPs are currently in use.

If you also want to inspect the content of npm registry responses (for example, to verify package signatures in transit), configure SSL bump on the Squid proxy and import the proxy CA certificate into the CI runner's trust store. This is operationally heavier but enables deep inspection of the npm API calls themselves.

### 3. DNS Monitoring for Unknown npm Package Names

Every package that `npm install` resolves makes at least one DNS query to `registry.npmjs.org` — but the HTTP request path contains the package name: `GET /plain-crypto-js`. More directly, if your CI runner's DNS resolver logs query names, you will see a query for `registry.npmjs.org` every time npm contacts the registry. The package name is in the HTTP layer, not the DNS query itself.

The more actionable signal is at the DNS level for phantom domains: `plain-crypto-js.registry.npmjs.org` is not how npm resolves packages — npm uses HTTPS with the package name in the URL path. The phantom dependency detection therefore requires correlating HTTP request logs from the Squid proxy (or from the CI runner's process-level network monitoring) against a known-good package inventory derived from all committed lockfiles.

Build that inventory and run the comparison on every CI build:

```bash
#!/bin/bash
# /usr/local/bin/check-phantom-deps.sh
# Compare packages being installed against lockfile inventory.
# Run as part of the CI pipeline before npm install.
# Requires: jq, access to organisation lockfile inventory.

LOCKFILE="${1:-package-lock.json}"
INVENTORY_FILE="/var/lib/ci-security/known-packages.txt"
ALERT_WEBHOOK="${CI_SECURITY_WEBHOOK:-}"

if [ ! -f "$LOCKFILE" ]; then
  echo "No lockfile found at $LOCKFILE — aborting build."
  exit 1
fi

# Extract all package names from the lockfile.
BUILD_PACKAGES=$(jq -r '.packages | keys[] | ltrimstr("node_modules/")' "$LOCKFILE" | sort -u)

# Check each package against the known-good inventory.
UNKNOWN_PACKAGES=()
while IFS= read -r pkg; do
  if [ -z "$pkg" ]; then continue; fi
  if ! grep -qxF "$pkg" "$INVENTORY_FILE"; then
    UNKNOWN_PACKAGES+=("$pkg")
  fi
done <<< "$BUILD_PACKAGES"

if [ ${#UNKNOWN_PACKAGES[@]} -gt 0 ]; then
  echo "ALERT: Unknown packages not in organisation inventory:"
  printf '  %s\n' "${UNKNOWN_PACKAGES[@]}"

  if [ -n "$ALERT_WEBHOOK" ]; then
    PAYLOAD=$(printf '%s\n' "${UNKNOWN_PACKAGES[@]}" | jq -Rs '{unknown_packages: split("\n"), repo: env.CI_REPO, pipeline: env.CI_PIPELINE_ID}')
    curl -sf -X POST -H "Content-Type: application/json" -d "$PAYLOAD" "$ALERT_WEBHOOK"
  fi

  exit 1
fi

echo "All packages present in organisation inventory."
```

Build and maintain the inventory by scanning all lockfiles in the organisation's repositories:

```bash
#!/bin/bash
# /usr/local/bin/build-package-inventory.sh
# Scan all package-lock.json files in a repository directory tree
# and produce a deduplicated list of known package names.
# Run nightly or on every merge to the main branch.

REPO_ROOT="${1:-/var/lib/ci/repositories}"
OUTPUT_FILE="/var/lib/ci-security/known-packages.txt"

find "$REPO_ROOT" -name "package-lock.json" -not -path "*/node_modules/*" \
  -exec jq -r '.packages | keys[] | ltrimstr("node_modules/")' {} \; \
  | sort -u > "$OUTPUT_FILE.tmp"

mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"

echo "Inventory built: $(wc -l < "$OUTPUT_FILE") unique packages"
```

When `plain-crypto-js` appears in a lockfile being installed on a CI runner and is absent from the inventory, the build fails before `npm install` executes — before the phantom dependency is ever downloaded.

### 4. Suricata Rules for npm Postinstall C2 Patterns

The Axios RAT's C2 callback has a specific network signature: an HTTPS connection initiated by a `node` or `npm` process, where the TLS SNI is not `registry.npmjs.org`, `cdn.jsdelivr.net`, or any other legitimate npm infrastructure. The connection occurs within seconds of `npm install` completing.

Suricata detects this through TLS metadata inspection. The `tls.sni` sticky buffer matches the SNI field in the TLS ClientHello. The `http.user_agent` keyword matches the HTTP User-Agent header for non-HTTPS fallback cases.

```conf
# /etc/suricata/rules/npm-supply-chain.rules

# Alert on TLS connections from Node.js processes to non-npm destinations.
# Matches TLS ClientHello SNI that is not a known npm infrastructure domain.
# The negation approach: alert when SNI is present but does NOT match allowlist.
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
  msg:"NPM Postinstall C2 Callback - TLS to non-registry destination";
  flow:established,to_server;
  tls.sni;
  content:!"registry.npmjs.org";
  content:!"cdn.jsdelivr.net";
  content:!"github.com";
  content:!"githubusercontent.com";
  content:!"codeload.github.com";
  content:!"objects.githubusercontent.com";
  metadata:affected_product npm, attack_target CI_Pipeline;
  classtype:trojan-activity;
  sid:9100001;
  rev:1;
)

# Alert specifically on the Axios RAT IOC C2 domains.
# Update this list as new IOCs are published.
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
  msg:"Axios RAT C2 Domain - Known IOC (Sapphire Sleet UNC1069)";
  flow:established,to_server;
  tls.sni;
  content:"pkg-validate.net";
  nocase;
  classtype:trojan-activity;
  reference:url,github.com/nicowillis/axios-rat-iocs;
  sid:9100002;
  rev:1;
)

alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
  msg:"Axios RAT C2 Domain - Known IOC (Sapphire Sleet UNC1069)";
  flow:established,to_server;
  tls.sni;
  content:"npm-health-check.io";
  nocase;
  classtype:trojan-activity;
  reference:url,github.com/nicowillis/axios-rat-iocs;
  sid:9100003;
  rev:1;
)

# Detect Node.js HTTP client connecting to non-registry over plain HTTP.
# Covers RAT variants that fall back from HTTPS to HTTP for C2.
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"NPM Postinstall C2 Callback - Node.js HTTP to non-registry destination";
  flow:established,to_server;
  http.user_agent;
  content:"node-fetch";
  http.host;
  content:!"registry.npmjs.org";
  content:!"cdn.jsdelivr.net";
  content:!"github.com";
  classtype:trojan-activity;
  sid:9100004;
  rev:1;
)

# Detect direct IP connection from Node.js — no SNI, no hostname, just an IP.
# RAT variants that bypass DNS and connect directly to a hardcoded IP.
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
  msg:"NPM Postinstall possible direct-IP C2 - TLS with no SNI";
  flow:established,to_server;
  tls.sni;
  content:!"";
  pcre:"/^$/";
  classtype:policy-violation;
  sid:9100005;
  rev:1;
)
```

Load the rules and test them against a replay capture:

```bash
# Test rule syntax without starting Suricata.
suricata -T -c /etc/suricata/suricata.yaml -l /tmp/suricata-test/

# Add rules file to suricata.yaml rule-files list.
# Then reload rules without restarting:
suricatasc -c reload-rules

# Verify rules loaded.
suricatasc -c ruleset-stats | grep 9100
```

### 5. Network Segmentation for Developer Workstations

Full egress filtering on developer workstations is not operationally viable. The detection-only approach uses DNS sinkholing for known Axios RAT IOC domains and relies on endpoint telemetry to correlate `npm install` process events with outbound connections.

Deploy a DNS sinkhole using Unbound or Pi-hole for workstation-facing DNS:

```conf
# /etc/unbound/unbound.conf.d/axios-rat-iocs.conf
# Sinkhole known Axios RAT C2 domains.
# Source: https://github.com/nicowillis/axios-rat-iocs

server:
    local-zone: "pkg-validate.net" redirect
    local-data: "pkg-validate.net A 10.0.0.99"

    local-zone: "npm-health-check.io" redirect
    local-data: "npm-health-check.io A 10.0.0.99"

    local-zone: "plain-crypto-js.net" redirect
    local-data: "plain-crypto-js.net A 10.0.0.99"

    local-zone: "axios-update-service.com" redirect
    local-data: "axios-update-service.com A 10.0.0.99"
```

The sinkhole IP (`10.0.0.99`) should run a lightweight HTTP listener that logs every request with its source IP, User-Agent, request body, and timestamp, then returns a 200 OK to keep the RAT's connection attempt alive long enough for full telemetry capture. Every request to the sinkhole is an incident indicator requiring investigation.

For Pi-hole deployments, add the IOC domains to a custom blocklist:

```bash
# Add Axios RAT IOC domains to Pi-hole custom blocklist.
# /etc/pihole/custom.list

10.0.0.99 pkg-validate.net
10.0.0.99 npm-health-check.io
10.0.0.99 plain-crypto-js.net
10.0.0.99 axios-update-service.com
```

On macOS developer workstations, pair the DNS sinkhole with a Zeek process-level network monitor or use the Endpoint Security Framework to correlate `npm` process activity with outbound connections. A connection from `/usr/local/bin/node` to any destination other than `registry.npmjs.org` during an `npm install` is an anomalous signal worth alerting on regardless of whether the destination is in the IOC list.

## Expected Behaviour After Hardening

After the Squid proxy is in place, `npm install axios@1.14.1` on a CI runner completes normally: the registry request for `registry.npmjs.org/axios` is allowlisted, the package downloads, and the `postinstall` hook executes. The RAT script opens an HTTPS connection to `pkg-validate.net`. Squid receives the `CONNECT pkg-validate.net:443` request, finds no match in the `npm_registries` ACL, and returns `403 Forbidden`. The connection is refused. The RAT writes the environment variables to a buffer but has no path to send them. Second-stage payloads are not downloaded. The `npm install` process exits. The malicious package is on the filesystem but the attack chain is broken.

After the phantom dependency check is in place, a CI build that references `plain-crypto-js` in its lockfile (injected by the compromised `axios@1.14.1` package) triggers the inventory comparison before `npm install` runs. `plain-crypto-js` is absent from the organisation's known-good package inventory. The build fails with an alert containing the unknown package names, the repository name, and the pipeline ID. The alert fires in the SIEM within seconds of the build starting — before the package is downloaded, before any `postinstall` hook executes.

After the Suricata rules are deployed, any CI runner or workstation that has already installed the compromised package and attempts the C2 callback generates a Suricata EVE alert with `sid:9100002` (or the relevant IOC rule). The alert is forwarded to the SIEM within seconds via the Filebeat/Promtail pipeline. The SIEM correlation rule flags the source IP for immediate investigation.

## Trade-offs and Operational Considerations

IP-based egress allowlisting for the npm registry is fragile over time. Cloudflare's CDN ranges are large and occasionally extended; the ranges listed in this article (`104.16.0.0/12`, `104.20.0.0/14`) cover the current allocation but may not cover future additions. Prefer the Squid hostname-based allowlist as the primary control and use IP allowlisting only as a defence-in-depth backstop.

TLS inspection via SSL bump on the Squid proxy enables deep inspection of npm registry API calls — you can verify that a package response contains the expected integrity hash before it reaches the build environment. The cost is operational: every CI runner and developer workstation must trust the proxy's CA certificate. In a Kubernetes-based CI environment this means injecting the CA cert into runner container images. For developer workstations, MDM deployment of the CA cert is required. The maintenance overhead is significant; only implement SSL bump if you have a managed fleet with centralised certificate distribution.

The DNS monitoring approach for phantom dependencies requires a centralised lockfile inventory that is accurate and current. In large organisations with hundreds of repositories, the inventory build job must run on a schedule that keeps pace with dependency updates — nightly is the minimum; on-merge-to-main is better. An inventory that is a week stale will produce false positives when legitimate new packages are added. False positives erode trust in the alert and create pressure to raise the detection threshold, which buries real IOC alerts.

The Suricata rules for TLS SNI allowlist matching require regular maintenance as legitimate npm infrastructure domains change. `cdn.jsdelivr.net` is currently used by some npm packages; if npm changes its CDN provider without your rules being updated, legitimate package installs will generate false positive alerts. Review the allowlist quarterly and after any npm registry infrastructure announcements.

## Failure Modes

The nftables egress filter applies to traffic originating from the CI runner host's network namespace. Build jobs running in Docker containers with `--network=bridge` traverse the `FORWARD` chain rather than the `OUTPUT` chain, and the host-level `ci_egress` table does not inspect forwarded traffic. A container running with the default bridge network bypasses the egress filter entirely. The fix is to add `DOCKER-USER` chain rules as shown in the hardening configuration, and to audit all CI pipeline definitions for containers launched with `--network=host` (which does traverse the host's OUTPUT chain and is safe) versus `--network=bridge` (which does not). Containers launched with `--network=none` cannot make any outbound connections and are the most restrictive option for build steps that do not require network access.

The Squid proxy blocks C2 calls only if npm is configured to route through it. If the CI pipeline definition sets `NO_PROXY=*` or if the `npm` command is invoked with `--no-proxy`, the proxy is bypassed entirely. Audit pipeline definitions for `NO_PROXY` overrides as part of the hardening review. In Kubernetes-based CI, enforce proxy configuration via a mutating admission webhook that injects `HTTP_PROXY` and `HTTPS_PROXY` into all build pod specs and prevents `NO_PROXY` values broader than internal network ranges.

The phantom dependency alert threshold requires calibration for large monorepos. A monorepo with 300 packages will frequently add new dependencies; every new package that has not yet been added to the inventory will trigger an alert. If the inventory is not kept current, the alert volume grows, the on-call team develops alert fatigue, and the threshold is raised until the alert is effectively disabled. The inventory update job must be treated as a production service, not a background task — it needs monitoring, alerting on failure, and an SLO for freshness.

The Suricata rules use negative matching on TLS SNI content — alert when SNI does not match known-good values. This approach can generate false positives from legitimate Node.js tooling (npm audit, node-gyp download, Electron update checks) that makes HTTPS connections to non-registry destinations during a build. Before enabling these rules in a production environment, run them in alert-only mode for two weeks and collect the full set of legitimate destinations that appear. Add those destinations to the allowlist in the rules before promoting to IPS `drop` action.

The Suricata TLS SNI rules do not fire on C2 connections that use direct IP addressing without a hostname — a RAT variant hardcoded to connect to `198.51.100.47:443` rather than `pkg-validate.net:443` will have an empty SNI field and will match `sid:9100005` (no-SNI rule) rather than the IOC domain rules. This is the correct behaviour, but the no-SNI rule has a higher false positive rate from misconfigured TLS clients. Combine TLS SNI monitoring with the IP-based egress filter as the primary blocking control; treat the Suricata SNI rules as a detection layer, not the sole blocking mechanism.

## Related Articles

- [Suricata IDS/IPS](/articles/network/suricata-ids-ips/)
- [Pipeline Egress Control](/articles/cicd/pipeline-egress-control/)
- [DNS Security DNSSEC CAA](/articles/network/dns-security-dnssec-caa/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
- [npm Supply Chain Runtime Detection](/articles/observability/npm-supply-chain-runtime-detection/)
