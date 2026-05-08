---
title: "Sandboxing npm postinstall Scripts with WASM: Containing the Axios RAT Pattern"
description: "The Axios RAT had unrestricted network and filesystem access via a postinstall hook. A WASM/WASI sandbox grants postinstall scripts only what they need — a build directory and no network — so a compromised package cannot reach C2 or exfiltrate credentials."
slug: wasm-npm-postinstall-sandbox
date: 2026-05-03
lastmod: 2026-05-03
category: wasm
tags:
  - supply-chain
  - npm
  - wasi
  - sandboxing
  - postinstall
personas:
  - platform-engineer
  - security-engineer
article_number: 422
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/wasm/wasm-npm-postinstall-sandbox/
---

# Sandboxing npm postinstall Scripts with WASM: Containing the Axios RAT Pattern

## The Problem

`npm install` runs arbitrary code. When a package declares a `postinstall` script in its `package.json`, npm executes it as a Node.js process under the installing user's credentials with no capability restriction whatsoever: full network access, filesystem access spanning the entire home directory, and access to every environment variable in the shell that launched the install. This is not a bug in npm — it is the documented, intentional behaviour of lifecycle hooks — but it means that any compromised package with a `postinstall` entry is a pre-authenticated code execution primitive on every machine that runs `npm install`.

The Axios supply chain compromise of March 31, 2026 made this concrete. The Axios attacker injected a RAT (remote access trojan) delivered via a `postinstall` hook. When any project ran `npm install` and pulled the compromised version, the RAT executed with the full capabilities of the installing process. It read environment variables to identify high-value credentials — `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and any other secrets present in the CI environment. It made outbound network connections to a C2 server to exfiltrate the credentials and to download a second-stage payload. It wrote files to the filesystem beyond the package directory to establish persistence. None of this required exploiting a vulnerability in a traditional sense. The hook mechanism worked exactly as designed; only the content of the hook was malicious.

The npm ecosystem has over 4 million packages. A significant fraction declare `postinstall` scripts. The ecosystem has no enforcement of least-privilege for those scripts. Every `npm install` on a developer laptop, in a CI runner, or in a production deployment pipeline is a trust decision being made implicitly, for every package in the dependency graph, with no boundaries on what the hook can do.

WASM and WASI together provide a capability-based sandbox model that can change this. A `postinstall` script run inside a Wasmtime sandbox with a restricted WASI context can only do what the host explicitly grants: read source files in the package directory, write a build output directory, nothing else. No network socket capability means no C2 connection. No environment variable access means no credential exfiltration even if the sandbox is entered. No filesystem access outside the package directory means no persistence mechanism outside the package's own files. The Axios RAT, run inside a correctly-configured WASI sandbox, would have trapped on its first attempt to read `AWS_SECRET_ACCESS_KEY` from the environment — and the host would have logged the capability violation.

This article describes the architecture of a WASM-based postinstall sandbox, the WASI capability grants required for the two major categories of legitimate `postinstall` use cases, a pragmatic near-term implementation path that does not require waiting for ecosystem-wide WASM adoption, and the failure modes that undermine the control if they go unaddressed.

## Threat Model

- **`postinstall` RAT reading credential files from the home directory.** The installing user's `~/.npmrc` contains their npm authentication token. `~/.aws/credentials` contains cloud access keys. `~/.ssh/id_rsa` is the private SSH key. A `postinstall` script has read access to all of these by default, because Node.js inherits the file descriptor namespace of the parent process without restriction. The Axios RAT read these files and transmitted their contents.

- **`postinstall` RAT exfiltrating environment variables via outbound HTTP.** CI pipelines inject secrets as environment variables: `GITHUB_TOKEN`, `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `DOCKER_PASSWORD`, `SONAR_TOKEN`. These are present in the environment of every process spawned during a CI job, including `npm install`. A one-line Node.js script can collect them all and send them to an attacker endpoint: `require('https').request({...}).end(JSON.stringify(process.env))`. This is the primary attack the Axios RAT used to harvest CI credentials at scale.

- **`postinstall` RAT writing persistence mechanisms outside the package directory.** A `postinstall` script running as a developer's user account can write to `~/.bashrc`, `~/.zshrc`, crontab entries (via `crontab -e` spawned as a child process), or `~/.config/systemd/user/` on Linux. This establishes persistence that survives the removal of the malicious package. A `postinstall` RAT that only needs to exfiltrate credentials once may accept a brief window; one that wants persistent access writes a mechanism that re-runs after removal.

- **Cross-package attack via `node_modules/` access.** A `postinstall` script can read `node_modules/` of any package installed in the same project — not just its own files. This allows a compromised package to read configuration files and credentials embedded in other packages (for example, packages that bundle `.env` configuration or private registry credentials as part of their setup), or to modify the source files of other installed packages to inject malicious code that runs later.

- **Access level for all scenarios.** The adversary requires only that a package they control or have compromised is added to the target's dependency graph — directly or transitively. No network access to the target, no prior authentication, no vulnerability in npm's own code. The postinstall mechanism is the access vector.

## Hardening Configuration

### 1. WASI Capability Model for postinstall

WASI's capability-based model grants access through explicit resource handles. A `WasiCtx` built with only the resources a script needs cannot access anything else — the runtime refuses calls to resources not in the context, producing a WASI capability error rather than a permission denied from the OS.

The two major categories of legitimate `postinstall` use cases require different capability profiles.

**Category A: Native module compilation.** Packages like `node-gyp`-based native modules compile C/C++ or Rust source into a `.node` binary during install. They need: read access to the source files in the package directory, write access to the `build/` subdirectory within the package, access to system compiler tools (typically via `PATH`-based execution), and nothing else. No network, no home directory, no environment variables beyond the local build context.

**Category B: Binary downloader.** Packages like Playwright and Puppeteer download pre-compiled browser binaries from a CDN during install. They need: write access to a cache directory (e.g., `~/.cache/playwright/`), outbound HTTPS to a specific set of CDN hostnames, and no filesystem access beyond the cache directory.

```rust
use wasmtime::*;
use wasmtime_wasi::preview2::{WasiCtxBuilder, DirPerms, FilePerms};
use wasmtime_wasi::preview2::SocketAddrCheck;

fn build_native_compile_wasi(package_dir: &str) -> anyhow::Result<WasiCtx> {
    let pkg = cap_std::fs::Dir::open_ambient_dir(
        package_dir, cap_std::ambient_authority())?;

    let build_path = format!("{}/build", package_dir);
    std::fs::create_dir_all(&build_path)?;
    let build_dir = cap_std::fs::Dir::open_ambient_dir(
        &build_path, cap_std::ambient_authority())?;

    let mut wasi = WasiCtxBuilder::new();
    wasi.preopened_dir(pkg, DirPerms::READ, FilePerms::READ, "/pkg")?;
    wasi.preopened_dir(build_dir, DirPerms::all(), FilePerms::all(), "/pkg/build")?;

    wasi.stdin(Box::new(wasmtime_wasi::preview2::pipe::ClosedInputStream));
    wasi.stdout(Box::new(wasmtime_wasi::preview2::pipe::MemoryOutputPipe::new(1024 * 1024)));
    wasi.stderr(Box::new(wasmtime_wasi::preview2::pipe::MemoryOutputPipe::new(512 * 1024)));

    Ok(wasi.build())
}

fn build_binary_downloader_wasi(cache_dir: &str, allowed_hosts: &[&str]) -> anyhow::Result<WasiCtx> {
    let cache = cap_std::fs::Dir::open_ambient_dir(
        cache_dir, cap_std::ambient_authority())?;

    let allowed: Vec<String> = allowed_hosts.iter().map(|s| s.to_string()).collect();

    let mut wasi = WasiCtxBuilder::new();
    wasi.preopened_dir(cache, DirPerms::all(), FilePerms::all(), "/cache")?;

    wasi.socket_addr_check(move |addr, _| {
        let host = addr.ip().to_string();
        allowed.iter().any(|h| h == &host)
    });
    wasi.allow_tcp(true);
    wasi.allow_udp(false);

    wasi.stdin(Box::new(wasmtime_wasi::preview2::pipe::ClosedInputStream));
    wasi.stdout(Box::new(wasmtime_wasi::preview2::pipe::MemoryOutputPipe::new(1024 * 1024)));
    wasi.stderr(Box::new(wasmtime_wasi::preview2::pipe::MemoryOutputPipe::new(512 * 1024)));

    Ok(wasi.build())
}
```

Neither context includes `wasi:cli/environment`. The sandbox process has no access to environment variables: `AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, and `GITHUB_TOKEN` are invisible to the hook. The network socket check in the binary downloader allows TCP connections only to pre-resolved IP addresses on the CDN allowlist — a `postinstall` script attempting a connection to an unlisted IP address traps immediately.

### 2. Architecture: a WASM-Based npm Hook Runner

A WASM-based npm hook runner sits between npm's lifecycle invocation and the actual `postinstall` script execution. npm fires lifecycle hooks by running the script value from `package.json`'s `"scripts"` map as a shell command. A hook runner intercepts this invocation — either via npm's `--script-shell` flag pointing to the runner binary, or via a registry-side policy that transforms all lifecycle scripts — and instead executes the script inside Wasmtime with a restricted WASI context built for the package's declared capability profile.

The runner's responsibilities:

1. **Identify the capability profile for the package.** Read the package's declared postinstall type from a policy file (or a package registry annotation). Determine whether the package is a native compiler, binary downloader, or other category. Packages not matching any known category default to the most restrictive policy or are blocked entirely.

2. **Compile or wrap the postinstall script.** If the `postinstall` script is a JavaScript file, compile it to WASM using a JS-to-WASM compiler (in 2026, tools like `componentize-js` and `StarlingMonkey` can compile JavaScript to WASM components). If the script is a shell script, wrap it in a WASM shell interpreter compiled to WASM. The resulting `.wasm` module is the execution unit.

3. **Build a `WasiCtx` with only the required capabilities.** Use the capability profile identified in step 1 to construct a `WasiCtx` containing only the preopened directory handles and socket allowlists appropriate for this package.

4. **Run the module in Wasmtime.** Instantiate the module with fuel limits (to prevent infinite loops) and memory limits. Capture stdout and stderr. Surface the exit code to npm's lifecycle machinery so npm proceeds normally on success and fails the install on failure.

5. **Log all capability access attempts.** Wasmtime traps on denied capability accesses. The runner captures these traps and logs them as structured events: package name, package version, attempted capability (filesystem path, network address, environment variable name), and disposition (denied).

This is an architectural pattern that, as of May 2026, is being pioneered by security-focused research tools and early-stage commercial products rather than mainstream npm infrastructure. The npm CLI itself does not yet support running lifecycle scripts in WASM sandboxes. The architecture describes the target state that tooling is moving toward.

### 3. Practical Near-Term Implementation: `--ignore-scripts` Plus Explicit Allowlist

Since a full WASM sandbox for all postinstall scripts is not yet production-ready across all package types, the pragmatic current approach is to disable lifecycle scripts entirely and selectively re-enable only those that have been reviewed and approved.

```bash
npm install --ignore-scripts
```

This flag causes npm to skip all lifecycle scripts — `preinstall`, `install`, `postinstall`, `prepare`, and others — for all packages in the dependency graph. It is the single highest-impact mitigation available today, applicable immediately without any tooling changes.

After `--ignore-scripts` install, run only the approved scripts for packages that genuinely require them. Execute each approved script in an isolated Docker container with networking disabled:

```bash
docker run \
  --network=none \
  --read-only \
  --tmpfs /tmp \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  -e NODE_ENV=production \
  -v "$(pwd)/node_modules/canvas:/pkg:rw" \
  node:22-slim \
  sh -c "cd /pkg && node install.js"
```

`--network=none` prevents any outbound connection. `--read-only` with `--tmpfs /tmp` prevents writes outside explicitly mounted paths. `--cap-drop ALL` removes all Linux capabilities from the container process. The only environment variable passed is `NODE_ENV` — secrets are not injected. The volume mount restricts the container's view to the single package's directory; it cannot read `node_modules/` of other packages.

Maintain an approved list of packages whose postinstall scripts are permitted to run, along with the specific Docker command used for each:

```toml
[[approved_postinstall]]
package = "canvas"
version = "^2.11.0"
reason = "Compiles native bindings for node-canvas"
run_command = "node install.js"
network = false
env = ["NODE_ENV"]

[[approved_postinstall]]
package = "playwright"
version = "^1.44.0"
reason = "Downloads browser binaries for E2E tests"
run_command = "node install.js"
network = true
network_allowlist = ["storage.googleapis.com", "playwright.azureedge.net"]
env = ["PLAYWRIGHT_BROWSERS_PATH"]
```

Any package not on the approved list runs with `--ignore-scripts` in effect — its `postinstall` never executes. This is the default-deny posture.

### 4. Environment Variable Sanitisation Before postinstall

Even without a WASM sandbox, removing sensitive environment variables before `npm install` eliminates the primary exfiltration payload for `postinstall` RATs. The Axios attacker's RAT could not transmit credentials it never had access to.

Wrap all `npm install` invocations in a script that unsets sensitive variables, runs the install, and relies on the caller's environment being restored after the subprocess returns:

```bash
#!/usr/bin/env bash
set -euo pipefail

SENSITIVE_VARS=(
  AWS_SECRET_ACCESS_KEY
  AWS_ACCESS_KEY_ID
  AWS_SESSION_TOKEN
  NPM_TOKEN
  GITHUB_TOKEN
  GITLAB_TOKEN
  DOCKER_PASSWORD
  SONAR_TOKEN
  SNYK_TOKEN
  VAULT_TOKEN
  GCP_SERVICE_ACCOUNT_KEY
  AZURE_CLIENT_SECRET
)

for var in "${SENSITIVE_VARS[@]}"; do
  unset "$var"
done

npm install --ignore-scripts "$@"
```

Save this as `safe-npm-install.sh` and replace all CI pipeline `npm install` calls with `./safe-npm-install.sh`. The secrets are present in the CI job's environment before the script runs and after it exits, but not in any process spawned by `npm install` during its execution. A `postinstall` script attempting `process.env.AWS_SECRET_ACCESS_KEY` receives `undefined`.

This does not protect against `postinstall` scripts that read credential files from the filesystem (`~/.aws/credentials`, `~/.npmrc`) — for filesystem credential isolation, combine this with either the WASM sandbox approach or the Docker isolation approach from section 3.

### 5. Monitoring for WASM Sandbox Violations

A WASM sandbox running via Wasmtime generates structured trap events when a module attempts to access a capability not in its `WasiCtx`. These traps are the primary detection signal for supply chain RAT activity. Configure Wasmtime to log capability violations to a structured format and forward them to a SIEM as high-priority alerts.

```rust
use wasmtime::*;

fn configure_engine_with_logging() -> Engine {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);

    config.on_trap(|trap_info| {
        let event = serde_json::json!({
            "event_type": "wasm_sandbox_trap",
            "trap_kind": format!("{:?}", trap_info.kind()),
            "package": std::env::var("POSTINSTALL_PACKAGE").unwrap_or_default(),
            "package_version": std::env::var("POSTINSTALL_VERSION").unwrap_or_default(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        eprintln!("{}", event);
    });

    Engine::new(&config).expect("engine configuration failed")
}
```

```toml
[siem_forwarding]
log_file = "/var/log/npm-sandbox/violations.jsonl"
alert_on = [
  "wasm_sandbox_trap",
  "capability_denied_network",
  "capability_denied_filesystem",
  "capability_denied_env",
]
severity = "HIGH"
```

Forward `violations.jsonl` to your SIEM via a log shipper (Filebeat, Fluent Bit, or the SIEM's native agent). Create a detection rule that fires on any `event_type: wasm_sandbox_trap` event where the package name is not on the approved-exceptions list. A single violation from an unknown package during an `npm install` warrants immediate investigation: abort the install, quarantine the CI runner, and review the package version for malicious content.

The structured log should include the package name and version, the specific capability that was denied (network address attempted, filesystem path attempted, environment variable name requested), the timestamp, and the CI job identifier if available. This gives the security team enough context to triage the violation without manual reconstruction.

## Expected Behaviour After Hardening

With WASI capability restriction in place, the Axios RAT's execution path collapses at the first privileged action it attempts.

The RAT's environment variable read — `process.env.AWS_SECRET_ACCESS_KEY` — maps to a WASI `wasi:cli/environment` capability call. That capability is not in the sandbox's `WasiCtx`. The runtime returns an empty environment or a capability error depending on how the sandbox is configured. `AWS_SECRET_ACCESS_KEY` is `undefined`. The credential exfiltration payload is empty.

The RAT's outbound network connection to its C2 server maps to a `wasi:sockets/tcp` call to an IP address not on the allowlist. The runtime's `socket_addr_check` callback returns `false`. The connection attempt raises a WASI capability error. The trap handler logs a `capability_denied_network` event with the attempted destination address. The C2 connection never establishes.

The RAT's attempt to read `~/.npmrc` maps to a `wasi:filesystem` `path_open` call for a path outside the package directory's preopened handle. The cap-std directory handle refuses paths that resolve outside its root. The file open fails with an `ENOENT`-equivalent error from the sandbox. `~/.npmrc` is inaccessible.

The RAT's attempt to write a persistence mechanism to `~/.bashrc` maps to a `path_open` with write intent on a path outside the preopened directory. The sandbox refuses. The write never reaches the filesystem.

With environment variable sanitisation alone (without WASM sandboxing): the RAT executes successfully as a Node.js process, reads the filesystem, and establishes its C2 connection. But `AWS_SECRET_ACCESS_KEY` is not in the environment. The credential exfiltration payload contains no secrets. The SIEM receives no alert at the time of execution, but the RAT's outbound connection to a known-malicious IP may be caught by network-layer monitoring.

The combination — environment variable sanitisation and WASM sandboxing — defeats both the exfiltration and the network callback entirely.

## Trade-offs and Operational Considerations

Full WASM sandboxing of `postinstall` scripts requires that each script be compilable to WASM. JavaScript-based `postinstall` scripts can be compiled using `componentize-js` or run in a JS WASM engine. Shell scripts can be interpreted by a WASM-compiled shell (mvdan/sh compiled to WASM, for example). Native binary executions — calling `node-gyp`, `cmake`, or `make` as subprocesses from a `postinstall` script — cannot trivially be sandboxed this way; native subprocesses escape the WASM sandbox. The WASM sandbox approach applies cleanly to pure-JS or pure-shell postinstall scripts. For packages that spawn native build tools, the Docker isolation approach from section 3 is the more practical containment mechanism in 2026.

Environment variable sanitisation before `npm install` is low-cost and immediately deployable. It requires no tooling changes beyond replacing `npm install` with a wrapper script in CI pipeline definitions. It eliminates the highest-value target of `postinstall` RATs — environment-injected CI secrets — without affecting the ability of legitimate `postinstall` scripts to compile native modules or download binaries. Implement this today, regardless of whether the WASM sandbox is in place.

Binary-downloading `postinstall` scripts (Playwright, Puppeteer, Electron) have legitimate requirements for network access to specific CDN endpoints. WASI capability grants for these must be scoped to the exact CDN hostnames and resolved IP ranges, not to `0.0.0.0/0`. These IP ranges change when CDN providers update their infrastructure, which means the allowlist requires maintenance. Pin the IP allowlist in a configuration file under version control and update it as part of dependency updates.

A WASM-sandboxed `postinstall` that fails because the script exceeded its capability grants will cause the npm install to fail. This is the correct security behaviour, but it will surprise developers the first time a legitimate `postinstall` triggers a capability violation because the sandbox was configured too narrowly. Run sandboxes in audit mode first: log capability violations but do not block execution. Review the audit logs for each package to identify what capabilities the script legitimately requires, update the capability profile, and then switch to enforce mode.

## Failure Modes

- **WASM sandbox in audit mode indefinitely.** The sandbox logs capability violations but allows execution to proceed, because no one has reviewed the audit logs and switched the package to enforce mode. The sandbox provides telemetry but not protection. Build a CI gate that fails if any package in the approved list has been in audit mode for more than 30 days without a documented capability profile review.

- **Environment variable unset wrapper not applied to `npm run` scripts.** The wrapper script covers `npm install` but the CI pipeline also runs `npm run build` or `npm run prepare` as separate steps, with the full secret-bearing environment restored. Malicious `prepare` or `prepack` scripts in compromised packages execute during these steps with complete credential access. The unset wrapper must wrap all npm lifecycle invocations, not only `npm install`.

- **Capability grant for the package directory set too broadly.** The preopened directory handle passed to the sandbox covers `node_modules/` of the entire project rather than only the specific package directory. This allows the sandboxed script to read other packages' files — including any embedded credentials, `.env` files, or configuration with secrets. The preopened handle must be scoped to the specific package's directory: `node_modules/canvas/`, not `node_modules/`.

- **WASI trap events logged but not forwarded to SIEM.** Trap events are written to a log file on the CI runner's local filesystem. The log file is not collected by the log shipper because the runner is ephemeral and the log directory is not in the shipper's collection path. Sandbox violations are recorded but never reviewed, and the next identical attack on a different runner produces no alert. Validate that trap events appear in the SIEM by running a test package with a known capability violation during sandbox configuration and confirming the alert fires.

## Related Articles

- [WASM OT Edge Sandboxing](/articles/wasm/wasm-ot-edge-sandboxing/)
- [WASI Preview 2 Capabilities](/articles/wasm/wasi-preview-2-capabilities/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [npm Postinstall Kernel Detection](/articles/linux/npm-postinstall-kernel-detection/)
- [npm Maintainer Account Security](/articles/cross-cutting/npm-maintainer-account-security/)
