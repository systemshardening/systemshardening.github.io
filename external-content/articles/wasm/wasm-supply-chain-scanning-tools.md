---
title: "WASM-Compiled Supply Chain Scanning Tools: Portable npm Security for Any CI Environment"
description: "The Axios attack needed fast, portable scanning tools deployable anywhere. WASM-compiled security scanners run on any platform without installation, with WASI capability sandboxing, and verifiable reproducible builds — the ideal CI supply chain tool format."
slug: wasm-supply-chain-scanning-tools
date: 2026-05-04
lastmod: 2026-05-04
category: wasm
tags:
  - supply-chain
  - npm
  - wasm
  - wasi
  - ci-security
personas:
  - platform-engineer
  - security-engineer
article_number: 430
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/wasm/wasm-supply-chain-scanning-tools/
---

# WASM-Compiled Supply Chain Scanning Tools: Portable npm Security for Any CI Environment

## The Problem

When the Axios compromise was disclosed on March 31 2026, security teams needed to run two types of tools immediately: scanners to determine which `package-lock.json` files in their repositories contained `axios@1.14.1`, and analysers to extract and inspect `postinstall` scripts from npm tarballs to understand the attack pattern. The problem with existing tools was threefold. They are native binaries requiring installation and OS-specific builds. They often need broad filesystem access — reading entire `node_modules` directories, accessing the npm cache, resolving paths against the home directory. And they cannot be easily distributed to heterogeneous environments: GitHub Actions runners on Ubuntu, Kubernetes init containers on Alpine Linux, developer laptops on a range of distributions, and air-gapped internal environments where fetching a new binary from GitHub Releases means a procurement and security review process that takes days.

During an incident, those days are not available. The question is whether you can run a scanner right now, on the machine you have, without installing anything.

A WASM-compiled scanner answers that question. It is a single `.wasm` file that runs identically on all these platforms via Wasmtime. WASI capability grants restrict it to only the directories it needs to read, so it cannot exfiltrate the lockfiles it scans or read credentials from the home directory. A reproducible build means the scanner binary itself carries a published SHA-256 hash that operators can verify before execution — a property that native binaries from a GitHub Releases page do not have in any practical sense. Three properties — portability, capability sandboxing, and binary verifiability — make WASM the appropriate format for supply chain scanning tools distributed to heterogeneous environments.

This article covers compiling a Rust lockfile scanner to the `wasm32-wasi` target, configuring the WASI capability grants for read-only scanning, establishing a reproducible build that publishes a verifiable hash, integrating the scanner into a GitHub Actions pipeline, and building a companion WASM postinstall script extractor that would have shown the Axios `postinstall` payload before any developer ran `npm install`.

## Threat Model

- **Supply chain attack on the scanning tool itself.** A compromised native binary scanner could exfiltrate the `package-lock.json` files it reads. Those files contain the complete list of every dependency name and version in the project — a detailed map of the attack surface. A scanner run with broad permissions can read far more than the lockfile: the entire home directory, `~/.npmrc`, credential files, environment-injected secrets. A WASM scanner with a correctly-scoped WASI capability grant cannot access anything beyond the directory it is pointed at. Network access is not granted. The home directory is not a preopened path. `wasi:cli/environment` is not in the context, so environment variables are invisible to the scanner.

- **Platform heterogeneity breaking native scanner deployment.** A scanner that works on the developer's Ubuntu laptop fails in an Alpine-based Kubernetes init container because it dynamically links against `glibc` that is not present on Alpine's `musl` libc. A statically-linked scanner binary built for `x86_64-linux` fails on an `arm64` runner. A scanner that requires Python 3.11 fails where only 3.9 is installed. WASM has no dynamic linking, no libc dependency, no architecture sensitivity. A single `scanner.wasm` file runs on any platform that has Wasmtime, and Wasmtime itself is a single static binary.

- **Scanner binary not verified before use.** A developer downloads a `lockfile-scanner` native binary from a GitHub Release attachment and runs it with broad permissions. The binary is not signed and has no published hash. A compromised release — whether from a compromised maintainer account, a build system backdoor, or a CDN cache poisoning — runs undetected. A WASM scanner with a reproducible build has a published SHA-256 hash computed from the source at a known commit. Any binary that does not match the expected hash is rejected before execution.

- **Incident response delay due to scanner installation overhead.** Every minute spent installing dependencies, troubleshooting `node_modules` conflicts, resolving OS-level package manager errors, and fighting network access restrictions in an air-gapped environment is time during which the compromised package is present in more production systems. A WASM scanner with its only runtime dependency being Wasmtime — itself a single static binary checked into the CI tool cache — reduces time-to-first-scan from tens of minutes to seconds.

## Hardening Configuration

### 1. Compiling a Rust lockfile scanner to WASM

The lockfile scanner reads a `package-lock.json` file, extracts all package name and version pairs from the `packages` map, and compares them against an IOC list provided as a YAML file. Any match causes the scanner to exit with a non-zero status and print the matching entry to stdout.

Rust is the right language for this tool. The `wasm32-wasi` target is fully supported by the stable Rust toolchain. The `serde_json` and `serde` crates compile cleanly to WASM without any OS-dependent behaviour. The output is a small self-contained binary — a JSON parser and a YAML reader together produce a `scanner.wasm` in the 400–600 KB range. There are no host function imports beyond WASI file I/O, so the WASI surface is minimal.

The core scanner logic reads the lockfile via a WASI preopened directory path. It never uses an absolute path like `/home/user/project/` — it opens the file relative to the preopened directory handle that Wasmtime provides, which constrains all file I/O to the granted directory.

```rust
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;

#[derive(Deserialize)]
struct IocList {
    packages: Vec<String>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: scanner <lockfile-path> <ioc-list-path>");
        std::process::exit(2);
    }

    let lockfile_content = fs::read_to_string(&args[1])
        .expect("failed to read package-lock.json");
    let ioc_content = fs::read_to_string(&args[2])
        .expect("failed to read ioc list");

    let lockfile: Value = serde_json::from_str(&lockfile_content)
        .expect("invalid package-lock.json");
    let ioc: IocList = serde_yaml::from_str(&ioc_content)
        .expect("invalid ioc list");

    let ioc_set: std::collections::HashSet<String> =
        ioc.packages.iter().cloned().collect();

    let mut found = false;
    if let Some(packages) = lockfile["packages"].as_object() {
        for (key, meta) in packages {
            let name = key.trim_start_matches("node_modules/");
            let version = meta["version"].as_str().unwrap_or("");
            let pkg_id = format!("{}@{}", name, version);
            if ioc_set.contains(&pkg_id) {
                println!("IOC match: {} found in package-lock.json", pkg_id);
                found = true;
            }
        }
    }

    std::process::exit(if found { 1 } else { 0 });
}
```

Compile to the WASI target. The `wasm32-wasip1` target corresponds to WASI Preview 1, which is what Wasmtime's `--dir` flag model addresses; use `wasm32-wasip2` if your Wasmtime version supports component model features.

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/lockfile-scanner.wasm scanner.wasm
```

The `Cargo.toml` profile for the release build strips debug info, enables link-time optimisation, and sets `panic = "abort"` to avoid pulling in the unwinding runtime:

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = "debuginfo"
panic = "abort"
```

### 2. WASI capability grant: read-only access to the scan directory

The scanner only needs two capabilities: read access to the directory containing the `package-lock.json` and the IOC list, and write access to stdout for results. Nothing else. No network socket, no home directory, no `/tmp`, no access to any other path on the filesystem.

The Wasmtime CLI expresses this through the `--dir` flag, which maps a host directory to a guest path via a WASI preopened directory. The scanner sees only what is under that path. Attempts to access paths outside it produce a WASI `EBADF` or `ENOTCAPABLE` error.

```bash
wasmtime run \
  --dir /path/to/repo/frontend::/ \
  scanner.wasm \
  /package-lock.json \
  /ioc-packages.yaml
```

The `::` syntax maps the host path on the left to the guest root `/` on the right. The scanner opens `/package-lock.json` and `/ioc-packages.yaml` relative to that root. The host directory `/path/to/repo/frontend` is the only filesystem resource accessible to the scanner process. The scanner cannot read `../backend/package-lock.json`, cannot access `~/.npmrc`, and cannot open any file descriptor beyond what Wasmtime provides.

Contrast this with a native binary scanner run as:

```bash
./lockfile-scanner /path/to/repo/frontend/package-lock.json ioc-packages.yaml
```

That binary runs as the invoking user with access to every file that user can read. If the scanner binary is compromised, it can read the entirety of `~`, post results to a network endpoint, and log environment variables — all within the same process that the user trusts to scan their lockfile.

Omit `--env` entirely to exclude all environment variables from the sandbox. The scanner does not need them, and excluding them ensures that secrets injected as CI environment variables — `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` — are invisible to the scanner process even if the scanner binary were somehow compromised.

### 3. Reproducible WASM build for scanner verification

A reproducible build ensures that any operator who builds `scanner.wasm` from the published source at the tagged commit gets the same byte sequence — and therefore the same SHA-256 hash — as the binary in the release. This makes the published hash meaningful: it is not just "the hash of the binary we happened to upload" but "the hash of the binary that anyone can reproduce from source".

Pin the Rust toolchain in `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.78.0"
targets = ["wasm32-wasip1"]
profile = "minimal"
```

Set `SOURCE_DATE_EPOCH` from the git commit timestamp and apply path remapping to eliminate machine-specific paths from any embedded metadata:

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)
export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME/.cargo=/cargo"
export CARGO_HOME=/tmp/cargo-isolated

cargo +1.78.0 build --release --target wasm32-wasip1 --locked

sha256sum target/wasm32-wasip1/release/lockfile-scanner.wasm
```

The `--locked` flag requires `Cargo.lock` to be present and up-to-date, preventing any dependency resolution that would produce a different set of crate versions across builds. `CARGO_HOME=/tmp/cargo-isolated` avoids pulling in any local cargo configuration that might differ between machines.

Publish the resulting hash in the release notes and as a file alongside the binary:

```bash
sha256sum target/wasm32-wasip1/release/lockfile-scanner.wasm \
  > scanner.wasm.sha256
```

Operators verify before use:

```bash
sha256sum --check scanner.wasm.sha256
```

A mismatch means the binary does not correspond to the published source. Do not execute it. The scanner is treated as untrusted and quarantined for investigation.

### 4. Integrating the WASM scanner into CI

A GitHub Actions workflow downloads the scanner binary, verifies its hash, and runs it against every `package-lock.json` in the repository. If any IOC package is found, the step fails and the build is blocked.

The IOC list is maintained in the repository under version control. On the day of the Axios disclosure, the security team commits `axios@1.14.1` to `ioc-packages.yaml`. Every subsequent CI run on every affected repository checks for the IOC without requiring any tool installation change.

```yaml
name: Supply Chain Scan

on:
  push:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4

      - name: Install Wasmtime
        run: |
          curl -L https://github.com/bytecodealliance/wasmtime/releases/download/v21.0.0/wasmtime-v21.0.0-x86_64-linux.tar.xz \
            -o wasmtime.tar.xz
          echo "EXPECTED_WASMTIME_HASH  wasmtime.tar.xz" | sha256sum --check
          tar -xf wasmtime.tar.xz
          mv wasmtime-v21.0.0-x86_64-linux/wasmtime /usr/local/bin/wasmtime

      - name: Download scanner
        run: |
          curl -L https://github.com/your-org/lockfile-scanner/releases/download/v1.2.0/scanner.wasm \
            -o scanner.wasm
          curl -L https://github.com/your-org/lockfile-scanner/releases/download/v1.2.0/scanner.wasm.sha256 \
            -o scanner.wasm.sha256

      - name: Verify scanner hash
        run: sha256sum --check scanner.wasm.sha256

      - name: Scan lockfiles
        run: |
          EXIT=0
          find . -name "package-lock.json" -not -path "*/node_modules/*" | while read lockfile; do
            dir=$(dirname "$lockfile")
            wasmtime run \
              --dir "${dir}::/" \
              scanner.wasm \
              /package-lock.json \
              /ioc-packages.yaml || EXIT=1
          done
          exit $EXIT
```

The scanner requires no installation beyond `wasmtime`, which is itself a single static binary with no runtime dependencies. The step adds under 10 seconds to the CI pipeline on typical lockfiles. The hash verification step runs before the scanner binary is ever executed, so a compromised release binary is rejected before it can read any repository files.

### 5. WASM-based postinstall script extractor

The companion tool to the lockfile scanner is a postinstall script extractor: it takes an npm tarball path, extracts `package.json` from the tarball without writing the full package contents to disk, and outputs the `scripts` fields — `preinstall`, `install`, `postinstall`, `prepare` — to stdout.

This is the tool that would have allowed any developer or security analyst to inspect `axios@1.14.1` before running `npm install`. The tarball is downloaded, its `package.json` is read, and the `postinstall` field is printed. The analyst sees the malicious command without executing it and without extracting the full package into `node_modules`.

The tool's architecture is a Rust binary compiled to `wasm32-wasip1` that:

1. Accepts a tarball path as its only argument, resolved via a WASI preopened directory.
2. Opens the tarball using the `tar` and `flate2` crates, which are pure Rust and compile cleanly to WASM without WASI socket or process capabilities.
3. Iterates tarball entries looking for `package/package.json` (the path prefix npm uses inside package tarballs).
4. Parses the `scripts` map from `package.json` using `serde_json`.
5. Prints each lifecycle script key and value to stdout in a structured format.
6. Exits 0 if no lifecycle scripts are present, 1 if any are found (so CI pipelines can flag packages with hooks for review).

```rust
use flate2::read::GzDecoder;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use tar::Archive;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: postinstall-extractor <tarball-path>");
        std::process::exit(2);
    }

    let file = File::open(&args[1]).expect("failed to open tarball");
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let mut found_scripts = false;

    for entry in archive.entries().expect("failed to read tarball") {
        let mut entry = entry.expect("invalid tarball entry");
        let path = entry.path().expect("invalid path").into_owned();
        let path_str = path.to_string_lossy();

        if path_str == "package/package.json" {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)
                .expect("failed to read package.json");

            let pkg: Value = serde_json::from_str(&contents)
                .expect("invalid package.json");

            if let Some(scripts) = pkg["scripts"].as_object() {
                let lifecycle = ["preinstall", "install", "postinstall", "prepare", "prepack"];
                for key in &lifecycle {
                    if let Some(val) = scripts.get(*key) {
                        println!("{}: {}", key, val);
                        found_scripts = true;
                    }
                }
            }
            break;
        }
    }

    std::process::exit(if found_scripts { 1 } else { 0 });
}
```

The WASI capability grant for this tool is similarly narrow. It receives read access to the directory containing the tarball — nothing more. No write access, no network, no home directory:

```bash
wasmtime run \
  --dir /path/to/tarballs::/ \
  postinstall-extractor.wasm \
  /axios-1.14.1.tgz
```

On the day of the Axios compromise, running this tool against the `axios@1.14.1` tarball would have immediately shown the `postinstall` script content — the malicious command — without executing it and without the tarball being installed anywhere. Security teams could have shared the extractor as a single `.wasm` file, runnable by anyone with `wasmtime`, across every type of machine in their environment.

## Expected Behaviour After Hardening

After the WASM scanner is integrated into CI and the IOC list is under version control: on the day of the Axios disclosure, the security team opens a pull request adding `axios@1.14.1` to `ioc-packages.yaml`. The PR is merged. Every subsequent CI run on every repository that uses the scanner workflow checks all `package-lock.json` files against the updated IOC list. Repositories containing `axios@1.14.1` fail their build with a structured output line: `IOC match: axios@1.14.1 found in package-lock.json`. The failure appears within the normal CI execution time — no additional installation steps, no compatibility troubleshooting — because `scanner.wasm` is already cached in the CI environment and Wasmtime is already installed. The security team gets a complete picture of affected repositories through CI build statuses rather than manual auditing.

After hash verification is enforced: if a compromised `scanner.wasm` binary with a different content is published at the release URL — whether through a compromised release pipeline, a CDN cache poisoning, or a compromised GitHub account — the `sha256sum --check` step in the CI workflow fails before the binary is executed. The scanner never reads any repository files. The CI job fails with a hash mismatch error, which is surfaced as a CI failure and triggers investigation.

The postinstall extractor runs in security team triage workflows: before any npm package version is approved for use in CI or production, the extractor is run against the tarball to surface lifecycle scripts. Packages with no lifecycle scripts pass automatically. Packages with lifecycle scripts enter a manual review queue where the script content is inspected before the package is added to the approved dependency list.

## Trade-offs and Operational Considerations

Wasmtime must be available in the CI environment. The recommended approach is to install Wasmtime as a single step early in the CI workflow — it is a static binary of approximately 30 MB with no runtime dependencies — or to use a base container image that includes Wasmtime. For air-gapped environments, Wasmtime is distributed as a self-contained binary that can be committed to an internal artifact repository and fetched from there. The Wasmtime binary itself should have its hash verified, forming the same trust anchor as the scanner.

WASM scanner performance is slightly slower than an equivalent native binary. Parsing a 5 MB `package-lock.json` in WASM via Wasmtime takes approximately 10–15% longer than the same code compiled and run as a native binary. For the typical CI use case — scanning one or a handful of lockfiles per build — this means the difference between 80 milliseconds and 90 milliseconds. It is not a meaningful factor in the decision to use WASM over native.

Reproducible builds require a pinned Rust toolchain. Updating the toolchain — even a patch release — requires rebuilding the scanner, verifying that the new build is reproducible (two independent builds from the same source produce the same hash), publishing the new hash, and updating any CI workflows that reference the hash. This is a deliberate friction: it ensures that toolchain updates are intentional and reviewed rather than silently applied by a floating `stable` toolchain reference. Establish a process for toolchain updates that includes a sign-off step before the new hash is published.

The WASM portability story depends on Wasmtime implementing WASI Preview 1 consistently across platforms. Wasmtime's WASI implementation is mature and consistent across Linux, macOS, and Windows for the file I/O capabilities used by these scanning tools. Platform-specific behaviour differences in WASI are rare for tools that only use filesystem and stdout capabilities, which are the only capabilities the scanner and extractor require.

## Failure Modes

- **WASM scanner SHA-256 not verified before use.** The CI workflow downloads `scanner.wasm` and runs it directly without verifying the hash. A compromised binary with a different hash is executed without detection. The scanner has read access to the directory containing the lockfile; a compromised scanner can exfiltrate it. Make hash verification a required gate: fail the CI job if the hash check step is absent or if `sha256sum --check` exits non-zero.

- **`--dir` WASI grant too broad.** The `--dir` flag is set to the repository root or, worse, to `/` — the entire filesystem. The WASI sandbox is technically active but provides no meaningful restriction: the scanner can read every file accessible to the CI runner's user account. Scope the `--dir` grant to the specific directory containing the lockfile being scanned. If scanning multiple lockfiles across subdirectories, invoke the scanner once per lockfile with a directory grant scoped to that lockfile's parent directory.

- **Scanner IOC list not updated promptly.** The WASM scanner is efficient and portable, but it only detects packages that appear in the IOC list. A novel attack pattern using a package name not on the IOC list — for example, a dependency of `axios` that was also compromised but disclosed later — is not detected. The IOC list must be maintained as a living artifact with a documented update process, a responsible team, and a defined SLA for adding newly disclosed malicious packages. The scanner is a known-bad detector, not a behavioural anomaly detector.

- **Scanner integrated in CI but not run against existing deployed images.** New builds are scanned and any repository that triggers a CI run after the IOC list update is checked. But production container images built before the IOC list update — and services that have not had a new build since the compromise — contain `axios@1.14.1` and are not identified by CI scanning. Run a separate one-time scan against the artifact registry: extract `package-lock.json` from each production image and run the WASM scanner against it outside the normal CI flow. The WASM scanner's portability makes this straightforward — it runs on the operator's workstation without any environment setup beyond Wasmtime.

## Related Articles

- [WASM npm Postinstall Sandbox](/articles/wasm/wasm-npm-postinstall-sandbox/)
- [Reproducible WASM Builds](/articles/wasm/reproducible-wasm-builds/)
- [WASM Static Analysis](/articles/wasm/wasm-static-analysis/)
- [SBOM Supply Chain Compromise Detection](/articles/observability/sbom-supply-chain-compromise-detection/)
- [npm Lockfile Integrity Security](/articles/cicd/npm-lockfile-integrity-security/)
