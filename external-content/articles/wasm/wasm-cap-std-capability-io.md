---
title: "Capability-Based File I/O Security in WASM with cap-std and WASI"
description: "Traditional POSIX I/O grants processes ambient authority over any path they have filesystem permission to access. cap-std eliminates that by replacing ambient functions with capability objects — every file operation is relative to a pre-opened Dir handle, making path traversal structurally impossible and WASM plugin sandboxing composable without root."
slug: wasm-cap-std-capability-io
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - cap-std
  - capabilities
  - wasi
  - file-io-security
  - ambient-authority
personas:
  - security-engineer
  - platform-engineer
article_number: 577
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-cap-std-capability-io/
---

# Capability-Based File I/O Security in WASM with cap-std and WASI

## Problem

Every POSIX process inherits a filesystem namespace scoped to the entire host tree. A Rust program that calls `std::fs::File::open("/etc/shadow")` will succeed if the process has permission to read that file — regardless of whether any of the code that led to that call was intended to access `/etc/shadow`. This is the ambient authority problem: file access authority is ambient, meaning it flows implicitly through the running program rather than being explicitly passed to code that needs it.

In traditional application security, the defences against ambient authority are operating-system facilities layered outside the process:

- **chroot jails** — restrict the root seen by the process, but require root to create and have well-known escapes.
- **Linux namespaces / mount namespaces** — powerful but require elevated privileges or a user namespace.
- **seccomp filters** — can block individual syscalls but cannot distinguish "open this specific directory" from "open any path" at the syscall level without complex BPF rules.
- **AppArmor / SELinux profiles** — effective but maintained in a separate policy language, checked at kernel level, and not composable with Rust's type system.

All of these work from outside the process. They do nothing to prevent one module, function, or library inside a process from using paths it should not know about. A plugin that receives the string `"../../../../etc/passwd"` from untrusted input can, with standard `std::fs` APIs, attempt to open it.

For WASM runtimes hosting untrusted plugins, this matters at two levels. First, the host process (typically Rust or a Go embedder) manages file access on behalf of WASM modules; if the host uses ambient I/O, a bug in the host can let a plugin access paths it was never intended to reach. Second, WASM's system interface (WASI) is built on a capability model, but implementing that model correctly in the host requires something better than ambient `std::fs` calls.

`cap-std` is a Rust library that replaces the entire `std::fs` and `std::net` API surface with capability-based equivalents. Its central type is `cap_std::fs::Dir` — a handle to a directory that can only open files and subdirectories relative to itself. There is no API in `cap_std` for opening an absolute path from a `Dir`; the type system makes it impossible. This makes capability confinement a compile-time property rather than a runtime policy.

**Target systems:** Rust applications hosting WASM plugins via Wasmtime; WASI embedder code using `wasmtime-wasi`; Rust services that expose filesystem access to untrusted code; any Rust codebase where `std::fs` ambient authority is a threat surface.

## Threat Model

- **Adversary 1 — Path traversal through a plugin:** An attacker controls input that becomes part of a file path used by a WASM plugin. The plugin calls a WASM host function to read a file. The host naively appends the user path to a base directory using string concatenation and opens the result with `std::fs::File::open`. The attacker provides `"../../etc/host-private-key.pem"` and reads a file outside the intended directory.
- **Adversary 2 — Symlink escape from a preopened directory:** A plugin is given a preopened directory `/var/plugins/tenant-a/data`. The directory contains a symlink that points to `/var/plugins/tenant-b/data` (created by a previous tenant who had write access). The plugin follows the symlink via a standard `readlink`-compatible call and reads files belonging to another tenant.
- **Adversary 3 — Absolute path injection in WASI:** A WASI module is given preopened directories but the host uses a WASI implementation that accepts absolute paths in `path_open` arguments when they resolve within the host's filesystem. The module submits an absolute path and escapes its preopen.
- **Adversary 4 — Host code using ambient I/O alongside capability I/O:** A Rust host mixes `cap_std::fs::Dir` for plugin-facing code and `std::fs` for internal code. A refactor accidentally routes plugin-controlled data through an internal code path using `std::fs::File::open`. The ambient call succeeds with ambient authority.
- **Access level:** Adversaries 1 through 3 need only to control input to a running WASM plugin. Adversary 4 requires the ability to trigger a code path in the host — achievable if the plugin controls any function argument that reaches the wrong code path.
- **Objective:** Read or write files outside the intended scope — another tenant's data, host credentials, system configuration files.
- **Blast radius:** Without cap-std, the blast radius is the full set of files readable/writable by the host process user. With cap-std used throughout, the blast radius is bounded to the `Dir` handles explicitly opened by the embedder for that plugin instance.

## Configuration

### Step 1: Add cap-std to the Host Codebase

```toml
# Cargo.toml (host embedder — the Rust process that runs the WASM runtime)
[dependencies]
cap-std = "3"
wasmtime = "25"
wasmtime-wasi = "25"
anyhow = "1"
```

`cap-std` 3.x tracks the `cap-primitives` crate family, which provides symlink-safe path resolution, `O_PATH`-based directory traversal on Linux, and the `AmbientAuthority` token type that controls where ambient I/O is still allowed.

### Step 2: Understand the Ambient Authority Token

`cap-std` makes the distinction between ambient and capability I/O explicit through the `AmbientAuthority` token type:

```rust
use cap_std::{ambient_authority, fs::Dir};

// ambient_authority() returns a token that explicitly marks this call
// as using the process's ambient filesystem access.
// This is the ONLY place in the file where ambient I/O is legitimate.
let root_dir = Dir::open_ambient_dir("/var/lib/wasm-host/plugins", ambient_authority())?;
```

The `ambient_authority()` function returns a zero-sized token value. Every function that takes ambient filesystem access requires it as an argument — `Dir::open_ambient_dir`, `File::open_ambient`, etc. Functions that take a `&Dir` as the entry point (like `Dir::open`) do not accept `AmbientAuthority` because they have no need for it; they are already capability-scoped.

The security pattern is: call `ambient_authority()` once during host startup, in a single clearly-audited function, to produce the top-level `Dir` objects. All subsequent I/O goes through those `Dir` handles. A code review looking for ambient I/O can grep for `ambient_authority()` and find every instance.

### Step 3: Build a Capability-Scoped Plugin Host

A plugin host that grants WASM modules access to specific directories using `cap-std`:

```rust
// plugin_host.rs
use cap_std::{ambient_authority, fs::{Dir, OpenOptions}};
use std::path::Path;

pub struct PluginCapabilities {
    /// Read-only: the plugin may only read from this directory.
    pub config_dir: Dir,
    /// Write-capable: the plugin may read and write this directory.
    pub output_dir: Dir,
}

impl PluginCapabilities {
    /// Called once per tenant during host initialisation.
    /// ambient_authority() is used here and nowhere else in this file.
    pub fn for_tenant(tenant_id: &str) -> anyhow::Result<Self> {
        let aa = ambient_authority();

        let config_path = format!("/var/lib/wasm-host/tenants/{tenant_id}/config");
        let output_path = format!("/var/lib/wasm-host/tenants/{tenant_id}/output");

        // Fail fast if the directories don't exist; never create them here
        // (creation would be an ambient write to an arbitrary path).
        let config_dir = Dir::open_ambient_dir(&config_path, aa)?;
        let output_dir = Dir::open_ambient_dir(&output_path, aa)?;

        Ok(Self { config_dir, output_dir })
    }
}

/// Read a plugin config file. The path comes from untrusted plugin code.
/// cap-std's Dir::open rejects absolute paths and ".." traversal out of the dir.
pub fn read_config(caps: &PluginCapabilities, plugin_path: &str) -> anyhow::Result<Vec<u8>> {
    // plugin_path is an arbitrary string from the WASM module.
    // Dir::open uses symlink-safe, capability-scoped resolution.
    // A path like "../../etc/passwd" will return an error, not that file.
    let mut file = caps.config_dir.open(plugin_path)?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut buf)?;
    Ok(buf)
}

/// Write a plugin output file. Same path safety as read_config.
pub fn write_output(caps: &PluginCapabilities, plugin_path: &str, data: &[u8]) -> anyhow::Result<()> {
    let file = caps.output_dir.open_with(
        plugin_path,
        OpenOptions::new().write(true).create(true).truncate(true),
    )?;
    std::io::Write::write_all(&mut { file }, data)?;
    Ok(())
}
```

The critical property: `Dir::open` on `cap-std` 3.x uses `openat2(2)` with `RESOLVE_BENEATH` on Linux (or equivalent safe logic on other platforms). `RESOLVE_BENEATH` is a kernel flag that causes `openat2` to return `EXDEV` if any component of the path — including symlink targets — resolves to a location above the base directory. There is no TOCTOU window, no symlink escape, and no need for userspace path canonicalisation.

### Step 4: Pass cap-std Directories to WASM via WASI Preopens

WASI uses "preopened directories" — directory file descriptors that the host hands to the WASM module at startup, before `_start` runs. The module can only open files relative to these preopens. `wasmtime-wasi` accepts `cap_std::fs::Dir` values directly as preopens, connecting the cap-std capability model to the WASM sandbox boundary.

```rust
// wasmtime_host.rs
use cap_std::{ambient_authority, fs::Dir};
use wasmtime::{Engine, Store};
use wasmtime::component::{Component, Linker};
use wasmtime_wasi::{WasiCtxBuilder, WasiCtx, WasiView, ResourceTable, DirPerms, FilePerms};

struct HostState {
    table: ResourceTable,
    wasi: WasiCtx,
}

impl WasiView for HostState {
    fn table(&mut self) -> &mut ResourceTable { &mut self.table }
    fn ctx(&mut self) -> &mut WasiCtx { &mut self.wasi }
}

pub fn run_plugin(tenant_id: &str, plugin_wasm: &[u8]) -> anyhow::Result<()> {
    let engine = Engine::default();
    let component = Component::from_binary(&engine, plugin_wasm)?;

    // Open capability-scoped dirs using ambient authority (once, here only).
    let aa = ambient_authority();
    let config_dir = Dir::open_ambient_dir(
        format!("/var/lib/wasm-host/tenants/{tenant_id}/config"),
        aa,
    )?;
    let output_dir = Dir::open_ambient_dir(
        format!("/var/lib/wasm-host/tenants/{tenant_id}/output"),
        aa,
    )?;

    // Build the WASI context. Each preopened_dir call maps a cap-std Dir
    // to a path that the WASM module will see as its root for that mount.
    // DirPerms::READ_ONLY means the dir handle is passed read-only to the module.
    // DirPerms::all() passes read+write access.
    let wasi_ctx = WasiCtxBuilder::new()
        .preopened_dir(config_dir, DirPerms::READ_ONLY, FilePerms::READ_ONLY, "/config")?
        .preopened_dir(output_dir, DirPerms::all(), FilePerms::all(), "/output")?
        // No env vars, no CLI args, no other directories.
        .build();

    let mut store = Store::new(&engine, HostState {
        table: ResourceTable::new(),
        wasi: wasi_ctx,
    });

    // Link standard WASI interfaces and run.
    let mut linker: Linker<HostState> = Linker::new(&engine);
    wasmtime_wasi::add_to_linker_sync(&mut linker)?;
    let instance = linker.instantiate(&mut store, &component)?;

    // Call the plugin's exported entrypoint.
    let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
    run.call(&mut store, ())?;

    Ok(())
}
```

The WASM module's view of the filesystem contains exactly two directories: `/config` (read-only) and `/output` (read-write). Any attempt by the module to open `/etc/passwd`, `/proc/self/environ`, or any path that does not descend from `/config` or `/output` returns `ENOENT` or `EACCES`. There is no host configuration file or profile that controls this; it is enforced by the cap-std `Dir` objects themselves, which the WASI layer uses for all `path_open` calls from the module.

### Step 5: Directory Traversal Prevention — What cap-std Actually Checks

`cap-std`'s path resolution does more than reject `..` components. The full list of what `Dir::open` prevents on Linux with `openat2 + RESOLVE_BENEATH`:

```rust
// All of these fail with an error from Dir::open — they do not reach
// the actual filesystem at the target path.

caps.config_dir.open("../../etc/passwd")?;          // EXDEV: above base
caps.config_dir.open("/etc/passwd")?;               // EXDEV: absolute path
caps.config_dir.open("subdir/../../../etc/passwd")?; // EXDEV: traversal after subdir

// Symlinks that point outside the cap-std directory also fail:
// If config_dir/link -> /etc/passwd, then:
caps.config_dir.open("link")?;                      // EXDEV: symlink target outside base

// Symlinks pointing within the directory are fine:
// If config_dir/link -> ./actual-config.toml, then:
caps.config_dir.open("link")?;                      // OK: symlink stays inside
```

On older kernels (pre-5.6, where `openat2` is unavailable), `cap-std` falls back to a userspace path walker that performs equivalent checks. The fallback is more expensive but maintains the same security properties. The `cap-primitives` dependency `CARGO_CFG_TARGET_OS` detection handles this transparently.

### Step 6: Auditing a Codebase for Ambient I/O

Converting an existing Rust codebase to use cap-std requires finding every ambient I/O call. The full audit list:

```bash
# Find all ambient filesystem access in a Rust project.
# These are the functions that bypass capability confinement.
rg --type rust \
  'std::fs::|fs::File::open|fs::read\b|fs::write\b|fs::read_to_string|fs::create_dir|fs::remove_file|fs::remove_dir|fs::rename|fs::copy|fs::metadata|fs::symlink_metadata|fs::canonicalize|fs::hard_link|fs::read_link|fs::read_dir|std::path::Path::new.*open' \
  src/

# Find any remaining ambient_authority() calls after migration.
# Every occurrence must be justified and code-reviewed.
rg --type rust 'ambient_authority\(\)' src/
```

After migration, the policy is: `ambient_authority()` appears exactly in `HostState::new()` (or equivalent startup code) and nowhere else. Any future PR that introduces a new `ambient_authority()` call requires explicit security review. CI can enforce this:

```bash
# .github/workflows/security.yml (or equivalent)
# Fail if ambient_authority() appears outside the approved file.
count=$(grep -r 'ambient_authority()' src/ \
        --include='*.rs' \
        --exclude='plugin_host_init.rs' | wc -l)
if [ "$count" -gt 0 ]; then
  echo "Unapproved use of ambient_authority() found"
  exit 1
fi
```

### Step 7: cap-std in the WASI Preview 2 Resource Model

WASI Preview 2 models filesystem access through the `wasi:filesystem/types/descriptor` resource type. A descriptor is a capability handle: the WASM module holds it, passes it to host functions, and cannot create one without the host giving it one. `wasmtime-wasi`'s Preview 2 implementation stores descriptors in the `ResourceTable` and resolves paths relative to the descriptor's backing `cap_std::fs::Dir`.

```wit
// From wasi:filesystem/types@0.2.0 (simplified)
interface types {
  resource descriptor {
    // All path operations are relative to the descriptor.
    // There is no global open() that takes an absolute path.
    open-at: func(
      path-flags: path-flags,
      path: string,
      open-flags: open-flags,
      flags: descriptor-flags,
    ) -> result<descriptor, error-code>;

    read-via-stream: func(offset: filesize) -> result<input-stream, error-code>;
    write-via-stream: func(offset: filesize) -> result<output-stream, error-code>;

    // stat, readdir, readlink, etc. are all relative to this descriptor.
    stat: func() -> result<descriptor-stat, error-code>;
    readdir: func(reuse-readdir: bool) -> result<directory-entry-stream, error-code>;
  }
}
```

The type system of WIT enforces what cap-std enforces in Rust: to open any file, you need a `descriptor` for its ancestor directory. The WIT world of a well-designed component never exposes a raw `path_open`-style function; it exposes `descriptor.open-at` relative to a pre-granted root. The host provides the root descriptor via `preopened_dir`; the module descends from there.

## Real-World Example: A Config-Reader / Report-Writer Plugin

The following shows a complete workflow: a host that grants a WASM plugin access to exactly one read-only config directory and one write-only output directory, with the plugin compiled from Rust targeting `wasm32-wasip2`.

**Plugin source (compiled to WASM):**

```rust
// plugin/src/lib.rs — compiled with: cargo component build --target wasm32-wasip2
use std::fs;
use std::path::Path;

#[export_name = "run"]
pub extern "C" fn run() {
    // Plugin's entire filesystem view:
    //   /config  — read-only, provided by host
    //   /output  — read-write, provided by host
    //
    // Any attempt to open /etc, /proc, /, or any path outside
    // these two trees will fail with ENOENT at the WASI layer.

    let config_raw = fs::read_to_string("/config/settings.toml")
        .expect("settings.toml must be present in the config dir");

    let report = process_config(&config_raw);

    // Path traversal in the output path is also prevented:
    // fs::write("/output/../../etc/cron.d/evil", ...) would fail.
    fs::write("/output/report.txt", report.as_bytes())
        .expect("failed to write report");
}

fn process_config(raw: &str) -> String {
    // Plugin logic here. No matter what the config contains,
    // it cannot cause the plugin to write outside /output.
    format!("Processed at plugin runtime:\n{raw}")
}
```

**Host initialisation (abbreviated):**

```rust
// host/src/main.rs
fn main() -> anyhow::Result<()> {
    let tenant_id = std::env::args().nth(1).expect("tenant_id arg required");
    let plugin_bytes = std::fs::read("plugin.wasm")?;  // one-time ambient read

    run_plugin(&tenant_id, &plugin_bytes)?;
    println!("Plugin completed for tenant {tenant_id}");
    Ok(())
}
```

The plugin reads `settings.toml` from `/config` and writes `report.txt` to `/output`. If the config file contains a path like `include = "../../host-secrets/key.pem"` and buggy plugin code tries to open that path directly, the `open` call fails — the string `"../../host-secrets/key.pem"` is resolved relative to the plugin's WASI preopen root, not the host filesystem root, and cap-std's `RESOLVE_BENEATH` prevents ascending past the preopen.

## cap-std vs Traditional Filesystem Sandboxing

| Mechanism | Requires root / privilege | Works in-process | Symlink-safe | Composable with Rust types | Language-level enforcement |
|---|---|---|---|---|---|
| chroot | Yes (or user namespace) | No (OS-level) | Partial (chroot escapes exist) | No | No |
| Mount namespaces | Yes or user ns | No | Yes | No | No |
| seccomp (path filtering) | No | No | Yes (blocks syscalls) | No | No |
| AppArmor / SELinux | No (policy setup needs root) | No | Yes | No | No |
| cap-std | No | Yes | Yes (`openat2 RESOLVE_BENEATH`) | Yes (`Dir` type) | Yes (type-checked) |

cap-std's key advantage over OS-level sandboxing is that it composes. A `Dir` value can be passed to a function, stored in a struct, or cloned — all while retaining the capability constraint. An OS namespace, by contrast, applies to the entire process and cannot be scoped to a function call or a plugin instance. A process that serves multiple tenants would need a separate OS-level sandbox per tenant; with cap-std, one process can serve many tenants, each with their own `Dir` values pointing to different directories, with no cross-tenant leakage.

## Expected Behaviour

With a correctly configured host using cap-std preopens:

| Action by WASM plugin | Expected result |
|---|---|
| Open `/config/settings.toml` | Success (within preopen, read-only) |
| Open `/config/../../etc/passwd` | `EXDEV` / `EACCES` from cap-std |
| Open `/etc/passwd` directly | `ENOENT` — no preopen covers `/etc` |
| Follow a symlink inside `/config` to a file also inside `/config` | Success |
| Follow a symlink inside `/config` to a file outside `/config` | `EXDEV` — `RESOLVE_BENEATH` blocks it |
| Write to `/config/modified.toml` | `EACCES` — config preopen is `DirPerms::READ_ONLY` |
| Write to `/output/report.txt` | Success (within preopen, read-write) |
| Write to `/output/../config/settings.toml` | `EXDEV` — traversal blocked |
| Open any path not under `/config` or `/output` | `ENOENT` |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| Capability-scoped `Dir` | Path traversal structurally impossible | API surface different from `std::fs`; existing code must be ported | Use `cap-std`'s `fs` module as a drop-in; most `std::fs` patterns map 1:1 |
| `ambient_authority()` token | Ambient I/O is grep-auditable | Startup code still uses ambient I/O | Isolate startup in one clearly-named function; enforce in CI |
| `openat2 RESOLVE_BENEATH` | Symlink-safe without userspace canonicalization | Requires Linux 5.6+; older kernels use fallback | The fallback in `cap-primitives` provides equivalent safety; document minimum kernel version |
| Per-plugin `Dir` handles | Tenants isolated from each other in one process | More file descriptors open per tenant | Close `Dir` handles when the plugin instance terminates; FDs are released |
| Read-only `DirPerms` | Config directory cannot be modified by a buggy plugin | Writes fail at runtime, not compile time | Document the expected permissions contract in the plugin API; test with a write attempt |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Host code uses `std::fs` alongside `cap-std` | Ambient I/O reachable through refactored code path | CI grep for `std::fs::File::open` in non-approved files | Enforce in CI; require `cap-std` for all I/O in files that handle plugin paths |
| `Dir` opened with too-broad path | Plugin can access more of the host tree than intended | Log the paths passed to `Dir::open_ambient_dir`; review against expected per-tenant tree | Tighten the ambient open to the narrowest needed directory |
| Kernel older than 5.6 uses fallback resolver | Path check is userspace; TOCTOU window opens under heavy concurrent rename | Monitor kernel version; test on old kernels with concurrent rename stress | Pin host kernel to 5.6+; treat older kernels as unsupported for multi-tenant WASM |
| Plugin stores a `descriptor` handle across invocations | Plugin accumulates open file handles, exhausting the `ResourceTable` limit | `ResourceTable::max_entries` returns error; plugin receives EMFILE | Set per-instance `ResourceTable` entry limits; drop handles at invocation boundaries |
| `DirPerms::all()` given to a config preopen | Plugin can modify its own config, enabling persistence of attacker data | Unit test: attempt a write to the config preopen; expect failure | Split config and output into separate `Dir` values; always pass config as `READ_ONLY` |

## Related Articles

- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM Component Model Security Boundaries](/articles/wasm/wasm-component-model-security/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [Wasmtime WASI Resource Limits](/articles/wasm/wasmtime-wasi-resource-limits/)
- [WASM Dynamic Linking Security](/articles/wasm/wasm-dynamic-linking-security/)
