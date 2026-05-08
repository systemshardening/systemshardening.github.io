---
title: "rust-openssl Buffer Overflow in Safe Rust: CVE-2026-41676"
description: "CVE-2026-41676 causes heap overflow from safe Rust code when rust-openssl calls EVP_PKEY_derive on OpenSSL 1.1.x. Learn how this breaks Rust's safety guarantees, how to detect affected crates, and how to harden your Rust PKI stack."
slug: rust-openssl-buffer-overflow
date: 2026-05-03
lastmod: 2026-05-03
category: cross-cutting
tags:
  - rust
  - openssl
  - buffer-overflow
  - cve
  - pki
personas:
  - security-engineer
  - platform-engineer
article_number: 397
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/cross-cutting/rust-openssl-buffer-overflow/
---

## The Problem

Rust's ownership model, borrow checker, and type system prevent buffer overflows in safe code — that is not a marketing claim, it is a language guarantee enforced at compile time. CVE-2026-41676 breaks that guarantee. A caller invoking `Deriver::derive` or `PkeyCtxRef::derive` from the `openssl` crate on a system running OpenSSL 1.1.x can trigger a heap or stack overflow without writing a single `unsafe` block. The buffer overflow happens inside a `safe fn`, in a crate that appears in hundreds of production Rust services.

The root cause sits at the FFI boundary between rust-openssl and the OpenSSL C library. When a Rust program performs key derivation, rust-openssl calls `EVP_PKEY_derive` from libcrypto and passes a pointer to an output buffer along with a `pkeylen` parameter that is supposed to limit how many bytes OpenSSL writes. The `pkeylen` parameter is documented as an in/out parameter: on entry the caller sets it to the buffer length; on exit OpenSSL sets it to the number of bytes written. rust-openssl pre-allocates an output buffer, sets `pkeylen` to that buffer's length, and passes both to `EVP_PKEY_derive`. On OpenSSL 3.x, this works correctly — the function respects the incoming length and refuses to write more bytes than the buffer holds. On OpenSSL 1.1.x, however, the implementation of `EVP_PKEY_derive` for X25519, X448, Diffie-Hellman, and HKDF-extract operations ignores the incoming `pkeylen` value entirely and unconditionally writes the full shared secret, regardless of the buffer size the caller declared. If the caller pre-allocated a shorter buffer — for instance, because it asked for a partial key derivation, passed an incorrect estimate, or encountered a mismatch between expected and actual key length — the C library writes past the end of the allocation.

The allocation being overflowed belongs to the Rust process's heap. Rust's allocator cannot prevent this because the overflow is performed by C code holding a raw pointer. The borrow checker has no visibility into what the C library does with the pointer once it crosses the FFI boundary. From Rust's perspective, the call is safe: the pointer is valid, the length is set, the function signature is satisfied. The memory corruption happens in a region of memory that the Rust compiler and runtime cannot observe or protect.

Any Rust binary performing key derivation via the `openssl` crate on an OpenSSL 1.1.x system is affected. The vulnerable operations are X25519 key exchange (used in TLS 1.3 key agreement), X448 key exchange, standard Diffie-Hellman key derivation, and HKDF-extract. This covers TLS handshake logic, VPN session establishment, certificate generation, and any key derivation function layered on top of OpenSSL. Crates that wrap the `openssl` crate transitively are also affected — including `rustls-openssl` backends, `openssl`-based TLS adapters for `reqwest` and `hyper`, and `rcgen` when it links against the system OpenSSL.

OpenSSL 1.1.x is not a legacy edge case. RHEL 8 and its downstream derivatives (CentOS Stream 8, AlmaLinux 8, Rocky Linux 8) ship OpenSSL 1.1.1 as the system library. Ubuntu 20.04 LTS, which reaches end of standard support in April 2025 but remains widely deployed in enterprise environments on extended maintenance, ships OpenSSL 1.1.1. Alpine Linux images prior to 3.19 also use OpenSSL 1.1.x. Amazon Linux 2, the most widely used Amazon Linux version in AWS, ships OpenSSL 1.0.2 for some configurations and 1.1.1 for others. Docker base images built on any of these distributions carry the vulnerable system OpenSSL regardless of when the container image was last rebuilt, unless the underlying OS package was explicitly updated.

The fix was merged to the `openssl-rs/openssl` GitHub repository and published to crates.io as `openssl` version 0.10.78 on April 19, 2026. The oss-sec mailing list advisory followed the same day, but there was a 72-hour window between the fix appearing on crates.io and the RustSec advisory database (RUSTSEC-2026-XXXX) and the GitHub Security Advisory (GHSA) being published. During this window, operators running `cargo audit` against their projects would have received no alerts — the vulnerability was fully public, the exploitable behaviour was documented in the fix commit, but the advisory databases had not yet been updated. Operators who monitor crates.io release feeds or GitHub release notifications for `openssl-sys` and `openssl` had a head start. The pattern mirrors the silent-publish dynamic seen in Go and npm ecosystems: the fix lands in the source and package registry before the advisory infrastructure catches up.

The CVE was disclosed on April 19, 2026. The fixed version is `openssl = "0.10.78"` on crates.io. Any project with a `Cargo.lock` pinning an older version of the `openssl` crate, regardless of whether `Cargo.toml` specifies a semver range that would permit 0.10.78, remains vulnerable until `cargo update` is run and the lock file is regenerated.

## Threat Model

The primary impact is a crash. An attacker who can induce a Rust service to perform key derivation with a mismatched buffer — for example, by manipulating the negotiated cipher suite in a TLS handshake, supplying a crafted DH public key, or triggering an HKDF-extract with an unexpected output length — can cause the service to crash with a heap corruption signal. This is a reliable denial-of-service primitive against any Rust service performing key derivation on OpenSSL 1.1.x.

Remote code execution via controlled heap layout is theoretically possible. Heap overflows have been weaponised for RCE in C and C++ programs throughout the history of memory-unsafe languages, and the underlying mechanism here is the same: a C library writing past the end of an allocation into heap metadata or adjacent allocations. The practical difficulty of turning this specific overflow into RCE depends on the Rust allocator in use, the exact allocation layout at the time of the overflow, and whether the attacker can control the size and content of the overflow. This is not a trivial bar to clear, but it is not impossible, particularly in long-running services with predictable allocation patterns.

**Affected environments:**
- RHEL 8 and downstream (AlmaLinux 8, Rocky Linux 8, CentOS Stream 8) — OpenSSL 1.1.1
- Ubuntu 20.04 LTS — OpenSSL 1.1.1
- Amazon Linux 2 — OpenSSL 1.1.x variants
- Alpine Linux < 3.19 — OpenSSL 1.1.x
- Any Docker image built `FROM` the above distributions without an explicit `openssl` package upgrade

**Affected Rust crates and systems:**
- Any crate using `openssl` directly for `Deriver::derive`, `PkeyCtxRef::derive`, or related key derivation APIs
- `rustls-openssl` backends — the OpenSSL provider path in rustls alternatives
- `openssl`-backed TLS for `reqwest` (feature flag `native-tls` with system OpenSSL)
- `rcgen` when linked against system OpenSSL 1.1.x
- cert-manager's Rust components if they use the system OpenSSL for key operations
- Any service performing TLS 1.3 handshakes, VPN session establishment, or certificate generation via the `openssl` crate

**Impact by operation:**
- X25519 / X448 key exchange: affects every TLS 1.3 connection using X25519 or X448 as the key agreement group
- DH key derivation: affects TLS connections using DHE cipher suites
- HKDF-extract: affects key material derivation layered on top of key exchange

The crash is not conditional on a configuration error or a developer mistake. A Rust developer writing `safe` code using the documented API of the `openssl` crate can trigger this overflow with a straightforward call to `Deriver::derive`. No `unsafe` block is required.

## Hardening Configuration

### Audit Your Dependency Tree

Before remediating, identify every location in your project's dependency graph where `openssl` or `openssl-sys` appears.

```bash
cargo tree -i openssl
```

```bash
cargo tree -i openssl-sys
```

These commands show every crate that depends on `openssl` or `openssl-sys`, including transitive dependencies. A crate three levels deep in your dependency graph can still trigger the vulnerability if it calls into `EVP_PKEY_derive`. For each crate shown, determine whether it performs key derivation (as opposed to, for example, only using OpenSSL for symmetric encryption or hashing).

Run `cargo audit` to check whether the installed versions appear in the RustSec advisory database:

```bash
cargo install cargo-audit
cargo audit
```

During the 72-hour window after the fix was published but before the advisory database was updated, `cargo audit` returned no results. After the advisory was published, `cargo audit` will flag any version of `openssl` below 0.10.78 with the RUSTSEC advisory identifier. Run `cargo audit` as part of your CI pipeline on every commit and on a scheduled basis against deployed lockfiles.

### Upgrade rust-openssl

Bump the `openssl` crate in `Cargo.toml` to the fixed version:

```toml
[dependencies]
openssl = "0.10.78"
```

After updating `Cargo.toml`, regenerate the lockfile:

```bash
cargo update -p openssl
cargo update -p openssl-sys
```

If a transitive dependency pins an older version of `openssl` via its own `Cargo.toml`, `cargo update -p openssl` alone may not be sufficient. Check whether the transitive pin is blocking the upgrade:

```bash
cargo tree -i openssl --duplicates
```

If `--duplicates` shows multiple versions of `openssl` in the tree, one of your transitive dependencies has a hard pin to an older version. Either upgrade that dependency to a version compatible with `openssl` 0.10.78 or open an issue with the upstream crate.

Verify the final lockfile contains only the fixed version:

```bash
grep -A1 'name = "openssl"' Cargo.lock | grep version
```

The output must show `version = "0.10.78"` or higher. If any `version = "0.10.7[0-7]"` entries remain, a transitive dependency is still pulling in the vulnerable version and needs to be addressed before deployment.

### Switch the System OpenSSL to 3.x

Upgrading the Rust crate alone is insufficient if the system OpenSSL remains at 1.1.x. The `openssl-sys` crate links against the system's libcrypto at compile time (or at runtime via dynamic linking). Even with `openssl = "0.10.78"`, the Rust code calls into whatever OpenSSL version is installed on the host. If that is still 1.1.1, the fixed Rust bindings are calling a still-vulnerable C library.

The cleanest remediation in containerised environments is to update the base image to one that ships OpenSSL 3.x:

```dockerfile
FROM ubuntu:22.04
```

```dockerfile
FROM alpine:3.19
```

```dockerfile
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
```

Ubuntu 22.04 ships OpenSSL 3.0.x. Alpine 3.19 ships OpenSSL 3.1.x. RHEL 9 / UBI 9 ships OpenSSL 3.0.x. All three respect the `pkeylen` in/out parameter in `EVP_PKEY_derive` and do not write past the declared buffer length.

For non-containerised deployments on RHEL 8 or Ubuntu 20.04 where upgrading the OS is not immediately feasible, install OpenSSL 3 from a parallel package location and set `OPENSSL_DIR` during compilation so that `openssl-sys` links against the newer version rather than the system default. This approach requires careful management of `LD_LIBRARY_PATH` or `rpath` settings and carries compatibility risk with other system packages that expect OpenSSL 1.1.x. Containerisation is the lower-risk path.

Verify which OpenSSL version your Rust binary has linked against after rebuilding:

```bash
ldd target/release/your-binary | grep libcrypto
openssl version
```

The `openssl version` command on the host must report `OpenSSL 3.x.y` for the system library to be safe. If it reports `OpenSSL 1.1.1`, the system library is still vulnerable.

### Consider rustls as an Alternative

`rustls` is a TLS library written entirely in safe Rust, backed by `ring` or `aws-lc-rs` for cryptographic operations. It has no FFI boundary to OpenSSL and is not affected by CVE-2026-41676 or any other OpenSSL-specific vulnerability.

If your service uses `reqwest` for HTTP and is currently linked against OpenSSL via the `native-tls` feature, switching to `rustls` eliminates the OpenSSL dependency:

```toml
[dependencies]
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls"] }
tokio-rustls = "0.26"
```

For `tokio`-based TLS servers, replace the OpenSSL backend with `tokio-rustls`:

```toml
[dependencies]
tokio-rustls = "0.26"
rustls = "0.23"
```

The migration from `native-tls` to `rustls` is not zero-effort. `rustls` does not support PKCS#12 keystores, OpenSSL engine integrations, or HSM-backed keys via the OpenSSL engine API. If your service loads certificates from PKCS#12 files or delegates private key operations to an HSM through the OpenSSL engine interface, `rustls` is not a drop-in replacement. Evaluate the specific features your service requires before committing to the migration.

### Pin and Verify in CI with cargo-deny

`cargo-deny` enforces policies on your dependency tree at build time, including minimum version requirements and advisory database checks. Create a `deny.toml` at the repository root:

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[bans]
multiple-versions = "warn"

[[bans.deny]]
name = "openssl"
version = "< 0.10.78"
wrappers = []

[[bans.deny]]
name = "openssl-sys"
version = "< 0.9.103"
```

The `[[bans.deny]]` entries fail the build if any version of `openssl` below 0.10.78 or `openssl-sys` below 0.9.103 appears anywhere in the resolved dependency graph, including transitive dependencies.

Add `cargo-deny` to your CI pipeline alongside `cargo audit`:

```bash
cargo install cargo-deny
cargo deny check advisories
cargo deny check bans
```

Run both checks on every pull request and on a nightly schedule against the production lockfile. The nightly run catches cases where a new advisory is published for a dependency version that was already in the lockfile before the advisory existed — the 72-hour window scenario described above.

### RustSec Advisory Database

The RustSec advisory database at `https://rustsec.org` is the canonical source for Rust-ecosystem vulnerability advisories. Configure `cargo-deny` to fetch the advisory database on every CI run rather than relying on a cached local copy:

```toml
[advisories]
db-urls = ["https://github.com/rustsec/advisory-db"]
db-path = "~/.cargo/advisory-db"
```

Subscribe to the RustSec advisory feed for new advisories affecting crates in your dependency tree. The RustSec GitHub repository also provides a machine-readable advisory format at `advisory-db/crates/` — each advisory is a TOML file with affected version ranges, CVE identifiers, and GHSA identifiers. Parsing this feed in a monitoring script allows you to alert on new advisories before your next CI run.

To query which advisories affect a specific crate version directly:

```bash
curl -s "https://api.osv.dev/v1/query" \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "openssl", "ecosystem": "crates.io"}, "version": "0.10.77"}' \
  | jq '.vulns[] | {id: .id, summary: .summary}'
```

This query returns all known advisories for `openssl` 0.10.77 from the OSV database, which aggregates RustSec, GHSA, and NVD data. Running this programmatically against every crate version in `Cargo.lock` provides an independent check against the advisory database that does not require `cargo audit` to be installed.

## Expected Behaviour After Hardening

After upgrading to `openssl` 0.10.78 or later and rebuilding against OpenSSL 3.x, `cargo audit` returns no advisories for `openssl` or `openssl-sys`. The output will resemble:

```bash
$ cargo audit
    Fetching advisory database from `https://github.com/rustsec/advisory-db`
      Loaded 123 security advisories (from ~/.cargo/advisory-db)
    Scanning Cargo.lock for vulnerabilities (123 unique packages)
        No vulnerable packages found
```

On OpenSSL 3.x, the `EVP_PKEY_derive` function correctly reads the incoming `pkeylen` value as a buffer length limit, writes at most that many bytes, and sets `pkeylen` to the actual number of bytes written on return. The asymmetry between what the Rust caller declared and what OpenSSL writes is resolved.

A regression test confirming the fix can be written as a standard Rust unit test that allocates a deliberately short output buffer and calls `Deriver::derive`. On the patched combination of crate and library, the call must return an error rather than silently writing past the buffer:

```rust
#[cfg(test)]
mod tests {
    use openssl::derive::Deriver;
    use openssl::pkey::PKey;

    #[test]
    fn derive_does_not_overflow_short_buffer() {
        let pkey = PKey::generate_x25519().unwrap();
        let peer_pkey = PKey::generate_x25519().unwrap();
        let peer_pub = PKey::public_key_from_raw_bytes(
            &peer_pkey.raw_public_key().unwrap(),
            openssl::pkey::Id::X25519,
        )
        .unwrap();

        let mut deriver = Deriver::new(&pkey).unwrap();
        deriver.set_peer(&peer_pub).unwrap();

        let mut short_buf = vec![0u8; 8];
        let result = deriver.derive(&mut short_buf);
        assert!(
            result.is_err(),
            "derive must return an error rather than overflow a short buffer"
        );
    }
}
```

On OpenSSL 1.1.x with `openssl` < 0.10.78, this test is undefined behaviour — the call writes 32 bytes into an 8-byte buffer, corrupting heap memory. On the patched combination, the call returns an error and the test passes. Run this test against a staging environment before promoting to production to confirm that both the Rust crate and the system OpenSSL are at the required versions.

## Trade-offs and Operational Considerations

Switching to `rustls` is the most complete remediation — it removes the OpenSSL FFI boundary entirely — but it is not universally applicable. Services that rely on OpenSSL-specific features cannot migrate without reworking those integrations:

- **PKCS#12 keystores**: `rustls` cannot load certificates and private keys from PKCS#12 (`.p12`, `.pfx`) files. Services that receive certificates in PKCS#12 format from enterprise PKI systems or cloud certificate managers must either convert the format at import time or retain the OpenSSL dependency.
- **HSM integration via OpenSSL engine API**: hardware security modules are frequently integrated into Rust services through OpenSSL's engine interface (`ENGINE_by_id`, `EVP_PKEY_new_with_libctx`). `rustls` has no equivalent extension point. Services that offload private key operations to HSMs via OpenSSL engines cannot switch to `rustls` without a separate HSM client library.
- **OpenSSL provider model (3.x only)**: OpenSSL 3 introduced the provider model as a replacement for the engine API. If your service already targets OpenSSL 3.x, it is unaffected by CVE-2026-41676, and the provider model offers a more stable long-term path for HSM integration than the legacy engine interface.

Upgrading the system OpenSSL from 1.1.x to 3.x on RHEL 8 or Ubuntu 20.04 carries its own risks. OpenSSL 3.x removed several deprecated APIs that were present in 1.1.x, and it changed the ABI for `EVP_MD_CTX`, `EVP_CIPHER_CTX`, and related structures. C libraries that were compiled against OpenSSL 1.1.x headers and link dynamically against libcrypto.so.1.1 will not load correctly if the system OpenSSL is replaced wholesale. Package managers on RHEL 8 and Ubuntu 20.04 will not upgrade the system OpenSSL to 3.x as part of a standard `dnf update` or `apt upgrade` because it is a major version change that would break package dependencies. Containerisation sidesteps this constraint cleanly: the container image's OpenSSL is isolated from the host, can be chosen independently, and does not affect other services running on the same host.

For teams that cannot migrate base images or OS versions immediately, the short-term safe state is: `openssl` crate pinned to 0.10.78 or later, system OpenSSL upgraded to 1.1.1w (the final 1.1.x release) or a distribution-patched 1.1.1 build, and `cargo deny` enforcing the version floor in CI. This does not fully close the CVE if the system OpenSSL is still 1.1.x, but it narrows the affected surface by preventing any crate from calling the vulnerable code paths through the unpatched bindings.

## Failure Modes

The most common remediation mistake is upgrading the Rust crate without addressing the system OpenSSL. Installing `openssl = "0.10.78"` in `Cargo.toml` and running `cargo update` regenerates `Cargo.lock` with the new crate version — but if the compiled binary still dynamically links against `libcrypto.so.1.1` from the host OS, the fix in the Rust bindings has no effect. The crate update changed which Rust code calls `EVP_PKEY_derive`; it did not change what `EVP_PKEY_derive` does. On OpenSSL 1.1.x, that C function still ignores `pkeylen` for the affected algorithms. `cargo audit` will show no vulnerabilities after the crate update, giving a false sense of remediation while the actual exposure remains.

The second common failure mode is a lockfile that does not reflect the `Cargo.toml` changes. Developers update `Cargo.toml` to specify `openssl = "0.10.78"` but do not run `cargo update` and do not commit the updated `Cargo.lock`. The CI pipeline builds from the existing `Cargo.lock`, which still pins the old version. The deployed binary contains `openssl` 0.10.77 despite the `Cargo.toml` change. Validate the deployed version by inspecting `Cargo.lock` directly and by checking the crate version embedded in the binary at runtime.

Using `cargo audit --deny warnings` in CI but not in the production build pipeline creates a gap. If `cargo audit` runs during pre-commit hooks or PR checks but not during the final production build, a lockfile that drifts between merge and deploy — or a build server with a stale advisory cache — can produce an unaudited binary. Run `cargo audit` as a gate in the final build job that produces the artifact deployed to production, not only in developer-facing checks.

Finally, crates that appear in the dependency tree through optional features may not be audited if those features are not enabled during `cargo audit`. If `openssl` is a conditional dependency behind a feature flag, and your `cargo audit` invocation does not enable that feature, the vulnerable crate will not appear in the audit results. Use `cargo audit --features all-features` or enumerate the specific features that are enabled in production builds.

## Related Articles

- [Go x509 PKI Security](/articles/cross-cutting/go-x509-pki-security/)
- [Post-Quantum Migration](/articles/cross-cutting/post-quantum-migration/)
- [SPIFFE SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
- [OpenSSF Scorecard Supply Chain](/articles/cross-cutting/openssf-scorecard-supply-chain/)
- [Cert-Manager PKI Hardening](/articles/kubernetes/cert-manager-pki-hardening/)
