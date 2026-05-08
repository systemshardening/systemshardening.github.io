---
title: "OpenSSL RSASVE Uninitialized Memory Disclosure: CVE-2026-31790"
description: "CVE-2026-31790 leaks heap bytes when OpenSSL's RSA key encapsulation fails on a malicious public key. Affects applications using RSASVE for hybrid key exchange. Patch OpenSSL 3.x and audit KEM usage to identify exposure."
slug: openssl-rsasve-memory-disclosure
date: 2026-05-07
lastmod: 2026-05-07
category: cross-cutting
tags:
  - openssl
  - memory-disclosure
  - cve
  - key-encapsulation
  - cryptography
personas:
  - security-engineer
  - platform-engineer
article_number: 453
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cross-cutting/openssl-rsasve-memory-disclosure/
---

# OpenSSL RSASVE Uninitialized Memory Disclosure: CVE-2026-31790

## The Problem

RSASVE — RSA Verified Encryption, also referred to as RSA-KEM or RSA-OAEP key encapsulation — is the mechanism by which an RSA public key is used to encapsulate a randomly-generated symmetric key. The encapsulating party generates a random secret, encrypts it under the recipient's RSA public key, and transmits the resulting ciphertext blob. The recipient decrypts using their RSA private key to recover the symmetric key. In hybrid key exchange schemes — including some post-quantum hybrid TLS implementations and custom PKCS#7 encryption tools — RSASVE provides the classical RSA component: the RSA-encapsulated key seeds a symmetric cipher, and a post-quantum KEM provides an independent key contribution that is combined with it.

CVE-2026-31790, disclosed in the January 27 2026 OpenSSL security release, is an uninitialized memory disclosure in OpenSSL's RSASVE implementation. When the RSA encryption step within the encapsulation operation fails — triggered by supplying a maliciously crafted RSA public key that causes an internal OpenSSL error — the function `EVP_PKEY_encapsulate()` returns `1`, indicating success, but leaves the output buffer incompletely written. The output buffer is allocated on the heap and is not zeroed before the encapsulation operation begins. The unwritten portion of the buffer therefore contains whatever bytes were previously stored at that heap location from prior allocations. If those prior allocations included material from another cryptographic operation — a fragment of a private key exponent, an HMAC key, a session secret, a password-derived key — the caller receives a partially-forged "encapsulated key" whose trailing bytes are leaked heap contents from an earlier operation.

The CVSS score is 7.5 (High), reflecting that this is bounded information disclosure rather than remote code execution. The distinction from CVE-2025-15467 — the CMS RCE covered in article #437 — is significant: that vulnerability allowed an attacker to execute arbitrary code by triggering a use-after-free during CMS message parsing; this one is a one-way information leak confined to applications that accept externally-supplied RSA public keys and use them with the RSASVE encapsulation API. No memory corruption occurs. The attacker learns bytes; they do not control execution.

The affected OpenSSL API is less widely used than standard RSA encryption with `EVP_PKEY_encrypt()`, but its presence in post-quantum hybrid KEM libraries makes the exposure significant for security-sensitive contexts. Libraries implementing hybrid key exchange — combining RSA-KEM as the classical component with a post-quantum KEM such as Kyber or ML-KEM — may call `EVP_PKEY_encapsulate()` internally. If such a library accepts a server-provided RSA public key as part of a TLS handshake (for example, a hybrid KEM TLS extension that includes an RSA-KEM ciphertext alongside the post-quantum ciphertext), an attacker acting as a malicious TLS server can supply a crafted RSA public key to trigger the disclosure on the connecting client.

Applications affected by this CVE are those that: call `EVP_PKEY_encapsulate()` or the lower-level `RSASVE_generate()` function directly; use a hybrid KEM library that calls these functions internally; or perform PKCS#7 or CMS encryption using RSA key transport and accept the RSA public key from an untrusted source. Standard TLS using RSA key exchange does not use the RSASVE API and is not affected. Applications that only decrypt using an RSA private key (i.e., the encapsulation recipient) are also not directly affected — the vulnerability is in the encapsulation path, not the decapsulation path.

All OpenSSL 3.x versions prior to the January 2026 patch release are affected. OpenSSL 1.1.1, which reached end-of-life in September 2023, does not implement the RSASVE API and is not affected by this specific CVE — though it remains exposed to all other unpatched vulnerabilities given its EOL status.

## Threat Model

An attacker who can supply an RSA public key to an application that uses RSASVE for key encapsulation is the primary threat actor. This includes:

- **Malicious server in a hybrid KEM TLS handshake**: if a TLS client uses a hybrid key exchange that includes an RSA-KEM component, and the server's RSA public key is accepted and passed to `EVP_PKEY_encapsulate()` without prior validation, the server can supply a crafted key to trigger the disclosure. The leaked bytes may include material from a prior heap allocation in the TLS client — another session's pre-master secret, a session ticket key, or cached private key material.

- **Untrusted RSA public key in custom PKCS#7 encryption**: applications that encrypt data to arbitrary recipients using PKCS#7 or CMS key transport, where the recipient's RSA public key is read from an untrusted source (a database, an API response, user input), are directly exposed. An attacker who controls the stored or transmitted public key can trigger the error path.

- **Post-quantum hybrid KEM library with OpenSSL backend**: libraries that implement hybrid KEM and use OpenSSL's RSASVE API internally may not validate the supplied RSA public key before passing it to the encapsulation function. Applications using such libraries inherit the vulnerability even if they never call the OpenSSL RSASVE API directly.

The leaked heap bytes may contain: fragments of private key exponents from prior RSA operations in the same process; session secrets or pre-master secrets from concurrent TLS connections in a multi-threaded server; password-derived key material (PBKDF2 or Argon2 outputs) if key derivation preceded the encapsulation call; HMAC keys from message authentication operations; or entropy from the CSPRNG's working buffer. The exact content is non-deterministic and depends on prior heap activity in the affected process, but in long-lived processes with high cryptographic activity — a TLS terminator, a key management service, a secrets manager — the probability of useful key material appearing in reused heap regions is non-negligible.

This CVE is not a remote code execution vulnerability. An attacker cannot overwrite memory or redirect control flow. The threat is confidentiality: the partial key material in the leaked buffer may be sufficient to assist in breaking a symmetric cipher, to reconstruct a short-lived session key, or to narrow the search space for a brute-force attack on key material derived from limited entropy. In contexts where RSASVE is used for key exchange, the key being encapsulated is intended to be ephemeral and secret; the leak partially undermines that guarantee.

## Hardening Configuration

### 1. Patch OpenSSL to Fixed Versions

The January 27 2026 OpenSSL security release fixes both CVE-2026-31790 and CVE-2025-15467 (CMS RCE) in the same patch versions. If you have already applied the CMS RCE patch, you are also protected against this CVE. The fixed versions are OpenSSL 3.0.17, 3.3.3, 3.4.1, 3.5.1, and 3.6.1.

```bash
openssl version

apt-get update && apt-get install --only-upgrade openssl libssl3

rpm -q openssl
dnf update openssl

openssl version

lsof | grep libssl | awk '{print $2}' | sort -u

systemctl list-units --type=service --state=running | awk '{print $1}' | \
  xargs -I{} sh -c 'lsof -p $(systemctl show -p MainPID --value {}) 2>/dev/null | grep -q libssl && echo {}'
```

After upgrading the shared library, any process that loaded the old `libssl.so` at startup must be restarted to use the patched version. Processes do not pick up a new shared library version without a restart.

### 2. Identify Applications Using RSASVE / RSA-KEM

The RSASVE API is less common than standard RSA encryption. Applications that call it are specifically implementing key encapsulation, not ordinary RSA encrypt/decrypt. Search for the relevant API calls in deployed binaries and application source.

```bash
grep -r "EVP_PKEY_encapsulate\|RSASVE_generate\|RSA_padding_add_PKCS1_OAEP" \
  /usr/lib/ /usr/local/lib/ /opt/ 2>/dev/null

grep -r "EVP_PKEY_encapsulate\|RSASVE\|RSA.KEM\|rsa_kem" \
  /usr/local/bin/ /opt/ /home/ \
  --include="*.c" --include="*.cpp" --include="*.h" --include="*.go" \
  --include="*.py" --include="*.rs" 2>/dev/null

find /usr/lib/ /usr/local/lib/ /opt/ -name "*.so*" -type f 2>/dev/null | \
  xargs -P4 -I{} sh -c 'nm -D {} 2>/dev/null | grep -q "EVP_PKEY_encapsulate" && echo {}'
```

Also check for post-quantum hybrid KEM libraries that use OpenSSL as the classical RSA-KEM component. Libraries such as `liboqs` (Open Quantum Safe), `kyber-openssl`, or custom hybrid TLS implementations frequently delegate their classical KEM component to OpenSSL's RSASVE API.

```bash
find /usr/lib/ /usr/local/lib/ -name "liboqs*" -o -name "libpqtls*" 2>/dev/null

pkg-config --libs liboqs 2>/dev/null
```

### 3. Validate Public Keys Before Use

Any application that accepts externally-supplied RSA public keys and uses them for encapsulation must validate the key before passing it to `EVP_PKEY_encapsulate()`. The vulnerability's error path is triggered by a malformed key; rejecting malformed keys before the encapsulation call prevents the trigger.

```bash
openssl rsa -pubin -in received_key.pem -check -noout

openssl rsa -pubin -in received_key.pem -text -noout | grep "Key Size"
```

In application code, use `EVP_PKEY_check()` for full key validation and verify the key meets minimum size requirements before encapsulation. Keys smaller than 2048 bits should be rejected regardless of structural validity. The validation should occur as close to the point of receipt as possible — before the key is stored, cached, or passed deeper into the application's call stack.

### 4. Initialise Output Buffers Explicitly

As a defence-in-depth measure in application code, zero-initialise the output buffer passed to `EVP_PKEY_encapsulate()` before calling it. This does not fix the underlying bug in unpatched OpenSSL versions, but it limits what the caller receives from an incompletely-written buffer. If the error path returns success on an unpatched build, the zeroed buffer contains no useful heap data — only zeros — rather than whatever the heap previously held.

```bash
grep -rn "EVP_PKEY_encapsulate" /path/to/application/src/ | \
  grep -v "memset\|calloc\|bzero" | \
  awk -F: '{print $1 ":" $2 " — buffer may not be zeroed before encapsulate call"}'
```

The pattern in C: allocate the output buffer with `calloc()` rather than `malloc()`, or call `OPENSSL_cleanse()` on the buffer immediately after allocation. In higher-level language bindings (Python's `cryptography` package, Go's `openssl` wrapper, Rust's `openssl` crate), check whether the binding zeroes the buffer on its own behalf — if not, zero the buffer at the application layer before passing it to the encapsulation function.

### 5. Monitor for Anomalous RSA Key Encapsulation Patterns

Log all uses of RSA key encapsulation in security-relevant application paths and alert on patterns consistent with the CVE trigger. The vulnerability requires an encapsulation operation to fail internally while returning success to the caller. Application-layer logging before and after the encapsulation call, combined with independent key validation, can detect when a supplied public key fails validation — which is the precondition for triggering the error path.

```bash
grep -r "EVP_PKEY_encapsulate\|RSASVE" /var/log/application/ 2>/dev/null | \
  grep -i "error\|fail\|invalid" | tail -50

journalctl -u your-kem-service --since "2026-01-27" | \
  grep -i "encapsulate\|key encap\|rsasve" | tail -50

ausearch -k kem_operations --start today 2>/dev/null | \
  grep -E "success|fail"
```

For applications instrumented with structured logging, add a log entry immediately after calling `EVP_PKEY_encapsulate()` that records the return code and the SHA-256 fingerprint of the supplied public key. This allows post-incident analysis to identify which keys triggered the error path and whether they match a pattern consistent with intentional exploitation.

## Expected Behaviour After Hardening

After patching OpenSSL to a fixed version (3.0.17, 3.3.3, 3.4.1, 3.5.1, or 3.6.1), a maliciously crafted RSA public key that triggers the internal error path causes `EVP_PKEY_encapsulate()` to return an error code — specifically a non-zero error in the OpenSSL error queue and a return value other than `1` — rather than returning `1` with a partial buffer. The caller's error-checking logic receives a genuine failure indication and does not process the output buffer. Applications that correctly check the return value of `EVP_PKEY_encapsulate()` are protected by the patch alone.

After adding output buffer initialisation as a defence-in-depth measure: even if the error path incorrectly returns success on an unpatched version, the zeroed buffer provides the caller with all-zero bytes rather than heap contents. The zero buffer is still cryptographically wrong — it is not a valid encapsulated key — and should cause downstream operations to fail with an integrity error rather than silently using leaked heap material as a key.

After adding public key validation before encapsulation: keys with malformed structure fail validation before reaching the encapsulation function, eliminating the trigger entirely. Even on unpatched OpenSSL, a key rejected at validation never causes the error path that exposes the uninitialized buffer.

## Trade-offs and Operational Considerations

This CVE is addressed in the same OpenSSL patch release that fixes CVE-2025-15467 (CMS RCE). If you applied the January 2026 OpenSSL patch in response to the CMS vulnerability — which was rated Critical — you are already protected against CVE-2026-31790 as well. Verify with `openssl version` that the installed version is one of the fixed versions listed above; if it is, no further patching action is required for this CVE.

Post-quantum hybrid KEM libraries that use OpenSSL internally may need to be rebuilt against the patched OpenSSL version. A dynamically linked library that depends on `libssl.so` will automatically use the patched version once the system OpenSSL is upgraded and the library's process is restarted. A statically linked library, or a library that bundles its own copy of OpenSSL, will not benefit from the system upgrade — it carries its own copy of the vulnerable code. Identify such libraries using `ldd` and check their bundled OpenSSL version.

The RSASVE API is documented in OpenSSL as part of the EVP KEM interface introduced in OpenSSL 3.0. Applications written before OpenSSL 3.0 that use older RSA encryption APIs (`RSA_public_encrypt()` with `RSA_PKCS1_OAEP_PADDING`) are not using the RSASVE code path and are not affected. Applications migrated to the EVP KEM interface as part of a post-quantum readiness effort are more likely to use the affected API and should be audited first.

Public key validation overhead is minimal relative to the computational cost of the RSA encapsulation operation itself. Calling `EVP_PKEY_check()` before `EVP_PKEY_encapsulate()` adds a key structure validation step that is significantly cheaper than the RSA modular exponentiation in the encapsulation. There is no meaningful performance argument against adding the pre-validation step.

## Failure Modes

**System OpenSSL is patched but an application statically links a vendor-supplied OpenSSL.** The package manager upgrades `/usr/lib/libssl.so.3` and `/usr/lib/libcrypto.so.3`, but an application binary that was compiled with `-static` or that vendors a copy of OpenSSL in its own directory (`/opt/myapp/lib/libssl.so.3`) continues to use the unpatched code. Use `ldd /path/to/binary` to confirm that the application links dynamically against the system OpenSSL. If `ldd` shows no OpenSSL dependency, the application is statically linked and must be recompiled against the patched version or have its vendor-supplied OpenSSL updated separately. Check `/proc/<pid>/maps` for running processes to confirm which libssl file is actually loaded.

**Key validation checks size but not structural validity.** An application adds a check that rejects keys shorter than 2048 bits, but does not call `EVP_PKEY_check()` for structural validation. An attacker constructs a 2048-bit key with a malformed structure — correct key size, invalid modulus or exponent relationship — that passes the size check but still triggers the internal OpenSSL error during encapsulation. The key size check provides no protection against a structurally malformed key of valid size. Always call `EVP_PKEY_check()` in addition to any custom size or format checks.

**Patch applied to production but not to development and test environments.** The vulnerability persists in any environment where the patched OpenSSL version has not been deployed. Development and test environments that run key encapsulation code against real or realistic keys — including integration test environments that connect to staging services using real credentials — are exposed. If a test environment has access to real private keys, session secrets, or credentials (a common anti-pattern in integration test setup), the heap leak in that environment can expose real key material. Apply the patch uniformly across all environments and verify with `openssl version` in each.

**Post-quantum library rebuilt against patched OpenSSL but not redeployed.** The library is recompiled and the new binary is placed in the application directory, but the running application still has the old shared library loaded in memory from before the rebuild. The library's in-memory code is the old version; the new binary on disk is irrelevant until the application process is restarted. Always restart services after upgrading dynamically-linked cryptographic libraries.

## Related Articles

- [OpenSSL CMS RCE Hardening](/articles/cross-cutting/openssl-cms-rce-hardening/)
- [rust-openssl Buffer Overflow](/articles/cross-cutting/rust-openssl-buffer-overflow/)
- [Post-Quantum Migration](/articles/cross-cutting/post-quantum-migration/)
- [Go x509 PKI Security](/articles/cross-cutting/go-x509-pki-security/)
- [HSM Key Management](/articles/cross-cutting/hsm-key-management/)
