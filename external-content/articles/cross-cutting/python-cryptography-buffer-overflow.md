---
title: "Python Cryptography Buffer Overflow: CVE-2026-39892 and Non-Contiguous Buffers"
description: "CVE-2026-39892 causes buffer overflow in Python's cryptography library when Hash.update() receives a non-contiguous buffer (e.g., from a strided slice). Safe Python code triggers unsafe C behaviour. Upgrade to 46.0.7 and audit code paths that pass sliced arrays to cryptographic APIs."
slug: python-cryptography-buffer-overflow
date: 2026-05-04
lastmod: 2026-05-04
category: cross-cutting
tags:
  - python
  - cryptography
  - buffer-overflow
  - cve
  - memory-safety
personas:
  - security-engineer
  - platform-engineer
article_number: 445
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/cross-cutting/python-cryptography-buffer-overflow/
---

## The Problem

CVE-2026-39892, disclosed May 2026 and fixed in `cryptography` 46.0.7, is a buffer overflow triggered by passing a non-contiguous memory buffer to `Hash.update()`, `HMAC.update()`, or any other `cryptography` API that accepts a `bytes-like` argument. The overflow happens in the library's C extension layer. The Python code that triggers it is syntactically correct, passes type checking, and contains no `unsafe` blocks or explicit pointer arithmetic — it is ordinary Python using standard language features.

Python's memory model distinguishes between two kinds of buffer. A contiguous buffer has all its bytes laid out sequentially in a single block of memory, as is the case for `bytes`, `bytearray`, and most `array.array` objects. A non-contiguous buffer has its bytes spread across memory with a defined stride — the step between logically adjacent bytes is larger than one. Strided buffers are created by step-slicing: `data[::2]` produces a view of every other byte from `data`, with each element two bytes apart in memory. A reversed view `data[::-1]` produces a non-contiguous buffer where the stride is negative. Multi-dimensional NumPy arrays with non-default memory layout are another common source. Both contiguous and non-contiguous buffers implement the Python buffer protocol, so they are accepted anywhere a `bytes-like` argument is expected, including `Hash.update()`.

The `cryptography` library's C extension code accepted buffer protocol objects but processed them assuming contiguous layout. Internally, when a Python buffer is presented to a C extension, the extension calls `PyArg_ParseTuple` or a related API with a buffer format code. The affected code used format codes that do not require contiguous layout — specifically, it did not use `PyBUF_SIMPLE` or `PyBUF_ND | PyBUF_FORMAT` flags that would force the Python runtime to produce a contiguous copy before handing the buffer to C. Instead, the C code received a `Py_buffer` struct, read `buf.buf` (the base pointer) and `buf.len` (the total length in bytes), and called the underlying hash or HMAC function with those values. For a contiguous buffer, this is correct. For a non-contiguous buffer created by `data[::2]`, `buf.buf` points to the start of the original allocation, `buf.len` reflects the logical length of the view, but the actual bytes of the view are not laid out sequentially from `buf.buf`. The C hash function reads `buf.len` bytes starting at `buf.buf` — reading the padding bytes between the intended elements, walking into adjacent heap objects, or overstepping the allocation boundary entirely.

The result is an out-of-bounds read when the C extension reads past the data the Python caller intended to hash, and potentially an out-of-bounds write when the hash state is written back. The most common real-world trigger: a developer processes a byte stream by selecting every other byte using `data[::2]` — to handle a specific encoding, to sample a data stream, or to process packed binary fields — and passes the resulting view directly to `Hash.update()` or `HMAC.update()`. A reversed buffer `data[::-1]` used for signature verification is another realistic path. Neither pattern is unusual Python. Neither gives any indication at the Python level that the resulting buffer is non-contiguous.

The impacts range from silent integrity failure to denial-of-service to information disclosure. When the C extension hashes the wrong bytes due to the strided layout mismatch, the computed hash value is incorrect and does not match a hash computed over the intended data — but neither the `Hash.update()` call nor the subsequent `finalize()` call raises an exception. The operation appears to succeed, and the wrong hash is returned. If that hash is then used in an HMAC comparison for message authentication, the HMAC passes against a different message than the one the developer believes was authenticated. This is a silent integrity failure with no error signal at any level of the stack. In cases where the OOB read crosses an allocation boundary, the C extension raises an unhandled exception or segfaults — crashing the Python process. In a server context, this is a denial-of-service. In cases where the OOB read happens to return bytes from an adjacent heap object before the process crashes or not at all, the returned data may contain fragments of other objects allocated nearby — potentially partial cryptographic key material, session tokens, or other users' data from a multi-tenant process.

The fix in 46.0.7 adds a `PyBUF_ND | PyBUF_FORMAT` buffer request to the affected C extension functions. When the C code requests a buffer with these flags, the Python runtime produces a contiguous copy of the data if the original buffer is non-contiguous. The C code always receives a contiguous allocation, and the length passed to the hash function correctly describes the bytes it will process.

## Threat Model

The primary impact is a silent integrity failure. When `Hash.update()` receives a strided buffer and computes the wrong hash without raising an error, any downstream integrity check — HMAC verification, signature validation, hash comparison — operates on an incorrect value. An HMAC computed over non-contiguous data with an affected `cryptography` version will not match an HMAC computed over the same data with any correct implementation, including a patched `cryptography` version, `hashlib`, or any other library. In an authentication workflow where the HMAC is verified server-side against a freshly computed expected value, the mismatch causes an authentication failure. In a workflow where both the generation and verification sides use the affected library on the same non-contiguous input — such as a library that generates an HMAC over a strided internal buffer and then verifies it in the same process — the wrong hash is generated and the wrong hash is verified, and the check passes for the wrong data. A modified message authenticated with a strided buffer on both sides appears valid.

An attacker who can influence which data a Python service hashes — by supplying input that the service processes into a strided view before authenticating — can arrange for the computed HMAC to be produced over different bytes than the service intends, enabling HMAC bypass without knowledge of the key.

The second impact class is denial-of-service. When the OOB read crosses a heap allocation boundary in a way that triggers a segfault in the C extension, the Python process terminates without a catchable Python exception. In a single-threaded service or a worker process model such as Gunicorn pre-fork, one malformed input kills a worker. Under sustained attack, all workers cycle through crashes, making the service unavailable. Requests that would otherwise succeed are also terminated if they share a worker with a crashing request.

The third impact class is information disclosure. Memory adjacent to the hash input buffer on the heap at the time of the OOB read may contain other Python objects: strings, bytes objects, dict backing stores, or cryptographic material from other operations in the same process. In a multi-tenant application where multiple users' requests are handled by the same process, this is a cross-tenant data leak. In a service that holds session tokens, API keys, or partial private key material in memory, the OOB read may disclose fragments of that data. The disclosure is probabilistic — it depends on heap layout at the moment of the call — and the returned value is embedded in the hash output rather than returned directly, but an attacker with sufficient control over inputs and the ability to observe hash outputs can potentially extract adjacent memory.

**Affected operations:** `Hash.update()`, `HMAC.update()`, `Cipher` context encrypt/decrypt with non-contiguous plaintext or ciphertext buffers, and any other `cryptography` API that accepts a `bytes-like` argument and passes it to C extension code without prior contiguity normalisation.

**Affected versions:** all `cryptography` releases before 46.0.7.

**Not affected:** operations that receive contiguous buffers — `bytes` literals, `bytearray` objects, `bytes()` calls, and any buffer that has not been sliced with a step other than 1 in absolute value.

## Hardening Configuration

### Upgrade to cryptography 46.0.7

The fix is a library upgrade. Every Python environment that has `cryptography` installed requires the upgrade — system Python, virtualenvs, container images, and `pipx`-managed tools.

Identify all installations before upgrading:

```bash
find /usr /home /opt /srv -name "METADATA" -path "*/cryptography-*.dist-info/METADATA" 2>/dev/null \
  | xargs grep "^Version: "
```

Upgrade in each virtualenv:

```bash
source /path/to/venv/bin/activate
pip install --upgrade "cryptography>=46.0.7"
pip show cryptography | grep Version
deactivate
```

Upgrade the system Python installation:

```bash
pip3 install --upgrade "cryptography>=46.0.7"
```

On Debian and Ubuntu:

```bash
apt-get update
apt-get install --only-upgrade python3-cryptography
dpkg -l python3-cryptography
```

On RHEL, AlmaLinux, and Rocky Linux:

```bash
dnf upgrade python3-cryptography
rpm -q python3-cryptography
```

Check running containers and upgrade within the image build layer, not at runtime:

```bash
docker ps -q | xargs -I{} docker exec {} pip show cryptography 2>/dev/null \
  | grep -E '^Name|^Version|^Location'
```

Add a version floor to `requirements.txt` or `pyproject.toml` to prevent the vulnerable version from being reinstalled:

```bash
cryptography>=46.0.7
```

Verify every environment shows the upgraded version before proceeding to the next step. An upgrade applied to the system Python is not inherited by virtualenvs; each environment must be checked and upgraded independently.

### Audit Code Paths That Pass Non-Contiguous Buffers

Search the codebase for slice patterns that create non-contiguous views and for call sites that pass buffers to cryptographic APIs. Strided slices use a step expression (`data[start:stop:step]`) where the step is not 1 or -1, or reversed slices (`data[::-1]`). Reversed slices are non-contiguous because the stride is -1 and the base pointer is at the end of the data.

Search for step-slices and reversed slices in Python source files:

```bash
grep -rn "\[::-1\]\|::-[0-9]\|::[0-9]" /path/to/project/src/ --include="*.py"
```

Search for call sites that pass arguments to `cryptography` hash or HMAC APIs:

```bash
grep -rn "\.update(\|Hash\.new\|HMAC\.new\|Cipher(" /path/to/project/src/ --include="*.py"
```

Cross-reference the two results. The risk is at call sites where a variable that may hold a strided view is passed to a `cryptography` API. Slice creation that feeds into string formatting, logging, or non-cryptographic processing is not in scope — only the data flow from slice to crypto call matters. Focus the audit on the call sites.

For NumPy-heavy codebases, non-contiguous buffers also arise from array transpositions, fancy indexing, and non-default memory order. Identify NumPy arrays passed to cryptographic operations:

```bash
grep -rn "numpy\|np\." /path/to/project/src/ --include="*.py" | grep -v "^#"
```

Check whether any NumPy array is passed to a `cryptography` API without an explicit `.tobytes()` or `np.ascontiguousarray()` call before the crypto operation.

### Add Explicit Contiguity Normalisation

For any code path that passes potentially non-contiguous data to `cryptography`, normalise to a contiguous buffer before the call. `bytes(buf)` produces a new contiguous `bytes` object regardless of the layout of `buf`. This is safe, correct, and independent of the `cryptography` version — it is the defensive pattern regardless of whether 46.0.7 is installed.

For small buffers, wrapping with `bytes()` is idiomatic:

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

data = bytearray(b"abcdefghijklmnop")
strided_view = data[::2]

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(bytes(strided_view))
result = digest.finalize()
```

For large buffers in hot paths, `memoryview.tobytes()` avoids an intermediate object and is marginally more efficient:

```python
import hmac as stdlib_hmac
from cryptography.hazmat.primitives import hashes, hmac

raw_buffer = bytearray(large_data)
strided_view = memoryview(raw_buffer)[::2]

h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(strided_view.tobytes())
mac = h.finalize()
```

Apply normalisation at the boundary where the buffer enters the cryptographic API, not at the point where the slice is created. The slice may be created for legitimate reasons — selecting specific bytes from a packed binary format, reversing a buffer for a protocol that requires it — and should remain a slice for as long as it is needed. The conversion to a contiguous buffer is specifically a pre-condition for the crypto call.

### Test With Non-Contiguous Inputs

Add unit tests that pass strided and reversed buffers to every cryptographic operation in the application. After upgrading to 46.0.7, these tests should pass and produce correct results. They also serve as regression tests — if a future dependency change or environment misconfiguration reinstates a vulnerable version, the tests will either fail (wrong hash value) or error (segfault or OOB crash).

```python
import pytest
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

TEST_DATA = b"the quick brown fox jumps over the lazy dog"
KEY = b"\x00" * 32

def test_hash_update_with_strided_buffer():
    strided = memoryview(TEST_DATA)[::2]
    expected = hashes.Hash(hashes.SHA256(), backend=default_backend())
    expected.update(bytes(strided))
    expected_digest = expected.finalize()

    actual = hashes.Hash(hashes.SHA256(), backend=default_backend())
    actual.update(strided)
    actual_digest = actual.finalize()

    assert actual_digest == expected_digest

def test_hash_update_with_reversed_buffer():
    reversed_view = memoryview(TEST_DATA)[::-1]
    expected = hashes.Hash(hashes.SHA256(), backend=default_backend())
    expected.update(bytes(reversed_view))
    expected_digest = expected.finalize()

    actual = hashes.Hash(hashes.SHA256(), backend=default_backend())
    actual.update(reversed_view)
    actual_digest = actual.finalize()

    assert actual_digest == expected_digest

def test_hmac_update_with_strided_buffer():
    strided = memoryview(TEST_DATA)[::2]
    expected = hmac.HMAC(KEY, hashes.SHA256(), backend=default_backend())
    expected.update(bytes(strided))
    expected_mac = expected.finalize()

    actual = hmac.HMAC(KEY, hashes.SHA256(), backend=default_backend())
    actual.update(strided)
    actual_mac = actual.finalize()

    assert actual_mac == expected_mac
```

On an unpatched `cryptography` version, these tests will either produce an `AssertionError` (wrong hash) or crash the test process (OOB segfault). On 46.0.7 or later with the explicit `bytes()` normalisation in production code, both the tests and the production path produce consistent, correct results.

### Monitor for Cryptographic Errors in Production

Unexpected exceptions from the `cryptography` library — particularly `ValueError`, `OverflowError`, or abrupt process termination — may indicate non-contiguous buffer issues reaching production code paths that were not caught by the audit. Configure structured exception logging to capture the full call stack and the type of the failing argument when `cryptography` operations raise.

Add exception monitoring at the call site level in high-risk code paths:

```python
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

def safe_hash(data, context="unknown"):
    try:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    except (ValueError, OverflowError, TypeError) as exc:
        buf = memoryview(data) if isinstance(data, (bytes, bytearray, memoryview)) else None
        logger.error(
            "cryptography hash failed",
            extra={
                "context": context,
                "exc_type": type(exc).__name__,
                "exc_msg": str(exc),
                "buf_contiguous": buf.contiguous if buf is not None else None,
                "buf_strides": buf.strides if buf is not None else None,
            },
        )
        raise
```

The `memoryview.contiguous` property is `True` for contiguous buffers and `False` for strided views. Logging this alongside the exception type and call context gives the information needed to identify which code path is producing non-contiguous data in production without requiring a debugger session against a live system.

## Expected Behaviour After Hardening

After upgrading to 46.0.7, `Hash.update(memoryview(b"test data")[::2])` either succeeds and returns the correct hash for the strided view (the library makes a contiguous copy internally before passing to the C hash function) or raises a clear `ValueError` with a message identifying the buffer layout issue — no silent wrong hash and no memory corruption.

After applying explicit `bytes()` normalisation at all crypto call sites, the application always passes contiguous buffers regardless of the `cryptography` library version installed. The normalisation adds a defensive layer that makes the application resilient to this class of bug in any future `cryptography` release where C extension code fails to handle non-contiguous inputs.

With monitoring in place, any non-contiguous buffer that reaches a cryptographic API and causes an exception produces a structured log entry that identifies the buffer's contiguity state and strides, pointing directly to the code path that needs normalisation.

## Trade-offs and Operational Considerations

The `bytes(buf)` normalisation call creates an extra memory allocation. For buffers up to a few kilobytes, this is negligible — the allocation, copy, and deallocation are faster than the hash computation itself. For multi-megabyte buffers in high-throughput pipelines — for example, a service that hashes large file chunks, processes bulk message payloads, or runs stream cipher operations over large plaintexts — the extra copy adds measurable overhead. In these cases, use `memoryview(buf).tobytes()` instead of `bytes(buf)`. The result is identical, but `tobytes()` is slightly more efficient because it avoids the intermediate `bytes` object construction through `__bytes__` dispatch.

If the high-throughput path has a requirement to avoid all copies for buffers it knows to be contiguous, add a contiguity check before deciding whether to normalise:

```python
mv = memoryview(data)
contiguous_data = data if mv.contiguous else mv.tobytes()
```

This path adds a single attribute check for the common case (contiguous buffer) and only copies when necessary. The `memoryview.contiguous` property is O(1) and does not read the buffer contents.

The audit for strided slices may produce false positives. A codebase that processes binary data heavily will have many slice expressions with step values — protocol parsers that extract every-other byte from a packed format, image processors that stride over pixel data, audio handlers that demux interleaved channels. Most of these will never pass their strided views to a cryptographic API. Focus the audit on the data flow from slice creation to crypto call site, not on slice creation alone. Static analysis tools such as `semgrep` can express this as a taint rule that tracks strided slices to `cryptography` call sites without flagging strided slices that flow only to non-crypto consumers.

## Failure Modes

The most common failure mode is a virtual environment that pins `cryptography==45.0.0` in `requirements.txt`. Upgrading the system Python or a separate virtualenv does not affect the pinned environment. Developers confirm `pip show cryptography` in their local virtualenv and see `46.0.7`, but the deployed application runs in a Docker container whose `requirements.txt` was not updated. The container image rebuild installs `45.0.0` because the pin is explicit. `trivy` or `grype` scans against the rebuilt image flag the vulnerability immediately, but if image scanning is not part of the deployment pipeline, the vulnerable version ships. Update `requirements.txt` pins before rebuilding container images.

A second failure mode is partial remediation: the `hash_data()` function at the main entry point has `bytes()` normalisation added, but a separate `verify_signature()` function in a utility module accepts an arbitrary buffer argument and passes it directly to `Hash.update()`. The audit found the primary entry point but missed the utility path. Both code paths need normalisation, and both must be covered by the non-contiguous input test cases. Structure the tests to exercise `verify_signature()` directly with a strided buffer rather than only testing through `hash_data()`.

A third failure mode is a CI environment that runs tests against a patched library version while the production environment runs an unpatched version. If the test suite was added after the upgrade was applied to the CI virtualenv but before it was applied to production, the tests pass in CI because the library makes a contiguous copy internally on 46.0.7 — and they would also pass on an older version if the explicit `bytes()` normalisation is in place. The tests are not sensitive to whether the library version is vulnerable; they only confirm that the hash output is correct. To catch a version mismatch between CI and production, add an explicit version check to the CI test suite:

```python
import cryptography
import pytest

def test_cryptography_version_meets_minimum():
    version = tuple(int(x) for x in cryptography.__version__.split(".")[:3])
    assert version >= (46, 0, 7), (
        f"cryptography {cryptography.__version__} is below the required 46.0.7 minimum"
    )
```

This test fails immediately if the CI or production virtualenv installs a version below the patched minimum, regardless of whether the non-contiguous buffer tests happen to produce correct output on the older version.

## Related Articles

- [Python Cryptography Cert Bypass](/articles/linux/python-cryptography-cert-bypass/)
- [rust-openssl Buffer Overflow](/articles/cross-cutting/rust-openssl-buffer-overflow/)
- [OpenSSL CMS RCE Hardening](/articles/cross-cutting/openssl-cms-rce-hardening/)
- [npm Package Integrity Verification](/articles/cross-cutting/npm-package-integrity-verification/)
- [Post-Quantum Migration](/articles/cross-cutting/post-quantum-migration/)
