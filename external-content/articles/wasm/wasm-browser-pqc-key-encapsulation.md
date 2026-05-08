---
title: "Hybrid PQC Key Encapsulation in Browser WASM: ML-KEM Integration for End-to-End Encrypted Web Applications"
description: "WebCrypto doesn't support ML-KEM — but WASM compiled from liboqs fills the gap for browser applications needing post-quantum key exchange today. This guide implements hybrid X25519+ML-KEM-768 key encapsulation in a browser application using WASM, integrates with WebCrypto for AES-GCM encryption, and covers key material handling to prevent leakage from WASM linear memory."
slug: wasm-browser-pqc-key-encapsulation
date: 2026-05-08
lastmod: 2026-05-08
category: wasm
tags:
  - wasm
  - post-quantum
  - ml-kem
  - webcrypto
  - browser-security
personas:
  - security-engineer
  - platform-engineer
article_number: 640
difficulty: Advanced
estimated_reading_time: 14
published: true
layout: article.njk
permalink: /articles/wasm/wasm-browser-pqc-key-encapsulation/
---

# Hybrid PQC Key Encapsulation in Browser WASM: ML-KEM Integration for End-to-End Encrypted Web Applications

## Problem

Browser applications performing end-to-end encryption have one built-in option for key exchange: the WebCrypto API. WebCrypto gives you ECDH (P-256, P-384, P-521) and X25519, RSA-OAEP for key transport, AES-GCM for symmetric encryption, HKDF and PBKDF2 for key derivation. These primitives are hardware-accelerated in modern browsers, run in a privileged context where private keys can be marked non-extractable, and are available without any third-party dependency.

What WebCrypto does not give you is ML-KEM.

FIPS 203 — the NIST standard for the Module-Lattice-Based Key Encapsulation Mechanism — was published in August 2024. It is the authoritative post-quantum key encapsulation algorithm. As of mid-2026, no major browser has shipped ML-KEM in WebCrypto. The W3C WebCrypto specification has an open issue tracking PQC algorithm additions, but timeline estimates for standardised browser support remain speculative. The gap between "we need PQC key exchange in the browser today" and "WebCrypto will eventually support it" is measured in years.

This gap matters because of harvest-now-decrypt-later (HNDL). An adversary recording your application's TLS-protected messages today does not need to break TLS — they need to break the *ephemeral key exchange* your browser performed with your server or peer. If that exchange used ECDH, the adversary stores the key exchange messages and waits. When a cryptographically relevant quantum computer becomes available, Shor's algorithm recovers the ECDH shared secret, decrypts the recorded session, and exposes every message exchanged.

For most web applications, this does not matter much. For browser-based E2E encrypted applications — messaging (Signal-web analogues), encrypted file sharing, end-to-end encrypted form submissions, browser-based key management portals, healthcare and legal applications with long confidentiality requirements — HNDL is a real threat against which ECDH-only key exchange provides no protection.

WASM closes the gap. liboqs (the Open Quantum Safe project's C library, implementing ML-KEM among other PQC algorithms) compiles to WASM via Emscripten. The resulting WASM module runs in any modern browser, provides ML-KEM-768 key generation, encapsulation, and decapsulation, and can be composed with WebCrypto operations to implement hybrid post-quantum key exchange entirely in-browser.

The hybrid approach — combining classical X25519 (via WebCrypto) with ML-KEM-768 (via WASM liboqs) — gives both classical and post-quantum security simultaneously. The session key is secure unless both X25519 and ML-KEM-768 are broken, which no feasible attacker can currently achieve. This is the same hybrid approach adopted by Chrome's X25519Kyber768 deployment, Signal's PQXDH protocol, and Apple's iMessage PQ3.

**Target systems:** Browser-based E2E encrypted applications running Chrome 90+, Firefox 90+, Safari 15+; applications using Web Workers for cryptographic operations; any frontend using the Signal Protocol, OPAQUE, or custom ECDH-based key exchange for E2E encryption.

## Threat Model

**Adversary 1 — HNDL against ECDH-protected E2E sessions.** An on-path adversary (ISP, cloud provider, national infrastructure) records the WebSocket or HTTPS traffic for a browser-based E2E encrypted messaging application. The application establishes sessions using WebCrypto X25519 ECDH. The adversary stores the complete session: the ECDH key exchange, all encrypted messages, and the ciphertext. In 10–15 years, with access to a cryptographically relevant quantum computer, they run Shor's algorithm against each recorded X25519 key exchange, recovering the shared secret and decrypting every stored message. The attack is entirely offline after the initial capture phase. Messages sent today with long-term confidentiality requirements are vulnerable.

**Adversary 2 — XSS key exfiltration via WASM memory access.** A cross-site scripting vulnerability in the application allows injected JavaScript to execute in the page's origin. WebCrypto non-extractable keys are protected against this: even with arbitrary JavaScript execution, `crypto.subtle.exportKey()` on a non-extractable key returns a rejection. ML-KEM private keys generated by a WASM module have no such protection — they live as bytes in the WASM linear memory array, which is an ordinary JavaScript `ArrayBuffer`. An XSS payload that locates and reads the `memory` export of the WASM module, then scans the linear memory for key-shaped byte sequences, can exfiltrate the ML-KEM private key. This is a meaningful asymmetry between WebCrypto classical keys and WASM-based PQC keys.

**Adversary 3 — WASM bundle substitution via supply chain compromise.** The application loads a WASM module providing ML-KEM functionality. If the application does not verify the WASM binary at load time — via Subresource Integrity (SRI) on the script loading it, or by checking a hash before instantiation — an attacker who compromises the CDN, the build pipeline, or a JavaScript dependency that loads the WASM can substitute a malicious module. The malicious module implements the same API but leaks key material: logging encapsulated secrets, sending private keys to an exfiltration endpoint, or weakening key generation.

**Adversary 4 — Cross-protocol confusion from absent HKDF domain separation.** Two applications share the same hybrid key exchange infrastructure but use the combined X25519+ML-KEM shared secret for different purposes. Without domain separation labels in the HKDF `info` parameter, an attacker who can observe messages from one context may be able to replay them in the other, or trick a party into processing a session under the wrong application's protocol. This is a protocol design failure enabled by absent KDF labelling, not an algorithm weakness.

**Access level:** Adversary 1 requires network-level traffic capture. Adversary 2 requires an XSS vulnerability in the application. Adversary 3 requires supply chain or CDN access. Adversary 4 requires both applications to be reachable.

**Blast radius:** HNDL retroactively decrypts all captured sessions. XSS key exfiltration allows the adversary to impersonate the victim or decrypt any future messages encrypted to their exfiltrated public key. WASM bundle substitution affects all users of the application after the substitution. Protocol confusion enables cross-application replay.

## Configuration

### Step 1: Build liboqs for WASM

liboqs is the canonical implementation of ML-KEM (and other NIST PQC standards) in C. Building it to WASM requires Emscripten. The key build flags disable OpenSSL (which cannot compile to WASM), enable library-only output (no standalone executable), and disable shared libraries.

```bash
# Prerequisites: Emscripten SDK installed at ~/emsdk
source ~/emsdk/emsdk_env.sh

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build-wasm && cd build-wasm

cmake -DCMAKE_TOOLCHAIN_FILE=$EMSDK/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_USE_OPENSSL=OFF \
      -DBUILD_SHARED_LIBS=OFF \
      -DOQS_ALGS_ENABLED=KEM_ml_kem_768 \
      ..

emmake make -j$(nproc)
# Output: liboqs.a — a static WASM object archive
```

Limiting `OQS_ALGS_ENABLED` to `KEM_ml_kem_768` reduces the compiled output substantially — including all KEM and signature variants produces a much larger binary than a browser application needs.

Next, write a thin C shim that exposes the ML-KEM operations with a predictable API, and compile it to a WASM module with Emscripten's `emcc`:

```c
// pqc_shim.c — thin wrapper exposing ML-KEM-768 to JavaScript
#include <oqs/oqs.h>
#include <string.h>
#include <stdlib.h>

// Caller allocates output buffers via the exported malloc.
// Returns 0 on success, non-zero on failure.

int mlkem768_keygen(uint8_t *public_key, uint8_t *secret_key) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int rc = OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_free(kem);
    return rc;
}

int mlkem768_encaps(uint8_t *ciphertext, uint8_t *shared_secret,
                    const uint8_t *public_key) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
    OQS_KEM_free(kem);
    return rc;
}

int mlkem768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext,
                    const uint8_t *secret_key) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) return -1;
    int rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
    OQS_KEM_free(kem);
    return rc;
}

// Zeroize a buffer — not optimised away by the compiler (use volatile trick).
void zeroize(uint8_t *buf, size_t len) {
    volatile uint8_t *p = buf;
    while (len--) *p++ = 0;
}
```

```bash
emcc pqc_shim.c \
  -I liboqs/include \
  -L liboqs/build-wasm/lib \
  -loqs \
  -O2 \
  -s EXPORTED_FUNCTIONS='["_mlkem768_keygen","_mlkem768_encaps","_mlkem768_decaps","_zeroize","_malloc","_free"]' \
  -s EXPORTED_RUNTIME_METHODS='["HEAPU8"]' \
  -s MODULARIZE=1 \
  -s EXPORT_NAME=PQCModule \
  -o pqc.js
# Produces pqc.js (Emscripten JS glue) and pqc.wasm (the WASM binary)
```

ML-KEM-768 sizes for reference when allocating buffers:

- Public key: 1184 bytes
- Secret key: 2400 bytes
- Ciphertext: 1088 bytes
- Shared secret: 32 bytes

### Step 2: Define the JavaScript WASM API Wrapper

Wrap the low-level WASM exports in a clean JavaScript API that manages buffer allocation and deallocation. This layer also prevents callers from forgetting to free or zeroize key material.

```javascript
// pqc-wrapper.js — safe wrapper around the WASM ML-KEM-768 exports
// WASM module exports:
// mlkem768_keygen(publicKeyPtr, secretKeyPtr) -> int (0 = success)
// mlkem768_encaps(ciphertextPtr, sharedSecretPtr, publicKeyPtr) -> int
// mlkem768_decaps(sharedSecretPtr, ciphertextPtr, secretKeyPtr) -> int
// zeroize(ptr, len) -> void

const ML_KEM_768 = {
  PUBLIC_KEY_BYTES: 1184,
  SECRET_KEY_BYTES: 2400,
  CIPHERTEXT_BYTES: 1088,
  SHARED_SECRET_BYTES: 32,
};

async function loadPQCModule() {
  // Verify WASM binary hash before instantiation (see Step 5).
  const module = await PQCModule();
  return module;
}

function mlkemKeygen(mod) {
  const pkPtr = mod._malloc(ML_KEM_768.PUBLIC_KEY_BYTES);
  const skPtr = mod._malloc(ML_KEM_768.SECRET_KEY_BYTES);
  try {
    const rc = mod._mlkem768_keygen(pkPtr, skPtr);
    if (rc !== 0) throw new Error(`ML-KEM keygen failed: ${rc}`);
    const publicKey = mod.HEAPU8.slice(pkPtr, pkPtr + ML_KEM_768.PUBLIC_KEY_BYTES);
    const secretKey = mod.HEAPU8.slice(skPtr, skPtr + ML_KEM_768.SECRET_KEY_BYTES);
    return { publicKey, secretKey };
  } finally {
    // Zeroize and free — even on exception.
    mod._zeroize(pkPtr, ML_KEM_768.PUBLIC_KEY_BYTES);
    mod._zeroize(skPtr, ML_KEM_768.SECRET_KEY_BYTES);
    mod._free(pkPtr);
    mod._free(skPtr);
  }
}
```

The `.slice()` call on `HEAPU8` creates a copy of the bytes into a new JavaScript `Uint8Array` outside WASM linear memory. The WASM-side buffers are immediately zeroized and freed. The caller receives JavaScript byte arrays — no persistent reference to WASM memory is retained.

### Step 3: Implement Hybrid X25519 + ML-KEM-768 Key Encapsulation

The full hybrid key exchange works as follows. Alice and Bob each hold a hybrid key pair: an X25519 key pair (generated by WebCrypto) and an ML-KEM-768 key pair (generated by the WASM module). Their combined public key is the concatenation of both public keys. When a sender wants to establish a shared secret with Alice, they:

1. Generate an ephemeral X25519 key pair via WebCrypto and perform ECDH with Alice's X25519 public key, producing a 32-byte classical shared secret.
2. Run ML-KEM encapsulation against Alice's ML-KEM-768 public key via WASM, producing a 1088-byte ciphertext and a 32-byte post-quantum shared secret.
3. Concatenate both shared secrets and run HKDF (via WebCrypto) to derive the session key.

```javascript
// hybrid-kem.js — X25519 (WebCrypto) + ML-KEM-768 (WASM) hybrid key encapsulation

// --- KEY GENERATION ---

async function generateHybridKeyPair(pqcModule) {
  // X25519: WebCrypto generates this; private key is non-extractable.
  const x25519KeyPair = await crypto.subtle.generateKey(
    { name: "X25519" },
    false,          // non-extractable — private key stays in WebCrypto
    ["deriveKey", "deriveBits"]
  );
  const x25519PublicKeyRaw = await crypto.subtle.exportKey(
    "raw", x25519KeyPair.publicKey
  );

  // ML-KEM-768: WASM generates this.
  const mlkemKeyPair = mlkemKeygen(pqcModule);

  // Combined public key = X25519 public (32 bytes) || ML-KEM-768 public (1184 bytes)
  const combinedPublicKey = new Uint8Array(32 + ML_KEM_768.PUBLIC_KEY_BYTES);
  combinedPublicKey.set(new Uint8Array(x25519PublicKeyRaw), 0);
  combinedPublicKey.set(mlkemKeyPair.publicKey, 32);

  return {
    publicKey: combinedPublicKey,               // transmit to peers
    x25519PrivateKey: x25519KeyPair.privateKey, // WebCrypto key handle (non-extractable)
    mlkemSecretKey: mlkemKeyPair.secretKey,     // Uint8Array — handle carefully
  };
}

// --- ENCAPSULATION (sender side) ---

async function hybridEncaps(recipientPublicKey, pqcModule) {
  // Parse the combined public key.
  const recipientX25519Pub = recipientPublicKey.slice(0, 32);
  const recipientMlkemPub  = recipientPublicKey.slice(32);

  // 1. X25519: generate ephemeral key pair and perform ECDH.
  const ephemeralX25519 = await crypto.subtle.generateKey(
    { name: "X25519" }, false, ["deriveBits"]
  );
  const ephemeralX25519PubRaw = await crypto.subtle.exportKey(
    "raw", ephemeralX25519.publicKey
  );

  // Import recipient X25519 public key.
  const recipientX25519Key = await crypto.subtle.importKey(
    "raw", recipientX25519Pub,
    { name: "X25519" }, false, []
  );

  // ECDH: derive 32 bytes of X25519 shared secret.
  const x25519SharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: recipientX25519Key },
    ephemeralX25519.privateKey,
    256 // 32 bytes
  );
  const x25519SharedSecret = new Uint8Array(x25519SharedBits);

  // 2. ML-KEM: encapsulate against recipient's ML-KEM-768 public key.
  const { ciphertext: mlkemCiphertext, sharedSecret: mlkemSharedSecret } =
    mlkemEncaps(pqcModule, recipientMlkemPub);

  // 3. Derive combined session key via HKDF over both shared secrets.
  const sessionKey = await deriveHybridSessionKey(
    x25519SharedSecret, mlkemSharedSecret
  );

  // Zeroize intermediate secrets — they are now only needed in the session key.
  x25519SharedSecret.fill(0);
  mlkemSharedSecret.fill(0);

  // Return: ephemeral X25519 public, ML-KEM ciphertext, and the derived key.
  return {
    ephemeralX25519Public: new Uint8Array(ephemeralX25519PubRaw),
    mlkemCiphertext,
    sessionKey, // WebCrypto AES-GCM CryptoKey — non-extractable
  };
}

// --- DECAPSULATION (recipient side) ---

async function hybridDecaps(
  ephemeralX25519Public, mlkemCiphertext,
  recipientPrivateKeys, pqcModule
) {
  const { x25519PrivateKey, mlkemSecretKey } = recipientPrivateKeys;

  // 1. X25519 ECDH: derive classical shared secret.
  const senderX25519Key = await crypto.subtle.importKey(
    "raw", ephemeralX25519Public,
    { name: "X25519" }, false, []
  );
  const x25519SharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: senderX25519Key },
    x25519PrivateKey, // WebCrypto non-extractable key handle
    256
  );
  const x25519SharedSecret = new Uint8Array(x25519SharedBits);

  // 2. ML-KEM: decapsulate using WASM.
  const mlkemSharedSecret = mlkemDecaps(
    pqcModule, mlkemCiphertext, mlkemSecretKey
  );

  // 3. Derive the same session key.
  const sessionKey = await deriveHybridSessionKey(
    x25519SharedSecret, mlkemSharedSecret
  );

  x25519SharedSecret.fill(0);
  mlkemSharedSecret.fill(0);

  return sessionKey;
}
```

### Step 4: Derive AES-GCM Key via WebCrypto HKDF

Once both shared secrets are in hand, use WebCrypto HKDF to derive the symmetric session key. The `info` field provides domain separation — it must be unique to this application and protocol version to prevent cross-protocol confusion attacks.

```javascript
async function deriveHybridSessionKey(x25519SharedSecret, mlkemSharedSecret) {
  // Concatenate both 32-byte shared secrets.
  const combinedSecret = new Uint8Array(64);
  combinedSecret.set(x25519SharedSecret, 0);
  combinedSecret.set(mlkemSharedSecret, 32);

  // Import as raw key material for HKDF.
  const rawKeyMaterial = await crypto.subtle.importKey(
    "raw", combinedSecret,
    "HKDF",
    false,         // not extractable
    ["deriveKey"]
  );

  // Zeroize the combined secret immediately after import.
  combinedSecret.fill(0);

  // HKDF with domain separation via the `info` field.
  const salt  = crypto.getRandomValues(new Uint8Array(32));
  const info  = new TextEncoder().encode("hybrid-kem-v1:app-name:session-key");

  const sessionKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt,
      info: info,
    },
    rawKeyMaterial,
    { name: "AES-GCM", length: 256 },
    false,         // non-extractable — once derived, stays in WebCrypto
    ["encrypt", "decrypt"]
  );

  // Return both the session key and the salt (salt must accompany the key exchange
  // so the decapsulating party can reproduce the same derivation).
  return { sessionKey, salt };
}
```

The session key is a non-extractable WebCrypto `CryptoKey`. After derivation, the hybrid shared secrets are no longer in JavaScript memory. The AES-GCM encryption and decryption operations from this point forward are entirely WebCrypto — no WASM involved.

### Step 5: Zeroing WASM Memory for Key Material

ML-KEM secret keys are 2400 bytes. After decapsulation, this memory must be explicitly cleared — no garbage collector will do it. JavaScript's GC manages object lifetimes but does not zero object contents; the WASM linear memory is a persistent `ArrayBuffer` that outlives the key object.

The `zeroize` export from the WASM module performs a volatile memset that will not be optimised away. Wrap every key operation in a `try/finally` block to guarantee zeroization even when exceptions occur:

```javascript
function mlkemDecaps(mod, ciphertext, secretKey) {
  const ctPtr  = mod._malloc(ML_KEM_768.CIPHERTEXT_BYTES);
  const skPtr  = mod._malloc(ML_KEM_768.SECRET_KEY_BYTES);
  const ssPtr  = mod._malloc(ML_KEM_768.SHARED_SECRET_BYTES);

  try {
    mod.HEAPU8.set(ciphertext, ctPtr);
    mod.HEAPU8.set(secretKey,  skPtr);

    const rc = mod._mlkem768_decaps(ssPtr, ctPtr, skPtr);
    if (rc !== 0) throw new Error(`ML-KEM decaps failed: ${rc}`);

    // Copy result out of WASM memory before zeroizing.
    return mod.HEAPU8.slice(ssPtr, ssPtr + ML_KEM_768.SHARED_SECRET_BYTES);
  } finally {
    mod._zeroize(ctPtr,  ML_KEM_768.CIPHERTEXT_BYTES);
    mod._zeroize(skPtr,  ML_KEM_768.SECRET_KEY_BYTES);
    mod._zeroize(ssPtr,  ML_KEM_768.SHARED_SECRET_BYTES);
    mod._free(ctPtr);
    mod._free(skPtr);
    mod._free(ssPtr);
  }
}
```

For the ML-KEM secret key held in JavaScript between operations (during session establishment), use a `SecretBytes` wrapper that zeroes on explicit disposal. JavaScript's `FinalizationRegistry` provides a best-effort cleanup hook, but it is not deterministic — rely on it as a safety net, not as the primary zeroization path:

```javascript
class SecretBytes {
  #data;
  #registry;

  constructor(bytes) {
    this.#data = new Uint8Array(bytes); // copy
    // Best-effort: zeroize when GC collects this object.
    const ref = new WeakRef(this.#data);
    this.#registry = new FinalizationRegistry((buf) => {
      buf?.fill(0);
    });
    this.#registry.register(this, this.#data);
  }

  get bytes() { return this.#data; }

  // Call explicitly as soon as the key is no longer needed.
  zeroize() {
    this.#data.fill(0);
    this.#data = null;
  }
}

// Usage:
const { secretKey } = mlkemKeygen(pqcModule);
const wrappedSk = new SecretBytes(secretKey);
secretKey.fill(0); // zeroize the keygen output immediately

// ... perform decapsulation ...
wrappedSk.zeroize(); // explicit disposal when session is established
```

### Step 6: Secure the WASM Bundle

The WASM module providing ML-KEM is a privileged dependency: a malicious substitution breaks the entire PQC scheme. Three defences apply in combination.

**Subresource Integrity (SRI).** The `<script>` tag loading the Emscripten JS glue must carry an SRI hash:

```html
<!-- Compute hash: openssl dgst -sha384 -binary pqc.js | openssl base64 -A -->
<script src="/static/pqc.js"
        integrity="sha384-<BASE64-HASH-OF-PQC.JS>"
        crossorigin="anonymous"></script>
```

The browser will refuse to execute `pqc.js` if its hash does not match. This prevents CDN compromise or network-level substitution.

**Content Security Policy.** The page must use a strict CSP that prevents arbitrary script injection:

```http
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-<PER-REQUEST-NONCE>' 'strict-dynamic';
  connect-src 'self' wss://your-signalling-server.example.com;
  style-src 'self';
```

A CSP that blocks inline scripts and only allows scripts with the correct nonce prevents XSS payloads from loading a malicious WASM module — the adversary's injected `<script>` tag will have no nonce and will be blocked.

**WASM binary hash verification before instantiation.** Even with SRI on the JS file, verify the WASM binary itself before calling `WebAssembly.instantiate`:

```javascript
async function loadAndVerifyPQCModule(expectedWasmHash) {
  const wasmResponse = await fetch("/static/pqc.wasm");
  const wasmBytes = await wasmResponse.arrayBuffer();

  // Verify hash using WebCrypto.
  const digest = await crypto.subtle.digest("SHA-256", wasmBytes);
  const hashHex = Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  if (hashHex !== expectedWasmHash) {
    throw new Error(
      `WASM binary hash mismatch: expected ${expectedWasmHash}, got ${hashHex}. ` +
      `Refusing to instantiate.`
    );
  }

  // Safe to instantiate.
  const { instance } = await WebAssembly.instantiate(wasmBytes);
  return instance.exports;
}
```

Embed the expected hash as a build-time constant, generated from your reproducible build. This creates a chain: SRI verifies the JS glue, JS verifies the WASM binary, and the WASM binary provides the ML-KEM operations.

### Step 7: Persistent Key Storage

Ephemeral hybrid key pairs — generated fresh for each session — are the safest option. When persistence is required (a user's long-term identity key in a messaging application, for example), the ML-KEM secret key must be stored securely in the browser.

WebCrypto non-extractable keys cannot be stored in IndexedDB directly — they are handles whose underlying bytes never leave the browser's secure key store, and IndexedDB cannot persist them across page loads in a portable way. ML-KEM keys are just bytes; they require application-level protection.

The recommended pattern: wrap the ML-KEM secret key with a WebCrypto AES-KW key derived from the user's password, then store the wrapped key in IndexedDB. The wrapping key is non-extractable and derived at login time using PBKDF2 or Argon2 (the latter requiring its own WASM module or a server-side derivation).

```javascript
async function storeMlkemSecretKey(mlkemSecretKey, passwordDerivedKey) {
  // passwordDerivedKey is a non-extractable WebCrypto AES-KW key.
  const wrappedKey = await crypto.subtle.wrapKey(
    "raw",
    // We need an extractable CryptoKey wrapping the raw bytes.
    await crypto.subtle.importKey(
      "raw", mlkemSecretKey, { name: "AES-GCM" }, true, ["encrypt"]
    ),
    passwordDerivedKey,
    { name: "AES-KW" }
  );
  // Store wrappedKey (an ArrayBuffer) in IndexedDB.
  await idbStore("mlkem-sk", new Uint8Array(wrappedKey));
}

async function loadMlkemSecretKey(passwordDerivedKey) {
  const wrappedKey = await idbLoad("mlkem-sk");
  const skKey = await crypto.subtle.unwrapKey(
    "raw", wrappedKey,
    passwordDerivedKey,
    { name: "AES-KW" },
    { name: "AES-GCM" },
    true,                    // extractable — we need the bytes for WASM
    ["encrypt"]
  );
  return new Uint8Array(await crypto.subtle.exportKey("raw", skKey));
}
```

This arrangement means the ML-KEM private key is only decryptable by someone who knows the user's password, and the wrapping key never leaves WebCrypto. The contrast with native WebCrypto keys is stark: X25519 private keys can be non-extractable throughout their lifetime; ML-KEM private keys are always bytes in memory whenever they are in use.

## Expected Behaviour

| Operation | Implementation | Estimated Latency (desktop browser) | Security Property |
|-----------|----------------|--------------------------------------|-------------------|
| X25519 key generation | WebCrypto | ~0.1 ms | Quantum-vulnerable; hardware-accelerated |
| ML-KEM-768 key generation | WASM liboqs | ~1–3 ms | Quantum-resistant (FIPS 203) |
| X25519 ECDH shared secret | WebCrypto | ~0.2 ms | Quantum-vulnerable; hardware-accelerated |
| ML-KEM-768 encapsulation | WASM liboqs | ~1–2 ms | Quantum-resistant |
| ML-KEM-768 decapsulation | WASM liboqs | ~1–2 ms | Quantum-resistant |
| HKDF key derivation | WebCrypto | ~0.1 ms | Classical; 256-bit output |
| AES-GCM encrypt (1 KB) | WebCrypto | ~0.1 ms | 256-bit symmetric security |
| Full hybrid session setup | WebCrypto + WASM | ~4–8 ms | Hybrid: classical + post-quantum |
| WASM module load + verify | JS fetch + hash | ~50–150 ms (one-time) | Supply chain integrity |

Session setup overhead of 4–8 ms is incurred once per session, not per message. For applications establishing sessions infrequently (new conversation, new file share, page load), this is imperceptible. The WASM module load is cached after the first page visit.

On mobile hardware, ML-KEM-768 WASM operations are typically 3–6× slower than on desktop. Budget 15–25 ms for the full hybrid session setup on a mid-range 2024 smartphone — still below perceptible latency for a one-time session establishment.

## Trade-offs

**WASM bundle size.** A liboqs build limited to ML-KEM-768, plus the Emscripten JS glue, adds approximately 350–500 KB to the page weight (before gzip). After gzip compression this typically reduces to 150–200 KB. This is significant for first-load performance but is loaded once and cached by the browser across subsequent visits. Applications on bandwidth-constrained networks should serve the WASM module only after user interaction that triggers the E2E crypto flow, not on initial page load.

**ML-KEM operation latency vs WebCrypto X25519.** WebCrypto X25519 operations complete in tenths of a millisecond because they run natively with hardware acceleration. WASM ML-KEM-768 runs in 1–3 ms on desktop — still fast, but 10–30× slower. For the hybrid session setup this is acceptable because key exchange is a one-time operation. If an application architecture requires per-message key encapsulation (unusual but possible in ratchet protocols), WASM latency accumulates; design should favour session-level key establishment.

**Key material exposure: WASM vs WebCrypto non-extractable keys.** This is the most significant security asymmetry in the hybrid approach. WebCrypto private keys marked `extractable: false` cannot be read by JavaScript code — not even by XSS. WASM linear memory is a JavaScript `ArrayBuffer`; any script running in the same origin can read it. ML-KEM private keys in WASM memory are therefore extractable by XSS. Mitigations: run ML-KEM operations in a Web Worker with strict CSP, zeroize immediately after use, avoid persisting keys in WASM memory between operations, and treat XSS prevention as a first-order security requirement for applications using WASM-based PQC.

**Algorithm agility.** The ML-KEM-768 parameter set is the primary NIST recommendation for general use; ML-KEM-1024 provides a larger security margin at roughly 40% higher computational cost. Structure the WASM API to allow parameter set selection so an upgrade to ML-KEM-1024 requires only a configuration change, not a code rewrite.

## Failure Modes

**WASM memory not zeroed after key operations.** If `zeroize()` calls are omitted from WASM buffer free paths — particularly in error branches — ML-KEM private key bytes persist in WASM linear memory indefinitely. An XSS vulnerability occurring hours or days after session establishment can still read the key from the heap of a long-running tab. The `try/finally` pattern in Step 3 is mandatory, not optional. A single missing `finally` block in the decapsulation path creates a window for key exfiltration.

**SRI check not enforced or misconfigured.** Without SRI on the `pqc.js` loader and hash verification of `pqc.wasm` before instantiation, a CDN or supply chain compromise silently replaces the WASM module with a key-logging variant. Applications that load WASM modules from third-party CDNs without SRI are particularly exposed — a CDN outage response that redirects to a fallback URL can also bypass integrity checking. Verify the WASM hash in code; do not rely on SRI alone, since SRI only covers the JS glue file, not the WASM binary it fetches.

**HKDF domain separation missing or incorrect.** The `info` parameter in the HKDF call is the mechanism that binds the derived key to a specific protocol, application, and version. If two different applications or protocol versions use the same concatenated X25519+ML-KEM shared secrets with the same (or absent) `info`, their derived session keys are identical for matching key pairs. This enables cross-protocol key reuse: a session key derived in one context is valid in another. The `info` field must encode the application name, protocol name, and version — for example, `"hybrid-kem-v1:myapp:session-key"` — and must differ between any two contexts that share key material.

**Entropy failure in WASM.** liboqs calls `getrandom()` for key generation entropy when compiled to WASM; Emscripten routes this to `crypto.getRandomValues()` in browsers. If the WASM module is loaded in a worker before the WebCrypto API is available, key generation may fail or fall back to a weaker source. Verify that `crypto.getRandomValues` is available in the execution context before loading the WASM module, and check the `mlkem768_keygen` return code — a non-zero return indicates a failure that must not be silently ignored.

**ML-KEM ciphertext not authenticated.** ML-KEM encapsulation does not authenticate the sender — it proves only that the sender knew the recipient's public key. An active adversary who intercepts the key exchange can substitute the ML-KEM ciphertext with one of their own construction, establishing a shared secret with the recipient that differs from the sender's. Authenticate the entire key exchange transcript (ephemeral public keys, ciphertexts, protocol metadata) with a MAC derived from the session key before using that session key for application data. This is the standard "KEM+DEM" construction: the KEM establishes the key, a MAC-over-transcript ensures the key is shared only with the intended peer.
