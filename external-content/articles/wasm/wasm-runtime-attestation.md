---
title: "WASM Runtime Attestation: Verifying Execution Environment Integrity"
description: "Remote parties can't trust a WASM execution result unless they can verify the runtime is unmodified and running the expected module. This guide covers runtime attestation using TPM measurements, TEE integration with confidential containers, module hash verification, and building attestable WASM execution services."
slug: wasm-runtime-attestation
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - attestation
  - tpm
  - confidential-computing
  - runtime-integrity
personas:
  - security-engineer
  - platform-engineer
article_number: 584
difficulty: Advanced
estimated_reading_time: 13
published: true
layout: article.njk
permalink: /articles/wasm/wasm-runtime-attestation/
---

# WASM Runtime Attestation: Verifying Execution Environment Integrity

## Problem

A WASM module signature proves a module was built by a trusted pipeline. It says nothing about what happens after the module is loaded. A remote party — a client submitting sensitive data for processing, a compliance auditor verifying confidential computation, or an orchestrator deciding whether to trust an execution result — needs to verify three independent claims:

1. **The runtime is unmodified.** The Wasmtime or WasmEdge binary executing the module has not been patched, replaced, or instrumented by a malicious host operator.
2. **The specific module was loaded.** The runtime is executing the expected module (identified by its content hash), not a substituted variant that passes a name check.
3. **The execution environment is trustworthy.** The operating system, firmware, and hardware configuration meet the security baseline the remote party requires. A module running in a normal VM on a compromised hypervisor is as untrustworthy as a module on a compromised host.

These three claims are not addressable by code signing alone. A valid signature on a module can coexist with a compromised runtime. An unmodified runtime can load the wrong module. A correct module in a correct runtime can run on hardware under adversarial control.

Runtime attestation addresses all three claims together through hardware-rooted evidence chains. The approach combines:

- **TPM platform configuration registers (PCRs)** measuring the boot chain, OS kernel, and runtime binary.
- **Trusted Execution Environments (TEEs)** such as AMD SEV-SNP or Intel TDX, providing hardware-enforced memory isolation and remote attestation reports signed by the processor.
- **Module hash binding** linking the specific module loaded to the hardware attestation.
- **Attestation-aware WASM platforms** such as Enarx and wasmCloud that make attestation a first-class deployment primitive.

**Target systems:** Wasmtime 20+, WasmEdge 0.14+, Enarx (keep) or its successor Steward, AMD SEV-SNP on EPYC 7003/8004 series, Intel TDX on 4th/5th gen Xeon Scalable, TPM 2.0 with tpm2-tools 5.x, tpm2-tss 4.x, keylime 7.x.

## Threat Model

- **Adversary 1 — Malicious host operator:** A cloud tenant has administrative access to the bare metal host. They patch the Wasmtime binary to log decrypted secrets before the WASM sandbox processes them. From the client's perspective, the function still returns the correct result.
- **Adversary 2 — Runtime substitution:** An attacker who has compromised the deployment pipeline replaces the runtime binary without changing the module or its signature. The execution environment is no longer the vetted runtime.
- **Adversary 3 — Module swap at load time:** The host intercepts the module load call and substitutes a backdoored module. The client submitted the correct signed module; a different module runs.
- **Adversary 4 — Hypervisor-level compromise:** The cloud provider's hypervisor is compromised or malicious. The attacker can observe all VM memory, including in-flight plaintext inside the WASM linear memory.
- **Adversary 5 — Replay of stale attestation:** An attacker replays a valid attestation report from a previous, correctly-configured machine to front a currently-compromised one.
- **Access level:** Adversary 1–3 have hypervisor or host OS control. Adversary 4 has hardware-level access. Adversary 5 has network access.
- **Objective:** Execute unauthorized WASM code, exfiltrate inputs or outputs, or deceive a remote party into trusting results from an untrusted environment.
- **Blast radius:** Without attestation, any execution result from an untrusted host is unverifiable. With attestation, the blast radius is bounded to the specific TEE's threat model (hardware bugs, firmware vulnerabilities) rather than the entire host trust model.

## Background: The Attestation Chain

A hardware attestation report is a signed statement from hardware-rooted firmware (the AMD SEP Secure Processor or Intel TDX Module) that contains:

- A measurement of the TCB (Trusted Computing Base): firmware versions, microcode, the initial VM memory image.
- An application-specific field (the `REPORT_DATA` or `HOSTDATA` field, 64 bytes for SEV-SNP) that the attesting workload populates with arbitrary data — typically a hash of the application state.
- A signature from a device-specific key whose certificate chain roots to AMD or Intel's Certificate Authority.

A remote verifier fetches the certificate chain, validates the signature, checks that the TCB meets its policy (firmware versions, debug mode disabled), and reads the application-specific field to confirm the expected workload state. The verifier then provisions secrets or grants access only to the attesting workload.

For WASM, the application-specific field carries the SHA-256 or SHA-384 hash of the WASM module loaded into the runtime. A verifier who requires `sha256:abc123...` will reject an attestation report carrying any other hash.

## Configuration

### Step 1: TPM-Based Measurement of the WASM Runtime Binary

On hosts without a TEE but with a TPM 2.0, measure the WASM runtime binary into a PCR during startup. This provides boot-time evidence of runtime integrity, verifiable by a remote attestation server.

```bash
# Hash the Wasmtime binary.
sha256sum $(which wasmtime)
# e3b0c44298fc1c149afb... /usr/local/bin/wasmtime

# Extend PCR 15 (user-defined; PCRs 0-7 are platform firmware) with the hash.
# This is irreversible for the current boot session.
WASMTIME_HASH=$(sha256sum $(which wasmtime) | awk '{print $1}')
tpm2_pcrextend 15:sha256=$WASMTIME_HASH

# Verify the PCR value.
tpm2_pcrread sha256:15
# sha256:
#   15: 0x9A3B...
```

Create a PCR policy that requires PCR 15 to contain the known-good value. Seal a secret (for example, a decryption key for module secrets) to this policy:

```bash
# Create a PCR policy requiring the expected PCR 15 value.
tpm2_startauthsession --policy-session -S session.ctx
tpm2_policypcr -S session.ctx -l sha256:15
tpm2_flushcontext session.ctx

# Seal the module secret to the PCR policy.
echo -n "module-decryption-key-value" | \
  tpm2_create -C 0x81000001 \
    -L pcr_policy.dat \
    -u sealed.pub \
    -r sealed.priv \
    -i -

# The sealed secret can only be unseal on a system where PCR 15
# contains the hash of the expected Wasmtime binary.
tpm2_load -C 0x81000001 -u sealed.pub -r sealed.priv -c sealed.ctx
tpm2_unseal -c sealed.ctx -p "pcr:sha256:15"
```

Use Keylime to automate TPM-based attestation and rotate secrets on policy failure:

```bash
# On the verifier/tenant side (keylime_tenant):
keylime_tenant \
  --command add \
  --uuid wasmtime-host-01 \
  --tpm-policy '{"15": ["9a3b..."]}' \
  --file /path/to/wasmtime-binary \
  --payload secrets.zip \
  --zip-dir /opt/wasm-secrets
```

Keylime's agent runs on the host, continuously reports PCR values to the verifier, and triggers revocation callbacks if the measurements drift from policy.

### Step 2: AMD SEV-SNP Confidential VM with Remote Attestation

For strong isolation from the hypervisor, run the WASM workload inside an AMD SEV-SNP confidential virtual machine. SEV-SNP encrypts VM memory with a key held exclusively by the AMD Secure Processor; the hypervisor cannot read or modify the VM's memory.

Launch a confidential VM with SNP enabled (on an SEV-SNP-capable host running QEMU 8+):

```bash
qemu-system-x86_64 \
  -enable-kvm \
  -machine q35,confidential-guest-support=sev0 \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 \
  -cpu EPYC-v4 \
  -m 4G \
  -drive file=wasmtime-worker.img,format=qcow2 \
  -nographic
```

Inside the confidential VM, generate a remote attestation report. The `REPORT_DATA` field carries the SHA-256 hash of the WASM module to be executed:

```bash
# Inside the SNP VM.
# Compute the module hash.
MODULE_HASH=$(sha256sum /opt/modules/payments.wasm | awk '{print $1}')

# Write the 64-byte REPORT_DATA (module hash padded to 64 bytes).
printf '%s' "$MODULE_HASH" | xxd -r -p > /tmp/report_data.bin
# Pad to 64 bytes.
truncate --size=64 /tmp/report_data.bin

# Request attestation report from the AMD SP.
# sev-guest-get-report is provided by the sev-guest kernel module via /dev/sev-guest.
sev-guest-get-report \
  --report-data /tmp/report_data.bin \
  --output /tmp/attestation_report.bin

# Convert to JSON for transport.
sev-snp-measure --report /tmp/attestation_report.bin --json > /tmp/attestation.json
```

The remote verifier receives `attestation.json`, fetches AMD's VCEK (Versioned Chip Endorsement Key) certificate for this processor, validates the signature, and reads `REPORT_DATA` to confirm the module hash. Only then does it release the input secrets or mark the result as trusted.

```python
# Verifier-side snippet (using amd-sev-snp-attestation Python library).
from snp_attestation import AttestationReport, VcekCertificate

report = AttestationReport.from_file("attestation.json")
vcek = VcekCertificate.fetch(report.chip_id, report.tcb_version)

# Validate the hardware signature.
assert report.verify(vcek), "attestation signature invalid"

# Check TCB policy: no debug mode, firmware meets minimum version.
assert not report.policy.debug_allowed, "debug mode must be disabled"
assert report.current_tcb >= MINIMUM_TCB, "TCB version below policy floor"

# Confirm the module hash matches what we expected to run.
expected_hash = hashlib.sha256(open("payments.wasm", "rb").read()).hexdigest()
report_data_hash = report.report_data[:32].hex()
assert report_data_hash == expected_hash, f"module hash mismatch: {report_data_hash}"

# Provision the secret.
send_encrypted_secret(report.measurement, session_key)
```

### Step 3: Intel TDX Trust Domain

Intel TDX provides similar isolation at the Trust Domain (TD) level. The attestation flow uses the Intel Trust Authority (ITA) or a self-hosted DCAP quote verification service.

```bash
# Inside a TDX TD guest.
# tdx-attest library provides the guest API.
MODULE_HASH=$(sha256sum /opt/modules/payments.wasm | awk '{print $1}')

# Generate a TD Quote with the module hash in REPORTDATA.
tdx-quote-gen \
  --report-data "$MODULE_HASH" \
  --output /tmp/tdx_quote.bin
```

Verify using Intel Trust Authority:

```bash
# On the verifier host.
curl -s -X POST https://api.trustauthority.intel.com/appraisal/v1/attest \
  -H "x-api-key: $ITA_API_KEY" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "quote": "$(base64 -w0 /tmp/tdx_quote.bin)",
  "runtime_data": {
    "data": "$(echo -n "$MODULE_HASH" | base64 -w0)",
    "data_type": "raw"
  },
  "policy_ids": ["$WASM_ATTESTATION_POLICY_ID"]
}
EOF
# Returns a signed JWT token with appraisal results if the TD is trustworthy.
```

The policy `WASM_ATTESTATION_POLICY_ID` encodes the acceptable TD measurement values and TCB level. The returned JWT is a portable, audience-scoped trust token the verifier can present downstream.

### Step 4: Enarx — WASM Workloads with Built-In TEE Attestation

The Enarx project (developed at Profian, now maintained under the Confidential Computing Consortium) runs WASM workloads natively inside TEEs with attestation baked into the deployment workflow. Enarx abstracts over AMD SEV-SNP and Intel SGX/TDX — the same WASM binary deploys to any supported TEE.

Enarx uses a Keep (an isolated TEE instance) and a Drawbridge server for attestation and secret provisioning. The workflow:

1. The client pushes the WASM module reference to the Drawbridge server.
2. Drawbridge provisions the Keep only after validating the TEE attestation report.
3. The Keep loads the WASM module and executes it; input secrets are injected post-attestation.

```toml
# Enarx.toml — workload configuration.
[exec]
wasm = "oci:ghcr.io/myorg/wasm/payments:sha256:abc123..."

[[files]]
kind = "stdin"

[[files]]
kind = "stdout"

[[files]]
kind = "stderr"

[attestation]
# Drawbridge server URL; validates TEE attestation before provisioning.
server = "https://drawbridge.myorg.internal"
# Policy: only run on SEV-SNP with firmware >= this TCB.
[attestation.policy]
min_tcb = "07060F00000000"
debug = false
```

Deploy to a TEE host:

```bash
# enarx deploys the workload into the available TEE (SNP, SGX, or TDX).
enarx run --wasmcfgfile Enarx.toml payments.wasm
```

Enarx handles the attestation handshake transparently. The application developer writes a standard WASM module; the platform guarantees the module runs inside a verified TEE or fails to launch.

### Step 5: wasmCloud Attestation and Actor Provenance

wasmCloud 1.0 introduced attestation claims in the actor JWT. Every actor carries a signed claim that includes the actor's module hash, the capability contracts it is allowed to use, and the issuer identity (the Account NKEY that signed the actor).

Inspect attestation claims on a running actor:

```bash
# Inspect the claims embedded in a compiled actor.
wash inspect ghcr.io/myorg/wasm/payments:1.2.3

# Output:
#                          Account  Axxx...
#                           Module  Mxxx...
#                    Expires in  never
#                         Version  1.2.3
#                    Capability  wasmcloud:httpserver
#                    Capability  wasmcloud:keyvalue
#                          Tags  (none)
#                   Module Hash  sha256:abc123...
```

The lattice only starts an actor whose module hash matches the hash embedded in the signed JWT. If the OCI artifact is tampered after signing, the hash comparison fails at load time.

For additional attestation, wasmCloud 1.1+ supports TEE-based host attestation. A wasmCloud host running inside a SEV-SNP VM can include a TEE attestation report in its NATS credential exchange, allowing the lattice to enforce that certain actors only run on attested hosts:

```yaml
# wasmCloud host config: require TEE attestation before joining this lattice.
tee_attestation:
  required: true
  policy_server: https://attestation-policy.myorg.internal
  min_tcb:
    amd_snp: "07060F00000000"
  module_hash_binding: true  # Require module hash in REPORT_DATA.
```

### Step 6: WASI Attestation Primitives

The WASI community has proposed `wasi-attestation` as a WASI interface for accessing attestation evidence from within the WASM module itself. While not yet a stable standard as of 2026, several runtimes expose a host-provided attestation function via a custom WASI interface.

A WASM module that needs to include its own evidence in a computation:

```rust
// src/lib.rs — using an unstable wasi-attestation prototype.
use std::io::Read;

// Called via a host-exported function registered as "attestation::get_report".
#[link(wasm_import_module = "attestation")]
extern "C" {
    fn get_report(report_data_ptr: *const u8, report_data_len: u32,
                  output_ptr: *mut u8, output_len: u32) -> i32;
}

pub fn process_with_evidence(input: &[u8]) -> Vec<u8> {
    // Hash the input to bind this execution to the attestation report.
    let input_hash = sha256(input);
    let mut report = vec![0u8; 4096];

    let report_len = unsafe {
        get_report(
            input_hash.as_ptr(), input_hash.len() as u32,
            report.as_mut_ptr(), report.len() as u32,
        )
    };
    report.truncate(report_len as usize);

    // Return result + evidence together.
    let result = compute(input);
    [result, report].concat()
}
```

The runtime registers the `attestation::get_report` host function, which calls into the TEE SDK (sev-guest or tdx-attest) and returns a serialized attestation report. The module bundles the report with its output; the caller verifies the report before accepting the result.

### Step 7: Building an Attestable WASM Execution Service

Putting the pieces together: a service that accepts a WASM module from a client, executes it inside a TEE, and returns a signed execution receipt.

**Architecture:**

```
Client
  │  1. POST /execute  {module_hash, encrypted_input}
  │
  ▼
Execution Service (running inside SNP VM)
  │  2. Verify module_hash against OCI registry signature
  │  3. Load module
  │  4. Generate attestation report (REPORT_DATA = module_hash ∥ input_hash)
  │  5. Send report to verifier → receive session token
  │  6. Decrypt input using session-scoped key
  │  7. Execute WASM module
  │  8. Sign execution receipt
  │
  ▼
Client
     9. Verify attestation in receipt
     10. Accept result
```

Execution service skeleton (Rust + Wasmtime):

```rust
use wasmtime::{Engine, Module, Store, Linker};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ExecutionReceipt {
    module_hash: String,
    input_hash: String,
    output_hash: String,
    attestation_report: String,  // base64 SEV-SNP report
    runtime_version: String,
    timestamp: u64,
    signature: String,           // signed by service key
}

async fn execute_with_attestation(
    module_bytes: &[u8],
    input: &[u8],
) -> Result<ExecutionReceipt, Error> {
    // 1. Hash the module and input.
    let module_hash = hex::encode(Sha256::digest(module_bytes));
    let input_hash = hex::encode(Sha256::digest(input));

    // 2. Bind both hashes in REPORT_DATA (first 32 bytes = module hash,
    //    next 32 bytes = input hash; total = 64 bytes for SNP).
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&Sha256::digest(module_bytes));
    report_data[32..].copy_from_slice(&Sha256::digest(input));

    // 3. Get TEE attestation report.
    let attestation = get_snp_report(&report_data)?;

    // 4. Execute the module.
    let engine = Engine::default();
    let module = Module::new(&engine, module_bytes)?;
    let mut store = Store::new(&engine, ());
    let linker = Linker::new(&engine);
    let instance = linker.instantiate(&mut store, &module)?;
    let run = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    run.call(&mut store, ())?;

    // 5. Collect output and build receipt.
    let output = collect_output(&mut store);
    let output_hash = hex::encode(Sha256::digest(&output));

    let receipt = ExecutionReceipt {
        module_hash,
        input_hash,
        output_hash,
        attestation_report: base64::encode(&attestation),
        runtime_version: wasmtime_version(),
        timestamp: unix_timestamp(),
        signature: String::new(), // filled below
    };

    // 6. Sign the receipt with the service's attestation key.
    let signed_receipt = sign_receipt(receipt, &SERVICE_SIGNING_KEY)?;
    Ok(signed_receipt)
}
```

The client receives the receipt, extracts `attestation_report`, verifies the SEV-SNP signature, confirms `REPORT_DATA` matches `sha256(module_bytes) ∥ sha256(input)`, and only then trusts the `output_hash` and the associated computation result.

## Expected Behaviour

| Scenario | Without attestation | With attestation |
|---|---|---|
| Host operator patches runtime | Undetectable; results appear correct | PCR extends to unexpected value; Keylime revokes secrets |
| Module substituted at load time | Undetectable; wrong module runs | REPORT_DATA hash mismatch; verifier rejects |
| Hypervisor reads VM memory | Plaintext exposed | SNP/TDX hardware encryption prevents hypervisor access |
| Stale attestation replay | Attacker can replay indefinitely | Nonce or timestamp bound in REPORT_DATA invalidates stale reports |
| TEE firmware downgrade attack | N/A | TCB policy floor rejects old firmware |
| WASM module runs on unverified host | Accepted by default | Enarx/wasmCloud fails to provision if host attestation fails |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|---|---|---|---|
| SEV-SNP / TDX | Hardware-rooted isolation; hypervisor cannot read VM memory | Requires specific CPU generations; instance types are more expensive | Accept the cost for high-sensitivity workloads; use TPM-only for lower tiers |
| TPM PCR sealing | Works on commodity servers; no special CPU needed | No memory encryption; OS-level attackers still present | Layer with OS hardening (dm-verity, IMA) for defense in depth |
| Enarx abstraction | Single WASM binary targets any supported TEE | Project maturity; keep current on successor tooling | Evaluate Enarx or Steward actively; keep a fallback to native TEE SDK |
| REPORT_DATA binding | Ties attestation to specific module + input | Adds 1-3ms per attestation report generation | Generate report once per session or per batch, not per invocation |
| wasmCloud actor JWTs | First-class attestation in the platform | Claims are static at build time; runtime TEE attestation requires additional integration | Use both: JWT for module identity, host TEE attestation for environment integrity |
| Attestation service dependency | Centralised policy enforcement | Single point of failure if attestation server is down | Cache valid session tokens with bounded TTLs; design for degraded-mode operation |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---|---|---|---|
| Runtime binary updated without re-sealing | Keylime reports PCR drift; sealed secrets refuse to unseal | Keylime revocation callback fires | Re-measure and re-seal against the new binary after validating the update |
| SEV-SNP firmware vulnerability (e.g., CacheWarp) | TCB policy floor check fails for affected firmware versions | Attestation verifier rejects reports from vulnerable TCB | Apply AMD firmware update; update minimum TCB policy |
| Debug mode left enabled in TEE | Attestation report `policy.debug_allowed = true`; verifier rejects | Verifier policy check at step 2 of receipt verification | Rebuild the confidential VM image with debug mode disabled |
| REPORT_DATA truncation error | Module hash and input hash overlap incorrectly; verifier sees unexpected hash | Attestation verification hash mismatch | Enforce strict 32-byte boundaries in REPORT_DATA construction; add unit tests |
| Attestation server unavailable | Execution service cannot provision secrets; requests fail | Health-check alerts; execution returns 503 | Implement token caching with short TTL; circuit breaker with safe failure (reject requests, not bypass) |
| Clock skew invalidates nonce | Timestamp-based nonce check fails | Verifier rejects reports with timestamps outside acceptable window | Use NTP with authenticated time sources inside the TEE; allow ±30s skew window |
| Wrong module hash in wasmCloud JWT | Actor fails to start; wash shows hash mismatch | `wash get inventory` shows actor in `Failed` state | Rebuild the actor; ensure the JWT is regenerated with the new module hash after recompilation |

## Related Articles

- [WASM OCI Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [WASM Multi-Tenancy Isolation](/articles/wasm/wasm-multi-tenancy/)
- [wasmCloud Security: Actor Authentication and Lattice Trust](/articles/wasm/wasmcloud-security/)
- [WASM Binary Analysis for Security Audits](/articles/wasm/wasm-binary-analysis-security/)
- [Confidential Containers: Kubernetes with Hardware-Based Isolation](/articles/kubernetes/confidential-containers/)
