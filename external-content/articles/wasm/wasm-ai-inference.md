---
title: "WASM AI Inference: Isolating ONNX Runtime Web, llama.cpp WASM, and On-Device Models"
description: "Running AI inference inside WASM is a new deployment pattern with novel isolation properties. The threat model differs from GPU-served inference."
slug: "wasm-ai-inference"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "ai", "inference", "onnx", "llama-cpp", "edge-ai"]
personas: ["ml-engineer", "platform-engineer", "security-engineer"]
article_number: 190
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasm-ai-inference/index.html"
---

# WASM AI Inference: Isolating ONNX Runtime Web, llama.cpp WASM, and On-Device Models

## Problem

AI inference has historically run on GPUs in dedicated services. By 2026, a parallel pattern has emerged: small models running entirely inside a WASM sandbox, deployed alongside application code, executing at the edge or as plugins. The drivers are practical:

- **ONNX Runtime Web** runs ONNX models in WASM in browsers and edge runtimes. With WebGPU acceleration available, model size up to ~3B parameters is workable.
- **llama.cpp** has a WASM build that runs quantized small models (Llama 3.2 1B/3B, Phi-3 Mini, Gemma 2B) on CPU. With SIMD, throughput is acceptable for embedded use cases.
- **Transformers.js** wraps ONNX Runtime Web with a Hugging Face-compatible API.
- **Spin and wasmCloud** support model files as components, distributed via OCI like any other artifact.

The deployment pattern: a WASM module containing the model weights (or fetching them from a separate OCI artifact) runs as a sandboxed inference service. Customers run their own models without trusting the platform with their model files; platforms offer multi-tenant inference without leaking models across tenants.

The security story differs from GPU inference in three ways:

- **No shared GPU memory.** GPU inference runs multiple tenants' kernels on the same hardware; side-channel mitigation is the platform's burden. WASM runs each tenant's model in its own linear memory; the side-channel surface is much smaller.
- **The model is data, not code.** A `.gguf` or `.onnx` file is parsed by the inference engine. Crafted models can exploit parser bugs to cause crashes or arbitrary memory access.
- **Prompt injection still applies.** A model running locally is still a model — text-in / text-out — and its outputs influence whatever consumes them. The classical prompt-injection attack works the same.

The specific gaps in a WASM-AI-inference deployment:

- Model files distributed via OCI without signing or content pinning.
- The inference engine's WASM build potentially has unaudited dependencies (BLAS, llama.cpp, ONNX Runtime).
- Resource caps (memory, CPU) sized for the largest model, leaving smaller deployments overprovisioned and exhaustion-prone.
- Output of the model fed directly to downstream tools without validation.
- Per-tenant model provisioning without isolation between tenants.

This article covers model file integrity, runtime configuration for inference engines, prompt-injection defense at the WASM layer, output validation, and per-tenant isolation patterns.

**Target systems:** ONNX Runtime Web 1.20+, llama.cpp WASM build (commit 2026-Q1 or later), Transformers.js 3.0+, WebLLM 0.2+. Compatible with Wasmtime + WASI Preview 2, Spin, wasmCloud, edge runtimes.

## Threat Model

- **Adversary 1 — Malicious model file:** an attacker uploads or distributes a `.gguf`/`.onnx` file with crafted structures designed to exploit the parser. Wants arbitrary read/write inside the inference engine's address space.
- **Adversary 2 — Prompt injection through user input:** end-user supplies input that, when fed to the model, causes the model to produce attacker-chosen output.
- **Adversary 3 — Model exfiltration:** competitor or insider obtains the proprietary model weights from the WASM artifact.
- **Adversary 4 — Cross-tenant inference leakage:** in a multi-tenant deployment, one tenant's prompt or output reaches another tenant.
- **Adversary 5 — Compromised inference engine WASM build:** the engine's WASM artifact contains a backdoor or known-CVE'd dependency.
- **Access level:** Adversary 1 has model-upload capability. Adversary 2 has only inference API access. Adversary 3 has artifact-pull access. Adversary 4 has tenant access. Adversary 5 has engine-distribution access.
- **Objective:** Crash or compromise the inference service; manipulate model output; steal model weights; cross tenant boundaries.
- **Blast radius:** WASM linear-memory isolation bounds the worst case to the engine's WASM VM. A crafted-model exploit cannot reach the host filesystem or other tenants without escaping the sandbox. Output manipulation affects only the request producing the prompt. Model exfiltration exposes the weights but not the runtime.

## Configuration

### Step 1: Model File Integrity

Model files are large (hundreds of MB to several GB). Distribute via OCI with content-addressing.

```bash
# Push model file as an OCI artifact.
oras push ghcr.io/myorg/models/phi-3-mini:q4_0 \
  --artifact-type application/vnd.gguf \
  phi-3-mini-q4_0.gguf:application/octet-stream

# Sign with cosign.
cosign sign --yes ghcr.io/myorg/models/phi-3-mini:q4_0
```

The WASM inference component fetches by digest, not tag:

```rust
// Pull and verify model before loading.
async fn load_model(client: &OciClient, model_ref: &str) -> Result<Vec<u8>, Error> {
    let manifest = client.fetch_manifest(model_ref).await?;
    let expected_digest = "sha256:abc123...";   // pinned in deployment config
    if manifest.layers[0].digest != expected_digest {
        return Err(Error::DigestMismatch);
    }
    let model_bytes = client.fetch_blob(&manifest.layers[0].digest).await?;
    Ok(model_bytes)
}
```

Admission control at the platform layer: only deploy WASM components whose `gguf_digest` annotation matches a registry of approved models.

### Step 2: Inference Engine Configuration

Wasmtime hosting an inference component needs aggressive resource caps. Models are memory-intensive but bounded; CPU is the larger concern (a 3B-parameter inference on CPU can take seconds per prompt).

```rust
let mut config = wasmtime::Config::new();
config.consume_fuel(true);
config.epoch_interruption(true);
config.wasm_simd(true);                  // critical for inference performance
config.wasm_relaxed_simd(false);         // smaller surface; relaxed_simd is newer
config.wasm_threads(false);              // most engines do not need threads
config.wasm_bulk_memory(true);
config.cranelift_opt_level(OptLevel::Speed);
config.static_memory_maximum_size(8 * 1024 * 1024 * 1024);   // 8 GiB ceiling for large models

let engine = Engine::new(&config)?;
let mut store = Store::new(&engine, ());
store.set_fuel(50_000_000_000)?;          // 50B ops budget per inference request
store.set_epoch_deadline(1);
```

A 50B fuel budget supports a few seconds of CPU on a typical inference workload; tune empirically. For latency-sensitive applications, prefer epoch-based deadlines over fuel — fuel adds per-op overhead that compounds for inference's tight inner loops.

### Step 3: Restrict the Engine's WASI Capabilities

The inference engine should not need filesystem write or network access at runtime. Models are loaded once at startup.

```rust
let wasi = WasiCtxBuilder::new()
    .preopened_dir(
        cap_std::fs::Dir::open_ambient_dir("/var/lib/inference/models",
            cap_std::ambient_authority())?,
        DirPerms::READ,
        FilePerms::READ,
        "/models")?
    .stdin(Box::new(ClosedInputStream))
    .stdout(Box::new(BoundedWriter::new(64 * 1024)))
    .stderr(Box::new(BoundedWriter::new(64 * 1024)))
    .build();
```

Read-only model directory; no network; no environment variables. The engine reads the model from the filesystem at startup, then holds it in memory; it never needs to read further files after the first load.

### Step 4: Prompt Injection Defense

A WASM-hosted model is still vulnerable to prompt injection. The defense is the same as for cloud-hosted models:

```typescript
// Wrap user input with a known-instruction-only prompt template.
function buildSafePrompt(systemInstructions: string, userInput: string): string {
    // Refuse user input that contains injection markers.
    const INJECTION_PATTERNS = [
        /ignore (all |previous )?instructions/i,
        /system:/i,
        /you are (now|actually)/i,
        /<\|im_start\|>/,
        /\[INST\]/,
    ];
    for (const pat of INJECTION_PATTERNS) {
        if (pat.test(userInput)) {
            throw new Error("rejected_input: injection pattern detected");
        }
    }

    // Use the model's actual chat template; do not concatenate strings.
    return `<|system|>\n${systemInstructions}\n<|end|>\n<|user|>\n${userInput}\n<|end|>\n<|assistant|>\n`;
}
```

The defense happens before the prompt reaches the model; once the model has the prompt, no internal mechanism distinguishes injected instructions from legitimate ones. WASM does not change this — the same patterns from cloud inference apply.

### Step 5: Output Validation

Models can produce arbitrary text. If the consuming code treats the output as command, code, JSON, or instructions, validate before use.

```typescript
async function inferAndValidate(prompt: string): Promise<ParsedResult> {
    const raw = await model.generate(prompt);
    const trimmed = raw.split("<|end|>")[0].trim();

    let parsed: any;
    try {
        parsed = JSON.parse(trimmed);
    } catch {
        throw new Error("model_output_not_json");
    }

    // Schema-validate the output before returning.
    const valid = ajv.validate(SCHEMA, parsed);
    if (!valid) {
        throw new Error("model_output_schema_violation");
    }

    return parsed as ParsedResult;
}
```

For model output that drives tool calls or downstream actions, the schema validation is the security boundary. A model that produces unexpected output is rejected; a model that consistently does so needs investigation.

### Step 6: Per-Tenant Isolation

In a multi-tenant deployment, run each tenant's inference in its own component instance.

```rust
// Each tenant gets a separate Wasmtime Store, separate fuel budget,
// separate model load.
struct TenantInference {
    tenant_id: String,
    store: Store<TenantState>,
    instance: Instance,
    last_used: Instant,
}

impl TenantInference {
    fn infer(&mut self, prompt: &str) -> Result<String, Error> {
        // Per-call deadline via epoch.
        self.store.set_epoch_deadline(1);
        self.store.set_fuel(50_000_000_000)?;

        let func = self.instance.get_typed_func::<(String,), String>(&mut self.store, "infer")?;
        let result = func.call(&mut self.store, (prompt.to_string(),))?;
        self.last_used = Instant::now();
        Ok(result)
    }
}
```

Tenants share the engine's compiled bytecode (cached) but have distinct linear memory and resource budgets. A crafted-model attack from one tenant cannot affect another's memory.

### Step 7: Telemetry

Track per-tenant and per-model metrics:

```
wasm_inference_requests_total{tenant, model}                counter
wasm_inference_duration_seconds{tenant, model}              histogram
wasm_inference_tokens_generated{tenant, model}              histogram
wasm_inference_traps_total{tenant, model, kind}             counter
wasm_inference_input_rejected_total{tenant, reason}         counter
wasm_inference_output_validation_failed_total{tenant}       counter
wasm_inference_model_load_seconds{model}                    histogram
```

Alert on rises in `wasm_inference_traps_total` (engine instability), `wasm_inference_input_rejected_total{reason="injection"}` (active prompt-injection attempts), or `wasm_inference_output_validation_failed_total` (model producing non-conforming output, possibly under attack).

## Expected Behaviour

| Signal | Without hardening | With |
|--------|--------------------|------|
| Crafted model file uploaded | Engine parses; potential exploit | Rejected at admission unless digest matches approved list |
| Prompt injection attempt | Reaches model; output may follow attacker | Rejected before model invocation |
| Model output not JSON when expected | Downstream parser fails or behaves unexpectedly | Schema validation rejects; structured error returned |
| Tenant A inference affects tenant B | Possible if engine state shared | Bounded by per-tenant Store; impossible without escape |
| Inference takes excessive CPU | Stalls other requests | Fuel/epoch deadline trips; structured error returned |
| Model file corrupted during distribution | Loaded; potential parser error | Digest mismatch at load; refused |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| WASM sandbox for inference | Bounded blast radius for crafted-model exploits | CPU inference is slower than GPU | Acceptable for small models (1B-3B parameters); use GPU services for larger. |
| Per-tenant Store | Strong isolation across customers | Memory footprint per tenant scales with engine size | Pool stores; LRU-evict idle tenants. |
| Aggressive fuel/epoch caps | Prevents runaway inference | Caps may interrupt legitimate long generations | Make the deadline configurable per tenant tier; alert on caps hit. |
| OCI distribution with digest pinning | Tamper detection | Update flow requires digest-aware deploy | Automate via deploy pipeline. |
| Prompt-injection regex | Catches obvious patterns | Sophisticated injections bypass | Combine with output validation; never rely on input filtering alone. |
| Model load at startup | Simple model lifecycle | Model swap requires restart | Use blue-green deploy for model updates; old version served until new is loaded. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Crafted model exploits engine parser | Engine panics; engine WASM VM trap | Trap metric rises; specific tenant correlated | Pull the engine, rebuild against current upstream (which often patches such bugs quickly). |
| Inference takes longer than fuel budget | Deadline error returned to the user | `wasm_inference_traps_total{kind="fuel_exhausted"}` rises | Profile representative prompts; raise budget if the workload genuinely needs more, or use streaming output to return partial results before deadline. |
| Model output not JSON when downstream expects | Parser error in downstream | `output_validation_failed` rises | Adjust the prompt to be more constraining; add few-shot examples; tighten the schema. |
| Multi-tenant Store leak | One tenant's inference state observable to another | Tenant-isolation regression test fails | Use distinct `Store` per tenant; never share. |
| Model digest mismatch | Deploy fails | Admission controller blocks the new component | Update the digest in the deploy manifest; investigate why the new digest differs (legitimate update vs. tampering). |
| Engine WASM dependency CVE | OSV-Scanner reports vulnerability in the engine | Scan output | Rebuild engine against fixed dependency; redeploy. |

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM Module Static Analysis and Vulnerability Scanning](/articles/wasm/wasm-static-analysis/)
- [LLM Deployment Security](/articles/ai-landscape/llm-deployment-security/)
- [Inference Endpoint Hardening](/articles/kubernetes/inference-endpoint-hardening/)
