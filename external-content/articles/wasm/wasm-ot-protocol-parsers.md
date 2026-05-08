---
title: "WebAssembly OT Protocol Parsers: Memory-Safe Modbus and DNP3 Parsing"
description: "CISA recommends protocol-aware OT monitoring. Compiling Modbus, DNP3, and EtherNet/IP parsers to WASM provides memory-isolated, fuzz-tested parsing — a corrupt protocol frame cannot escape the sandbox to compromise the monitoring tool."
slug: wasm-ot-protocol-parsers
date: 2026-05-03
lastmod: 2026-05-03
category: wasm
tags:
  - ot-security
  - modbus
  - dnp3
  - wasm
  - protocol-parsing
personas:
  - security-engineer
  - platform-engineer
article_number: 414
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/wasm/wasm-ot-protocol-parsers/
---

# WebAssembly OT Protocol Parsers: Memory-Safe Modbus and DNP3 Parsing

## The Problem

Zeek's Modbus, DNP3, and BACnet protocol analysers are written in C++ and compiled as native binaries. They process attacker-controlled bytes from the OT network wire. A carefully crafted malformed Modbus frame — for example, a response with a manipulated byte count field causing an integer overflow in the parser — can trigger a buffer overflow in the Zeek process, potentially compromising the monitoring tool. This is not hypothetical: CVEs in pcap-based protocol parsers arise regularly from exactly this attack surface. Wireshark has accumulated dozens of parser-level CVEs across its Modbus, DNP3, and BACnet dissectors. tcpdump's protocol parsers have a comparable history. A C-based parser consuming bytes from the wire is, structurally, one integer arithmetic mistake away from a memory corruption primitive.

Replacing native C-based parsers with WASM-compiled equivalents eliminates the host memory safety risk. WASM's linear memory model means a corrupt parser state cannot write outside its allocated memory region — an overflow in the parser's heap stays within the WASM sandbox. A parser crash produces a trap (a clean, catchable failure) rather than a memory corruption primitive that the attacker can weaponise. The monitoring tool process continues running. The next packet is processed. The corrupt frame is dropped and logged.

CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" recommends protocol-aware monitoring as a core detection capability for OT Zero Trust implementations. That guidance is predicated on the monitoring toolchain being trustworthy — but the security of the monitoring tool itself is rarely examined. A compromised CISA Malcolm instance that has been monitoring OT traffic for years is a catastrophic intelligence loss: the attacker gains visibility into the OT network topology, device fingerprints, communication patterns, and any credentials or engineering parameters that traverse the monitored segments. Compromising the monitor is in many ways more valuable than compromising any single monitored device.

The WASM parser approach is distinct from running OT application plugins in WASM sandboxes (covered in `wasm-ot-edge-sandboxing`). This article focuses on one specific attack surface: the protocol parser — the code that takes a raw byte buffer from the network and produces structured data. That code runs on every packet, processes attacker-supplied bytes, and in current OT security tooling is almost universally written in C or C++. The parser is the narrowest, highest-leverage place to apply memory isolation.

## Threat Model

- **Attacker on the OT network sending crafted malformed protocol frames.** A threat actor who has gained a foothold on the OT network — or who operates a compromised field device — sends deliberately malformed Modbus, DNP3, or EtherNet/IP frames. The goal is not to attack a PLC; it is to trigger a memory corruption bug in Zeek, Arkime, or Malcolm's C++ parser, compromising the monitoring tool. A compromised monitor is then used to suppress alerts, exfiltrate traffic captures, or pivot to the monitoring server's network segment.

- **Supply chain attack on a native C-based OT protocol parser library.** OT security products share parsing libraries. A compromise of a widely-used open-source OT parsing library — for example, a backdoor committed to a `libmodbus` fork used by multiple commercial products — affects every product that depends on it. A WASM-compiled parser from a pinned, reproducibly-built source narrows the supply chain to a single audited artefact rather than a transitive dependency graph of native C code.

- **Memory corruption in a native parser running with the same privileges as the monitoring daemon.** Zeek's native parsers run within the Zeek process at the same privilege level as the analysis engine, log writer, and alert dispatcher. A memory corruption primitive in the Modbus parser gives an attacker arbitrary write within the Zeek process — sufficient to corrupt log output, disable specific signatures, or achieve remote code execution on the monitoring server.

- **Parser state confusion: blind spot injection via forged DNP3 packets.** A forged DNP3 packet with a valid-looking header but crafted session identifiers can manipulate Zeek's session state tracking tables in the C++ DNP3 analyser. If the parser's state machine accepts the forged packet, Zeek may attribute subsequent legitimate attack traffic to the wrong session or drop it from analysis entirely — a blind spot injected into the monitoring tool without crashing it.

- **Cross-parser contamination in a multi-tenant parsing server.** A centralised OT monitoring platform parses traffic from multiple customer OT segments in the same process. A native parser processing one customer's traffic overwrites another customer's parser state via a heap overflow. The attacker on customer A's network manipulates customer B's monitoring data — or suppresses alerts for customer B's segment entirely.

## Hardening Configuration

### 1. WASM Compilation of a Modbus Parser

A `nom`-based Rust Modbus parser compiles cleanly to `wasm32-wasi` with no platform-specific dependencies. The parser crate should have no OS thread, no network socket, and no filesystem access — it takes bytes in, returns structured records out.

```toml
[package]
name = "modbus-parser-wasm"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
nom = "7"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
overflow-checks = true
strip = "symbols"
```

The `overflow-checks = true` flag is critical for a parser: byte count arithmetic that silently wraps on overflow is the root cause of most parser-level CVEs. The `opt-level = "z"` minimises binary size, which matters for deployment on OT edge gateways with constrained flash storage.

A minimal `nom`-based Modbus ADU (Application Data Unit) parser:

```rust
use nom::{
    bytes::complete::take,
    number::complete::{be_u8, be_u16},
    IResult,
};

#[derive(Debug)]
pub struct ModbusPdu {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub data: Vec<u8>,
}

pub fn parse_modbus_tcp(input: &[u8]) -> IResult<&[u8], ModbusPdu> {
    let (input, transaction_id) = be_u16(input)?;
    let (input, protocol_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let remaining_len = (length as usize).saturating_sub(1);
    let (input, unit_id) = be_u8(input)?;
    let (input, function_code) = be_u8(input)?;
    let data_len = remaining_len.saturating_sub(1);
    let (input, data_bytes) = take(data_len)(input)?;
    Ok((input, ModbusPdu {
        transaction_id,
        protocol_id,
        length,
        unit_id,
        function_code,
        data: data_bytes.to_vec(),
    }))
}
```

Build the parser to a WASM binary and validate it:

```bash
rustup target add wasm32-wasi

cargo build --target wasm32-wasi --release \
    --manifest-path modbus-parser-wasm/Cargo.toml

wasm-validate target/wasm32-wasi/release/modbus_parser_wasm.wasm
```

`wasm-validate` confirms the binary is structurally valid WASM. It does not confirm correctness — that is the job of the fuzz tests in step 3.

### 2. Running the WASM Parser in Wasmtime

The host embedder reads raw bytes from a PCAP file or a `AF_PACKET` socket, passes them to the WASM parser module via linear memory writes, and receives structured Modbus records back. WASI capabilities are restricted to the minimum: no filesystem access, no network access, write to stdout only.

```rust
use wasmtime::*;
use wasmtime_wasi::preview2::{WasiCtxBuilder, WasiCtx, Table};

fn build_parser_ctx() -> anyhow::Result<WasiCtx> {
    let ctx = WasiCtxBuilder::new()
        .inherit_stdout()
        .build();
    Ok(ctx)
}

fn run_parser(
    engine: &Engine,
    module: &Module,
    raw_frame: &[u8],
) -> anyhow::Result<()> {
    let ctx = build_parser_ctx()?;
    let mut store = Store::new(engine, ctx);
    store.set_fuel(500_000)?;

    let instance = Instance::new(&mut store, module, &[])?;
    let memory = instance.get_memory(&mut store, "memory")
        .ok_or(anyhow::anyhow!("no memory export"))?;

    let parse_fn = instance.get_typed_func::<(u32, u32), u32>(&mut store, "parse_frame")?;

    let offset = 0u32;
    let len = raw_frame.len() as u32;
    memory.write(&mut store, offset as usize, raw_frame)?;

    let result_ptr = parse_fn.call(&mut store, (offset, len))?;
    Ok(())
}
```

The WASI context constructed here has no preopened directories, no socket capabilities, and no environment variables. A bug in the WASM parser cannot open files, make network connections, or read the host environment. The parser's only output channel is stdout, which the host embedder captures and parses as newline-delimited JSON.

The fuel limit of 500,000 instructions is sufficient for parsing one Modbus TCP frame — calibrated by profiling representative traffic. A parser that exceeds this budget traps cleanly; the host logs the oversized input and moves to the next frame.

### 3. Fuzz Testing the WASM Parser

Fuzzing a WASM parser is safer than fuzzing a native parser: a crash within the WASM sandbox produces a trap, not a memory corruption event that could affect the fuzzing harness or the host OS. The fuzzer can safely run millions of iterations with malformed inputs without risking the fuzzing infrastructure.

```toml
[package]
name = "modbus-parser-fuzz"
version = "0.0.1"
edition = "2021"

[[bin]]
name = "fuzz_modbus_frame"
path = "fuzz_targets/fuzz_modbus_frame.rs"
```

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use modbus_parser_wasm::parse_modbus_tcp;

fuzz_target!(|data: &[u8]| {
    let _ = parse_modbus_tcp(data);
});
```

Run the fuzzer against the native Rust parser first to find panics, then compile to WASM and confirm all previously-panicking inputs produce traps rather than memory corruption:

```bash
cargo +nightly fuzz run fuzz_modbus_frame -- \
    -max_len=512 \
    -runs=2000000 \
    fuzz/corpus/modbus/
```

A sample malformed Modbus response in the fuzz corpus — a frame advertising a `length` field of `0xFFFF` (65535) to trigger integer overflow in a naive byte-count parser:

```bash
printf '\x00\x01\x00\x00\xff\xff\x01\x03\x04\x00\x0a\x00\x0b' \
    > fuzz/corpus/modbus/malformed_length_overflow
```

After completing a fuzz run, any crash inputs found are placed in `fuzz/artifacts/fuzz_modbus_frame/`. Review each one: in a Rust parser with `overflow-checks = true`, these will be panics (integer overflow, index out of bounds) that compile to WASM traps. In a C parser, the same inputs would produce silent memory corruption.

### 4. Reproducible WASM Builds for Audit

OT operators need to verify that a WASM parser binary deployed to their monitoring infrastructure matches the source that was reviewed by their security team. Reproducible builds make this verification possible: two independent builds from the same commit and toolchain version produce identical SHA256 hashes.

Pin the Rust toolchain version and set `SOURCE_DATE_EPOCH` to suppress any embedded timestamp:

```toml
[toolchain]
channel = "1.87.0"
targets = ["wasm32-wasi"]
```

```bash
export SOURCE_DATE_EPOCH=1746230400

cargo build --target wasm32-wasi --release \
    --manifest-path modbus-parser-wasm/Cargo.toml

sha256sum target/wasm32-wasi/release/modbus_parser_wasm.wasm \
    > modbus_parser_wasm.sha256
```

To verify a deployed parser on an OT monitoring server against the reviewed build:

```bash
sha256sum -c modbus_parser_wasm.sha256
```

Commit `Cargo.lock` to version control — pinned dependency versions are a prerequisite for reproducibility. A build that resolves dependencies at build time cannot be reproduced if any dependency version changes.

In CI, build the WASM binary, publish the SHA256 alongside it as a build artefact, and require that deployments verify the hash before loading the parser. The hash check belongs in the deployment script, not as an optional manual step.

### 5. Integration with Zeek via WASM Plugin

Zeek's native C++ analyser architecture does not yet have a stable WASM plugin API as of 2026. Two integration patterns are viable in current deployments.

The first pattern runs the WASM parser as a sidecar process alongside Zeek. The sidecar receives raw packet bytes via a Unix domain socket (or reads from a shared PCAP ring buffer), invokes the WASM parser, and writes structured output to a directory that Zeek reads via `zeek-logger` or an `InputFramework` source:

```bash
wasmtime run \
    --wasm-features all \
    --dir /var/lib/zeek-parser-input::/input:ro \
    --dir /var/lib/zeek-parser-output::/output \
    modbus_parser_wasm.wasm
```

The `--dir` flags preopened here are the sidecar's entire filesystem capability: read-only access to a directory containing raw frame dumps, write access to the output directory. The WASM parser cannot reach any other path.

The second pattern, appropriate for a custom Zeek build, wraps the WASM parser invocation in a thin Zeek C++ shim. The shim receives bytes from Zeek's existing packet pipeline, calls into the Wasmtime embedder C API, and returns the parsed record to Zeek's script layer. This confines the unsafe C++ surface to the shim (which is small and auditable) and moves all byte-processing logic into the WASM sandbox:

```bash
zeek -C -r capture.pcap \
    Site::local_nets+=10.0.0.0/8 \
    modbus-wasm-analyser.zeek
```

Contrast this with the current C++ plugin approach: a C++ analyser runs with the same privileges as the Zeek process, shares the process address space, and a memory corruption bug in the analyser gives an attacker control over the Zeek engine. The WASM shim approach reduces the native code surface to the shim alone — a function of perhaps 200 lines rather than a full protocol parser.

### 6. Portable Deployment: Edge Gateway and Browser

The same `.wasm` binary produced in step 1 runs without modification on an ARMv7 OT edge gateway (via Wasmtime AOT compilation), in a Node.js or Deno process for a browser-based OT dashboard backend, and within a Malcolm deployment's Zeek component. This portability is a concrete audit benefit: one binary, one hash, one security review.

AOT-compile the parser for ARM deployment to eliminate JIT overhead at runtime:

```bash
wasmtime compile \
    --target aarch64-unknown-linux-gnu \
    modbus_parser_wasm.wasm \
    -o modbus_parser_wasm_arm64.cwasm
```

Run the parser against a PCAP-derived byte sequence on an OT edge gateway:

```bash
wasmtime run \
    --fuel 500000 \
    modbus_parser_wasm.wasm \
    < /tmp/modbus_frame.bin
```

For a Deno-based OT dashboard backend, the same WASM binary is loaded via the `WebAssembly` API — no recompilation, no platform-specific shims:

```bash
deno run --allow-read dashboard-parser.ts modbus_parser_wasm.wasm
```

The `--fuel` flag in the Wasmtime CLI invocation enforces the same computational budget as the embedded host from step 2. A malformed frame that triggers an infinite loop in a buggy parser version is interrupted within milliseconds rather than hanging the edge gateway's monitoring process.

## Expected Behaviour After Hardening

After WASM compilation: `wasm-validate parser.wasm` returns success with no output — an exit code of zero. The binary is portable: `wasmtime run` executes it on both x86_64 and ARMv7 without modification or recompilation. The binary size with `opt-level = "z"` is typically under 200 KB for a Modbus TCP parser.

After fuzzing: the fuzz corpus identifies at least three malformed-frame inputs that caused panics in the Rust parser before adding `saturating_sub` bounds checks — a frame with `length = 0`, a frame with `length = 0xFFFF`, and a frame truncated mid-field. After adding bounds checks and recompiling to WASM, all three inputs produce WASM traps (clean, catchable failures) rather than panics or memory corruption. The fuzzer runs for two million iterations with no new crashes.

After reproducible build: two independent builds from the same commit — one on the CI server, one on an air-gapped operator workstation using a cloned toolchain — produce identical SHA256 hashes. The deployed parser on the Malcolm instance matches the operator's locally-verified hash. The audit trail links source commit → WASM binary hash → deployment record.

## Trade-offs and Operational Considerations

WASM compilation of parsers written in C — including Zeek's existing C++ analysers — requires either a Clang/LLVM WASM target or a rewrite in Rust or Go. This is not a drop-in replacement. Clang's `wasm32-wasi` target can compile many C codebases, but POSIX threading, signal handling, and certain file descriptor patterns require shims or restructuring. Existing Zeek C++ analysers use Zeek-internal APIs that have no WASM equivalent. For existing tools, the practical path is to write new parsers in Rust targeting `wasm32-wasi` and run them as sidecars, rather than recompiling existing analysers.

WASM parser performance is typically 5–15% slower than native for tight parsing loops due to bounds-checked memory accesses and the absence of SIMD in some WASM configurations. For OT traffic volumes — a Modbus network polling 50 PLCs at one-second intervals produces on the order of 50 frames per second — this overhead is irrelevant. OT networks are not enterprise Ethernet; 15% parsing overhead on 50 frames per second is noise.

Zeek's native WASM plugin interface is emerging as of 2026. The Zeek project has discussed WASM-based analyser extensibility, but there is no stable API. The sidecar pattern described in step 5 is the production-viable approach today. Teams that need native Zeek integration without a sidecar should track the Zeek plugin roadmap and plan for a migration path when a stable WASM analyser API ships.

Reproducible builds require all transitive dependencies to be pinned. Commit `Cargo.lock`. Pin the Rust toolchain via `rust-toolchain.toml`. Document the `SOURCE_DATE_EPOCH` value in the build pipeline. Any of these omissions breaks reproducibility silently — the build succeeds but produces a different binary on a different machine, and the hash verification step fails in a way that looks like a deployment error rather than a reproducibility failure.

## Failure Modes

**WASM parser run with `allow_all` WASI capabilities.** The operator sets `WasiCtxBuilder::new().inherit_env().inherit_stdio().inherit_args()` and adds `allow_all_sockets()` during development to simplify testing. The configuration is committed and promoted to production without review. The WASM sandbox is present — the parser is compiled to WASM, it traps on out-of-bounds memory access — but capability restriction is absent. A malicious input that achieves code execution within the WASM sandbox has full socket access to the OT network from the WASM process. The sandbox provides memory isolation but no network isolation. Mitigate by requiring WASI capability configurations to pass schema validation before deployment, with `inherit_*` and `allow_all_sockets` rejected as invalid values for production contexts.

**Fuzz corpus not maintained after parser updates.** The parser is updated to support EtherNet/IP CIP routing headers. The new code path adds three new length fields that are read before bounds checking. The existing fuzz corpus covers the original Modbus TCP frame format. The CI pipeline runs the fuzzer against the old corpus for the configured time budget, finds no crashes, and the pipeline passes. The new length fields are not exercised. A malformed EtherNet/IP frame triggers a panic in production. Mitigate by adding specific corpus entries for every new protocol variant and running the fuzzer with coverage-guided instrumentation (`cargo fuzz coverage`) to confirm new code paths are reached.

**Reproducible build verification skipped in the deployment pipeline.** The SHA256 hash is published as a build artefact alongside the WASM binary. The deployment script downloads and installs the binary but does not verify the hash — the verification step was commented out during a deployment incident two months prior and never re-enabled. An unverified WASM binary is deployed to the Malcolm monitoring infrastructure. Mitigate by making hash verification a blocking step in the deployment pipeline with no override path, not a best-effort advisory check.

**WASM parser used for alerting but native parser still used for session state tracking.** The team deploys the WASM Modbus parser for signature matching and alert generation, but Zeek's native C++ Modbus analyser continues to run for session tracking (connection logs, service identification). A malformed frame that bypasses the WASM parser's alert logic is still processed by the native C++ analyser for session state. The memory isolation benefit applies only to the WASM parser's code path — the native parser remains on the attack surface. The attacker crafts frames that are benign from the WASM parser's perspective but trigger memory corruption in the native session tracker. Mitigate by replacing the native parser entirely, or by confirming that the native parser's session tracking path is not reachable by frames the WASM parser has already validated.

## Related Articles

- [WASM OT Edge Sandboxing](/articles/wasm/wasm-ot-edge-sandboxing/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [Reproducible WASM Builds](/articles/wasm/reproducible-wasm-builds/)
- [OT Network Monitoring Malcolm](/articles/observability/ot-network-monitoring-malcolm/)
- [WASM Static Analysis](/articles/wasm/wasm-static-analysis/)
