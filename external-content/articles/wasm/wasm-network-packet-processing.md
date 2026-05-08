---
title: "WASM for Network Packet Processing: Security Filters and Traffic Inspection"
description: "WASM enables safe, user-space packet processing for network security applications — without eBPF's kernel privilege requirements. This guide covers WASM-based packet filters with libpcap, network security functions in WasmEdge, comparing WASM vs eBPF for security use cases, and safe packet dissection in WASM."
slug: wasm-network-packet-processing
date: 2026-05-07
lastmod: 2026-05-07
category: wasm
tags:
  - wasm
  - network-security
  - packet-processing
  - ebpf-comparison
  - wasi-sockets
personas:
  - security-engineer
  - network-engineer
article_number: 589
difficulty: Advanced
estimated_reading_time: 12
published: true
layout: article.njk
permalink: /articles/wasm/wasm-network-packet-processing/
---

# WASM for Network Packet Processing: Security Filters and Traffic Inspection

## The Problem

Network packet processing sits at an uncomfortable intersection of performance and safety. The code that inspects raw bytes from the wire — protocol dissectors, IDS rules, DPI engines — is written almost universally in C or C++. It processes attacker-controlled input on every packet. And it runs either in the kernel (eBPF, kernel modules) or in a privileged user-space daemon with broad system access. A memory corruption bug in a Suricata protocol dissector, a Zeek analyser, or a Snort preprocessor runs in a process with network capture privileges, direct access to packet ring buffers, and typically root or `CAP_NET_RAW`. The attacker who sends a crafted packet triggering the bug does not just crash the IDS — they can potentially take over the monitoring infrastructure.

WebAssembly changes this risk model. By compiling packet inspection logic to `.wasm` and running it in a sandboxed runtime, the host process remains intact even when the parser encounters a malformed frame that would have caused a buffer overflow in native code. WASM's linear memory model bounds any overflow within the sandbox. An attacker who exploits a logic bug in a WASM-compiled dissector gains control only within the WASM module's sandbox — limited to whatever WASI capabilities the host granted, which for a packet inspector should be none beyond reading from a pre-opened input stream and writing to a structured output channel.

This article covers four concrete applications of WASM to network security: pcap-based packet filtering, safe protocol dissection, intrusion detection rule evaluation, and network function virtualisation. It then provides a direct comparison with eBPF to clarify when each technology is the right choice.

## WASM vs eBPF for Network Security

Before writing any code, it is worth being precise about the trade-offs. eBPF and WASM are both sandboxed execution environments, but they sit at completely different layers of the network stack and have different security properties.

**eBPF** runs in the Linux kernel. Its verifier enforces safety properties at load time — no unbounded loops (pre-5.3), no out-of-bounds memory access, no NULL pointer dereferences — but the verifier itself has a CVE history (CVE-2021-3490, CVE-2022-23222, CVE-2023-2163 among others). Loading an eBPF program requires `CAP_BPF` or `CAP_SYS_ADMIN`. eBPF programs attached to XDP hooks run before the kernel network stack processes the packet, enabling line-rate packet drop and modification. eBPF is the right choice when you need kernel-level performance, XDP line-rate filtering, or access to kernel data structures (TCP socket state, process credentials, system calls).

**WASM** runs in user space. The sandbox is enforced by the WASM runtime (Wasmtime, WasmEdge, Wasmer) without kernel privilege requirements. WASM programs can be written in any language that compiles to WASM (Rust, C, Go, AssemblyScript). WASM is slower than eBPF for packet processing — a WASM-based filter operates on a copy of packet data passed through a ring buffer or pcap handle, not on the packet in the kernel's receive path. WASM cannot drop packets at the XDP layer. What WASM provides is multi-language support, no kernel privilege requirement, and a more mature and auditable sandbox story for complex parsing logic.

The practical division: use eBPF for high-performance packet filtering (XDP DDoS mitigation, connection rate limiting, fast packet classification) where you need kernel-layer access and can accept the `CAP_BPF` privilege requirement. Use WASM for complex, stateful protocol dissection, IDS rule evaluation, and traffic inspection functions where the parsing logic is complex enough that native-code memory safety bugs are a real concern and the latency of user-space processing is acceptable.

Neither is a replacement for the other. A well-architected network security stack uses eBPF for the fast path (packet classification and drop) and WASM for the slow path (deep inspection, anomaly detection, protocol dissection of flagged flows).

| Property | eBPF | WASM |
|---|---|---|
| Execution context | Kernel | User space |
| Privilege required | `CAP_BPF` / `CAP_SYS_ADMIN` | None (runtime is unprivileged) |
| Line-rate XDP | Yes | No |
| Language support | C, Rust (via aya), limited Go | Any language targeting WASM |
| Verifier model | Kernel verifier at load time | Runtime bounds checking |
| Parser complexity | Limited (verifier rejects loops) | Unlimited |
| Memory safety | Verifier-enforced | Sandbox-enforced |
| Portability | Linux kernel only | Linux, macOS, Windows, edge |
| Kernel CVE surface | Verifier bugs affect security | No kernel exposure |

## pcap-Based WASM Packet Processing

The simplest integration path is a WASM module that receives raw packet bytes from a libpcap handle operated by the host process. The host reads packets from the network interface or a PCAP file, writes frame bytes into the WASM module's linear memory, and invokes the module's inspection function. The module returns a verdict (pass, drop, alert) and optionally writes structured metadata to an output buffer that the host reads as newline-delimited JSON.

The WASM module is a standard `wasm32-wasi` cdylib crate. It has no pcap dependency — pcap is a host-side concern. The module's job is pure parsing and classification from a byte buffer.

```toml
[package]
name = "packet-inspector-wasm"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
nom = "7"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
overflow-checks = true
strip = "symbols"
```

A minimal Ethernet/IPv4/TCP dissector that classifies packets and flags suspicious port combinations:

```rust
use nom::{
    bytes::complete::take,
    number::complete::{be_u8, be_u16, be_u32},
    IResult,
};

#[derive(Debug)]
pub struct EthernetFrame<'a> {
    pub dst_mac: &'a [u8],
    pub src_mac: &'a [u8],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct Ipv4Header {
    pub src: u32,
    pub dst: u32,
    pub protocol: u8,
    pub total_len: u16,
}

pub fn parse_ethernet(input: &[u8]) -> IResult<&[u8], EthernetFrame> {
    let (input, dst_mac) = take(6usize)(input)?;
    let (input, src_mac) = take(6usize)(input)?;
    let (input, ethertype) = be_u16(input)?;
    Ok((input, EthernetFrame { dst_mac, src_mac, ethertype, payload: input }))
}

pub fn parse_ipv4(input: &[u8]) -> IResult<&[u8], Ipv4Header> {
    let (input, ver_ihl) = be_u8(input)?;
    let ihl = ((ver_ihl & 0x0f) * 4) as usize;
    if ihl < 20 { return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::LengthValue))); }
    let (input, _dscp_ecn) = be_u8(input)?;
    let (input, total_len) = be_u16(input)?;
    let (input, _) = take(4usize)(input)?; // id, flags, fragment offset
    let (input, _ttl) = be_u8(input)?;
    let (input, protocol) = be_u8(input)?;
    let (input, _checksum) = be_u16(input)?;
    let (input, src) = be_u32(input)?;
    let (input, dst) = be_u32(input)?;
    let options_len = ihl.saturating_sub(20);
    let (input, _options) = take(options_len)(input)?;
    Ok((input, Ipv4Header { src, dst, protocol, total_len }))
}

#[no_mangle]
pub extern "C" fn inspect_packet(ptr: *const u8, len: usize) -> i32 {
    let data = unsafe { std::slice::from_raw_parts(ptr, len) };
    match classify_frame(data) {
        Verdict::Pass => 0,
        Verdict::Alert => 1,
        Verdict::Drop => 2,
    }
}

enum Verdict { Pass, Alert, Drop }

fn classify_frame(data: &[u8]) -> Verdict {
    let Ok((payload, eth)) = parse_ethernet(data) else { return Verdict::Drop; };
    if eth.ethertype != 0x0800 { return Verdict::Pass; }
    let Ok((tcp_payload, ipv4)) = parse_ipv4(payload) else { return Verdict::Drop; };
    if ipv4.protocol != 6 { return Verdict::Pass; }
    if tcp_payload.len() < 4 { return Verdict::Pass; }
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
    // Flag connections to uncommon high ports that match known C2 patterns
    if matches!(dst_port, 4444 | 5555 | 8888 | 31337) { return Verdict::Alert; }
    Verdict::Pass
}
```

Build and validate:

```bash
rustup target add wasm32-wasi
cargo build --target wasm32-wasi --release
wasm-validate target/wasm32-wasi/release/packet_inspector_wasm.wasm
```

The host embedder, written in Rust using Wasmtime, reads from a pcap handle and passes each frame to the WASM module:

```rust
use wasmtime::*;
use pcap::Capture;

fn main() -> anyhow::Result<()> {
    let engine = Engine::default();
    let module = Module::from_file(&engine, "packet_inspector_wasm.wasm")?;
    let mut store = Store::new(&engine, ());

    let instance = Instance::new(&mut store, &module, &[])?;
    let memory = instance.get_memory(&mut store, "memory").unwrap();
    let inspect_fn = instance.get_typed_func::<(u32, u32), i32>(&mut store, "inspect_packet")?;

    let mut cap = Capture::from_device("eth0")?.open()?;
    while let Ok(packet) = cap.next_packet() {
        let data = packet.data;
        memory.write(&mut store, 0, data)?;
        let verdict = inspect_fn.call(&mut store, (0, data.len() as u32))?;
        match verdict {
            1 => eprintln!("ALERT: suspicious packet ({} bytes)", data.len()),
            2 => eprintln!("DROP: malformed packet"),
            _ => {}
        }
    }
    Ok(())
}
```

The WASM module has no WASI capabilities at all in this embedding — no filesystem, no network, no clock. It is a pure function from bytes to a verdict integer. A memory corruption bug in the dissector cannot reach the host process, open a file, or make a network connection.

## Safe Protocol Dissection in WASM

The safety argument for WASM-based dissectors is not theoretical. Wireshark's CVE history reads as a catalogue of protocol-parser memory corruption: CVE-2022-3725 (OPUS dissector heap overflow), CVE-2023-0666 (RTPS dissector heap overflow), CVE-2023-2853 (GDSDB dissector heap overflow). Each of these involves a C-based dissector processing attacker-controlled bytes and writing past the end of a heap buffer. In a WASM sandbox, the same logic error produces a trap — the module aborts cleanly, the host logs the frame as unparseable, and the next packet is processed.

The trap behaviour is the critical property. In native code, a buffer overflow gives the attacker a memory write primitive. In WASM, attempting to write past the end of a module's linear memory raises an immediate trap (a `MemoryOutOfBounds` error in Wasmtime's terminology) that the host catches via the Wasmtime API. The overflow is detected at the point of the bad write, not after the attacker has constructed an exploit. There is no window for exploitation.

For complex protocol dissectors — TLS record layer parsing, DNS name decompression, protocol buffers decoding, QUIC frame parsing — the WASM sandbox boundary is the correct place to isolate the parsing logic from the rest of the security application. The dissector crate runs in a dedicated WASM instance per parsing context. A crash in the TLS dissector does not affect the DNS dissector running in a separate instance in the same process.

A Suricata-compatible dissector plugin, compiled to WASM and loaded by a thin host shim, demonstrates this isolation. The shim allocates a fresh WASM instance for each flow. When the flow ends or the instance traps, the shim discards the instance and creates a new one for the next flow. State corruption in a single flow's dissector cannot affect other flows. This is structurally impossible in the current C-based Suricata plugin architecture, where a bug in one flow's dissector writes into the shared Suricata process heap.

## Intrusion Detection Rules in WASM

The Suricata project has discussed a WASM-based rule engine as an alternative to the current Lua scripting interface for complex detection logic. The motivation is identical to the dissector case: Lua rules have a well-defined embedding boundary (the Lua VM), but adding detection logic that requires binary parsing, bitfield manipulation, or state across packets benefits from a language like Rust or C compiled to WASM.

A WASM-compiled IDS rule is a function that takes packet bytes and flow state and returns a match result. The rule crate exports a single `match_rule` function:

```rust
#[no_mangle]
pub extern "C" fn match_rule(ptr: *const u8, len: usize, flow_state_ptr: *const u8, flow_state_len: usize) -> i32 {
    let packet = unsafe { std::slice::from_raw_parts(ptr, len) };
    let flow_state = unsafe { std::slice::from_raw_parts(flow_state_ptr, flow_state_len) };
    if detect_shellcode_pattern(packet) && is_suspicious_flow(flow_state) {
        return 1; // match
    }
    0
}

fn detect_shellcode_pattern(data: &[u8]) -> bool {
    // Detect common x86 shellcode NOP sled patterns
    let nop_threshold = 16;
    let nop_count = data.windows(1).filter(|w| w[0] == 0x90).count();
    nop_count >= nop_threshold
}

fn is_suspicious_flow(state: &[u8]) -> bool {
    // Check if flow has seen SYN with unusual TCP options
    state.first().map_or(false, |&flags| flags & 0x01 != 0)
}
```

Each rule is a separate `.wasm` module loaded by the IDS engine. Rules are loaded and validated at startup. A rule that crashes during matching produces a trap that the engine handles as a non-match — the engine logs the trap and continues processing the packet with remaining rules. No rule can affect another rule's execution state.

Distributing IDS rules as signed `.wasm` binaries enables a verification workflow that Snort and Suricata rule text cannot provide: the rule publisher signs the binary with a key the IDS operator trusts, and the IDS engine verifies the signature before loading. A rule file that has been tampered with (to suppress detection of attacker activity) fails signature verification and is rejected. Current text-based IDS rule formats have no equivalent integrity guarantee.

## WasmEdge Network Security Functions

WasmEdge provides networking extensions specifically designed for user-space network functions. The WasmEdge socket extension (`wasmedge_wasi_socket`) gives WASM modules access to TCP and UDP sockets within a capability-controlled environment. This enables WASM-based network security applications that make active network connections — for example, a threat intelligence lookup that queries an external API to enrich a flagged IP address.

A WasmEdge-based network security function that enriches packet metadata with threat intelligence:

```rust
use wasmedge_wasi_socket::*;

#[no_mangle]
pub extern "C" fn enrich_ip(ip_bytes_ptr: *const u8, ip_len: usize) -> i32 {
    let ip_str = unsafe {
        std::str::from_utf8(std::slice::from_raw_parts(ip_bytes_ptr, ip_len))
            .unwrap_or("")
    };

    // Query a local threat intelligence service via WASI socket
    let mut stream = TcpStream::connect("127.0.0.1:9000").unwrap();
    stream.write_all(ip_str.as_bytes()).unwrap();

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).unwrap();

    // Response: 0 = clean, 1 = suspicious, 2 = malicious
    response[0] as i32
}
```

The WasmEdge operator configures which socket endpoints the WASM module may connect to. A module that should only query `127.0.0.1:9000` cannot be permitted to reach arbitrary external hosts — the capability configuration is enforced at the WasmEdge host level, not by the module itself. If the module's socket capability is misconfigured to allow arbitrary outbound connections, a bug in the enrichment function that exposes an SSRF vulnerability becomes much more dangerous. Least-privilege socket configuration is as important for WasmEdge network functions as filesystem capability restriction is for WASI file access.

## Network Function Virtualisation with WASM

WASM's portability makes it attractive for network function virtualisation (NFV): packaging firewall rules, load balancer policies, traffic shapers, and DPI engines as portable `.wasm` modules that run on any host with a WASM runtime — from a cloud VM to a network appliance to an edge gateway.

The key NFV properties that WASM delivers are isolation, portability, and rapid deployment. An NFV platform based on WASM can run hundreds of isolated network function instances on a single host, each with distinct capability grants, without the overhead of VMs or containers. A firewall module can be updated by deploying a new `.wasm` binary without restarting the NFV platform. A new instance is instantiated with the new module while the old instance completes in-flight processing; traffic switches to the new instance atomically.

Envoy's WASM filter model is the most mature production example of this architecture. An Envoy WASM filter is a `.wasm` module loaded by Envoy's embedding of the WASM for Proxies specification. The filter receives L7 request and response data, can modify headers and bodies, and signals allow/deny/pause verdicts back to the Envoy processing pipeline. Security-relevant filters — JWT validation, rate limiting, custom authentication schemes, threat signature matching — are implemented as WASM modules rather than compiled Envoy extensions. The filter module runs in an isolated WASM sandbox; a panic or memory error in the filter does not crash the Envoy process.

The Nginx WASM module (nginx-wasm-module, based on the nginx-wasm-sdk) provides an equivalent capability for Nginx deployments. A WASM filter can inspect request bodies for injection patterns, validate API keys against a local cache in linear memory, or compute request signatures — all in a sandbox that cannot affect Nginx's core request handling.

## Packet Fuzzing with WASM

The combination of WASM's sandbox isolation and standard fuzzing tooling makes WASM-based dissectors excellent fuzzing targets. Running a native C-based dissector under a fuzzer requires careful memory sanitiser configuration and carries the risk that a crash in the fuzzing target corrupts the fuzzing harness itself. A WASM-compiled dissector running under a Wasmtime-based fuzzing harness cannot corrupt the harness — a crash produces a trap that the harness catches, records the crashing input, and continues.

A `cargo-fuzz` target for a WASM packet dissector uses the Wasmtime API directly:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use wasmtime::*;

thread_local! {
    static ENGINE: Engine = Engine::default();
    static MODULE: Module = {
        ENGINE.with(|e| {
            Module::from_file(e, "packet_inspector_wasm.wasm").unwrap()
        })
    };
}

fuzz_target!(|data: &[u8]| {
    ENGINE.with(|engine| {
        MODULE.with(|module| {
            let mut store = Store::new(engine, ());
            if let Ok(instance) = Instance::new(&mut store, module, &[]) {
                if let Some(memory) = instance.get_memory(&mut store, "memory") {
                    if memory.write(&mut store, 0, data).is_ok() {
                        if let Ok(inspect_fn) = instance.get_typed_func::<(u32, u32), i32>(&mut store, "inspect_packet") {
                            let _ = inspect_fn.call(&mut store, (0u32, data.len() as u32));
                        }
                    }
                }
            }
        })
    });
});
```

Run the fuzzer against a corpus of representative packets to seed coverage:

```bash
mkdir -p fuzz/corpus/packets
# Seed with representative Ethernet frames from a PCAP
tcpdump -r sample.pcap -w - | \
    python3 -c "import sys,struct; d=sys.stdin.buffer.read(); [open(f'fuzz/corpus/packets/pkt{i}','wb').write(d[o+4:o+4+struct.unpack_from('>H',d,o+2)[0]+14]) for i,o in enumerate(range(0,len(d)-18,18))]"

cargo +nightly fuzz run fuzz_packet_inspector -- \
    -max_len=1500 \
    -runs=5000000 \
    fuzz/corpus/packets/
```

The critical safety property: when the fuzzer finds a crashing input — a frame that triggers an integer overflow in the IPv4 header parser, for example — the crash is a WASM trap caught by the Wasmtime harness. The fuzzer process continues. The crashing input is saved to `fuzz/artifacts/`. The fuzzer does not exit, the fuzzing host is not compromised, and the next mutation round begins immediately. A native C-based dissector under the same fuzzer would likely produce a memory corruption event; with address sanitiser enabled, the fuzzer process terminates, and each crash requires manual triage before fuzzing continues.

## Expected Behaviour After Deployment

After building and deploying a WASM-based packet inspection pipeline:

`wasm-validate packet_inspector_wasm.wasm` exits 0 with no output. The binary is portable: running `wasmtime run` on the module on both x86_64 and aarch64 produces identical results against the same packet corpus. Binary size with `opt-level = "z"` for an Ethernet/IPv4/TCP dissector is under 150 KB.

The fuzzing harness runs five million iterations against a seed corpus of representative packets without the fuzzer process terminating unexpectedly. Crashing inputs — frames with truncated headers, zero-length length fields, and maximum-value length fields — all produce WASM traps logged as `MemoryOutOfBounds` or `UnreachableCodeReached`. None produce silent corruption. After adding saturating arithmetic in all length-field arithmetic paths and recompiling, the same inputs produce clean non-matches rather than traps.

The host pcap integration processes 50,000 packets per second on a single CPU core (a reasonable workload for a dedicated inspection host on moderate-traffic enterprise segments). Latency per packet (WASM function call overhead plus parsing) is approximately 2–4 microseconds on x86_64. This is suitable for offline analysis and moderate-rate live inspection, but not for line-rate 10Gbps+ inspection — that use case requires eBPF/XDP.

## Trade-offs and Operational Considerations

**Performance ceiling.** WASM packet processing operates on packet copies — the host pcap handle buffers the frame, the host writes it into WASM linear memory, and the WASM module reads it. This copy introduces latency that eBPF/XDP avoids entirely by operating on the packet in the kernel receive path. For applications where per-packet latency is measured in microseconds and packet rates exceed 500,000 pps, WASM user-space processing will not keep up without horizontal scaling. Use eBPF for line-rate filtering.

**Fuel limits matter for production.** A WASM packet inspector without a computational budget can be forced into a long parse by a specially crafted packet (for example, a DNS packet with a maximally compressed name that requires following many pointers before the decompression loop terminates). Set fuel limits calibrated to the maximum legitimate packet size and complexity for your environment. A Modbus TCP frame on an OT network warrants a different fuel budget than a TLS ClientHello on an enterprise proxy.

```rust
store.set_fuel(200_000)?; // calibrate per protocol
store.out_of_fuel_trap(); // trap, don't return fuel-exhausted error
```

**Instance reuse vs fresh instantiation.** Creating a new WASM instance per packet is safe but expensive — instantiation overhead is on the order of 10–100 microseconds depending on module size and runtime configuration. For flow-based inspection (inspect every packet in a TCP flow), create one instance per flow and reuse it across packets in that flow. For connection-independent packet classification, maintain a pool of pre-instantiated modules and reset state between uses by calling an exported `reset()` function rather than re-instantiating.

**WASM does not replace eBPF in the fast path.** Network security architectures should use eBPF XDP for the first filter pass (drop known-bad IPs, enforce rate limits, deflect volumetric DDoS) and WASM for deep inspection of traffic that passes the eBPF filter. Attempting to replace an XDP-based DDoS mitigation filter with WASM user-space processing will leave the inspection host overwhelmed at moderate attack volumes.

## Failure Modes

**WASM module instantiated with overly permissive WASI capabilities.** A developer adds `WasiCtxBuilder::new().inherit_env().allow_all_sockets()` to simplify debugging. The configuration reaches production. The WASM packet inspector now has outbound socket access. A bug in the dissector that achieves within-sandbox code execution gives the attacker full outbound network connectivity from the host, enabling data exfiltration or C2 communication. Packet inspection WASM modules should have no WASI capabilities beyond reading from a pre-opened byte channel. Enforce this by linting the `WasiCtxBuilder` configuration in CI and rejecting any capability beyond pre-opened input/output pipes.

**Fuel limit not set, allowing algorithmic complexity attacks.** The WASM module processes DNS packets without a fuel limit. An attacker sends a stream of DNS packets with maximally compressed names that trigger O(n²) pointer-following in the decompression loop. Each packet consumes seconds of CPU time. The inspection host's CPU is exhausted processing a small packet volume. Mitigate by setting fuel limits before every WASM call and calibrating against the worst-case legitimate packet for each protocol.

**Fuzzing performed on the Rust source but not on the compiled WASM binary.** The fuzz target calls the native Rust parser directly rather than invoking it through the Wasmtime harness. The native parser and the WASM-compiled parser have different arithmetic behaviour in edge cases: the native parser uses platform integer widths, while the WASM parser uses WASM's 32-bit integer semantics. An integer wraparound that does not occur in the native parser triggers a different code path in the WASM-compiled version. The fuzz corpus finds no bugs, but the WASM binary contains an untested crash. Always fuzz the compiled `.wasm` binary through the WASM runtime harness, not the source language's native execution environment.

**Fresh WASM instance per packet without fuel limits leaks instantiation overhead.** A team deploys a WASM-based inspector that creates a new Wasmtime instance per packet, but has not set a fuel limit. Under moderate load (100,000 pps), the instantiation overhead alone saturates a CPU core. The alert that "the WASM inspector is 50 microseconds behind" is interpreted as a WASM performance limitation and the project is abandoned in favour of a native implementation. Mitigate by profiling instantiation cost, implementing instance pooling, and setting appropriate fuel limits.

## Related Articles

- [WASM OT Protocol Parsers](/articles/wasm/wasm-ot-protocol-parsers/)
- [WASI Sockets Hardening](/articles/wasm/wasi-sockets-hardening/)
- [Envoy WASM Plugin Hardening](/articles/wasm/envoy-wasm-plugin-hardening/)
- [Nginx WASM Filters](/articles/wasm/nginx-wasm-filters/)
- [WASM Fuzzing and Security Testing](/articles/wasm/wasm-fuzzing-security-testing/)
- [WasmEdge Security](/articles/wasm/wasmedge-security/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
