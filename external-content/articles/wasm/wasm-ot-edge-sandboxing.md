---
title: "WebAssembly Sandboxing for OT Edge: WASI Capabilities as Conduit Enforcement"
description: "CISA's OT Zero Trust guidance requires application-layer capability enforcement. WASM + WASI provides a sandboxing model for OT edge plugins where each vendor module gets only the network socket or filesystem access it needs — no more."
slug: wasm-ot-edge-sandboxing
date: 2026-05-03
lastmod: 2026-05-03
category: wasm
tags:
  - ot-security
  - wasi
  - sandboxing
  - industrial-edge
  - wasmtime
personas:
  - platform-engineer
  - security-engineer
article_number: 406
difficulty: Advanced
estimated_reading_time: 11
published: true
layout: article.njk
permalink: /articles/wasm/wasm-ot-edge-sandboxing/
---

# WebAssembly Sandboxing for OT Edge: WASI Capabilities as Conduit Enforcement

## The Problem

OT edge gateways — industrial IoT concentrators, protocol converters, edge historians — increasingly run software plugins from multiple OT vendors simultaneously: a Rockwell Automation Modbus collector, a Siemens PROFINET parser, a custom analytics function from a system integrator. In a traditional Linux process model, all these plugins run as the same user with the same access to the network stack, filesystem, and environment variables. A compromised or malicious plugin from any one of those vendors can read credentials from environment variables, open TCP connections to other OT devices on the same segment, or write to the filesystem. Vendor isolation is structurally absent.

CISA's April 2026 guidance "Adapting Zero Trust Principles to Operational Technology" formalises what many OT security architects have long argued: the Application/Workload pillar of Zero Trust applies to OT just as it does to enterprise IT. No OT application should have more access than its defined function requires. A Modbus polling plugin should be able to reach one PLC on one port. It should not be able to reach the engineering workstation, query DNS, or read the gateway's credential store. That is a capability grant, not a firewall rule — and it needs to be enforced at the application layer, not just at the network perimeter.

WASM + WASI addresses this directly. A WASM module compiled to the WASI component model runs inside a Wasmtime host that constructs a `WasiCtx` for each plugin before instantiation. That context is the complete set of capabilities the plugin has access to: a single preopened directory handle, a socket capability restricted to one IP and port, no environment variables, no DNS. The WASM runtime's linear memory isolation means the Modbus plugin cannot read memory belonging to the PROFINET parser, even when both run in the same host process. WASI preview 2's capability-passing model means a plugin cannot acquire a capability it was not handed at instantiation — there is no `open("/proc/1/environ")` path, no ambient authority to exploit.

This model maps directly onto CISA's zones-and-conduits framework. A conduit in the Purdue model is a defined, controlled path between zones that permits specific communication types. A WASM module's WASI capability grant is a software-enforced conduit definition: this plugin may communicate via TCP to 10.0.1.5:502, and nothing else. The conduit enforcement moves from the network layer (firewall rules, VLAN ACLs) down to the application layer, where it is enforceable per-plugin even when plugins share a physical gateway and a physical network interface.

Fermyon's Spin framework is relevant here for the HTTP trigger pattern: an OT gateway exposing a REST interface for upstream SCADA systems can be modelled as Spin components where each vendor's data-normalisation logic is a separate WASM component with explicit `allowed_outbound_hosts` entries. Spin's manifest becomes an auditable, version-controlled policy document. For raw TCP polling plugins (Modbus, DNP3, IEC 61850), the Wasmtime embedder model with a custom `WasiCtx` per plugin is the right approach.

The OT edge compute pattern is not theoretical. By 2026, industrial IoT gateways from vendors including Moxa, Advantech, and Siemens run Linux on ARMv7 or x86_64 hardware with sufficient headroom for a Wasmtime host process. The constraint is not compute — it is the absence of a software architecture that enforces vendor isolation. WASM provides that architecture.

## Threat Model

- **Malicious vendor OT plugin with unrestricted Linux process access.** A plugin supplied by a vendor — or a plugin build that has been tampered with in the supply chain — runs as a Linux process with the same UID as the gateway's data-collection service. It reads credentials from environment variables, opens connections to engineering workstations on the OT network, or exfiltrates PLC configuration to an external host. No application-layer control prevents this in the default Linux process model.

- **Compromised OT edge gateway running all plugins as root.** Many embedded Linux OT gateways run all services as root because the original firmware was built without privilege separation. A single compromised plugin has full system access: it can install persistent backdoors, modify other plugins, or rewrite the gateway's own configuration.

- **Supply chain attack on a vendor-supplied plugin binary.** The gateway's update mechanism fetches a new version of a vendor plugin over the internet or a local update server. No signature verification is performed. A build-pipeline compromise or a MITM on the update channel delivers a malicious binary that is executed with full process privileges.

- **Plugin memory corruption bug that overwrites another plugin's credential cache.** Two plugins share a host process; one has a heap-overflow vulnerability. The corrupted memory region belongs to the other plugin's in-memory credential cache. The attacker reads PLC credentials through the first plugin's exfiltration channel.

- **OT edge gateway running a general-purpose container runtime with no OT-specific network isolation.** A Docker-based plugin architecture gives each plugin a container but uses `--network=host` for convenience (a common pattern on constrained OT hardware without a container-capable network stack). Every plugin container has access to all network interfaces, including the OT segment interface, even if it only needs to reach one PLC.

## Hardening Configuration

### 1. WASM Plugin Isolation Model

Each vendor plugin is compiled to a `.wasm` binary and loaded by a Wasmtime host embedder that constructs a separate `WasiCtx` per plugin. The `WasiCtx` is the totality of the plugin's capability grant. The host process does not pass the host's environment, filesystem, or network access to the plugin unless it is explicitly added to the context.

The following illustrative Rust host code shows how to build a minimal capability context for a Modbus polling plugin:

```rust
// Illustrative: actual WasiCtxBuilder API follows wasmtime-wasi 22+ conventions.
use wasmtime::*;
use wasmtime_wasi::preview2::{WasiCtxBuilder, WasiCtx};
use cap_std::net::TcpListener;

fn build_modbus_plugin_ctx(plc_ip: &str, plc_port: u16) -> anyhow::Result<WasiCtx> {
    let data_dir = cap_std::fs::Dir::open_ambient_dir(
        "/var/lib/ot-gateway/modbus-plugin/data",
        cap_std::ambient_authority(),
    )?;

    let ctx = WasiCtxBuilder::new()
        .preopened_dir(data_dir, DirPerms::READ | DirPerms::WRITE, FilePerms::READ | FilePerms::WRITE, "/data")?
        .allow_ip_name_lookup(false)
        .allow_tcp(true)
        .socket_addr_check(move |addr, _| addr.ip().to_string() == plc_ip && addr.port() == plc_port)
        .allow_udp(false)
        .build();

    Ok(ctx)
}
```

The key constraints are: `allow_ip_name_lookup(false)` prevents the plugin from resolving any DNS name; `socket_addr_check` limits TCP connections to exactly one IP and port; `preopened_dir` gives access to a single plugin-scoped data directory. The plugin receives no environment variables, no stdin, no access to other directories, and no access to other network addresses. A plugin that calls `connect("10.0.2.99:502")` when its grant covers only `10.0.1.5:502` receives a permissions error from the WASM runtime — the OS firewall is never consulted.

Wasmtime's linear memory isolation is enforced by the runtime's memory model: each instance has its own contiguous linear memory region, and out-of-bounds accesses trap rather than reaching adjacent memory. Two plugins running in the same host process cannot read each other's memory regardless of bugs in either plugin.

### 2. OT-Specific Capability Mapping

CISA's zones-and-conduits model defines conduits as controlled pathways between security zones. Each conduit has a defined set of permitted communication types, directions, and endpoints. This maps directly onto WASI capability grants.

| CISA Conduit Definition | WASI Capability Grant |
|---|---|
| Modbus collector → PLC at 10.0.1.5:502, TCP, poll-only | `socket_addr_check` to `10.0.1.5:502`; `allow_udp(false)` |
| PROFINET parser → multicast group 239.192.0.0/29 | `socket_addr_check` for the specific multicast range |
| Analytics plugin → read-only historian data directory | `preopened_dir` with `DirPerms::READ`, `FilePerms::READ` |
| OTA update receiver → update server at 10.0.0.10:8443 | `socket_addr_check` to `10.0.0.10:8443` only |
| Credential-free telemetry exporter → no network | No socket capabilities granted; write to preopened log dir |

Each row in this table corresponds to one `WasiCtx` construction in the host embedder. The conduit policy and the plugin capability grant are the same artefact — a change to the conduit definition requires a change to the host embedder configuration, which is version-controlled and auditable.

The host embedder reads plugin capability grants from a configuration file at startup:

```yaml
plugins:
  - id: modbus-rockwell
    wasm_path: /opt/ot-plugins/modbus-rockwell.wasm
    vendor_pubkey: /etc/ot-gateway/keys/rockwell.pub
    capabilities:
      tcp_allow:
        - host: "10.0.1.5"
          port: 502
      data_dir: /var/lib/ot-gateway/modbus-rockwell/data
      dns_lookup: false
      udp: false

  - id: profinet-siemens
    wasm_path: /opt/ot-plugins/profinet-siemens.wasm
    vendor_pubkey: /etc/ot-gateway/keys/siemens.pub
    capabilities:
      tcp_allow: []
      udp_multicast:
        - group: "239.192.0.1"
          port: 34964
      data_dir: /var/lib/ot-gateway/profinet-siemens/data
      dns_lookup: false
```

The host embedder validates this file against a JSON Schema at startup and refuses to load any plugin whose capability grant exceeds what the schema permits.

### 3. Plugin Signature Verification

Before loading a plugin's `.wasm` binary, the host embedder verifies its signature against the vendor's code-signing public key. Vendor public keys are stored in a local trust store on the gateway — they are not fetched from the internet at runtime, which is critical for OT networks that may be air-gapped or have restricted external connectivity.

```rust
// Illustrative: signature verification before Module::from_binary.
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use std::fs;

fn load_verified_plugin(
    wasm_path: &str,
    sig_path: &str,
    pubkey_path: &str,
    engine: &Engine,
) -> anyhow::Result<Module> {
    let wasm_bytes = fs::read(wasm_path)?;
    let signature_bytes = fs::read(sig_path)?;
    let pubkey_bytes = fs::read(pubkey_path)?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap())?;
    let signature = Signature::from_bytes(&signature_bytes.try_into().unwrap());

    verifying_key.verify(&wasm_bytes, &signature)?;

    Module::from_binary(engine, &wasm_bytes)
}
```

The signature covers the full `.wasm` binary. A plugin with a missing, invalid, or mismatched signature is refused before any parsing or compilation occurs. This prevents supply-chain-substituted plugin binaries from executing even if they reach the gateway's plugin directory.

Vendor public keys are provisioned to the gateway during its initial configuration and updated through the same authenticated channel used for gateway firmware updates. A separate key per vendor means compromise of one vendor's signing key does not affect other vendors' plugins.

### 4. Fuel and Epoch Limits

OT polling plugins operate on fixed cycles: a Modbus plugin polls one PLC every 500 ms, reads a defined set of registers, writes the result to a data directory, and exits. A plugin that runs longer than its cycle budget is either buggy or malicious. Wasmtime's fuel and epoch interruption mechanisms enforce this.

Fuel assigns a computational budget to each plugin invocation. Epoch interruption enforces a wall-clock deadline independently of fuel. Using both together handles both the CPU-intensive runaway (fuel) and the I/O-blocked loop (epoch).

```rust
fn configure_engine_for_ot() -> Engine {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config.wasm_threads(false);
    config.wasm_multi_memory(false);
    Engine::new(&config).unwrap()
}

fn run_plugin_invocation(
    engine: &Engine,
    module: &Module,
    wasi_ctx: WasiCtx,
    fuel_budget: u64,
) -> anyhow::Result<()> {
    let mut store = Store::new(engine, wasi_ctx);
    store.set_fuel(fuel_budget)?;
    store.set_epoch_deadline(1);

    let instance = Instance::new(&mut store, module, &[])?;
    let poll_fn = instance.get_typed_func::<(), ()>(&mut store, "poll")?;
    poll_fn.call(&mut store, ())?;
    Ok(())
}
```

Fuel budgets are calibrated per plugin type. A 500 ms Modbus polling cycle at typical PLC response times needs far less fuel than a batch historian upload that processes thousands of data points. Calibrate fuel budgets by profiling representative workloads in a test environment and setting the production budget at 2x the observed maximum.

The epoch incrementer runs in a dedicated host thread, incrementing the engine's epoch counter every 50 ms. With `set_epoch_deadline(1)`, a plugin that exceeds one epoch tick (50–100 ms beyond its deadline) is interrupted cleanly. The host process and all other plugin instances continue running.

```rust
fn start_epoch_thread(engine: Engine) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            engine.increment_epoch();
        }
    });
}
```

### 5. Memory Isolation Verification

WASM linear memory isolation is enforced by the Wasmtime runtime: each instance's linear memory is a separate allocation, and the WASM memory model prohibits out-of-bounds access. Verify this property holds in your deployment by running two plugins in the same host process and confirming they cannot observe each other's linear memory addresses.

```bash
wasmtime run --wasm-features all -- /opt/test/memory-probe.wasm 2>&1 | grep "access denied"
```

A memory probe test module attempts to read from a pointer outside its linear memory bounds. Wasmtime should trap with an out-of-bounds memory access error. If the trap does not occur, the Wasmtime build or configuration is incorrect.

For a more rigorous test, run two plugin instances in parallel and have one attempt to read from the known linear memory base address of the other (obtained by inspecting the host process's `/proc/<pid>/maps`). The read should fail — WASM linear memory is not addressable from another instance's instruction stream regardless of the host process's virtual address layout.

### 6. Deployment on Constrained OT Hardware

Wasmtime supports ARMv7 and ARM64 targets, which cover most commercial OT gateway hardware. AOT (ahead-of-time) compilation via `wasmtime compile` produces a `.cwasm` artefact that loads without JIT compilation at runtime, eliminating JIT overhead and meeting deterministic startup requirements.

```bash
wasmtime compile --target armv7-unknown-linux-gnueabihf \
    /opt/ot-plugins/modbus-rockwell.wasm \
    -o /opt/ot-plugins/modbus-rockwell.cwasm
```

Minimum hardware requirements for a Wasmtime host running four concurrent OT plugins:

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | ARMv7 Cortex-A7 @ 800 MHz | ARMv8 Cortex-A53 @ 1.2 GHz |
| RAM | 128 MB (plugins + host) | 256 MB |
| Flash/Storage | 64 MB | 128 MB |
| OS | Linux 4.9+ (ARMv7) | Linux 5.4+ LTS |

AOT-compiled WASM startup overhead on Cortex-A53 is 2–5 ms per plugin instance, compared to 0.5–1 ms for a native binary loaded via `dlopen`. For a 500 ms polling cycle, this startup overhead is negligible. For hard real-time requirements under 10 ms, keep plugin instances warm between polling cycles using Wasmtime's instance pooling rather than creating a new instance per poll.

```toml
# wasmtime host configuration for instance pooling on OT gateways
[pool]
max_instances = 8
strategy = "reuse"
instance_memory_pages = 512
```

## Expected Behaviour After Hardening

After WASI capability restriction: a Modbus plugin that attempts to open a TCP connection to `10.0.2.99:502` — an address not in its capability grant — receives a permissions error from the Wasmtime runtime before any system call reaches the OS. The OS firewall does not see the connection attempt. The host embedder logs the denied capability attempt with the plugin ID and the attempted address. Other plugins continue running without interruption.

After fuel and epoch limits: a plugin that enters an infinite loop — whether due to a bug or a malicious payload — is interrupted at the next epoch boundary (within 50–100 ms). The trap is caught by the host embedder's error handler, which logs the interruption and schedules the plugin for the next polling cycle. The host process does not crash. Other plugins in the same process are unaffected because Wasmtime's epoch mechanism does not block other instances' execution.

After signature verification failure: a plugin whose `.wasm` binary has been modified since signing fails verification before any parsing or compilation. The host embedder logs the vendor ID, the plugin path, and the verification failure reason, then starts without that plugin. An alert is raised to the OT security operations centre.

After memory isolation: a heap-overflow bug in the PROFINET parser plugin cannot corrupt the Modbus plugin's memory. The overflow produces a Wasmtime out-of-bounds trap within the PROFINET plugin's own linear memory, which is caught and logged. The Modbus plugin's credential cache is intact.

## Trade-offs and Operational Considerations

WASM compilation of existing C/C++ OT software — vendor PLCopen libraries, proprietary data collectors, licensed protocol stacks — requires recompilation with a WASM target. Many OT vendors do not offer WASM builds and have no plans to do so. This sandboxing model applies to new edge software and integrator-written plugins first. Existing vendor binaries remain in the traditional Linux process model until the vendor provides a WASM-compiled version or the operator rewrites the plugin. This is not a reason to defer adoption; it is a reason to apply the model incrementally, starting with new plugin development.

WASI preview 2 (the component model) is required for fine-grained socket capability grants via `socket_addr_check`. WASI preview 1 provides coarser capability control — it can restrict which directories are preopened but cannot enforce per-IP socket allowlists at the WASI level. If your Wasmtime version or toolchain does not support preview 2, preview 1 still provides meaningful filesystem isolation; supplement it with OS-level network controls (nftables rules per plugin user ID) as a compensating control.

Wasmtime AOT compilation achieves near-native performance on ARMv7 and ARM64. JIT compilation on constrained OT hardware introduces latency that may be incompatible with polling cycles under 100 ms. Always use AOT-compiled `.cwasm` artefacts in production OT deployments. The `wasmtime compile` step belongs in the plugin's build pipeline, not on the gateway at runtime.

Plugin signature verification requires the gateway to have access to a local trust store containing vendor public keys. For air-gapped OT segments, this trust store must be provisioned and updated through an offline process — USB transfer, sneakernet, or a secure management VLAN that does not cross into the OT field network. Ensure the trust store replication process is documented and tested before deploying signature verification as a hard requirement. A gateway that cannot verify plugin signatures due to a stale trust store must fail closed: refuse to load unverifiable plugins rather than failing open.

## Failure Modes

**WASI capability grants configured too broadly.** An operator configures `allow_all_sockets` on the `WasiCtxBuilder` during debugging and the configuration is promoted to production. The sandbox is present but provides no network isolation. The conduit enforcement goal is defeated while creating a false sense of security. Mitigate by requiring capability configurations to pass schema validation against an allowlist of permitted fields — `allow_all_sockets` should not be a permitted value in production configuration.

**Plugin signed by a vendor key that has since been compromised.** A vendor's code-signing key is compromised in a supply-chain incident. The attacker produces a malicious plugin signed with the legitimate key. The gateway's trust store still contains the compromised key, so verification passes and the malicious plugin loads. Mitigate by subscribing to vendor security advisories, maintaining a key revocation list alongside the trust store, and verifying plugin signatures against both the key and the revocation list. On air-gapped OT segments, the revocation list update process must be part of the incident response playbook.

**Fuel budget calibrated in a lab environment but production PLCs respond slower under load.** A Modbus plugin's fuel budget was set to 2x the lab-measured maximum fuel consumption. Under production load, PLC response times are 3x higher than in the lab, the plugin performs more computation processing error-retries, and fuel is exhausted mid-polling-cycle. The plugin traps, the polling cycle is missed, and the upstream historian receives a data gap. Mitigate by calibrating fuel budgets against production traffic during an initial observation period, with the budget temporarily set high. After one week of production data, set the budget to 3x the observed 99th percentile.

**Host embedder runs plugins in a single thread without epoch interruption.** Epoch interruption is not enabled in the `Config`. One slow or blocked plugin occupies the host thread indefinitely, preventing all other plugins from polling. Head-of-line blocking defeats the isolation model. Mitigate by always enabling epoch interruption and running each plugin invocation in its own thread or async task. The epoch mechanism is designed for this pattern — it adds negligible overhead when no plugin is running over its deadline.

## Related Articles

- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASI Preview 2 Capabilities](/articles/wasm/wasi-preview-2-capabilities/)
- [WASM IoT Embedded](/articles/wasm/wasm-iot-embedded/)
- [OT Network Segmentation Zero Trust](/articles/network/ot-network-segmentation-zero-trust/)
- [Spin Framework Security](/articles/wasm/spin-framework-security/)
