---
title: "WASI Sockets API Hardening: TCP, UDP, and TLS Capability Scoping for Network-Bound WASM"
description: "wasi:sockets/tcp and wasi:sockets/udp give WASM modules network access. The capability model is fine-grained — most embedders use it as a coarse on/off switch."
slug: "wasi-sockets-hardening"
date: 2026-04-27
lastmod: 2026-04-27
category: "wasm"
tags: ["wasm", "wasi", "sockets", "networking", "capability-security"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 206
difficulty: "advanced"
estimated_reading_time: 14
published: true
layout: article.njk
permalink: "/articles/wasm/wasi-sockets-hardening/index.html"
---

# WASI Sockets API Hardening: TCP, UDP, and TLS Capability Scoping for Network-Bound WASM

## Problem

WASI Preview 2 introduced `wasi:sockets/tcp` and `wasi:sockets/udp` — interfaces that let WASM modules establish outbound TCP connections and send / receive UDP datagrams. Until 2024 these interfaces were emerging; by late 2025 they are the standard for any WASM workload that needs network — Spin's HTTP fetch, wasmCloud's network-bound capabilities, custom WASM services.

The capability model is rich:

- `wasi:sockets/tcp/tcp-socket` — a resource handle representing one TCP socket. Bind, connect, listen, accept, send, receive.
- `wasi:sockets/udp/udp-socket` — same, for UDP.
- `wasi:sockets/network/network` — a resource representing a network namespace; the host decides what's reachable.
- `wasi:sockets/ip-name-lookup/network` — DNS resolution gated by the network resource.
- `wasi:sockets/instance-network/instance-network` — a singleton handle to the host's "outside view"; restricted by the embedder.

The scope of the host's permission decision is the `network` resource itself. The embedder constructs the `network`, applies a filter (allowed CIDRs, allowed ports, allowed hostnames), and hands it to the module. From there, the module can do anything within that filter.

Most production embeddings use sockets as a coarse on/off — `allow_tcp(true)` or nothing. This loses the entire point of the capability model: any module that gets sockets at all gets the broadest reach the embedder bothered to configure.

The specific gaps in a default deployment:

- Network resources are constructed once at instance creation; can't be revoked mid-execution.
- Allowlists encoded as wildcards (`*.example.com`) leak DNS-rebinding-style attacks.
- TLS is the module's responsibility; WASI sockets are byte-streams. A module that doesn't enforce TLS leaks credentials.
- DNS resolution happens before the connect-time check; an attacker who controls a CNAME can cause the module to connect to an unintended host.
- UDP sockets, by their connectionless nature, fall outside many connection-allowlist mechanisms.
- The host has no direct visibility into per-socket bytes-in / bytes-out for billing / quota.

This article covers per-socket capability scoping with explicit allowlists, DNS-rebinding mitigations, TLS enforcement at the host boundary, UDP socket policies, and per-tenant socket quotas.

**Target systems:** Wasmtime 22+ with WASI Preview 2 sockets via `wasmtime-wasi/sockets`; Spin 2.6+; wasmCloud 1.2+; Fastly Compute (managed).

## Threat Model

- **Adversary 1 — Untrusted module attempts data exfiltration:** module given some network capability tries to send sensitive data to an attacker-controlled endpoint outside the intended set.
- **Adversary 2 — DNS-rebinding:** module is allowed to connect to `intended.example.com`; attacker controls DNS for that host and rebinds it to an internal IP after the initial resolution.
- **Adversary 3 — SSRF via host header / URL parameter:** module accepts user input that includes a URL; attempts to fetch internal-only addresses (`169.254.169.254`, `127.0.0.1`).
- **Adversary 4 — UDP amplification:** module sends spoofed-source UDP packets to amplify against a target.
- **Adversary 5 — Quota exhaustion:** module establishes thousands of connections / sends gigabytes of data, exhausting host resources or running up cloud egress costs.
- **Access level:** Adversary 1 has untrusted module bytes; Adversary 2 has DNS control; Adversary 3 has only request-input access; Adversary 4 has untrusted module bytes; Adversary 5 same.
- **Objective:** exfiltrate data; reach internal-only systems; abuse network resources for amplification or financial damage.
- **Blast radius:** Without scoping, a module given any TCP capability can reach anything on the network the host can reach. With proper scoping, the module reaches only intended endpoints; SSRF and rebinding fail at the host check.

## Configuration

### Pattern 1: Per-Socket Allowlist Closures

Wasmtime's `WasiCtxBuilder` accepts a closure that decides each connection attempt:

```rust
use wasmtime_wasi::preview2::{WasiCtxBuilder, SocketAddrCheck};

fn build_wasi(tenant_id: &str) -> WasiCtx {
    let mut builder = WasiCtxBuilder::new();

    // Per-tenant allowlist. Closures are evaluated at each connect.
    let tenant = tenant_id.to_string();
    builder.socket_addr_check(move |addr, addr_use| {
        let allowed = match tenant.as_str() {
            "payments" => match addr_use {
                SocketAddrUse::TcpConnect => allowed_payments_tcp(addr),
                SocketAddrUse::UdpBind => false,    // payments doesn't need UDP listen
                _ => false,
            },
            _ => false,
        };
        // Audit every check.
        log::info!("socket_check tenant={tenant} addr={addr:?} use={addr_use:?} allowed={allowed}");
        allowed
    });

    builder.build()
}

fn allowed_payments_tcp(addr: &SocketAddr) -> bool {
    use std::net::IpAddr;
    let ip = addr.ip();
    let port = addr.port();
    // Internal IPs only.
    let internal = match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 10 || (v4.octets()[0] == 192 && v4.octets()[1] == 168),
        IpAddr::V6(_) => false,   // strict: no IPv6 for this tenant
    };
    if !internal { return false; }
    // Specific allowed hosts.
    matches!((ip, port),
        (IpAddr::V4(v4), 5432) if v4.octets() == [10, 0, 1, 5],   // postgres
        | (IpAddr::V4(v4), 6379) if v4.octets() == [10, 0, 1, 6]) // redis
}
```

Every connect attempt invokes the closure with the resolved address. Returning `false` causes the connect to fail at the WASI boundary.

### Pattern 2: DNS-Rebinding Mitigation

The closure runs at connect time, after DNS resolution. An attacker who controls DNS for a host on the allowlist can rebind it to a different IP between resolution and connect. Mitigate:

```rust
builder.socket_addr_check(move |addr, addr_use| {
    let ip = addr.ip();
    // Refuse private IPs even if the hostname-based allowlist would normally pass.
    if is_private_ip(&ip) {
        return false;
    }
    if is_link_local(&ip) {
        return false;
    }
    // Refuse cloud-instance metadata addresses universally.
    if matches!(ip,
        IpAddr::V4(v4) if v4.octets() == [169, 254, 169, 254])
        || matches!(ip,
            IpAddr::V6(v6) if v6.segments()[0] == 0xfd00) {
        return false;
    }
    // Continue with normal allowlist...
    allowed_payments_tcp(addr)
});
```

A DNS-rebinding attack returns a private or metadata IP; the connect-time check refuses it. The legitimate connect to a public IP succeeds.

For higher assurance, lock the allowlist to specific IPs rather than hostnames. Hostnames can change (legitimately or maliciously); an IP allowlist is invariant.

### Pattern 3: TLS Enforcement at the Host

WASI sockets are byte streams. TLS is implemented inside the WASM module (e.g., via rustls compiled to WASM, or `wasi:tls` once it's stable). A module that doesn't enforce TLS sends data plaintext over the network, exposing it to passive observation.

For high-assurance deployments, route socket traffic through a host-side TLS terminator before it reaches the wire:

```rust
// Conceptually: the WASI socket connects to a localhost TLS proxy.
// The proxy decrypts the WASM-side TLS (if any), inspects, re-encrypts.
builder.socket_addr_check(|addr, _| {
    // Only allow connects to localhost; the TLS proxy is the egress.
    addr.ip().is_loopback()
});

// Spawn the local proxy that connects on the module's behalf.
// The proxy enforces the actual destination policy and does TLS.
```

This creates a man-in-the-middle for the module's traffic; legitimate for trust-boundary purposes (the embedder is the trust authority) but the module cannot establish E2E TLS to an arbitrary destination through the proxy.

For internal-only traffic where the proxy itself can be trusted, this is the right boundary. For modules that must establish E2E TLS to external services (banking APIs, third-party SaaS), the proxy approach is wrong; rely on the address-check filter and accept that TLS is the module's responsibility.

### Pattern 4: UDP Socket Policy

UDP is stateless; a per-packet policy is needed.

```rust
builder.udp_send_policy(|local, remote, packet_size| {
    // No outbound UDP at all by default.
    if !is_internal_dns(remote.ip()) { return false; }
    // DNS lookups: max 512 bytes.
    if remote.port() == 53 && packet_size > 512 { return false; }
    // No UDP except DNS.
    remote.port() == 53
});
```

For modules that need DNS resolution but no other UDP, this restricts to a specific use. For modules with broader UDP needs (NTP, custom protocols), explicit per-protocol allowance.

UDP amplification depends on spoofing the source — the attacker sends packets with the victim's IP as source. Wasmtime / WASI doesn't allow setting raw source IPs; the host-allocated source IP is the actual sender. So WASI UDP isn't directly weaponizable for amplification, but volume control still matters:

```rust
builder.udp_send_rate_limit(|tenant_id, packets_per_sec, bytes_per_sec| {
    // Bound aggregate UDP send.
    packets_per_sec < 1000 && bytes_per_sec < 1024 * 1024
});
```

### Pattern 5: Per-Tenant Socket Quotas

Limit the number of concurrent sockets and total bytes per tenant.

```rust
struct TenantSocketQuota {
    open_sockets: AtomicUsize,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl TenantSocketQuota {
    fn try_open(&self, max: usize) -> Option<SocketGuard> {
        let prev = self.open_sockets.fetch_add(1, Ordering::AcqRel);
        if prev >= max {
            self.open_sockets.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(SocketGuard { quota: self.clone() })
        }
    }
}
```

Wrap the WASI socket implementation to check the quota at open and release at close. Track bytes in / out for billing and abuse detection.

### Pattern 6: Audit Every Socket Operation

Per-socket telemetry:

```
wasm_socket_open_total{tenant, type, allowed}
wasm_socket_close_total{tenant, type}
wasm_socket_check_denied_total{tenant, reason}
wasm_socket_bytes_in_total{tenant, type}
wasm_socket_bytes_out_total{tenant, type}
wasm_socket_dns_queries_total{tenant}
```

Alert on:
- `wasm_socket_check_denied_total` rising — module attempting unauthorized destinations. Could be exploited or buggy.
- `wasm_socket_bytes_out_total` for one tenant disproportionate — possible exfil.
- `wasm_socket_open_total{type="udp"}` non-zero for a tenant that shouldn't use UDP — investigate.

### Pattern 7: TLS Cert-Pinning Inside the Module

Where E2E TLS is required, modules should pin certificates rather than trust system roots. A WASM module that uses `rustls` can be configured with a fixed root CA bundle.

```rust
// Inside the module (Rust + rustls compiled to WASM).
let mut root_store = rustls::RootCertStore::empty();
root_store.add(&rustls::Certificate(include_bytes!("../trusted-ca.pem").to_vec()))?;
let config = rustls::ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

The trust root is baked into the module bytecode; an attacker who substitutes a system-trusted CA cert cannot defeat the module's pinned trust.

## Expected Behaviour

| Signal | Default WASI sockets | Hardened |
|--------|------------------------|----------|
| Module connects to attacker IP | Succeeds if any TCP allowed | Blocked at address-check |
| DNS-rebinding to internal IP | Succeeds | Blocked at connect-time IP check |
| SSRF to instance metadata | Succeeds | Blocked at IP allowlist |
| UDP amplification source-spoof | Source IP allocated by host; spoofing impossible | Same; plus rate-limit |
| Per-tenant socket exhaustion | Possible | Bounded by per-tenant socket cap |
| Audit visibility | None | Per-tenant per-destination metrics |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| Per-tenant address-check closure | Fine-grained control | Closure runs on every connect; hot path | Closure is cheap (constant-time IP check); not a bottleneck. |
| IP allowlist over hostname | Defeats DNS rebinding | Must update allowlist when target IPs change | Combine: hostname allowlist for DNS resolution, IP check at connect (defense in depth). |
| TLS-terminator proxy | Strong host-side inspection | Modules can't establish E2E TLS through it | Use only for internal-trust-boundary scenarios. |
| UDP rate limit | Bounds amplification potential | Some legitimate workloads need higher rates | Per-tenant tier the limit. |
| Per-tenant socket quotas | Fairness across tenants | Operational overhead | Set defaults conservatively, raise per tenant on request. |
| Audit logging | Forensic visibility | Log volume per socket op | Sample at coarse rate for high-volume tenants. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Allowlist too narrow | Legitimate module fails connect | `wasm_socket_check_denied_total` rises for known-good tenant | Add the missing destination after verification. |
| DNS-rebinding allowlist update lag | New legitimate target IP not in allowlist | Connect fails; logs show allowlist mismatch | Refresh allowlist from DNS regularly; or use the address-check to allow on hostname after resolution. |
| Module bypasses TLS | Sensitive traffic on the wire as plaintext | Network observation reveals plaintext | Enforce via host-proxy pattern (Pattern 3) where viable; for E2E TLS, audit the module's TLS implementation. |
| Quota too low | Module crashes during legitimate burst | Quota-rejected counter rises with no apparent attacker | Profile; raise quota; add per-tier defaults. |
| UDP rate limit too aggressive | DNS resolution slow / fails | DNS query rate metrics; module logs show timeouts | Loosen UDP-to-port-53 specifically. |
| Network resource leak | Module doesn't drop sockets; per-tenant quota exhausts | `wasm_socket_open_total` > `wasm_socket_close_total` cumulatively | Wrap WASI socket bindings to enforce drop on Wasmtime resource cleanup. |
| Allowlist injection | An operator adds an overly-broad CIDR | Audit shows new CIDR doesn't match documented intent | Treat allowlist as code; review changes via PR; cap CIDR sizes. |

## Related Articles

- [WASI Preview 2 Capability-Based Security](/articles/wasm/wasi-preview-2-capabilities/)
- [Wasmtime Production Hardening](/articles/wasm/wasmtime-production-hardening/)
- [WASM Multi-Tenancy Patterns](/articles/wasm/wasm-multi-tenancy/)
- [Edge Runtime WASM Hardening](/articles/wasm/edge-wasm-hardening/)
- [WASI HTTP Server Hardening](/articles/wasm/wasi-http-server-hardening/)
