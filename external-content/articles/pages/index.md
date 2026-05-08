---
title: "systemshardening.com"
description: "Production-ready hardening guides for Linux, Kubernetes, networking, CI/CD, observability, AI workloads, and WebAssembly. Threat models, configs, trade-offs."
layout: page.njk
permalink: /index.html
published: true
---

# Hardening Real Systems in Production

Practical, production-ready hardening guides for engineers who actually run systems. Every article includes complete configurations, quantified trade-offs, and documented failure modes.

## What You'll Find Here

- **Linux / OS Hardening:** sysctl, [systemd](https://systemd.io) sandboxing, [SELinux](https://github.com/SELinuxProject/selinux), [AppArmor](https://apparmor.net), SSH, PAM, firewalls, audit logging
- **[Kubernetes](https://kubernetes.io) / Platform:** network policies, admission control, RBAC, seccomp, runtime detection, node hardening
- **Network & API Security:** [NGINX](https://nginx.org), [Envoy](https://www.envoyproxy.io), [HAProxy](https://www.haproxy.org), [Traefik](https://traefik.io), TLS, DNS, rate limiting, mTLS, WAF, gRPC, API gateways, request smuggling prevention
- **CI/CD & Supply Chain:** runner security, GitHub Actions, [Helm](https://helm.sh) chart signing, SLSA provenance, SBOM, dependency pinning, [Terraform](https://www.terraform.io), container registry hardening, GitOps security, artifact integrity
- **Observability & Detection:** audit log pipelines, [Prometheus](https://prometheus.io) security metrics, [Falco](https://falco.org), [Tetragon](https://tetragon.io), [OpenTelemetry](https://opentelemetry.io) Collector hardening, incident response runbooks, dashboards
- **AI & Security Landscape:** threat model evolution, AI agent security, [Claude](https://claude.ai) for security detection, prompt injection, model serving hardening, LLM jailbreak defence, MCP server security, EU AI Act compliance, red teaming, AI governance pipelines
- **Cross-Cutting Guides:** [PostgreSQL](https://www.postgresql.org) and [Redis](https://redis.io) hardening, [HashiCorp Vault](https://www.vaultproject.io), [SPIFFE](https://spiffe.io)/SPIRE workload identity, zero-trust networking, post-quantum migration, threat modeling at scale, secrets rotation, incident response, compliance-as-code
- **WebAssembly:** [Wasmtime](https://wasmtime.dev) hardening, [Spin](https://www.fermyon.com/spin) and [wasmCloud](https://wasmcloud.com) on Kubernetes, [WASI](https://wasi.dev) Preview 2 capabilities, [Envoy](https://www.envoyproxy.io) and [NGINX](https://nginx.org) WASM plugins, edge runtimes ([Cloudflare Workers](https://workers.cloudflare.com), [Fastly Compute](https://www.fastly.com/products/edge-compute)), OCI signing, multi-tenancy, IoT and embedded deployment

## How We Write

Every article follows the same structure:

1. **Problem:** what is the specific risk
2. **Threat Model:** who is the adversary, what do they want
3. **Configuration:** complete, copy-pasteable commands and configs
4. **Expected Behaviour:** how to verify it works
5. **Trade-offs:** what it costs (performance, complexity, compatibility)
6. **Failure Modes:** what breaks, how to detect it, how to fix it

No fluff. No "it depends" without constraints. No pseudocode.

[Browse all articles](/articles/)
