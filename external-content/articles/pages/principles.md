---
title: "Core Principles"
description: "The six principles behind every guide: production-first security, minimal attack surface, performance-aware hardening, observability, deterministic..."
layout: page.njk
permalink: /principles/index.html
published: true
---

# Core Principles

These principles govern every piece of content on this site.

## 1. Production-First Security

Every recommendation must be safe to apply to a running system. Staged rollout paths, rollback procedures, and clear preconditions. A hardening guide that requires a maintenance window for every change is a hardening guide that never gets applied.

## 2. Minimal Attack Surface

Remove what you do not need before hardening what remains. Disable unused services, close unnecessary ports, strip unneeded binaries. The most secure code is code that does not exist.

## 3. Performance-Aware Hardening

Security controls have runtime costs. We quantify them. TLS inspection adds latency. Syscall filtering adds overhead. Audit logging consumes disk I/O. You make informed trade-offs for your workload profile.

## 4. Observability as a Security Primitive

Prevention without detection is incomplete. Every hardening measure produces observable signals (logs, metrics, or traces) that confirm the control is active and functioning. If you cannot tell whether a security control is working, it is not working.

## 5. Deterministic Configurations

Ambiguity is the enemy of security. Configurations are explicit, reproducible, and version-controllable. No "it depends" without defined constraints. No "adjust to taste" without specifying the variables and their valid ranges.

## 6. Defence in Depth Through Layers, Not Duplication

Multiple layers of security are valuable only when each layer addresses a distinct failure mode. Running three WAFs in series is not defence in depth; it is operational overhead. Each control has a clear, non-overlapping purpose.
