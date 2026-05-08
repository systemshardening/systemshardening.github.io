---
title: "wasmCloud Security: Actor Authentication, Capability Providers, and Lattice Trust"
description: "wasmCloud's actor model isolates components behind capability contracts. Security rests on NKEY-based actor identity, lattice authentication via NATS, and OCI-signed actor distribution."
slug: "wasmcloud-security"
date: 2026-04-30
lastmod: 2026-04-30
category: "wasm"
tags: ["wasmcloud", "wasm", "nkeys", "lattice", "capability-providers"]
personas: ["platform-engineer", "security-engineer", "ml-engineer"]
article_number: 254
difficulty: "advanced"
estimated_reading_time: 13
published: true
layout: article.njk
permalink: "/articles/wasm/wasmcloud-security/index.html"
---

# wasmCloud Security: Actor Authentication, Capability Providers, and Lattice Trust

## Problem

wasmCloud runs WebAssembly actors (components) across a distributed lattice — a cluster of wasmCloud hosts connected via NATS messaging. Each actor is isolated behind a capability contract: it can only invoke capabilities (HTTP client, key-value store, blob store, messaging) that are explicitly linked at runtime by an operator. No capability, no access.

This default-deny capability model is wasmCloud's primary security advantage over traditional microservice architectures. An actor cannot open a socket, write to disk, or call an external API unless a capability provider link is established.

The security model is only as strong as its trust infrastructure:

- **NKEY authentication.** Actors, providers, and hosts are identified by Ed25519 NKEY pairs. If a private NKEY is leaked, an attacker can impersonate any identity in the lattice.
- **Lattice authentication.** All inter-host communication transits NATS. Without NATS credential files and JWT-based authentication, the lattice is unauthenticated.
- **OCI actor distribution.** Actors are distributed as OCI artifacts. Without signature verification at load time, a tampered actor image is indistinguishable from a legitimate one.
- **Capability link configuration.** Links between actors and providers are established by operators. A misconfigured link grants an actor capabilities beyond its intended scope.
- **Account and operator hierarchy.** wasmCloud uses a chain of trust: Operator keys sign Account keys, Account keys sign Actor/Provider/Host keys. If the operator key is compromised, all downstream trust is broken.

By 2026, wasmCloud is deployed in multi-tenant serverless platforms, edge computing, and as the runtime for AI agent tooling. The blast radius of a trust compromise scales with the deployment breadth.

**Target systems:** wasmCloud 1.0+; NATS 2.10+ with JetStream; wash (wasmCloud shell) 0.27+; wasmcloud-operator 0.3+ (Kubernetes); cosign 2.4+ for actor signing.

## Threat Model

- **Adversary 1 — NKEY private key theft:** An attacker obtains an actor's private NKEY from a compromised host, build server, or leaked secret. They sign arbitrary actor JWTs that the lattice trusts.
- **Adversary 2 — Unauthenticated lattice access:** A wasmCloud lattice uses NATS without authentication. An attacker on the internal network subscribes to NATS subjects, intercepting lattice control messages and actor RPC calls.
- **Adversary 3 — Tampered OCI actor image:** An attacker substitutes a backdoored actor image in the OCI registry. Without signature verification, wasmCloud loads and runs it.
- **Adversary 4 — Capability link escalation:** An operator accidentally links an untrusted user-facing actor to the key-value provider for the payments namespace. The actor now has read/write access to payment data.
- **Adversary 5 — Operator key compromise:** The top-level operator NKEY is compromised. The attacker issues new account and actor credentials, gaining control of the entire lattice.
- **Access level:** Adversary 1 has file system access on a host or build server. Adversary 2 has internal network access. Adversary 3 has OCI registry write access. Adversary 4 is a legitimate operator with a misconfiguration. Adversary 5 has access to the operator key material.
- **Objective:** Run arbitrary code in the lattice, intercept actor RPC calls, exfiltrate data through mislinked capabilities.
- **Blast radius:** NKEY compromise = impersonation of all actors signed by that key. Operator key compromise = control of entire account's trust chain. Misconfigured capability link = data exfiltration from a capability the actor shouldn't have.

## Configuration

### Step 1: Generate and Protect NKEYs

wasmCloud uses Ed25519 NKEYs for all identity. The key hierarchy:

```
Operator NKEY (top level; sign account keys)
└── Account NKEY (sign actor/provider/host keys)
    ├── Actor NKEYs (per-actor identity)
    ├── Provider NKEYs (per-provider instance)
    └── Host NKEYs (per-wasmCloud host)
```

```bash
# Install nk (NKEY CLI tool).
cargo install nkeys --features cli

# Generate the operator key pair (protect this like a root CA private key).
nk gen operator
# Output:
# Public Key: Oxxxxxxxxxxxxxxxxxxxxxxxx   (starts with O = Operator)
# Seed: SOxxxxxxxxxxxxxxxxxxxxxxxx       (starts with SO = Seed Operator; KEEP PRIVATE)

# Generate account key pair.
nk gen account
# Public Key: Axxxxxxxxxxxxxxxxxxxxxxxx   (A = Account)
# Seed: SAxxxxxxxxxxxxxxxxxxxxxxxx

# Generate actor key pair (one per actor).
nk gen module
# Public Key: Mxxxxxxxxxxxxxxxxxxxxxxxx   (M = Module/Actor)
# Seed: SMxxxxxxxxxxxxxxxxxxxxxxxx

# Generate host key pair (one per wasmCloud host).
nk gen server
# Public Key: Nxxxxxxxxxxxxxxxxxxxxxxxx   (N = Server/Host)
# Seed: SNxxxxxxxxxxxxxxxxxxxxxxxx
```

Store seeds in a secrets manager — never in source code or environment variables:

```bash
# Store in HashiCorp Vault.
vault kv put secret/wasmcloud/operator seed="SOxxxxxxx"
vault kv put secret/wasmcloud/account seed="SAxxxxxxx"

# Retrieve at deployment time (never persist to disk).
OPERATOR_SEED=$(vault kv get -field=seed secret/wasmcloud/operator)
```

### Step 2: Sign Actors with wash and cosign

Actors must be signed to be loadable in the wasmCloud lattice. The actor JWT embeds:

- The actor's public key (from its NKEY)
- Declared capability claims (what the actor is allowed to use)
- Signing key chain (account key signed by operator key)
- Expiry (optional but recommended)

```bash
# Build the actor WASM component.
wash build

# Sign the actor.
# The signed actor embeds a JWT that the host verifies at load time.
wash claims sign ./target/wasm32-wasip2/release/my_actor.wasm \
  --name "payments-processor" \
  --version 1.2.3 \
  --rev 1 \
  --issuer $(vault kv get -field=seed secret/wasmcloud/account) \
  --subject $(vault kv get -field=seed secret/wasmcloud/actor-payments) \
  --cap wasmcloud:httpserver \
  --cap wasmcloud:keyvalue \
  --expires-in-days 90 \
  -o payments-processor_s.wasm

# Verify the signed actor.
wash claims inspect payments-processor_s.wasm
# Output shows: issuer, subject, capabilities, expiry.
```

Additionally sign the OCI image with cosign for registry-level integrity:

```bash
# Push the signed actor as an OCI artifact.
wash push ghcr.io/myorg/payments-processor:v1.2.3 payments-processor_s.wasm

# Sign the OCI artifact with cosign (keyless).
cosign sign --yes ghcr.io/myorg/payments-processor:v1.2.3
```

Configure wash to verify cosign signatures before loading:

```yaml
# wasmcloud.yaml
actor_signing:
  required: true
  verify_cosign: true
  cosign_policy:
    certificate_identity: "https://github.com/myorg/wasmcloud-actors/.github/workflows/build.yml@refs/heads/main"
    certificate_oidc_issuer: "https://token.actions.githubusercontent.com"
```

### Step 3: Authenticate the NATS Lattice

All wasmCloud hosts communicate via NATS. Secure the NATS cluster:

```conf
# nats-server.conf
port: 4222

# TLS for client connections.
tls {
  cert_file: "/etc/nats/tls/server.crt"
  key_file:  "/etc/nats/tls/server.key"
  ca_file:   "/etc/nats/tls/ca.crt"
  verify:    true   # Require client TLS.
}

# NATS account/user authentication via decentralised JWT (NKEYs).
operator: "/etc/nats/operator.jwt"

# System account for internal monitoring.
system_account: SYS

# Resolver for account JWTs.
resolver: {
  type: full
  dir: "/etc/nats/accounts"
}
```

Generate NATS credentials for wasmCloud hosts:

```bash
# Using nsc (NATS security credentials tool).
nsc add operator --name wasmcloud-lattice
nsc add account --name wasmcloud-account
nsc add user --name wasmcloud-host-1
nsc generate creds --name wasmcloud-host-1 > host-1.creds

# Each host gets its own credential file.
nsc generate creds --name wasmcloud-host-2 > host-2.creds
```

Configure wasmCloud hosts with the credential file:

```bash
wasmcloud --nats-credsfile /etc/wasmcloud/host-1.creds \
          --nats-host nats.internal:4222 \
          --lattice-prefix prod-lattice
```

### Step 4: Capability Link Policy

Capability links are the policy enforcement point. Define which actors can use which providers with which configuration:

```bash
# Link the payments actor to the KV store — with a specific bucket configuration.
wash link put \
  Mxxxxxxx-payments-actor-key \
  Vxxxxxxx-kv-provider-key \
  wasmcloud:keyvalue \
  values='{"bucket":"payments-data","prefix":"pay:"}'

# The KV provider enforces the bucket configuration:
# the payments actor can only read/write keys prefixed with "pay:" in "payments-data".
# It cannot access any other bucket.
```

Enumerate and audit all links periodically:

```bash
# List all active capability links in the lattice.
wash get links

# Output:
# Actor ID | Provider ID | Contract ID | Link Name | Values
# Mxxxxxx  | Vxxxxxx     | wasmcloud:keyvalue | default | {"bucket":"payments-data"}
# Mxxxxxx  | Vxxxxxx     | wasmcloud:httpserver | default | {"address":"0.0.0.0:8080"}

# Any link not in the approved list should be investigated and removed.
wash remove link <actor-key> <contract-id> <link-name>
```

Enforce link policy with OPA (using wash's policy hooks):

```rego
# link_policy.rego
package wasmcloud.links

default allow = false

allow {
  input.actor_public_key == known_actors[_]
  input.provider_contract == "wasmcloud:keyvalue"
  input.link_values.bucket in allowed_buckets[input.actor_public_key]
}

known_actors = {"Mxxxxxx-payments-actor"}
allowed_buckets = {
  "Mxxxxxx-payments-actor": {"payments-data"}
}
```

### Step 5: Host-Level Security Configuration

```bash
# Run wasmCloud with policy server enforcement.
wasmcloud \
  --policy-service-endpoint http://opa.internal:8181/v1/data/wasmcloud \
  --nats-credsfile /etc/wasmcloud/host.creds \
  --host-seed $(vault kv get -field=seed secret/wasmcloud/hosts/host-1) \
  --allow-file-load false \         # Actors loaded from OCI only; no local filesystem.
  --lattice-prefix prod \
  --js-domain wasmcloud              # JetStream domain for state persistence.
```

On Kubernetes via wasmcloud-operator:

```yaml
apiVersion: core.oam.dev/v1beta1
kind: WasmCloudHostConfig
metadata:
  name: prod-host-config
  namespace: wasmcloud
spec:
  lattice: prod
  secretName: wasmcloud-nats-creds    # Kubernetes Secret with NATS credentials.
  hostLabels:
    region: us-east-1
    environment: production
  policyService: http://opa-policy.security.svc.cluster.local:8181/v1/data/wasmcloud
  registryCredentialSecretName: wasmcloud-registry-creds

  podSpec:
    securityContext:
      runAsNonRoot: true
      seccompProfile:
        type: RuntimeDefault
    containers:
      - name: wasmcloud-host
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: [ALL]
```

### Step 6: Actor Capability Claims Minimisation

When signing actors, declare only the capabilities the actor uses. The wasmCloud host rejects links to undeclared capabilities:

```bash
# Minimal capability set for a read-only API actor.
wash claims sign my-api-actor.wasm \
  --cap wasmcloud:httpserver \        # Receive HTTP requests.
  --cap wasmcloud:keyvalue \          # Read cache.
  # NOT: wasmcloud:blobstore         # Actor doesn't write files.
  # NOT: wasmcloud:messaging         # Actor doesn't produce messages.
  --name "api-read-only" \
  --issuer $ACCOUNT_SEED \
  --subject $ACTOR_SEED

# If an operator tries to link this actor to the blob store:
# Error: actor does not have capability claim for wasmcloud:blobstore
```

### Step 7: Rotate NKEYs and Actor Signing Keys

```bash
# Rotate an actor NKEY when the seed is suspected compromised.
# 1. Generate a new actor key pair.
nk gen module > new-actor.nkey

# 2. Re-sign the actor with the new key.
wash claims sign my-actor.wasm \
  --subject $(cat new-actor.nkey | grep Seed | awk '{print $2}') \
  --issuer $ACCOUNT_SEED \
  [other flags] \
  -o my-actor-new-key_s.wasm

# 3. Push the re-signed actor to the OCI registry.
wash push ghcr.io/myorg/my-actor:v1.2.4 my-actor-new-key_s.wasm

# 4. Update the running lattice to use the new actor version.
wash update actor <host-id> <old-actor-public-key> ghcr.io/myorg/my-actor:v1.2.4

# 5. Update all capability links from the old public key to the new one.
wash remove link <old-actor-public-key> wasmcloud:keyvalue default
wash link put <new-actor-public-key> <provider-key> wasmcloud:keyvalue default

# 6. Revoke the old NKEY by removing it from the account's trust list.
nsc revoke add user --name old-actor-key-name
```

### Step 8: Telemetry

```
wasmcloud_actor_starts_total{actor_name, host_id}            counter
wasmcloud_actor_invocations_total{actor, provider, contract} counter
wasmcloud_actor_errors_total{actor, error_type}              counter
wasmcloud_link_established_total{actor, provider, contract}  counter
wasmcloud_link_removed_total{actor, provider, contract}      counter
wasmcloud_host_up{host_id, lattice}                          gauge
nats_auth_failure_total{server, client}                      counter
wasmcloud_policy_denial_total{actor, capability}             counter
```

Alert on:

- `nats_auth_failure_total` — NATS credential failure; possible key compromise or misconfiguration.
- `wasmcloud_policy_denial_total` — link attempted with an undeclared capability; investigate the actor deployment.
- `wasmcloud_actor_errors_total` spike — unexpected actor failure; possible capability misconfiguration or actor bug.
- `wasmcloud_link_established_total` for unexpected actor/provider pairs — unauthorised link; remove and audit.

## Expected Behaviour

| Signal | Default wasmCloud | Hardened wasmCloud |
|--------|------------------|-------------------|
| Unauthenticated NATS access | Allowed if no auth configured | NATS credentials required; connection rejected |
| Unsigned actor loaded | Loaded without verification | Rejected; JWT signature required |
| Actor uses undeclared capability | Link established; actor uses it | Link rejected; actor lacks the capability claim |
| OCI image tampered | Loaded silently | cosign verification fails; actor not started |
| NKEY seed leaked | Attacker can impersonate any actor | Rotate seed; re-sign actors; old key revoked |
| Capability link to wrong bucket | Actor accesses all buckets | Provider enforces configuration; only declared bucket accessible |

## Trade-offs

| Aspect | Benefit | Cost | Mitigation |
|--------|---------|------|------------|
| NKEY identity for all components | Cryptographic identity; no shared secrets | Key generation and rotation overhead | Automate via wash and Vault; treat NKEYs like TLS certificates. |
| Signed actors with capability claims | Host refuses undeclared capabilities | Actor re-sign required after capability change | Build signing into CI; re-sign on every release automatically. |
| Policy server enforcement | Link-level policy; OPA for complex rules | Additional latency per link establishment | Links are established at deploy time, not per-request; latency is one-time. |
| NATS JWT authentication | Decentralised; no single secret file | nsc tooling complexity | Document key generation; use nsc push to a NATS resolver for centralised management. |
| cosign actor verification | OCI-level integrity | Requires OIDC CI pipeline for keyless signing | Reuses Sigstore infrastructure already in place for container signing. |

## Failure Modes

| Failure | Symptom | Detection | Recovery |
|---------|---------|-----------|----------|
| Actor signing key seed leaked | Attacker can sign actors with the compromised identity | Unexpected actor versions in the lattice | Rotate the actor NKEY; re-sign all actors; revoke old key in the account. |
| NATS credential expired | wasmCloud host cannot connect to lattice | Host disappears from `wash get hosts`; actor invocations fail | Rotate NATS credentials; update the host's creds file or Kubernetes Secret. |
| OCI cosign verification fails | Actor fails to start on host | Host logs show `cosign verification failed`; actor count drops | Verify the actor was signed in CI; check cosign policy configuration. |
| Misconfigured capability link | Actor has access to wrong bucket/topic | Data anomalies in unrelated services | Remove the incorrect link; add correct link; audit all links after incidents. |
| Operator key compromised | All downstream actors/accounts can be spoofed | Unusual actor activity; unexpected key identities in lattice | Emergency: rotate operator key; re-issue all account and actor keys; re-sign all actors. |
| Policy server unreachable | Link establishment blocked (fail-closed) | `wasmcloud_policy_denial_total` spike; actors cannot start | Restore policy server; or configure fail-open temporarily (document the risk). |

## Related Articles

- [WASM on Kubernetes with SpinKube and wasmCloud](/articles/wasm/wasm-on-kubernetes/)
- [WASM Multi-Tenancy Patterns](/articles/wasm/wasm-multi-tenancy/)
- [Spin Framework Security](/articles/wasm/spin-framework-security/)
- [WASM OCI Module Signing and Verification](/articles/wasm/wasm-oci-signing/)
- [SPIFFE/SPIRE Workload Identity](/articles/cross-cutting/spiffe-spire-workload-identity/)
